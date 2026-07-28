### A Pluto.jl notebook ###
# v0.19.40

using Markdown
using InteractiveUtils

# ╔═╡ e5cb4932-16b8-40ff-95d5-693813b15678
md"""
# Digital Legacy Protocol — A Formal Mathematical Analysis

Companion notebook to `README.md`, `WHITEPAPER.md`, `spec/SPEC.md`, `MANIFESTO.md`, and `docs/ARCHITECTURE.md`.

Every other document in this repository argues *why* the protocol is sound, or *what* it commits to.
This notebook asks a narrower, harder question: what can actually be **proven, computed, or simulated**
about it, and what is the theoretical and practical ceiling this design could be pushed toward.

Depends only on Julia's standard library — `Random`, `LinearAlgebra`, `Printf`, `Statistics` — the same
dependency-light posture the reference Python implementation holds for `dlp/shamir.py` and `dlp/crypto.py`.

**Structure**
1. GF(256) field arithmetic — faithful port of `dlp/shamir.py`
2. Shamir's Secret Sharing — split / reconstruct
3. Gaussian elimination over GF(256) — general linear solver
4. Perfect secrecy, demonstrated — not asserted, computed
5. Quorum reliability model — false-positive / false-negative
6. Switch state machine as a Markov chain
7. Monte Carlo validation of Parts 5 and 6
8. Computational complexity of the reference implementation
9. Maturity roadmap — what level this protocol can reach

*A note on scope:* Parts 1–3 are a direct, checkable port of the Python reference implementation's
algorithm, not a reinterpretation of it. Parts 5–6 are formal **models** of the protocol's dynamics —
the probabilities and transition rates are named parameters, not measured real-world values.
"""

# ╔═╡ faba2256-f823-4f71-87a4-e28d56b9ac01
using Random, LinearAlgebra, Printf, Statistics

# ╔═╡ 517ac829-55d3-4f74-beb1-b41fc5a53d57
md"""
## Part 1 — GF(256) Field Arithmetic

Ported directly from `dlp/shamir.py`'s `_init_tables`, `gf_mul`, `gf_div`, `gf_pow`. The field is
GF(2⁸) reduced by the AES polynomial x⁸+x⁴+x³+x+1 (`0x11B` = 283 decimal), using generator **3** —
not 2, which is not primitive for this particular reduction polynomial and would silently produce
a degenerate table.
"""

# ╔═╡ 5765199e-5d08-4c68-ba3c-101ae432dabf
function init_gf_tables()
    exp_table = zeros(Int, 512)
    log_table = zeros(Int, 256)
    reduction_poly = 283  # 0x11B
    p = 1
    for i in 0:254
        exp_table[i + 1] = p
        log_table[p + 1] = i
        xtime = (p & 128) != 0 ? xor(p << 1, reduction_poly) : (p << 1)
        p = xor(xtime, p) & 255
    end
    for i in 255:511
        exp_table[i + 1] = exp_table[i - 255 + 1]
    end
    return exp_table, log_table
end

# ╔═╡ de7d11ca-2d17-461d-a1f1-7785ad0490d9
const GF_EXP, GF_LOG = init_gf_tables()

# ╔═╡ 5d2d8adb-511e-42ff-be30-e4a8fda1e105
begin
	gf_mul(a::Int, b::Int)::Int = (a == 0 || b == 0) ? 0 : GF_EXP[GF_LOG[a + 1] + GF_LOG[b + 1] + 1]

	function gf_div(a::Int, b::Int)::Int
	    a == 0 && return 0
	    b == 0 && throw(DivideError())
	    return GF_EXP[mod(GF_LOG[a + 1] - GF_LOG[b + 1], 255) + 1]
	end

	function gf_pow(a::Int, power::Int)::Int
	    power == 0 && return 1
	    a == 0 && return 0
	    return GF_EXP[mod(GF_LOG[a + 1] * power, 255) + 1]
	end

	gf_add(a::Int, b::Int)::Int = xor(a, b)  # addition == subtraction in GF(2^n)

	function eval_poly(coeffs::Vector{Int}, x::Int)::Int
	    result = 0
	    for c in reverse(coeffs)
	        result = xor(gf_mul(result, x), c)
	    end
	    return result
	end
end

# ╔═╡ 498c3984-1d78-49f7-80ce-ac39fd1a26d6
let
	a, b = 83, 202
	mul = gf_mul(a, b)
	div_back = gf_div(mul, b)
	(a=a, b=b, a_times_b=mul, division_recovers_a=(div_back == a))
end

# ╔═╡ 3cf11134-5765-43f9-993b-f633110273eb
md"""
## Part 2 — Shamir's Secret Sharing

`split_secret` builds one random degree-`(threshold-1)` polynomial per secret byte, with the byte
itself as the constant term, then evaluates it at `x = 1, 2, ..., n` — one point per trustee.
`reconstruct_secret` recovers the constant term via Lagrange interpolation at `x = 0`, entirely
in GF(256) arithmetic (XOR in place of +/-, table lookups in place of ordinary multiplication).
"""

# ╔═╡ 3a49bd86-8322-4d88-93a5-44335d97d8b7
struct Share
    index::Int
    trustee_id::String
    data::Vector{Int}
end

# ╔═╡ c16e11ee-c99c-4fa7-afe5-3082ca844db5
function split_secret(secret::Vector{Int}, threshold::Int, trustee_ids::Vector{String};
                       rng = Random.default_rng())::Vector{Share}
    n = length(trustee_ids)
    threshold < 2 && throw(ArgumentError("threshold must be >= 2"))
    threshold > n && throw(ArgumentError("threshold cannot exceed number of trustees"))
    n >= 255 && throw(ArgumentError("maximum 254 trustees supported"))
    isempty(secret) && throw(ArgumentError("secret must not be empty"))

    xs = collect(1:n)
    share_bytes = [Int[] for _ in 1:n]

    for secret_byte in secret
        coeffs = vcat([secret_byte], [rand(rng, 0:255) for _ in 1:(threshold - 1)])
        for (i, x) in enumerate(xs)
            push!(share_bytes[i], eval_poly(coeffs, x))
        end
    end

    return [Share(xs[i], trustee_ids[i], share_bytes[i]) for i in 1:n]
end

# ╔═╡ 3d4322ae-61d7-478e-af73-e7bd9e4e8800
function reconstruct_secret(shares::Vector{Share})::Vector{Int}
    length(shares) < 2 && throw(ArgumentError("need at least 2 shares to reconstruct"))
    lengths = Set(length(s.data) for s in shares)
    length(lengths) != 1 && throw(ArgumentError("all shares must encode equal-length secrets"))
    secret_len = first(lengths)

    xs = [s.index for s in shares]
    length(Set(xs)) != length(xs) && throw(ArgumentError("duplicate share indices"))

    out = zeros(Int, secret_len)
    for byte_pos in 1:secret_len
        ys = [s.data[byte_pos] for s in shares]
        acc = 0
        for i in eachindex(xs)
            xi, yi = xs[i], ys[i]
            num, den = 1, 1
            for j in eachindex(xs)
                if i != j
                    xj = xs[j]
                    num = gf_mul(num, xj)
                    den = gf_mul(den, xor(xi, xj))
                end
            end
            acc = xor(acc, gf_mul(yi, gf_div(num, den)))
        end
        out[byte_pos] = acc
    end
    return out
end

# ╔═╡ b7b26548-6539-4c16-8d57-f329ea793226
let
	trustee_ids = ["t1", "t2", "t3", "t4", "t5"]
	secret_bytes = [0x44, 0x4C, 0x50] .|> Int  # "DLP" as bytes
	shares = split_secret(secret_bytes, 3, trustee_ids)
	recovered = reconstruct_secret(shares[[1, 3, 5]])  # any 3 of 5
	(original=secret_bytes, recovered_from_3_of_5=recovered, matches=(recovered == secret_bytes))
end

# ╔═╡ a6cafa2d-6943-4e98-a43e-79e663b1d599
md"""
## Part 3 — Gaussian Elimination over GF(256)

A general k×k linear solver over GF(256), used in Part 4 to test, for every candidate secret byte,
whether a consistent polynomial exists given a set of known shares. Returns `nothing` if the system
is singular.
"""

# ╔═╡ 9e1190e7-83e7-44dc-8eb4-e715d035500b
function gf_gaussian_solve(A::Matrix{Int}, b::Vector{Int})::Union{Vector{Int},Nothing}
    k = length(b)
    M = hcat(copy(A), reshape(copy(b), k, 1))  # k x (k+1) augmented matrix

    row = 1
    for col in 1:k
        pivot = findfirst(r -> M[r, col] != 0, row:k)
        pivot === nothing && return nothing
        pivot += row - 1
        if pivot != row
            tmp = M[row, :]
            M[row, :] = M[pivot, :]
            M[pivot, :] = tmp
        end
        pivot_val = M[row, col]
        for c in col:(k + 1)
            M[row, c] = gf_div(M[row, c], pivot_val)
        end
        for r in 1:k
            if r != row && M[r, col] != 0
                factor = M[r, col]
                for c in col:(k + 1)
                    M[r, c] = xor(M[r, c], gf_mul(factor, M[row, c]))
                end
            end
        end
        row += 1
    end
    return M[:, k + 1]
end

# ╔═╡ 69b60edd-2d29-4cf6-812f-d2ba030a0102
md"""
## Part 4 — Perfect Secrecy, Demonstrated

`SECURITY.md` states that Shamir's Secret Sharing below threshold reveals **zero information** —
information-theoretic, not just computationally hard. This part does not merely assert that; it
computes it.

**Claim:** given any `(threshold - 1)` shares, every one of the 256 possible byte values is equally
consistent with those shares as the "true" secret. The known shares impose `(threshold - 1)` linear
equations in `(threshold - 1)` unknown non-constant coefficients (the constant term is fixed to the
candidate secret being tested). The coefficient matrix is a scaled Vandermonde-type matrix in
distinct nonzero field elements, so it is provably nonsingular — the cell below confirms this holds
for all 256 candidates rather than relying on that argument alone.
"""

# ╔═╡ b95da1d7-821e-41ca-9f2a-429e63756894
function verify_perfect_secrecy(threshold::Int, n_trustees::Int; rng = Random.default_rng())
    trustee_ids = ["t$(i)" for i in 1:n_trustees]
    true_secret = rand(rng, 0:255)
    shares = split_secret([true_secret], threshold, trustee_ids; rng = rng)

    known = shares[1:(threshold - 1)]  # exactly one share short of threshold
    xs_known = [s.index for s in known]
    ys_known = [s.data[1] for s in known]
    k = threshold - 1

    consistent_secrets = Int[]
    for candidate_secret in 0:255
        A = zeros(Int, k, k)
        b = zeros(Int, k)
        for (row, (xi, yi)) in enumerate(zip(xs_known, ys_known))
            for col in 1:k
                A[row, col] = gf_pow(xi, col)
            end
            b[row] = xor(yi, candidate_secret)
        end
        solution = gf_gaussian_solve(A, b)
        solution !== nothing && push!(consistent_secrets, candidate_secret)
    end

    return true_secret, consistent_secrets
end

# ╔═╡ 4d834602-78bb-470d-a356-d89bd817bda9
let
	results = NamedTuple[]
	for (threshold, n) in [(2, 3), (3, 5), (5, 9)]
		true_secret, consistent = verify_perfect_secrecy(threshold, n)
		push!(results, (threshold=threshold, n_trustees=n, true_secret=true_secret,
		                 consistent_candidates=length(consistent),
		                 perfect_secrecy_holds=(length(consistent) == 256)))
	end
	results
end

# ╔═╡ 19b6a473-9396-42bd-abb6-ad3bfa383388
md"""
## Part 5 — Quorum Reliability Model

`spec/SPEC.md`'s activation state machine is deliberately asymmetric: a single trustee attesting
"reachable" aborts activation, while activation itself requires `threshold` trustees to positively
attest "unreachable." This part formalizes what that asymmetry buys, in closed form.
"""

# ╔═╡ 03fa665e-b451-4c27-8e55-af867ea70d4f
begin
	"""
	    false_positive_probability(individual_error_rate, n_trustees)

	Probability the system wrongly activates while the owner is alive.
	Requires ALL `n_trustees` to independently make the same (rare) mistake
	of attesting "unreachable" — because a single correct "reachable"
	attestation aborts the process. This is what makes the false-positive
	rate fall EXPONENTIALLY in the number of trustees, not linearly.
	"""
	false_positive_probability(individual_error_rate::Float64, n_trustees::Int)::Float64 =
	    individual_error_rate^n_trustees

	"""
	    false_negative_probability(individual_reliability, n_trustees, threshold)

	Probability the system fails to activate though the owner is, in fact,
	gone: the classical k-out-of-n reliability formula — probability that
	fewer than `threshold` of `n_trustees` correctly attest "unreachable,"
	each independently correct with probability `individual_reliability`.
	"""
	function false_negative_probability(individual_reliability::Float64, n_trustees::Int, threshold::Int)::Float64
	    total = 0.0
	    for k in 0:(threshold - 1)
	        total += binomial(n_trustees, k) *
	                 individual_reliability^k *
	                 (1 - individual_reliability)^(n_trustees - k)
	    end
	    return total
	end
end

# ╔═╡ 8505a4fa-8363-4c69-85d9-6201a92c2aab
let
	fp_results = [(n_trustees=n, per_trustee_error=0.01, system_false_positive=false_positive_probability(0.01, n))
	              for n in [1, 3, 5, 9]]
	fp_results
end

# ╔═╡ 31246851-9b90-4b28-b783-496fbe0190c0
let
	fn_results = [(n_trustees=n, threshold=thr, per_trustee_reliability=0.95,
	               system_false_negative=false_negative_probability(0.95, n, thr))
	              for (n, thr) in [(3, 2), (5, 3), (9, 5)]]
	fn_results
end

# ╔═╡ 9f26b921-6802-4475-ba64-b0ee1aa0fe26
md"""
## Part 6 — The Switch State Machine as an Absorbing Markov Chain

`dlp/switch.py`'s five states — `ACTIVE`, `OVERDUE`, `VERIFICATION`, `ACTIVATED`, `ABORTED` — form a
discrete-time chain with two absorbing states (`ACTIVATED`, `ABORTED`). This part builds the
transition matrix and computes, via the fundamental-matrix method, the expected number of periods to
absorption and the probability of ending in each absorbing state, as a function of named per-period
parameters.

These parameters are illustrative, not measured — the point is that the chain's long-run behavior is
fully determined once they are supplied, which is itself a useful property for anyone tuning
`interval_days` / `grace_days` against a real trustee population.
"""

# ╔═╡ acf8fcf2-584b-40fa-9ff7-d1b892eb84d0
function switch_markov_chain(;
    p_owner_checks_in::Float64 = 0.97,                    # ACTIVE -> ACTIVE
    p_owner_recovers::Float64 = 0.60,                     # OVERDUE -> ACTIVE
    p_grace_expires::Float64 = 0.30,                      # OVERDUE -> VERIFICATION
    p_owner_returns_during_verification::Float64 = 0.40,  # VERIFICATION -> ABORTED
    p_quorum_confirms::Float64 = 0.50,                    # VERIFICATION -> ACTIVATED
)
    # State order: 1=ACTIVE 2=OVERDUE 3=VERIFICATION 4=ACTIVATED 5=ABORTED
    P = zeros(Float64, 5, 5)

    P[1, 1] = p_owner_checks_in
    P[1, 2] = 1 - p_owner_checks_in

    P[2, 1] = p_owner_recovers
    P[2, 3] = p_grace_expires
    P[2, 2] = 1 - p_owner_recovers - p_grace_expires

    P[3, 5] = p_owner_returns_during_verification
    P[3, 4] = p_quorum_confirms
    P[3, 3] = 1 - p_owner_returns_during_verification - p_quorum_confirms

    P[4, 4] = 1.0  # ACTIVATED is absorbing
    P[5, 5] = 1.0  # ABORTED is absorbing

    return P
end

# ╔═╡ eeb4955f-98b3-4e60-baed-f53337d63480
function absorption_analysis(P::Matrix{Float64})
    transient = 1:3
    absorbing = 4:5
    Q = P[transient, transient]
    R = P[transient, absorbing]
    Ik = Matrix{Float64}(I, 3, 3)
    N = inv(Ik - Q)               # fundamental matrix
    expected_steps = N * ones(3)  # expected periods to absorption per starting state
    absorption_probs = N * R      # columns: P(end ACTIVATED), P(end ABORTED)
    return N, expected_steps, absorption_probs
end

# ╔═╡ 3471068a-ac34-4586-83c7-d3a97cf08de9
let
	P = switch_markov_chain()
	_, expected_steps, absorption_probs = absorption_analysis(P)
	state_names = ["ACTIVE", "OVERDUE", "VERIFICATION"]
	[(from=state_names[i], expected_periods_to_absorption=round(expected_steps[i], digits=3),
	  P_ACTIVATED=round(absorption_probs[i, 1], digits=4),
	  P_ABORTED=round(absorption_probs[i, 2], digits=4)) for i in 1:3]
end

# ╔═╡ 7bb31208-1147-4398-8df8-662303d6be86
md"""
## Part 7 — Monte Carlo Validation

Independent simulation of the same dynamics analyzed in closed form above, to cross-check the
Markov-chain absorption probabilities and the exponential false-positive formula from Part 5.
"""

# ╔═╡ b4a3960e-fbd0-47e3-8d81-6b003475e342
function simulate_switch(P::Matrix{Float64}, start_state::Int; rng = Random.default_rng())
    state = start_state
    steps = 0
    while state <= 3
        steps += 1
        r = rand(rng)
        cum = 0.0
        next_state = state
        for j in 1:5
            cum += P[state, j]
            if r <= cum
                next_state = j
                break
            end
        end
        state = next_state
    end
    return state, steps
end

# ╔═╡ 8fc9b51a-335f-46ea-9eb2-31e49c375e22
begin
	function monte_carlo_validation(P::Matrix{Float64}, trials::Int = 100_000; rng = Random.default_rng())
	    activated = 0
	    total_steps = 0
	    for _ in 1:trials
	        final_state, steps = simulate_switch(P, 1; rng = rng)
	        total_steps += steps
	        final_state == 4 && (activated += 1)
	    end
	    return activated / trials, total_steps / trials
	end

	function monte_carlo_false_positive(individual_error_rate::Float64, n_trustees::Int, trials::Int = 200_000;
	                                     rng = Random.default_rng())
	    false_activations = 0
	    for _ in 1:trials
	        all_err = all(rand(rng) < individual_error_rate for _ in 1:n_trustees)
	        all_err && (false_activations += 1)
	    end
	    return false_activations / trials
	end
end

# ╔═╡ 6f107814-3365-41a3-bdb6-af0a1da6cb28
let
	P = switch_markov_chain()
	_, expected_steps, absorption_probs = absorption_analysis(P)
	mc_activated_rate, mc_avg_steps = monte_carlo_validation(P)
	(analytic_P_ACTIVATED=round(absorption_probs[1, 1], digits=4),
	 simulated_P_ACTIVATED=round(mc_activated_rate, digits=4),
	 analytic_expected_steps=round(expected_steps[1], digits=4),
	 simulated_average_steps=round(mc_avg_steps, digits=4))
end

# ╔═╡ 6c064dcc-77d1-4400-9dc9-ee7198a95706
let
	analytic_fp = false_positive_probability(0.01, 5)
	mc_fp = monte_carlo_false_positive(0.01, 5)
	(analytic=analytic_fp, simulated=mc_fp)
end

# ╔═╡ 7fdb56bd-8ef8-4081-82d1-9044029fe482
md"""
## Part 8 — Computational Complexity of the Reference Implementation
"""

# ╔═╡ ceb3fe31-e652-4667-be55-e20744f6b09e
const COMPLEXITY_TABLE = [
    ("gf_mul / gf_div / gf_pow",        "O(1)",         "table lookup, precomputed once at module load"),
    ("split_secret(secret, t, n)",      "O(L * t * n)", "L = secret length in bytes, t = threshold, n = trustees"),
    ("reconstruct_secret(m shares)",    "O(L * m^2)",   "naive Lagrange interpolation per byte, m = shares used"),
    ("gf_gaussian_solve(k x k)",        "O(k^3)",       "full Gauss-Jordan elimination, k = threshold - 1"),
    ("canonicalize(manifest)",          "O(S log S)",   "S = serialized manifest size (RFC 8785 key sort)"),
    ("sign / verify (Ed25519)",         "O(1)",         "fixed-cost elliptic-curve operation, independent of S"),
    ("SwitchMonitor.tick(manifest_id)", "O(1) amortized","one state read + at most one notification per call"),
    ("LocalFileStore.save/load",        "O(S)",         "S = manifest size; one file read or write"),
]

# ╔═╡ 1912618d-ae3b-47a0-9915-a0f64881886c
let
	for (op, complexity, note) in COMPLEXITY_TABLE
		@printf("%-32s %-16s %s\n", op, complexity, note)
	end
end

# ╔═╡ 7fba3e0f-e6a3-4c60-8fde-5cf8d5beb8c3
md"""
## Part 9 — Maturity Roadmap: What Level This Protocol Can Reach

The reference implementation at v0.6.0 sits at what the roadmap below calls **RESEARCH-GRADE**:
sound primitives, tested state machine, one real adapter, zero independent audits, zero legal
grounding. Four further levels are identifiable, each with a concrete, checkable criterion — not a
vague aspiration — for having been reached.

**Level 0 — Research-grade** *(current, v0.6.0)*
Criterion met: from-scratch, tested cryptographic primitives; a formally describable (this notebook)
state machine; one working platform adapter proving the interface is implementable.
Gap to close: none of this has been reviewed by anyone without a stake in it being correct.

**Level 1 — Audited-grade**
Criterion to reach: an independent security review of `dlp/shamir.py`, `dlp/crypto.py`, and
`dlp/switch.py` by a party with no authorship stake, published alongside the finding. Formal
verification would exceed this bar: the state machine in Part 6 is a natural candidate for a TLA+
specification checking for deadlock and unreachable-absorption states; the perfect-secrecy property
in Part 4 is a natural candidate for a machine-checked proof in Coq or Isabelle rather than the
empirical demonstration given here.

**Level 2 — Ecosystem-grade**
Criterion to reach: per `GOVERNANCE.md`, a second production `DLPAdapter` for a real,
non-proof-of-concept platform, plus at least one non-Python implementation of the manifest format
and RFC 8785 canonicalization — proving the spec, not just this codebase, is portable.
Threshold-BLS aggregate signatures become relevant at this stage: they would let a quorum of
trustees produce a single constant-size attestation rather than N separate Ed25519 signatures,
which matters once N grows past the small circles this design was first built for.

**Level 3 — Standards-grade**
Criterion to reach: a published Internet-Draft (or a W3C Community Group report) describing the
manifest format and activation semantics independent of this repository's own prose. At this level,
post-quantum hybrid signing (Ed25519 + a lattice-based scheme such as Dilithium, run in parallel
rather than as a replacement) stops being speculative and starts being a standards-track question,
since a specification meant to remain valid for decades has to outlive "classical cryptography is
safe" as a working assumption.

**Level 4 — Legally-grounded**
Criterion to reach: not code. An actual jurisdiction's actual recognition — through case law,
statute, or notarial practice — that trustee-quorum attestation carries evidentiary standing for
death or incapacitation. `WHITEPAPER.md` and `README.md` both already say explicitly that no amount
of engineering reaches this level unilaterally; this notebook does not revise that position, and
treats it as the load-bearing limitation the whole project is honest about rather than one more
milestone on a roadmap.

---

**A further, orthogonal research direction** worth naming explicitly: secure multi-party computation
(MPC) for the split step itself. Today, the owner's own machine generates the full polynomial (see
`split_secret` above) before any share leaves that machine — meaning the owner's own device is a
single point of exposure for the instant the secret is whole, even though no party downstream of
that moment ever sees it whole again. An MPC-based split, where trustees' public keys participate in
generating the shares such that no single machine — including the owner's — ever holds the
reconstructed polynomial in full, would close that specific, narrow gap. It is a meaningfully harder
engineering problem than anything currently in `dlp/`, and is named here as a direction rather than
a near-term plan.
"""

# ╔═╡ fedebda8-e0f1-4fd8-8d04-36ed0af781c6
md"""
---
*End of analysis. Run interactively with Pluto (`using Pluto; Pluto.run()`, then open this file) to
tweak thresholds, trustee counts, and Markov-chain parameters live and watch every downstream cell
recompute.*
"""

# ╔═╡ Cell order:
# ╠═e5cb4932-16b8-40ff-95d5-693813b15678
# ╠═faba2256-f823-4f71-87a4-e28d56b9ac01
# ╠═517ac829-55d3-4f74-beb1-b41fc5a53d57
# ╠═5765199e-5d08-4c68-ba3c-101ae432dabf
# ╠═de7d11ca-2d17-461d-a1f1-7785ad0490d9
# ╠═5d2d8adb-511e-42ff-be30-e4a8fda1e105
# ╠═498c3984-1d78-49f7-80ce-ac39fd1a26d6
# ╠═3cf11134-5765-43f9-993b-f633110273eb
# ╠═3a49bd86-8322-4d88-93a5-44335d97d8b7
# ╠═c16e11ee-c99c-4fa7-afe5-3082ca844db5
# ╠═3d4322ae-61d7-478e-af73-e7bd9e4e8800
# ╠═b7b26548-6539-4c16-8d57-f329ea793226
# ╠═a6cafa2d-6943-4e98-a43e-79e663b1d599
# ╠═9e1190e7-83e7-44dc-8eb4-e715d035500b
# ╠═69b60edd-2d29-4cf6-812f-d2ba030a0102
# ╠═b95da1d7-821e-41ca-9f2a-429e63756894
# ╠═4d834602-78bb-470d-a356-d89bd817bda9
# ╠═19b6a473-9396-42bd-abb6-ad3bfa383388
# ╠═03fa665e-b451-4c27-8e55-af867ea70d4f
# ╠═8505a4fa-8363-4c69-85d9-6201a92c2aab
# ╠═31246851-9b90-4b28-b783-496fbe0190c0
# ╠═9f26b921-6802-4475-ba64-b0ee1aa0fe26
# ╠═acf8fcf2-584b-40fa-9ff7-d1b892eb84d0
# ╠═eeb4955f-98b3-4e60-baed-f53337d63480
# ╠═3471068a-ac34-4586-83c7-d3a97cf08de9
# ╠═7bb31208-1147-4398-8df8-662303d6be86
# ╠═b4a3960e-fbd0-47e3-8d81-6b003475e342
# ╠═8fc9b51a-335f-46ea-9eb2-31e49c375e22
# ╠═6f107814-3365-41a3-bdb6-af0a1da6cb28
# ╠═6c064dcc-77d1-4400-9dc9-ee7198a95706
# ╠═7fdb56bd-8ef8-4081-82d1-9044029fe482
# ╠═ceb3fe31-e652-4667-be55-e20744f6b09e
# ╠═1912618d-ae3b-47a0-9915-a0f64881886c
# ╠═7fba3e0f-e6a3-4c60-8fde-5cf8d5beb8c3
# ╠═fedebda8-e0f1-4fd8-8d04-36ed0af781c6
