#=
================================================================================
 DIGITAL LEGACY PROTOCOL — A FORMAL MATHEMATICAL ANALYSIS
================================================================================

  Companion document to:
    README.md        — practical overview
    WHITEPAPER.md     — motivation, related work, threat model
    spec/SPEC.md      — normative protocol specification
    MANIFESTO.md      — stated principles
    docs/ARCHITECTURE.md — implementation module map

  Purpose
  -------
  Every other document in this repository argues *why* the protocol is
  sound, or *what* it commits to. This one asks a narrower, harder
  question: what can actually be proven, computed, or simulated about it,
  and what is the theoretical and practical ceiling this design could be
  pushed toward.

  This file is executable. Run it with:

      julia dlp_formal_analysis.jl

  It depends only on Julia's standard library — Random, LinearAlgebra,
  Printf, Statistics — the same dependency-light posture the reference
  Python implementation holds for `dlp/shamir.py` and `dlp/crypto.py`.

  Structure
  ---------
    PART 1  GF(256) field arithmetic          — faithful port of dlp/shamir.py
    PART 2  Shamir's Secret Sharing            — split / reconstruct
    PART 3  Gaussian elimination over GF(256)  — general linear solver
    PART 4  Perfect secrecy, demonstrated      — not asserted, computed
    PART 5  Quorum reliability model           — false-positive / false-negative
    PART 6  Switch state machine as a Markov chain
    PART 7  Monte Carlo validation of Parts 5 and 6
    PART 8  Computational complexity of the reference implementation
    PART 9  Maturity roadmap — what level this protocol can reach

  A note on scope: Parts 1-3 are a direct, checkable port of the Python
  reference implementation's algorithm, not a reinterpretation of it.
  Parts 5-6 are formal *models* of the protocol's dynamics — the
  probabilities and transition rates are named parameters, not measured
  real-world values, and the document says so at each point rather than
  presenting simulation output as empirical fact about real trustees.
================================================================================
=#

using Random
using LinearAlgebra
using Printf
using Statistics

# ==============================================================================
# PART 1 — GF(256) FIELD ARITHMETIC
# ==============================================================================
#
# Ported directly from dlp/shamir.py's `_init_tables`, `gf_mul`, `gf_div`,
# `gf_pow`. The field is GF(2^8) reduced by the AES polynomial
# x^8 + x^4 + x^3 + x + 1 (0x11B = 283 decimal), using generator 3 — not 2,
# which is not primitive for this particular reduction polynomial and would
# silently produce a degenerate table.

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

const GF_EXP, GF_LOG = init_gf_tables()

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

# ==============================================================================
# PART 2 — SHAMIR'S SECRET SHARING
# ==============================================================================

struct Share
    index::Int
    trustee_id::String
    data::Vector{Int}
end

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

# ==============================================================================
# PART 3 — GAUSSIAN ELIMINATION OVER GF(256)
# ==============================================================================
#
# A general k×k linear solver over GF(256), used in Part 4 to test, for
# every candidate secret byte, whether a consistent polynomial exists given
# a set of known shares. Returns `nothing` if the system is singular.

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

# ==============================================================================
# PART 4 — PERFECT SECRECY, DEMONSTRATED
# ==============================================================================
#
# SECURITY.md states that Shamir's Secret Sharing below threshold reveals
# "zero information — information-theoretic, not just computationally
# hard." This part does not merely assert that; it computes it.
#
# Claim: given any (threshold - 1) shares, EVERY one of the 256 possible
# byte values is equally consistent with those shares as the "true"
# secret — i.e. for any candidate secret s, there exists exactly one
# completion of the degree-(threshold-1) polynomial matching the known
# points. If that holds for all 256 candidates, an observer holding
# fewer than `threshold` shares learns nothing: the posterior over the
# secret byte is uniform, exactly as large as the prior.
#
# The known shares impose (threshold - 1) linear equations in the
# (threshold - 1) unknown non-constant coefficients (the constant term is
# fixed to the candidate secret being tested). The coefficient matrix is
# a scaled Vandermonde-type matrix in distinct nonzero field elements, so
# it is provably nonsingular — the computation below confirms this holds
# for all 256 candidates rather than relying on that argument alone.

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

# ==============================================================================
# PART 5 — QUORUM RELIABILITY MODEL
# ==============================================================================
#
# spec/SPEC.md's activation state machine is deliberately asymmetric: a
# SINGLE trustee attesting "reachable" aborts activation, while activation
# itself requires `threshold` trustees to positively attest "unreachable."
# This part formalizes what that asymmetry buys, in closed form.

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

# ==============================================================================
# PART 6 — THE SWITCH STATE MACHINE AS AN ABSORBING MARKOV CHAIN
# ==============================================================================
#
# dlp/switch.py's five states — ACTIVE, OVERDUE, VERIFICATION, ACTIVATED,
# ABORTED — form a discrete-time chain with two absorbing states
# (ACTIVATED, ABORTED). This part builds the transition matrix and
# computes, via the fundamental-matrix method, the expected number of
# periods to absorption and the probability of ending in each absorbing
# state, as a function of named per-period parameters.
#
# These parameters are illustrative, not measured — the point is that the
# chain's long-run behavior is fully determined once they are supplied,
# which is itself a useful property for anyone tuning `interval_days` /
# `grace_days` against a real trustee population.

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

# ==============================================================================
# PART 7 — MONTE CARLO VALIDATION
# ==============================================================================

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

# ==============================================================================
# PART 8 — COMPUTATIONAL COMPLEXITY OF THE REFERENCE IMPLEMENTATION
# ==============================================================================

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

# ==============================================================================
# PART 9 — MATURITY ROADMAP: WHAT LEVEL CAN THIS PROTOCOL REACH
# ==============================================================================

const MATURITY_ROADMAP = """
The reference implementation at v0.6.0 sits at what the table below calls
RESEARCH-GRADE: sound primitives, tested state machine, one real adapter,
zero independent audits, zero legal grounding. Four further levels are
identifiable, each with a concrete, checkable criterion — not a vague
aspiration — for having been reached.

  LEVEL 0 — RESEARCH-GRADE                              (current, v0.6.0)
    Criterion met: from-scratch, tested cryptographic primitives; a
    formally describable (this document) state machine; one working
    platform adapter proving the interface is implementable.
    Gap to close: none of this has been reviewed by anyone without a
    stake in it being correct.

  LEVEL 1 — AUDITED-GRADE
    Criterion to reach: an independent security review of dlp/shamir.py,
    dlp/crypto.py, and dlp/switch.py by a party with no authorship stake,
    published alongside the finding. Formal verification would exceed
    this bar: the switch state machine in Part 6 above is a natural
    candidate for a TLA+ specification checking for deadlock and
    unreachable-absorption states; dlp/shamir.py's perfect-secrecy
    property (Part 4) is a natural candidate for a machine-checked proof
    in Coq or Isabelle rather than the empirical demonstration given here.

  LEVEL 2 — ECOSYSTEM-GRADE
    Criterion to reach: per GOVERNANCE.md, a second production
    DLPAdapter for a real, non-proof-of-concept platform, plus at least
    one non-Python implementation of the manifest format and RFC 8785
    canonicalization — proving the spec, not just this codebase, is
    portable. Threshold-BLS aggregate signatures become relevant at this
    stage: they would let a quorum of trustees produce a single
    constant-size attestation rather than N separate Ed25519 signatures,
    which matters once N grows past the small circles this design was
    first built for.

  LEVEL 3 — STANDARDS-GRADE
    Criterion to reach: a published Internet-Draft (or a W3C Community
    Group report) describing the manifest format and activation
    semantics independent of this repository's own prose — the same
    transition CONTRIBUTING.md already names as a goal for project
    governance, applied to the specification's external standing rather
    than its internal decision process. At this level, post-quantum
    hybrid signing (Ed25519 + a lattice-based scheme such as Dilithium,
    run in parallel rather than as a replacement) stops being
    speculative and starts being a standards-track question, since a
    specification meant to remain valid for decades has to outlive
    "classical cryptography is safe" as a working assumption.

  LEVEL 4 — LEGALLY-GROUNDED
    Criterion to reach: not code. An actual jurisdiction's actual
    recognition — through case law, statute, or notarial practice — that
    trustee-quorum attestation carries evidentiary standing for death or
    incapacitation. WHITEPAPER.md and README.md both already say
    explicitly that no amount of engineering reaches this level
    unilaterally; this document does not revise that position, and
    treats it as the load-bearing limitation the whole project is
    honest about rather than one more milestone on a roadmap.

A further, orthogonal research direction worth naming explicitly: secure
multi-party computation (MPC) for the SPLIT step itself. Today, the
owner's own machine generates the full polynomial (see split_secret
above) before any share leaves that machine — meaning the owner's own
device is a single point of exposure for the instant the secret is whole,
even though no party downstream of that moment ever sees it whole again.
An MPC-based split, where trustees' public keys participate in generating
the shares such that no single machine — including the owner's — ever
holds the reconstructed polynomial in full, would close that specific,
narrow gap. It is a meaningfully harder engineering problem than anything
currently in dlp/, and is named here as a direction rather than a
near-term plan.
"""

# ==============================================================================
# RUN THE FULL ANALYSIS
# ==============================================================================

function run_full_analysis()
    println("=" ^ 78)
    println("DIGITAL LEGACY PROTOCOL — FORMAL ANALYSIS")
    println("=" ^ 78)

    # --- Part 2 sanity check: split then reconstruct -------------------------
    println("\n[PART 2] Shamir split / reconstruct — sanity check")
    trustee_ids = ["t1", "t2", "t3", "t4", "t5"]
    secret_bytes = [0x44, 0x4C, 0x50] .|> Int  # "DLP" as bytes
    shares = split_secret(secret_bytes, 3, trustee_ids)
    recovered = reconstruct_secret(shares[[1, 3, 5]])  # any 3 of 5
    @printf("  original secret bytes : %s\n", secret_bytes)
    @printf("  recovered from 3 of 5 : %s\n", recovered)
    @printf("  match                 : %s\n", recovered == secret_bytes)

    # --- Part 4: perfect secrecy ----------------------------------------------
    println("\n[PART 4] Perfect secrecy — empirical verification")
    for (threshold, n) in [(2, 3), (3, 5), (5, 9)]
        true_secret, consistent = verify_perfect_secrecy(threshold, n)
        @printf("  threshold=%d, n=%-2d | true secret=%-3d | consistent candidates out of 256: %d %s\n",
                threshold, n, true_secret, length(consistent),
                length(consistent) == 256 ? "(perfect secrecy holds)" : "(!!! UNEXPECTED)")
    end

    # --- Part 5: reliability model --------------------------------------------
    println("\n[PART 5] Quorum reliability model")
    println("  False positive P(wrongful activation) — falls exponentially in n_trustees:")
    for n in [1, 3, 5, 9]
        fp = false_positive_probability(0.01, n)
        @printf("    n=%d, per-trustee error=1%%  ->  system false-positive P = %.10f\n", n, fp)
    end
    println("  False negative P(fails to activate though owner is gone) — k-out-of-n reliability:")
    for (n, thr) in [(3, 2), (5, 3), (9, 5)]
        fn = false_negative_probability(0.95, n, thr)
        @printf("    n=%d, threshold=%d, per-trustee reliability=95%%  ->  system false-negative P = %.6f\n",
                n, thr, fn)
    end

    # --- Part 6 + 7: Markov chain + Monte Carlo validation --------------------
    println("\n[PART 6] Switch state machine — absorbing Markov chain")
    P = switch_markov_chain()
    _, expected_steps, absorption_probs = absorption_analysis(P)
    state_names = ["ACTIVE", "OVERDUE", "VERIFICATION"]
    for (i, name) in enumerate(state_names)
        @printf("  from %-12s: expected periods to absorption = %.3f | P(ACTIVATED)=%.4f  P(ABORTED)=%.4f\n",
                name, expected_steps[i], absorption_probs[i, 1], absorption_probs[i, 2])
    end

    println("\n[PART 7] Monte Carlo validation (100,000 trials from ACTIVE)")
    mc_activated_rate, mc_avg_steps = monte_carlo_validation(P)
    @printf("  analytic  P(ACTIVATED | start=ACTIVE) = %.4f\n", absorption_probs[1, 1])
    @printf("  simulated P(ACTIVATED | start=ACTIVE) = %.4f\n", mc_activated_rate)
    @printf("  analytic  expected steps               = %.4f\n", expected_steps[1])
    @printf("  simulated average steps                = %.4f\n", mc_avg_steps)

    println("\n  Monte Carlo cross-check of the false-positive formula (n=5, error=1%%, 200,000 trials):")
    analytic_fp = false_positive_probability(0.01, 5)
    mc_fp = monte_carlo_false_positive(0.01, 5)
    @printf("    analytic  = %.10f\n", analytic_fp)
    @printf("    simulated = %.10f\n", mc_fp)

    # --- Part 8: complexity table ----------------------------------------------
    println("\n[PART 8] Computational complexity — reference implementation")
    @printf("  %-32s %-16s %s\n", "Operation", "Complexity", "Notes")
    println("  " * "-" ^ 90)
    for (op, complexity, note) in COMPLEXITY_TABLE
        @printf("  %-32s %-16s %s\n", op, complexity, note)
    end

    # --- Part 9: maturity roadmap -----------------------------------------------
    println("\n[PART 9] Maturity roadmap")
    println(MATURITY_ROADMAP)

    println("=" ^ 78)
    println("END OF ANALYSIS")
    println("=" ^ 78)
end

if abspath(PROGRAM_FILE) == @__FILE__
    run_full_analysis()
end
