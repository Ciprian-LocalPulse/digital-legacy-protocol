# Security Policy

## Threat model (short version)

DLP's security depends on three things holding at once:

1. **Ed25519 signatures** are unforgeable without the owner's private key.
2. **Shamir's Secret Sharing** below threshold reveals zero information about the secret (this is information-theoretic, not just computationally hard — even infinite compute doesn't help an attacker with `M-1` shares).
3. **The quorum verification flow** cannot be bypassed by a single compromised or malicious trustee, and requires real attestation, not just the passage of time.

If you find a way to break any of these three properties in the reference implementation — forge a signature without the private key, reconstruct a secret from fewer than the threshold number of shares, or activate a switch without genuine quorum agreement — that's a critical issue.

## What's actually been done to verify this, and what hasn't

Being specific about the difference between "tested" and "audited" matters here.

**Done:**
- **Fixed example tests** for every module, including deliberately adversarial cases (tampered signatures, wrong keys, insufficient shares, path traversal, malformed input).
- **Property-based testing** (`tests/test_*_properties.py`, via [Hypothesis](https://hypothesis.readthedocs.io/)) generating hundreds of randomized inputs per run against the hand-rolled cryptography specifically — `dlp.shamir`'s GF(256) arithmetic and Lagrange interpolation, `dlp.crypto`'s sign/verify contract, `dlp.hint_crypto`'s encrypt/decrypt round-trip. This exists because `dlp.shamir` is implemented from scratch rather than calling a vetted library, which is exactly the kind of code where a subtle arithmetic mistake is easy to miss by eye. In the course of writing these tests, Hypothesis surfaced two flawed assumptions in the *tests themselves* (not the underlying code) — both documented in `tests/test_shamir_properties.py` and `tests/test_hint_crypto_properties.py` — which is a reasonable illustration of why this kind of testing is worth having even when it doesn't find a bug in the code under test.
- **Static security analysis** ([Bandit](https://bandit.readthedocs.io/)) runs as a hard CI gate on every push. Every current finding has been triaged and either fixed (e.g. explicit URL scheme allowlisting before any `urlopen` call) or justified inline with a `# nosec` comment explaining why it's safe in context — a new, unjustified finding blocks the build.

**Not done:**
- **Independent security audit.** Everything above was written and tested by this project's own author. That is a meaningfully different and weaker guarantee than review by a party with no stake in the outcome, and it should be weighted accordingly by anyone deciding whether to rely on this for something real.
- **Formal verification** of the cryptographic protocol design itself (as opposed to testing this particular implementation of it).
- **Fuzzing at the binary/memory-safety level** — moot for pure Python, but worth naming as a category of testing this project doesn't need rather than silently skipping.

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities. Instead:

- Open a [GitHub Security Advisory](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol/security/advisories/new) (private, visible only to maintainers until resolved), or
- Email details privately if the repository's contact listed in the GitHub profile is available.

Please include:
- A description of the issue and its impact (what an attacker could actually achieve)
- Steps to reproduce, ideally with a minimal script against `dlp/`
- Whether it affects the specification itself or only this particular implementation

## What's explicitly out of scope

- Vulnerabilities in third-party `DLPAdapter` implementations that live outside this repository — report those to the platform that built them.
- Social engineering of trustees (e.g. tricking a trustee into falsely attesting) — this is a human process risk the spec discusses in `SPEC.md` section 7, not a code vulnerability.
- Loss of a private key by the owner or a trustee — DLP cannot protect against key loss any more than any other cryptographic system can; this is why quorum thresholds should always be set below the total trustee count.

## Disclosure timeline

We aim to acknowledge reports within 7 days and to have a fix or mitigation plan within 30 days for confirmed critical issues. Given this is a volunteer-maintained protocol project rather than a funded security team, please be patient — but confirmed cryptographic breaks will be prioritized over everything else, including new features.
