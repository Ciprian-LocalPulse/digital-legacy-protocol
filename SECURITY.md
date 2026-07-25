# Security Policy

## Threat model (short version)

DLP's security depends on three things holding at once:

1. **Ed25519 signatures** are unforgeable without the owner's private key.
2. **Shamir's Secret Sharing** below threshold reveals zero information about the secret (this is information-theoretic, not just computationally hard — even infinite compute doesn't help an attacker with `M-1` shares).
3. **The quorum verification flow** cannot be bypassed by a single compromised or malicious trustee, and requires real attestation, not just the passage of time.

If you find a way to break any of these three properties in the reference implementation — forge a signature without the private key, reconstruct a secret from fewer than the threshold number of shares, or activate a switch without genuine quorum agreement — that's a critical issue.

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
