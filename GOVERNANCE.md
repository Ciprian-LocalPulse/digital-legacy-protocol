# Governance

## Current state: single maintainer, stated intent to change

Digital Legacy Protocol is, as of this document, maintained by one person (Ciprian Ștefan Pleșca, GitHub `Ciprian-LocalPulse`), who has final say over both the specification (`spec/SPEC.md`) and the reference implementation (`dlp/`). This is disclosed here plainly rather than obscured behind organizational language, for the same reason the README and whitepaper disclose the project's technical limitations plainly: a protocol intended to outlive individual platforms should not overstate the durability of its own decision-making structure any more than it overstates the maturity of its code.

This document exists to do two things: describe how decisions are actually made today, and commit to a specific, triggerable path toward a more distributed structure as the project grows — rather than leaving that transition as a vague aspiration, as it was previously in [CONTRIBUTING.md](CONTRIBUTING.md).

## What is governed separately

The specification and the reference implementation are versioned and licensed independently — CC0 1.0 for `spec/SPEC.md`, MIT for everything under `dlp/`, `tests/`, and `examples/` — and this document's governance model applies to decisions about both, but not identically:

- **Specification changes** (anything altering `spec/SPEC.md`) are held to a higher bar, because a specification change can obsolete manifests or adapters already deployed against an earlier version. Backward-incompatible specification changes require a documented rationale in the relevant pull request and, where feasible, a migration note for existing `.dlp.json` manifests.
- **Reference implementation changes** follow the process in [CONTRIBUTING.md](CONTRIBUTING.md) and are held to the bar described there — tests accompanying any change to `shamir.py`, `crypto.py`, or `switch.py`, and no new dependency without prior discussion in an issue.
- **Platform adapters** (`dlp/adapters/`) are additive by nature and require the lowest bar to merge: a working `DLPAdapter` implementation with tests, even a proof-of-concept against a small self-hosted service, is a welcome contribution regardless of how widely adopted the target platform is.

## Decision-making today

Design questions are resolved through public discussion in GitHub issues, with the maintainer making the final call when consensus does not emerge on its own. This is not intended as a permanent arrangement; it is the practical minimum for a project at this stage, disclosed rather than dressed up as something more participatory than it currently is.

Two categories of decision are treated with particular weight, given the subject matter:

1. **Anything affecting the security properties described in [SECURITY.md](SECURITY.md)** — the unforgeability of signatures, the information-theoretic secrecy of Shamir shares below threshold, and the integrity of the quorum verification flow — is never merged without accompanying tests demonstrating the property still holds.
2. **Anything narrowing the project's non-negotiable commitments in [MANIFESTO.md](MANIFESTO.md)** — for instance, a proposal that would have DLP itself custody a whole secret — is treated as a fork-worthy disagreement rather than an ordinary feature request, and will be discussed as such openly rather than merged quietly.

## The path to structured governance

This project commits to moving toward a more formal, multi-maintainer process, modeled loosely on how IETF and W3C specifications evolve — RFC-style proposals for specification changes, a defined path from "contributor" to "maintainer" status, and decisions made by documented rough consensus among maintainers rather than by one person's judgment. Concretely, that transition is expected to begin once either of the following occurs, whichever comes first:

- **A second production `DLPAdapter`** is merged for a real, non-proof-of-concept platform (beyond the existing GitHub adapter), since that is the point at which decisions about the specification start to have consequences for parties beyond this repository's own maintainer.
- **Three or more contributors** have sustained, ongoing involvement (multiple merged substantive pull requests across at least two release cycles), since that is the point at which single-maintainer decision-making stops scaling regardless of adapter count.

When either trigger is reached, the maintainer commits to opening a public issue proposing a specific governance structure for discussion, rather than adopting one unilaterally — consistent with the principle in [MANIFESTO.md, Section VI](MANIFESTO.md#vi-the-protocol-must-survive-its-author) that a protocol about outliving its author's presence should not remain permanently dependent on that presence for its own decision-making either.

## Amending this document

Changes to this governance document itself follow the same process as specification changes: proposed in a public issue or pull request, with rationale, open for comment before being merged. A governance document that could be silently rewritten by whoever currently holds merge access would not actually constrain anything.
