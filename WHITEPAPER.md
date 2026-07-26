# The Digital Legacy Protocol: A Quorum-Based Framework for Verifiable Digital Inheritance

**Author:** Ciprian Ștefan Pleșca
**Affiliation:** Independent Researcher
**Repository:** [github.com/Ciprian-LocalPulse/digital-legacy-protocol](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol)
**Version:** Companion paper to Protocol Specification v0.4
**Date:** July 2026
**License:** This document is released under CC0 1.0 (public domain), matching the protocol specification it describes.

---

## Abstract

The disposition of a person's digital assets after death or incapacitation is, at present, governed by no consistent standard. Custodial platforms — cryptocurrency exchanges, email providers, password managers, financial institutions — each implement ad-hoc, mutually incompatible policies, and a substantial fraction implement none at all. The consequence is well documented in aggregate even where individual cases are not: billions of dollars in cryptocurrency alone are estimated to be permanently unreachable due to private key loss following the holder's death, and surviving family members routinely spend months navigating platform support processes with no clear authority to draw on.

This paper presents the **Digital Legacy Protocol (DLP)**, an open specification and reference implementation addressing this gap through three design commitments: (1) verification of incapacitation via a trustee quorum rather than unilateral platform determination, (2) cryptographic secret splitting such that no single party — including the protocol's own reference implementation — can access protected assets alone, and (3) a deliberately minimal, platform-agnostic core that any custodial service can adopt without seeking permission or paying a fee. We describe the protocol's manifest structure, its use of Shamir's Secret Sharing and Ed25519/X25519 primitives, the dead man's switch state machine governing activation, and a reference implementation comprising 132 automated tests, a working platform adapter against a real external API, and both command-line and web interfaces. We conclude with an unusually explicit accounting of the protocol's current limitations, on the view that overstating a security-relevant system's maturity is itself a harm the literature should actively discourage.

---

## 1. Introduction

### 1.1 The problem

Digital estate management sits at an uncomfortable intersection of three domains that rarely talk to each other: applied cryptography, platform engineering, and estate law. Each domain, considered alone, has produced adequate tools — secret-sharing schemes have existed since Shamir's original 1979 construction [1], authenticated encryption is a solved engineering problem, and testamentary law has handled the transfer of assets after death for centuries. What has not existed is a **standard connective layer**: a way for the cryptographic guarantee ("this key can only be reconstructed by agreement of a defined group") to interoperate with the legal and human process ("this person has, in fact, died or become incapacitated") without requiring a single company to sit at the center of both.

The absence of this layer is not for lack of demand. It is, we argue, a coordination failure: no individual platform has sufficient incentive to build "what happens when the user dies" functionality in isolation, because there is nothing for that functionality to be *compatible with*. A protocol adopted by zero other parties provides no interoperability benefit over an in-house solution, and an in-house solution serving a grim, low-frequency event competes poorly for engineering resources against user-facing features. DLP's core wager is that a sufficiently minimal, permissionless standard — one requiring no registration, no fee, and no dependency on the protocol's authors remaining involved — lowers the adoption barrier enough to break this equilibrium.

### 1.2 Contributions

This paper and its accompanying repository make the following contributions:

1. A manifest format (Section 3) that separates *intent* (what should happen, expressed in a signed, human-auditable document) from *capability* (the actual secrets required to act on that intent, which the manifest never contains in reconstructible form).
2. A trustee-quorum activation model (Section 4) in which incapacitation is attested by a group the owner personally selects, with single-attestor veto power against false positives.
3. A reference implementation (Section 5) including a from-scratch, tested Shamir's Secret Sharing implementation over GF(256); hybrid X25519/AES-256-GCM encryption for metadata confidentiality; a pluggable storage interface; real SMTP-based notification delivery; a minimal web interface; and a working adapter against the GitHub API demonstrating the platform-adapter interface is genuinely implementable rather than merely plausible on paper.
4. An explicit, itemized limitations section (Section 7) distinguishing between gaps this project can close through further engineering and gaps — legal standing, third-party adoption, independent audit — that no amount of code can resolve unilaterally.

---

## 2. Related Work and Positioning

Commercial "digital legacy" features exist within individual platforms (for instance, inactive account management tools offered by some large email providers, and beneficiary-designation features on some cryptocurrency exchanges). These share a common structural limitation relevant to this work: verification of the triggering event and custody of the underlying secret are both controlled by the same single entity. This is not a criticism of engineering quality; it is an observation that single-party verification is a single point of failure and a single point of institutional discretion, neither of which is easily audited or portable across services.

Academic and applied work on Shamir's Secret Sharing [1], threshold cryptography more broadly [2], and dead man's switch constructions in distributed systems provides the cryptographic and mechanism-design foundation this protocol builds on directly. DLP's contribution relative to this prior work is not novel cryptography — the primitives used (Shamir's scheme, Ed25519 [3], X25519 [4]) are all well-established and deliberately unmodified — but rather the specific combination and manifest format that makes these primitives usable as a cross-platform standard rather than a bespoke implementation detail of any one system.

---

## 3. Manifest Structure

A DLP manifest is a canonicalized, Ed25519-signed JSON document (full schema in `spec/SPEC.md`, Section 4) declaring:

- The **owner's** public key and, optionally, a display name.
- A **check-in policy** (interval and grace period) governing how the owner demonstrates continued control.
- A **trustee quorum**: a list of trustees, their public keys, and a threshold `M` of `N` required for activation.
- One or more **assets**: references to protected resources (a wallet, an account, a message), each associated with a beneficiary, an action to take on activation, and the set of trustees holding a Shamir share of the underlying secret.

Critically, the manifest is a description of *intent and structure*, not a container of secrets. Contact information for trustees and beneficiaries may be stored either in plaintext or, since specification v0.2, encrypted per-recipient via a hybrid X25519 + HKDF-SHA256 + AES-256-GCM construction (Section 4.1 of the specification), such that a party holding the manifest but not the relevant private key learns nothing about who a listed trustee or beneficiary actually is.

---

## 4. Activation: The Dead Man's Switch

Activation follows a deliberately conservative state machine (implemented in `dlp.switch`, Section 7 of the specification):

```
ACTIVE → OVERDUE → VERIFICATION → ACTIVATED
                         ↓
                     ABORTED (any single trustee attests the owner is reachable)
```

Two design choices merit explicit justification. First, activation requires *quorum agreement* (M of N trustees affirmatively attesting the owner is unreachable), not merely the passage of time — a missed check-in alone never releases anything. Second, and asymmetrically, a **single** trustee reporting the owner is fine is sufficient to abort the process. This asymmetry is intentional: the cost of a false negative (failing to activate when the owner has, in fact, died) is recoverable — trustees can re-attest — while the cost of a false positive (releasing assets to a living owner's beneficiaries) is not. The protocol is therefore biased toward caution at the activation boundary.

---

## 5. Reference Implementation

The reference implementation, released under MIT license (the specification itself under CC0), comprises:

| Component | Description |
|---|---|
| `dlp.shamir` | Shamir's Secret Sharing over GF(256), implemented from first principles rather than via an external library, to keep the trusted computing base auditable line-by-line. |
| `dlp.crypto` | Ed25519 signing and RFC 8785-style canonical JSON serialization. |
| `dlp.hint_crypto` | Hybrid X25519/HKDF-SHA256/AES-256-GCM encryption for contact metadata. |
| `dlp.recovery` | Opt-in Shamir-based backup of the *owner's own* signing key among trustees, at a threshold independent of the activation quorum. |
| `dlp.storage` | A `ManifestStore` interface with a working local-filesystem backend. |
| `dlp.notify` | Real SMTP-based notification delivery, plus a console channel for testing. |
| `dlp.adapters.github` | A working `DLPAdapter` implementation against the live GitHub REST API. |
| `dlp.webapp` | A minimal server-rendered web interface for manifest creation, inspection, and verification. |

As of this writing, the implementation is covered by 132 automated tests (94% statement coverage; 100% on the cryptographic core, the activation state machine, and the key-recovery module), exercised continuously via GitHub Actions across four Python versions.

A methodological note: during development of the owner-key-recovery module, an index-tracking defect was identified in which the original Shamir share x-coordinate was not preserved through serialization, silently corrupting reconstruction for any share subset that excluded the first-generated trustee. The defect was caught by systematic testing across all threshold-subset combinations prior to release, rather than by inspection — an argument, we think, for the testing discipline applied throughout this project rather than for any particular cleverness in avoiding the error in the first place. Errors of this kind are the expected cost of implementing cryptographic protocols from scratch, and we report it here rather than omitting it.

---

## 6. Threat Model (Summary)

The protocol's security rests on three properties holding simultaneously: (i) Ed25519 signatures are unforgeable without the owner's private key; (ii) Shamir shares below the declared threshold reveal no information about the underlying secret, information-theoretically rather than merely computationally; and (iii) quorum verification cannot be satisfied by fewer than the declared threshold of genuine, independent trustee attestations. The full threat model, including explicit non-goals (the protocol does not custody funds, does not replace a legal will, and assumes trustees are not uniformly colluding against the owner), is documented in `SECURITY.md` and specification Section 6.

---

## 7. Limitations

We consider it a methodological obligation, particularly for a system whose stated purpose involves other people's cryptographic keys, to state plainly what has *not* been established:

- **No independent security audit.** All testing to date has been conducted by this paper's author. This is a materially different and weaker guarantee than review by a party with no stake in the outcome, and readers should weight it accordingly.
- **No legal validation.** Nothing in this specification or implementation establishes that trustee-quorum attestation carries evidentiary weight regarding death or incapacity in any jurisdiction. This is a question for legal scholarship and practice, not software engineering, and we make no claim to have answered it.
- **Limited real-world adoption.** A single working platform adapter (GitHub) demonstrates that the `DLPAdapter` interface is implementable against a genuine external API. It does not demonstrate market or institutional adoption; no financial institution, cryptocurrency exchange, or password manager currently honors DLP manifests.
- **No multi-tenant deployment story.** The reference web interface generates private keys server-side, an acceptable design for single-user local operation and an unacceptable one for any hosted service handling multiple users' keys.

We regard explicit enumeration of these gaps as preferable to their omission, on the grounds that a security-relevant open-source project's greatest risk of harm is not slow adoption but premature over-trust.

---

## 8. Conclusion

The Digital Legacy Protocol offers a technically defensible, openly licensed foundation for a problem that has, to date, been addressed only piecemeal and only within single-platform silos. Its core cryptographic and mechanism-design choices are conservative and built on well-studied primitives rather than novel constructions, a deliberate choice given the domain. What remains — third-party adoption, legal grounding, and independent audit — lies substantially outside what further software engineering alone can resolve, and we invite contribution, critique, and adversarial review from readers positioned to advance any of those fronts.

---

## References

[1] Shamir, A. (1979). "How to Share a Secret." *Communications of the ACM*, 22(11), 612–613.

[2] Desmedt, Y. (1994). "Threshold Cryptography." *European Transactions on Telecommunications*, 5(4), 449–457.

[3] Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y. (2012). "High-speed high-security signatures." *Journal of Cryptographic Engineering*, 2(2), 77–89. (Ed25519.)

[4] Langley, A., Hamburg, M., & Turner, S. (2016). "Elliptic Curves for Security." RFC 7748, Internet Engineering Task Force. (X25519.)

[5] Krawczyk, H., & Eronen, P. (2010). "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)." RFC 5869, Internet Engineering Task Force.

---

## About the Author

<div align="center">
  <img src="assets/CIPRIAN-STEFAN-PLESCA.jpg" alt="Ciprian Ștefan Pleșca" width="220" style="border-radius: 8px;" />
</div>

**Ciprian Ștefan Pleșca** is an independent researcher and open-source developer working across applied cryptography, security tooling, and public-interest software infrastructure. He is the author of the Digital Legacy Protocol specification and its reference implementation, and maintains a portfolio of open-source projects spanning healthcare research infrastructure, threat intelligence, and privacy-preserving systems, published under the `Ciprian-LocalPulse` GitHub organization.

Correspondence regarding this protocol, its specification, or this paper may be directed via the repository's issue tracker at [github.com/Ciprian-LocalPulse/digital-legacy-protocol](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol).

---

*This paper describes protocol specification v0.4 and its accompanying reference implementation as of July 2026. Both the protocol and this document will continue to evolve; readers should consult the repository directly for the current state of either.*
