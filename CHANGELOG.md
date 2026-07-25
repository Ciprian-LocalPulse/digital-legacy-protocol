# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] — 2026-07-25

Closes three of the gaps called out as "known limitations" in 0.1.0: plaintext contact hints, no storage layer, and no owner key recovery story.

### Added
- `dlp.hint_crypto` — real hybrid encryption (X25519 + HKDF-SHA256 + AES-256-GCM) for `contact_hint` fields, so a manifest can be read by a platform or backup system without exposing who a trustee or beneficiary actually is. `ManifestBuilder.add_trustee()` / `add_beneficiary()` now accept an optional `encryption_public_key` to encrypt hints automatically.
- `dlp.recovery` — opt-in owner key backup: split the owner's own signing key via Shamir's Secret Sharing among trustees, at a threshold independent from the switch's activation threshold. Documented tradeoffs (trustee collusion risk) in spec section 11.
- `dlp.storage` — `ManifestStore` interface plus a working `LocalFileStore` backend (one JSON file per manifest), including `load_latest_in_chain()` to follow `supersedes` links forward.
- CLI: `dlp enckeygen`, `dlp store-save`, `dlp store-list`, `dlp store-load`.
- Spec sections 4.1 (contact hint encryption), 10 (storage), 11 (owner key recovery). Spec bumped to v0.2.
- 40 new tests (91 total, up from 51). CLI coverage went from 0% to 97%; overall package coverage from 72% to 94%.

### Fixed
- Caught and fixed an index-tracking bug in the initial `dlp.recovery` implementation where `OwnerKeyBackup` didn't preserve each share's original x-coordinate, silently breaking reconstruction for any subset that skipped the first trustee. Verified against every possible threshold combination before shipping.

### Still open (tracked for 0.3+)
- No reference platform adapters for real third-party services — the `DLPAdapter` interface exists, `InMemoryDemoAdapter` demonstrates it works, but nothing production-real implements it yet.
- No trustee notification system (email/SMS/push) — check-ins and attestations are modeled correctly in `dlp.switch`, but nothing currently delivers "please attest" messages to a real human.
- No web or mobile UI — this remains a library and CLI. Someone who isn't comfortable with a terminal cannot use it today.
- `LocalFileStore` is single-machine and not concurrency-safe; a database or object-store backend implementing `ManifestStore` is a natural next contribution.
- No independent security audit. The cryptography here is built from well-understood primitives and tested thoroughly by this project, but "tested by its own author" is not the same bar as "reviewed by someone with no stake in it being correct."
- No legal review of whether trustee-quorum attestation has standing anywhere as evidence of death or incapacity — this is explicitly outside what code can settle.

## [0.1.0] — 2026-07-25

Initial public release.

### Added
- `spec/SPEC.md` — Digital Legacy Protocol specification v0.1 (CC0)
- `dlp.shamir` — from-scratch Shamir's Secret Sharing over GF(256)
- `dlp.crypto` — Ed25519 signing, verification, and canonical JSON serialization for manifests
- `dlp.manifest` — `ManifestBuilder` and structural validation
- `dlp.switch` — dead man's switch state machine (check-ins, trustee attestation, quorum activation)
- `dlp.adapter` — `DLPAdapter` interface for platforms, plus an in-memory demo adapter
- `dlp.cli` — `dlp keygen / demo / verify / inspect`
- 51 tests covering signature forgery resistance, threshold reconstruction correctness, quorum edge cases, and manifest validation
- GitHub Actions CI across Python 3.9–3.12, plus lint/type-check job

### Known limitations (tracked for 0.2)
- No reference platform adapters for real third-party services yet — see open call in CONTRIBUTING.md
- Trustee notification/communication is entirely out of scope of this implementation (by design — see spec section 9) but a reference notification adapter (email/SMS) would lower the barrier for non-technical users
- No key-recovery story if the *owner's* private key itself is lost before activation — currently the manifest simply can't be updated in that case, only reissued from scratch with a new key
