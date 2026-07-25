# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

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
