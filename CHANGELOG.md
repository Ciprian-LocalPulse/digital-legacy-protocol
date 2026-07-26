# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] — 2026-07-25

The first real `DLPAdapter` implementation — closes the "no bank, exchange, or password manager actually honors DLP manifests today" gap for at least one real service.

### Added
- `dlp.adapters.github.GitHubAdapter` — a genuine `DLPAdapter` implementation calling the real GitHub REST API (`api.github.com`) over stdlib `urllib`, no new dependency. Supports two of the four spec actions against real GitHub behavior: `deliver_message` (creates a private Gist containing the reconstructed message and returns its URL) and `grant_access` (adds a beneficiary as a collaborator on a private repository). `release_key` and `execute_webhook` are explicitly reported as unsupported by this adapter rather than silently ignored.
- `examples/github_adapter_demo.py` — an end-to-end example that actually calls the live API when a `GITHUB_TOKEN` environment variable is set, and explains what it would have done (without failing) when one isn't.
- 14 new tests (131 total, 2 skipped by design). Write operations (Gist creation, collaborator invites) are tested by mocking `urllib.request.urlopen`, matching how `SMTPEmailChannel` is tested — real external calls have no place in a CI suite that needs to be deterministic. One additional opportunistic test hits the real, unauthenticated `api.github.com/zen` endpoint and skips cleanly if the environment is rate-limited or offline, rather than failing the build.

### Notes
- This adapter is stateless: `on_revocation()` is a documented no-op, since nothing here tracks which manifests it has already acted on. A production adapter with its own persistence would use that hook to cancel a pending collaborator invitation, for instance.
- CI now installs the `web` extra alongside `dev` so the webapp test suite (added in 0.3.0) actually runs Flask-backed tests in CI, and lints `examples/` in addition to `dlp/` and `tests/`.

### Still open (tracked for 0.5+)
- Only one real adapter exists. The interface has now been proven against a genuine external API, but "GitHub can receive a Gist" is a long way from "a bank or exchange has agreed to honor this protocol."
- No independent security audit.
- No legal review of trustee-quorum attestation's standing as evidence of death or incapacity.
- The web UI remains single-user/local-only by design.

## [0.3.0] — 2026-07-25

Closes two more gaps from the "current status" section of the README: no way to actually notify a real person, and no way to use DLP without a terminal.

### Added
- `dlp.notify` — real notification delivery: `SMTPEmailChannel` sends actual email over SMTP+TLS (works with Gmail app passwords, SES, Postmark, self-hosted servers — anything standard), `ConsoleChannel` for local development and tests. `NotificationService` wraps either with the actual message content for check-in reminders, trustee attestation requests, and beneficiary activation notices.
- `dlp.webapp` — a minimal local web UI (Flask, server-rendered, no JS build step): create a manifest through a form instead of writing Python, view stored manifests, verify a pasted manifest's signature. Installed via the optional `web` extra (`pip install -e ".[web]"`) so the core library stays dependency-light. Launch with `dlp web`.
- 27 new tests (118 total, up from 91): SMTP sending is tested by mocking `smtplib.SMTP` rather than requiring real mail infrastructure; the web UI is tested end-to-end through Flask's test client, including a path-traversal rejection test and an assertion that trustee hints created through the form are actually encrypted, not just accepted as plaintext.

### Explicitly out of scope for this UI (see the warning banner on its create-manifest page)
`dlp.webapp` generates and displays private keys server-side, in-process. That's an acceptable tradeoff for a local, single-user tool running on your own machine — it is not acceptable for a hosted, multi-tenant service. Deploying this UI for multiple people over a network without moving key generation to the browser (WebCrypto) or a separate device would mean a server operator could see every private key it generates. This reference implementation does not attempt that harder problem; the banner says so explicitly rather than leaving it as a silent gap.

### Still open (tracked for 0.4+)
- No reference platform adapters for real third-party services.
- No independent security audit.
- No legal review of trustee-quorum attestation's standing as evidence of death or incapacity.
- The web UI is single-user/local-only by design — a real multi-tenant deployment needs client-side key generation, which is a separate, harder project.
- `LocalFileStore` remains single-machine and not concurrency-safe.

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
