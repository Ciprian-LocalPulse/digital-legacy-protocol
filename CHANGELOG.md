# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.8.0] — 2026-07-27

A second real notification channel — `NotificationChannel` had shipped with exactly one working implementation (email) since 0.3.0; this closes that gap for trustees who don't check email reliably but do carry a phone.

### Added
- `dlp.notify.TwilioSMSChannel` — sends real SMS via Twilio's REST API, stdlib `urllib` only (no Twilio SDK dependency, consistent with every other network-calling piece of this project). HTTP Basic Auth with Account SID + Auth Token, exactly as Twilio's own docs describe.
  - Subject is prefixed onto the body rather than dropped (SMS has no subject line), and the combined message is truncated to a conservative length with a trailing ellipsis — long DLP notification text is not what SMS is for; email remains the channel for anything that needs the full text.
  - Twilio's own error messages are surfaced through `NotificationError` rather than just the raw HTTP status, matching how `SMTPEmailChannel` and the platform adapters already report failures.
- CLI: `dlp switch-tick` now accepts `--sms-account-sid` / `--sms-auth-token` / `--sms-from` as an alternative to `--smtp-*` (SMTP takes precedence if both are configured; console remains the default if neither is set).
- 13 new tests (218 total, 2 skipped by design): request construction, Basic Auth header correctness, subject prefixing, truncation at the configured length, Twilio HTTP error unwrapping (including a fallback path when the error body isn't JSON), network-error handling, and the channel working correctly through `NotificationService`.

### Notes
- Consistent with `dlp switch-tick`'s existing SMTP behavior, and with the web UI's notification button remaining console-only by design (see 0.6.0's notes) — no browser form was added for SMS credentials either. A Twilio Auth Token has no more business being typed into a web form than an SMTP password does.

## [0.7.0] — 2026-07-27

The second real `DLPAdapter` implementation, and the one that finally covers `execute_webhook` — the only spec action `GitHubAdapter` explicitly declined to implement, since GitHub's API has no natural mapping for "call an arbitrary URL."

### Added
- `dlp.adapters.webhook.WebhookAdapter` — delivers `execute_webhook` activations as a signed HTTP POST to any endpoint that can receive one: Zapier, a Discord/Slack incoming webhook, a self-hosted script, anything. Stdlib `urllib` only, no new dependency.
  - HMAC-SHA256 request signing (`X-DLP-Signature` header, same convention as GitHub/Stripe webhooks) when a `signing_secret` is configured, so receivers can verify authenticity. `verify_webhook_signature()` is provided for the receiving side.
  - Refuses to send secret material over plain `http://` by default — `allow_insecure_http=True` is required to opt out, intended only for local development against `http://localhost`.
  - Reports unsupported actions, malformed URLs, non-2xx responses, and unreachable endpoints all as clear `ActionResult` failures rather than raising or silently doing nothing.
- `examples/webhook_adapter_demo.py` — unlike the GitHub demo, this one needs no external account or token: it stands up a real local HTTP server to receive its own webhook, so the entire signed-delivery flow is visible end to end with nothing but `python examples/webhook_adapter_demo.py`.
- 16 new tests (205 total, 2 skipped by design) — and unlike every other adapter test in this repo, these run against a **real local HTTP server** (`http.server` in a background thread) rather than mocking `urllib`. The adapter's actual network code executes exactly as it would against a real third-party endpoint; only the destination is localhost. `dlp/adapters/webhook.py` reached 100% test coverage this way.

### Notes
- Two working adapters now exist, targeting genuinely different kinds of platform (a specific third-party API vs. an arbitrary webhook receiver), which is a better test of whether `DLPAdapter` generalizes than a single adapter could be on its own.

## [0.6.0] — 2026-07-26

Connects two pieces that had existed side by side since 0.3.0/0.5.0 without anything linking them: `dlp.switch`'s state machine and `dlp.notify`'s message delivery. Before this, a trustee had no way to learn they needed to attest except being told out-of-band by someone manually running `dlp switch-attest` on their behalf.

### Added
- `dlp.orchestrator.SwitchMonitor` — the connector. `tick(manifest_id)` inspects current switch state, sends exactly the notifications appropriate for that state (owner check-in reminder on `overdue`, trustee attestation requests on `verification`, beneficiary activation notices on `activated`, an owner reassurance notice on `aborted`), and tracks `last_notified_state` on the switch itself so repeated calls — e.g. from a daily cron job — don't resend the same email every time.
- `NotificationService.send_abort_notice()` — the one message type that didn't already have a dedicated method.
- A new, deliberately separate `notification_address` field on owners, trustees, and beneficiaries (`ManifestBuilder.add_trustee()` / `add_beneficiary()` / the constructor for owners). This is **not** encrypted the way `contact_hint` is — automated delivery needs a plaintext destination to send to, and encrypting it the same way as the privacy-preserving hint would make automated delivery impossible without one party holding every trustee's decryption key, which contradicts the whole point of that encryption. Leave it unset if you'd rather deliver attestation requests manually.
- CLI: `dlp switch-tick <manifest_id>` — prints to console by default; pass `--smtp-host` (with `--smtp-user`/`--smtp-password`/`--smtp-from`) to send real email instead. Safe to run repeatedly or from cron.
- Web UI: manifest pages now have a "Send due notifications" button showing exactly what was (or wasn't) sent, and the create-manifest form collects optional email addresses for the owner, each trustee, and the beneficiary.
- 23 new tests (190 total, 1 skipped by design): every state transition's notification content, idempotency across repeated ticks, graceful handling of missing addresses and channel failures (reported, never raised), and the full loop exercised through both the CLI and Flask's test client.

### Notes
- The web UI's notification button intentionally only prints to the server's own console (`ConsoleChannel`), never sends real email — wiring an SMTP password into a browser form is a worse idea than it sounds, and the button's help text says so. Real delivery from automation is a CLI/cron concern (`dlp switch-tick --smtp-host ...`), consistent with this UI's existing single-user/local-only scope (spec section 14).

## [0.5.0] — 2026-07-26

Closes a gap that had persisted since 0.1.0 without anyone flagging it explicitly: `dlp.switch.DeadMansSwitch` was fully implemented and 100%-tested as a library, but had no persistence and no CLI or web exposure. Every check-in and attestation had to happen inside a single Python process — there was no way to actually *run* a switch across multiple real-world days.

### Added
- `DeadMansSwitch.to_dict()` / `.from_dict()` / `.from_manifest()` — serialization for the switch state machine, including correct round-tripping of the internal abort timestamp and all attestations.
- `dlp.storage.LocalSwitchStore` — persists switch state to one JSON file per manifest, deliberately separate from `ManifestStore` (switch state mutates constantly; the signed manifest should not).
- CLI: `dlp switch-init`, `dlp switch-status`, `dlp switch-checkin`, `dlp switch-attest`. Manually verified end-to-end, including backdating a switch to simulate 130 days without a check-in and walking it through verification, quorum activation, and the single-trustee abort path.
- Web UI: every manifest page now shows live switch status (or a "Start monitoring" button if none exists yet), a check-in button, and an attestation form once verification has started — so the entire owner/trustee lifecycle, not just manifest creation, is usable without a terminal.
- 36 new tests (167 total, 2 skipped by design): switch serialization round-trips (including the abort and activation edge cases), `LocalSwitchStore` CRUD and path-traversal rejection, all four new CLI commands, and the full switch lifecycle exercised through Flask's test client and against a real running server via `curl`.

### Notes
- `switch-attest` intentionally refuses (CLI: exits with an error; web: silently no-ops) if called before verification has actually started — matching `DeadMansSwitch.record_attestation()`'s existing guard rather than working around it.
- The web UI's attestation form only appears once a switch has entered `verification` or `activated` state, so the "too early" case is normally unreachable through the UI itself; the CLI and the underlying library still enforce it either way, since a browser isn't the only client that will ever call these routes.

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
