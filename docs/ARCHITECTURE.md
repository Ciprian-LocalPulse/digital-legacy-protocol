# Architecture

## Purpose and scope of this document

[`spec/SPEC.md`](../spec/SPEC.md) defines the protocol: the manifest format, the state machine, the interfaces any implementation must expose. [`WHITEPAPER.md`](../WHITEPAPER.md) argues why that design is sound. Neither document describes how *this particular* reference implementation is put together — which module owns which responsibility, where trust boundaries actually sit in running code, and how a request travels from a CLI invocation or an HTTP form down to a cryptographic primitive. That is this document's job.

Everything here describes `dlp/` as it exists at v0.6.0. Where the implementation diverges from what the specification permits — because a feature is intentionally deferred, not because the spec forbids it — that divergence is noted explicitly rather than left for a reader to discover by diffing against `spec/SPEC.md` themselves.

## Layering

The package is organized as four layers, each depending only on the layer below it:

```
┌──────────────────────────────────────────────────────────┐
│  Interfaces         cli.py            webapp/             │
│                      (dlp <cmd>)       (Flask app.py)     │
├──────────────────────────────────────────────────────────┤
│  Orchestration      orchestrator.py    switch.py          │
│                      (state → notification)               │
├──────────────────────────────────────────────────────────┤
│  Domain             manifest.py   recovery.py   notify.py │
│                      adapter.py    adapters/github.py     │
├──────────────────────────────────────────────────────────┤
│  Primitives         crypto.py   shamir.py   hint_crypto.py│
│                      storage.py                            │
└──────────────────────────────────────────────────────────┘
```

Nothing in the **Primitives** layer imports from any layer above it. This is enforced by convention rather than tooling today; keeping `dlp/shamir.py` and `dlp/crypto.py` free of upward dependencies is what makes the claim in [`CONTRIBUTING.md`](../CONTRIBUTING.md) — that these modules stay "dependency-light and auditable" — actually verifiable by reading the import statements at the top of the file, rather than something a reader has to take on trust.

## Primitives layer

| Module | Responsibility | Notable properties |
|---|---|---|
| `crypto.py` | Ed25519 keypair generation, RFC 8785 JSON canonicalization, manifest signing and verification | `canonicalize()` is what makes signatures reproducible across languages — any conforming reimplementation of JCS should produce byte-identical output for the same manifest, which is the whole precondition for a non-Python `DLPAdapter` to verify a Python-generated manifest. |
| `shamir.py` | Shamir's Secret Sharing over GF(256), built from first principles | No external cryptography dependency, by design (see [`CONTRIBUTING.md`](../CONTRIBUTING.md), Code style). `split_secret()` / `reconstruct_secret()` operate on raw `bytes`; the security property — zero information below threshold — is a property of the finite-field construction itself, not of anything this implementation adds on top. |
| `hint_crypto.py` | X25519 key agreement + HKDF-SHA256 + AES-256-GCM for encrypting trustee/beneficiary contact hints | Separate keypair type from the Ed25519 signing keys (`generate_encryption_keypair()` vs. `crypto.generate_keypair()`) — a trustee's ability to decrypt their own hint is deliberately independent of their ability to sign attestations, so compromising one does not compromise the other. |
| `storage.py` | Persistence abstractions: `ManifestStore` (ABC) with a `LocalFileStore` implementation, plus `LocalSwitchStore` for switch state | The only layer that touches a filesystem. A hosted or multi-tenant deployment would replace `LocalFileStore`/`LocalSwitchStore` at this boundary; nothing above this layer should need to change to support a different backend, since callers only depend on the abstract interface. |

## Domain layer

| Module | Responsibility | Notable properties |
|---|---|---|
| `manifest.py` | `ManifestBuilder` (fluent construction), `validate_manifest()`, `is_signature_valid()` | The builder pattern exists specifically so a manifest cannot be signed in an invalid state — `build_and_sign()` runs validation before it ever calls into `crypto.sign_manifest()`. |
| `recovery.py` | Opt-in Shamir backup of the *owner's own* signing key (`backup_owner_key()` / `recover_owner_key()`) | A distinct, explicitly-labeled tradeoff from the trustee-facing secret splitting elsewhere in the protocol — see [`spec/SPEC.md`, Section 11](../spec/SPEC.md#11-owner-key-recovery) before using it. Reuses `shamir.py` rather than a parallel implementation. |
| `adapter.py` | The `DLPAdapter` abstract interface every platform integration implements, plus `ActionResult` and a non-persistent `InMemoryDemoAdapter` for testing | This is the seam the entire "platforms opt in" principle in [`MANIFESTO.md`](../MANIFESTO.md) depends on structurally — anything conforming to this interface can receive activation events without this repository knowing it exists. |
| `adapters/github.py` | The one adapter, as of v0.6.0, that calls a real external API | Deliberately implemented against stdlib `urllib` rather than a GitHub client library, keeping the pattern any future adapter author copies dependency-free by default. |
| `notify.py` | `NotificationChannel` (ABC) with `SMTPEmailChannel` and `ConsoleChannel` implementations, plus `NotificationService`, which owns the actual message text sent for each event | Message content lives here specifically so that what a trustee or beneficiary actually reads during an emotionally difficult moment is reviewable in one place, not scattered across whatever call site happens to trigger a notification. |

## Orchestration layer

| Module | Responsibility | Notable properties |
|---|---|---|
| `switch.py` | `DeadMansSwitch`, `SwitchState`, `Attestation` — the state machine itself: `ACTIVE → OVERDUE → VERIFICATION → ACTIVATED`, with `ABORTED` reachable from `VERIFICATION` | Serializable (`to_dict()`/`from_dict()`/`from_manifest()`) so that state can persist across the days or months this process is meant to span — a dead man's switch that only worked within a single running process would not be one. |
| `orchestrator.py` | `SwitchMonitor.tick()` — inspects current switch state and sends exactly the notifications appropriate to that state, tracking `last_notified_state` for idempotency | This is the module that closed the gap described in `CHANGELOG.md` under 0.6.0: before it existed, `switch.py`'s state transitions and `notify.py`'s message delivery had no code connecting them. `tick()` is safe to call repeatedly — from a cron job, from a manually-triggered CLI command, or from the web UI's notification button — because idempotency is a property of the orchestrator's own bookkeeping, not an assumption placed on the caller. |

## Interfaces layer

Two independent front ends sit on top of the same orchestration and domain layers, and neither one contains protocol logic of its own:

- **`cli.py`** exposes every lifecycle operation as a subcommand — `keygen`, `enckeygen`, `demo`, `verify`, `inspect`, `store-*`, `switch-init`, `switch-status`, `switch-checkin`, `switch-attest`, `switch-tick`, `web`. This is the reference entry point for anything that needs to run unattended (e.g., `switch-tick` from cron).
- **`webapp/`** is a minimal Flask application (`app.py` plus Jinja templates) offering the same lifecycle operations through a browser — manifest creation, inspection, verification, and live switch status with check-in/attestation forms — for a single local user, without a terminal.

Both interfaces call into the same `manifest.py`, `switch.py`, and `orchestrator.py` functions; neither reimplements validation, signing, or state-transition logic independently. This is a load-bearing design choice, not an incidental one: it is what makes the claim "the web UI and the CLI drive the same lifecycle" (README, "Running the actual dead man's switch") true by construction rather than by convention that could silently drift.

## Trust boundaries

The most important architectural fact about this codebase is not a module boundary — it is where whole secrets can and cannot exist in memory at all:

1. **The manifest never contains a reconstructible secret.** `ManifestBuilder` has no code path that accepts raw key material; `dlp.shamir.split_secret()` is called separately, out of band, and its output (`Share` objects) is distributed to trustees by whatever channel the owner chooses — the reference implementation does not automate this distribution, deliberately.
2. **`shamir.reconstruct_secret()` is the only point in the codebase where a split secret becomes whole again**, and it requires the caller to already possess at least `threshold` shares — nothing upstream of it (not `switch.py`, not `orchestrator.py`, not either interface) has a code path that can call it with fewer.
3. **`LocalFileStore` and `LocalSwitchStore` persist manifests and switch state, never raw secrets or shares.** A compromise of the local `.dlp_store` directory exposes manifest metadata and switch history, not reconstructible assets — consistent with the information-theoretic guarantee described in [`SECURITY.md`](../SECURITY.md).
4. **The reference web UI generates private keys server-side**, which is explicitly scoped to local, single-user use. This is the one place the implementation's trust model does not extend to a hypothetical hosted deployment — see [`spec/SPEC.md`, Section 14](../spec/SPEC.md#14-reference-web-ui) and [`MANIFESTO.md`, Section VII](../MANIFESTO.md#vii-what-this-project-will-not-become) — and any multi-tenant deployment would need to relocate key generation to the client before it could inherit this codebase's other trust properties.

## What this document does not cover

This is an implementation map, not a security analysis or a protocol rationale — for those, see [`SECURITY.md`](../SECURITY.md) and [`WHITEPAPER.md`](../WHITEPAPER.md) respectively. It also does not track wire-level or on-disk schema details already fully specified in [`spec/SPEC.md`](../spec/SPEC.md), Sections 4 and 10; where this document and the specification could be read as disagreeing, the specification is authoritative and this document should be corrected to match it.
