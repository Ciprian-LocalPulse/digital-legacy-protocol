# Digital Legacy Protocol (DLP) — Specification v0.4

**Status:** Draft / Request for Comments
**Author:** Stefano (Ciprian-LocalPulse) & contributors
**License:** This specification is released under CC0 1.0 — public domain. Anyone can implement it, fork it, or embed it in a commercial product without asking permission.

## 1. Why this exists

Every platform that holds part of your digital life — banks, exchanges, email providers, social networks, password managers — has invented its own ad-hoc "what happens when the account holder dies" policy. Most have none at all. The result:

- Billions of dollars in cryptocurrency are permanently unreachable because private keys died with their owners.
- Families spend months in probate court arguing with support tickets instead of grieving.
- There is no machine-readable, cryptographically verifiable way to say "if I disappear, here is exactly what should happen to my digital assets" that more than one platform can honor.

DLP is not a company, not an app, not a walled garden. It is an **open manifest format** plus a **reference protocol** for verifying, with a quorum of trusted humans instead of a single corporation, that a person is actually gone — and then releasing exactly what that person authorized, to exactly who they authorized, and nothing more.

## 2. Design principles

1. **No single company decides you're dead.** Verification is done by a trustee quorum (M-of-N), not a platform's support department.
2. **The manifest is useless without the quorum.** A stolen or leaked `.dlp` file grants no access by itself — it only describes *intent*. The actual secrets are split via Shamir's Secret Sharing among trustees.
3. **Platforms opt in, they don't own it.** Any service can implement the `DLPAdapter` interface and honor manifests without paying anyone or asking permission.
4. **Reversible until the last moment.** The owner can revoke or update a manifest at any time before quorum activation, with a newer signature always overriding an older one.
5. **Minimal disclosure.** A trustee only ever learns their own share and the specific instructions relevant to actions they're asked to help execute — never the whole picture unless the owner explicitly designates them as an "executor" role.

## 3. Core concepts

| Term | Meaning |
|---|---|
| **Owner** | The person whose digital legacy the manifest describes. |
| **Manifest** | A signed, structured document (`.dlp.json`) declaring beneficiaries, assets, conditions, and actions. |
| **Trustee** | A person the owner nominates to help verify death/incapacity and participate in secret reconstruction. |
| **Quorum** | The minimum number of trustees (M of N) who must agree before the switch activates. |
| **Beneficiary** | A person or entity designated to receive an asset or access. |
| **Asset Reference** | A pointer to something governed by the manifest (an account, a wallet, a file, a message) — the manifest never stores the secret itself, only a reference and a share. |
| **Dead Man's Switch (DMS)** | The check-in mechanism: owner proves they're alive periodically; missing N consecutive check-ins triggers trustee verification. |
| **Platform Adapter** | Code a third-party service implements to read manifests and act on activated instructions. |

## 4. Manifest structure

A manifest is a JSON document, canonicalized (RFC 8785 JCS) before signing.

```json
{
  "dlp_version": "0.1",
  "manifest_id": "uuid-v4",
  "owner": {
    "public_key": "ed25519:base64...",
    "display_name": "optional, owner's choice"
  },
  "created_at": "ISO-8601",
  "updated_at": "ISO-8601",
  "supersedes": "previous manifest_id or null",
  "checkin": {
    "interval_days": 90,
    "grace_days": 30,
    "method": "signed_ping | email_confirm | app_heartbeat"
  },
  "quorum": {
    "threshold": 3,
    "trustees": [
      {
        "trustee_id": "uuid",
        "public_key": "ed25519:...",
        "contact_hint": "encrypted or plaintext, see 4.1",
        "contact_hint_encrypted": true
      }
    ]
  },
  "assets": [
    {
      "asset_id": "uuid",
      "type": "crypto_wallet | account_access | file | message | custom",
      "reference": "human-readable label, no secrets",
      "share_scheme": "shamir",
      "shares_distributed_to": ["trustee_id", "..."],
      "beneficiary_id": "uuid",
      "conditions": ["quorum_reached", "optional additional condition"],
      "action": "release_key | grant_access | deliver_message | execute_webhook"
    }
  ],
  "beneficiaries": [
    { "beneficiary_id": "uuid", "public_key": "ed25519:... or null", "contact_hint": "encrypted or plaintext", "contact_hint_encrypted": false }
  ],
  "signature": "ed25519 signature over canonicalized manifest minus this field"
}
```

### 4.1 Contact hint encryption

A manifest may be read by parties other than its intended trustees before activation — stored on a platform, backed up somewhere, or simply seen by whoever has file access. `contact_hint` is optional plaintext in its simplest form, but any deployment handling real personal information should encrypt it.

The reference implementation (`dlp.hint_crypto`) provides this via a minimal ECIES construction: X25519 key agreement, HKDF-SHA256 key derivation, AES-256-GCM authenticated encryption. Every trustee and beneficiary gets a dedicated X25519 encryption keypair, separate from their Ed25519 signing keypair — the two curves serve different purposes and mixing them is a common source of subtle mistakes, so this implementation keeps them apart rather than trying to reuse one key for both. When `contact_hint_encrypted` is `true`, only the holder of the matching X25519 private key can recover the plaintext; the manifest's signer, the storage layer, and anyone else who sees the manifest cannot.

## 5. Lifecycle

```
CREATE → SIGN → DISTRIBUTE SHARES → ACTIVE (check-ins) → 
   ↳ [missed check-ins beyond grace period] → TRUSTEE VERIFICATION →
      ↳ [quorum confirms] → ACTIVATED → ASSETS RELEASED
      ↳ [owner responds / false alarm] → back to ACTIVE
   ↳ [owner updates manifest] → new signature, supersedes old
```

## 6. Secret splitting

Each asset's actual secret (a private key, a password, a decryption key for a message) is **never stored in the manifest**. It is split using Shamir's Secret Sharing into N shares matching the quorum's trustees, requiring M shares to reconstruct. This means:

- No trustee alone can access anything.
- The platform storing the manifest never sees the secret, only metadata.
- Losing up to `N - M` trustees doesn't break the system.

## 7. Trustee verification flow

1. Owner misses `interval_days + grace_days` of check-ins.
2. Each trustee is notified independently and asked to attest: "to my knowledge, is the owner alive and able to check in?"
3. If `threshold` trustees attest "no" (or the owner cannot be reached after a defined attempt window), the switch activates.
4. Any single trustee (or the owner) can abort activation up until the threshold is reached — this is intentional friction against false positives.

## 8. Platform Adapter interface

Any platform can implement:

```
DLPAdapter.verify_manifest(manifest) -> bool
DLPAdapter.on_activation(manifest, asset_id, reconstructed_secret) -> ActionResult
DLPAdapter.on_revocation(manifest_id) -> None
```

This is intentionally minimal so it can sit on top of a bank's internal systems, a crypto exchange's cold storage policy, or a hobby project's SQLite database.

## 9. Non-goals

- DLP does not custody funds or secrets. It is a protocol, not a vault.
- DLP does not replace a legal will. It is a technical layer that can be *referenced* by a will, not a substitute for one.
- DLP is not a company and has no token, no fee, no central server requirement.

## 10. Storage

Manifests need to live somewhere durable, but the spec deliberately does not mandate a single storage backend — a manifest's integrity comes from its signature, not from where it's kept. The reference implementation defines a small `ManifestStore` interface (`dlp.storage`) with one working backend, a local JSON-file store, meant for development and single-machine use.

A real deployment should not rely on a single server for this: if the only copy of a manifest lives on one company's disk, that company has effectively become the single point of failure DLP was designed to avoid. Reasonable options include replicating the manifest to each trustee's own device (they already need to trust each other for quorum, so this adds little additional exposure), a small number of independently-operated mirrors, or a content-addressed store like IPFS where the manifest's hash — not its location — is what beneficiaries and trustees are given in advance.

## 11. Owner key recovery

A gap in earlier drafts of this spec: if the owner loses their own private key before the switch ever activates, the manifest they signed becomes unmodifiable and unrevocable — updating or superseding it requires a fresh signature, which requires the key that's now gone.

The reference implementation (`dlp.recovery`) offers an opt-in mitigation: the owner may split their own private key with Shamir's Secret Sharing among some or all of the same trustees who hold asset shares, at a threshold the owner sets independently of the quorum threshold used for switch activation. This is a genuine tradeoff, not a free fix — trustees who can collectively reconstruct the owner's signing key could, in principle, forge a manifest update while the owner is still alive, if enough of them colluded. For that reason:

- The recovery threshold should generally be set **higher** than the activation threshold (e.g. requiring all N trustees to recover a live owner's key, but only M-of-N to activate the switch after death).
- This mechanism is opt-in. An owner who decides the collusion risk isn't worth it can simply not use it — losing the key then means reissuing a fresh manifest from scratch, exactly as in the original design.

## 12. Open questions for the community

- Should manifests support partial activation (some assets release before others)?
- How should minors or dependents with no public key be represented as beneficiaries?
- What's the right default for `grace_days` across cultures and use cases?

## 13. Notification delivery

The check-in and trustee-attestation flow described in section 7 is only useful if the messages it implies — "please check in," "please attest," "an asset has been released to you" — actually reach a real person. Earlier drafts of this spec modeled the *logic* of check-ins and attestations (`dlp.switch`) without addressing *delivery* at all.

The reference implementation (`dlp.notify`) closes that gap with a small `NotificationChannel` interface and one working implementation, `SMTPEmailChannel`, which sends real email over standard SMTP with TLS and username/password auth — compatible with Gmail app passwords, Amazon SES, Postmark, or any self-hosted mail server. A `ConsoleChannel` implementation exists for local development and testing, where standing up real mail infrastructure would be unnecessary overhead.

This is intentionally one channel, not a notification platform. A real deployment will likely want SMS, push notifications, or postal mail as a fallback for trustees who don't check email reliably — implement `NotificationChannel` for any of those the same way you'd implement `DLPAdapter` or `ManifestStore`.

## 14. Reference web UI

The reference implementation ships a minimal, server-rendered web interface (`dlp.webapp`, an optional extra) so that using DLP does not strictly require comfort with a command line or the Python API. It covers manifest creation, inspection, and signature verification through plain HTML forms.

This UI generates and displays private keys server-side, in the same process serving the page. That is an acceptable tradeoff for a local tool running on hardware the user controls, and an **unacceptable** one for a hosted, multi-tenant service — a server operator in that scenario would see every private key it generates on a user's behalf, which defeats a fair amount of the point of DLP existing at all. Anyone deploying this UI for multiple people over a network should move key generation and signing into the browser (e.g. via WebCrypto) or a separate trusted device, rather than assuming this reference implementation's approach scales to that setting unchanged.

## 15. A worked Platform Adapter: GitHub

Section 8 describes the `DLPAdapter` interface in the abstract. `dlp.adapters.github.GitHubAdapter` is a genuine, working implementation of it against a real external API, included specifically to prove the interface is implementable and not just a plausible-looking abstraction.

It maps two of the four standard actions onto real GitHub behavior:

- **`deliver_message`** creates a private Gist containing the reconstructed message, returning its URL — appropriate for a manifest asset that is really a final letter, a set of instructions, or a small document rather than a credential.
- **`grant_access`** adds the beneficiary as a collaborator on a private repository, using an `owner/repo:username` convention in the asset's `reference` field.

It deliberately does **not** attempt `release_key` or `execute_webhook` — GitHub's API has no natural mapping for either, and the adapter says so explicitly rather than pretending otherwise. This is the intended shape for future adapters generally: implement what a given platform can actually do well, and report unsupported actions clearly rather than partially faking them.

Contributions and critique welcome — see `CONTRIBUTING.md`.
