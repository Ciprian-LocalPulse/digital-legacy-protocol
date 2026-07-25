# Digital Legacy Protocol (DLP) — Specification v0.1

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
      { "trustee_id": "uuid", "public_key": "ed25519:...", "contact_hint": "encrypted" }
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
    { "beneficiary_id": "uuid", "public_key": "ed25519:... or null", "contact_hint": "encrypted" }
  ],
  "signature": "ed25519 signature over canonicalized manifest minus this field"
}
```

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

## 10. Open questions for the community

- Should manifests support partial activation (some assets release before others)?
- How should minors or dependents with no public key be represented as beneficiaries?
- What's the right default for `grace_days` across cultures and use cases?

Contributions and critique welcome — see `CONTRIBUTING.md`.
