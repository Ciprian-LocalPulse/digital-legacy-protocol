<div align="center">
  <img src="assets/digital-legacy-protocol.png" alt="Digital Legacy Protocol" width="100%" />
</div>

# Digital Legacy Protocol (DLP)

[![CI](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/Ciprian-LocalPulse/digital-legacy-protocol/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Spec: CC0](https://img.shields.io/badge/Spec-CC0%201.0-blue.svg)](spec/SPEC.md)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

**An open protocol for what happens to your digital life after you're gone — verified by people you trust, not by a company's support ticket queue.**

Billions of dollars in cryptocurrency are permanently lost because private keys died with their owners. Families spend months fighting platform support to close a deceased parent's account. Every service — banks, exchanges, email providers, password managers — has invented its own incompatible, usually nonexistent policy for this. DLP is a small attempt to fix that with a standard instead of a company.

There is no server to sign up for, no token, no subscription. It's a spec plus a reference implementation. Fork it, embed it, ignore it.

## The idea in one paragraph

You write a signed manifest: *"if I disappear, give my daughter access to this wallet, delete this account, deliver this message."* The actual secrets (private keys, passwords) are never stored anywhere whole — they're split with Shamir's Secret Sharing among people you nominate as trustees, so no single trustee, platform, or attacker can act alone. If you stop checking in for long enough, your trustees are asked one question each: *"is Stefano actually gone, or did he just forget?"* Only when enough of them agree does anything get released — and any one of them can call it off if you're just on a boat with no signal.

## Why this doesn't already exist

It's not a hard cryptography problem — Shamir's Secret Sharing is decades old, Ed25519 signing is a solved problem. It's a coordination problem: no platform wants to build "what if the user dies" because it's grim, unprofitable, and nobody else supports it either, so there's nothing to be compatible *with*. DLP tries to be the thing everyone can be compatible with, released as public domain so no one has a reason not to adopt it.

## Quick start

```bash
pip install -e .
dlp demo
```

That runs a full scenario end to end: generates keys for an owner and three trustees, builds and signs a 2-of-3 manifest, splits a demo secret, simulates 200 days passing with no check-in, gathers two trustee attestations, reconstructs the secret, and hands it to a demo platform adapter. Nothing touches the network — it's all local, so you can read `dlp/cli.py`'s `cmd_demo` function alongside the output and see exactly what happened at each step.

## Using it as a library

```python
from dlp import ManifestBuilder, crypto, shamir

# Generate keys for the owner and three trustees
owner_priv, owner_pub = crypto.generate_keypair()
t1_priv, t1_pub = crypto.generate_keypair()
t2_priv, t2_pub = crypto.generate_keypair()
t3_priv, t3_pub = crypto.generate_keypair()

# Build a 2-of-3 manifest
manifest = (
    ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Stefano")
    .add_trustee("t1", t1_pub, contact_hint="brother")
    .add_trustee("t2", t2_pub, contact_hint="close friend")
    .add_trustee("t3", t3_pub, contact_hint="lawyer")
    .set_quorum_threshold(2)
    .add_beneficiary("daughter", contact_hint="my daughter")
    .add_asset(
        asset_type="crypto_wallet",
        reference="cold storage wallet #1",
        beneficiary_id="daughter",
        action="release_key",
        shares_distributed_to=["t1", "t2", "t3"],
    )
    .build_and_sign(owner_priv)
)

# The real secret never lives in the manifest — it's split separately
private_key_material = b"...actual wallet key..."
shares = shamir.split_secret(private_key_material, threshold=2,
                              trustee_ids=["t1", "t2", "t3"])
# distribute shares[i] to each trustee out of band (encrypted email, paper, etc.)
```

Verifying a manifest you received:

```python
from dlp import validate_manifest, is_signature_valid

validate_manifest(manifest)          # raises ManifestValidationError if malformed
is_signature_valid(manifest)         # True/False
```

Reconstructing once quorum is reached:

```python
from dlp import shamir

secret = shamir.reconstruct_secret([shares[0], shares[1]])  # any 2 of the 3
```

## What's in this repository

```
digital-legacy-protocol/
├── spec/SPEC.md          the actual protocol — start here if you're implementing DLP elsewhere
├── dlp/
│   ├── manifest.py        build, validate, and sign manifests
│   ├── crypto.py          Ed25519 signing/verification, canonical JSON serialization
│   ├── shamir.py          Shamir's Secret Sharing over GF(256), built from scratch
│   ├── switch.py          the dead man's switch state machine (check-ins, trustee attestation, quorum)
│   ├── adapter.py         the interface platforms implement to become DLP-aware
│   └── cli.py             `dlp keygen / demo / verify / inspect`
├── tests/                 51 tests, 100% coverage on the crypto and switch logic
└── examples/              sample manifests and a worked-through inheritance scenario
```

## Design principles (details in [spec/SPEC.md](spec/SPEC.md))

1. **No single company decides you're dead.** A quorum of trustees you personally chose does.
2. **The manifest alone grants nothing.** It describes intent; the actual secrets are split and require quorum to reconstruct.
3. **Platforms opt in — they don't own the standard.** The spec is CC0, public domain.
4. **Reversible until the last moment.** Update or revoke your manifest any time; newer signatures win.
5. **Minimal disclosure.** Trustees only ever see their own share and the instructions relevant to them.

## What this project is *not*

- Not a company, not a vault, not custody of your funds or secrets.
- Not a replacement for a legal will — it's a technical layer a will can reference, written for the parts a lawyer can't verify cryptographically.
- Not finished. This is a v0.1 draft spec plus a reference implementation, built to be argued with. See the open questions at the end of `SPEC.md`.

## Contributing

Bug reports, spec critique, and platform adapter implementations are all welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). If you build a `DLPAdapter` for a real service (a password manager, an exchange, anything), open a PR linking it; this repo will keep a registry of known implementations.

<img src="assets/section-divider.svg" alt="" width="100%" />

<div align="center">
  <img src="assets/donations-matrix-banner.svg" alt="Digital Legacy Protocol" width="100%" />
</div>

## Support this project

This is released as public infrastructure — free, MIT-licensed, no paywall, no account required. If it saved your family a headache or you just want to support the research, donations are welcome and go directly toward maintaining the spec and reference implementations:

| Method | Address / Details |
|---|---|
| Bitcoin (BTC) | `bc1q-see-DONATIONS.md-for-current-address` |
| Ethereum (ETH) | `0x-see-DONATIONS.md-for-current-address` |
| Bank transfer (RON/EUR) | see [DONATIONS.md](DONATIONS.md) |
| GitHub Sponsors | see repository sidebar |

Full details, including why donation addresses live in a separate file instead of hardcoded here, are in [DONATIONS.md](DONATIONS.md).

## License

- **Code** (everything under `dlp/`, `tests/`, `examples/`): MIT — see [LICENSE](LICENSE).
- **Specification** (`spec/SPEC.md`): CC0 1.0, public domain. Nobody should ever need permission to implement a death-notification protocol.
