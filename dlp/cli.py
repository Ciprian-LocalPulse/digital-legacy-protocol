"""
Command-line interface for DLP.

    dlp keygen
    dlp demo                     # runs a full end-to-end scenario
    dlp verify <manifest.json>
    dlp inspect <manifest.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from . import crypto, shamir
from .adapter import InMemoryDemoAdapter
from .manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)
from .switch import DeadMansSwitch, SwitchState


def cmd_keygen(_args: argparse.Namespace) -> None:
    priv, pub = crypto.generate_keypair()
    print(json.dumps({"private_key": priv, "public_key": pub}, indent=2))
    print("\nKeep the private key secret. Never put it in a manifest file.", file=sys.stderr)


def cmd_verify(args: argparse.Namespace) -> None:
    with open(args.manifest_path) as f:
        manifest = json.load(f)
    try:
        validate_manifest(manifest)
    except ManifestValidationError as e:
        print(f"INVALID structure: {e}")
        sys.exit(1)
    if is_signature_valid(manifest):
        print("Manifest is structurally valid and the signature checks out.")
    else:
        print("Manifest structure is valid but the SIGNATURE DOES NOT MATCH.")
        sys.exit(1)


def cmd_inspect(args: argparse.Namespace) -> None:
    with open(args.manifest_path) as f:
        manifest = json.load(f)
    print(f"Manifest {manifest['manifest_id']}  (dlp v{manifest['dlp_version']})")
    print(f"  Owner: {manifest['owner'].get('display_name') or '(unnamed)'}")
    q = manifest["quorum"]
    print(f"  Quorum: {q['threshold']} of {len(q['trustees'])} trustees")
    print(
        f"  Check-in: every {manifest['checkin']['interval_days']} days, "
        f"{manifest['checkin']['grace_days']} day grace period"
    )
    print(f"  Assets ({len(manifest['assets'])}):")
    for asset in manifest["assets"]:
        print(f"    - [{asset['type']}] {asset['reference']} -> action: {asset['action']}")


def cmd_demo(_args: argparse.Namespace) -> None:
    """End-to-end scenario: build a manifest, split a secret, simulate a
    missed check-in, gather trustee attestations, reconstruct the secret,
    and hand it to a demo platform adapter."""

    print("=== 1. Generating keys for owner + 3 trustees ===")
    owner_priv, owner_pub = crypto.generate_keypair()
    trustees = {tid: crypto.generate_keypair() for tid in ("t1", "t2", "t3")}
    for tid, (_, pub) in trustees.items():
        print(f"  trustee {tid}: {pub[:24]}...")

    print("\n=== 2. Building and signing the manifest (2-of-3 quorum) ===")
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Demo Owner")
    for tid, (_, pub) in trustees.items():
        builder.add_trustee(tid, pub, contact_hint=f"trustee {tid}")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("ben1", contact_hint="beneficiary")
    builder.add_asset(
        asset_type="crypto_wallet",
        reference="demo cold wallet",
        beneficiary_id="ben1",
        action="release_key",
        shares_distributed_to=list(trustees.keys()),
    )
    signed_manifest = builder.build_and_sign(owner_priv)
    print(f"  manifest_id: {signed_manifest['manifest_id']}")
    print(f"  signature valid: {is_signature_valid(signed_manifest)}")

    print("\n=== 3. Splitting the actual secret (never stored in the manifest) ===")
    secret = b"this-would-be-a-real-private-key-in-production"
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=list(trustees.keys()))
    for s in shares:
        print(f"  share for {s.trustee_id}: {s.data.hex()[:20]}...")

    print("\n=== 4. Simulating time passing without a check-in ===")
    dms = DeadMansSwitch(
        manifest_id=signed_manifest["manifest_id"],
        interval_days=90,
        grace_days=30,
        quorum_threshold=2,
        last_checkin=datetime.now(timezone.utc) - timedelta(days=200),
    )
    print(f"  switch state: {dms.state().value}")

    print("\n=== 5. Two trustees attest the owner is unreachable ===")
    dms.record_attestation("t1", confirms_unreachable=True)
    dms.record_attestation("t2", confirms_unreachable=True)
    print(f"  switch state: {dms.state().value}")

    if dms.state() == SwitchState.ACTIVATED:
        print("\n=== 6. Reconstructing the secret from 2 of 3 shares ===")
        reconstructed = shamir.reconstruct_secret([shares[0], shares[1]])
        print(f"  matches original: {reconstructed == secret}")

        print("\n=== 7. Handing off to a platform adapter ===")
        demo_adapter = InMemoryDemoAdapter()
        asset_id = signed_manifest["assets"][0]["asset_id"]
        result = demo_adapter.on_activation(signed_manifest, asset_id, reconstructed)
        print(f"  {result.detail}")

    print("\nDone. This whole flow never required a single company to decide anyone was dead.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="dlp", description="Digital Legacy Protocol CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="generate an Ed25519 keypair").set_defaults(func=cmd_keygen)
    sub.add_parser("demo", help="run a full end-to-end demo scenario").set_defaults(func=cmd_demo)

    p_verify = sub.add_parser("verify", help="validate a manifest file's structure and signature")
    p_verify.add_argument("manifest_path")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="print a human-readable summary of a manifest")
    p_inspect.add_argument("manifest_path")
    p_inspect.set_defaults(func=cmd_inspect)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
