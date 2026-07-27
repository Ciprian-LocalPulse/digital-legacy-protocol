"""
Command-line interface for DLP.

    dlp keygen                    # Ed25519 signing keypair
    dlp enckeygen                 # X25519 keypair for encrypting contact hints
    dlp demo                      # runs a full end-to-end scenario
    dlp verify <manifest.json>
    dlp inspect <manifest.json>
    dlp store-save <manifest.json> [--dir PATH]
    dlp store-list [--dir PATH]
    dlp store-load <manifest_id> [--dir PATH]
    dlp switch-init <manifest_id> [--dir PATH]
    dlp switch-status <manifest_id> [--dir PATH]
    dlp switch-checkin <manifest_id> [--dir PATH]
    dlp switch-attest <manifest_id> <trustee_id> (--unreachable | --reachable) [--dir PATH]
    dlp switch-tick <manifest_id> [--dir PATH]   # sends any due notifications (run from cron)
    dlp web [--dir PATH] [--host HOST] [--port PORT]   # requires the 'web' extra
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from . import crypto, hint_crypto, shamir
from .adapter import InMemoryDemoAdapter
from .manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)
from .notify import ConsoleChannel, NotificationService
from .orchestrator import SwitchMonitor
from .storage import (
    LocalFileStore,
    LocalSwitchStore,
    ManifestNotFoundError,
    SwitchNotFoundError,
)
from .switch import DeadMansSwitch, SwitchState

_DEFAULT_STORE_DIR = ".dlp_store"
_DEFAULT_SWITCH_DIR = ".dlp_store/switches"


def cmd_keygen(_args: argparse.Namespace) -> None:
    priv, pub = crypto.generate_keypair()
    print(json.dumps({"private_key": priv, "public_key": pub}, indent=2))
    print("\nKeep the private key secret. Never put it in a manifest file.", file=sys.stderr)


def cmd_enckeygen(_args: argparse.Namespace) -> None:
    priv, pub = hint_crypto.generate_encryption_keypair()
    print(json.dumps({"private_key": priv, "public_key": pub}, indent=2))
    print(
        "\nThis is a SEPARATE keypair from `dlp keygen` — use it only for "
        "encrypting/decrypting contact_hint fields, never for signing.",
        file=sys.stderr,
    )


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


def cmd_store_save(args: argparse.Namespace) -> None:
    with open(args.manifest_path) as f:
        manifest = json.load(f)
    store = LocalFileStore(args.dir)
    try:
        store.save(manifest)
    except ManifestValidationError as e:
        print(f"Refusing to store invalid manifest: {e}")
        sys.exit(1)
    print(f"Saved manifest {manifest['manifest_id']} to {args.dir}/")


def cmd_store_list(args: argparse.Namespace) -> None:
    store = LocalFileStore(args.dir)
    ids = store.list_ids()
    if not ids:
        print(f"(no manifests stored in {args.dir}/)")
        return
    for manifest_id in ids:
        manifest = store.load(manifest_id)
        owner = manifest["owner"].get("display_name") or "(unnamed)"
        print(f"  {manifest_id}  —  owner: {owner}")


def cmd_store_load(args: argparse.Namespace) -> None:
    store = LocalFileStore(args.dir)
    try:
        manifest = store.load(args.manifest_id)
    except ManifestNotFoundError:
        print(f"No manifest found with id {args.manifest_id!r} in {args.dir}/")
        sys.exit(1)
    print(json.dumps(manifest, indent=2))


def cmd_web(args: argparse.Namespace) -> None:
    try:
        from .webapp import create_app
    except ImportError:
        print(
            "The web UI needs Flask, which is an optional dependency.\n"
            "Install it with: pip install -e '.[web]'",
            file=sys.stderr,
        )
        sys.exit(1)
    app = create_app(store_dir=args.dir)
    print(f"Serving DLP web UI at http://{args.host}:{args.port}  (manifests in {args.dir}/)")
    app.run(host=args.host, port=args.port, debug=args.debug)


def cmd_switch_init(args: argparse.Namespace) -> None:
    manifest_store = LocalFileStore(args.dir)
    try:
        manifest = manifest_store.load(args.manifest_id)
    except ManifestNotFoundError:
        print(f"No manifest found with id {args.manifest_id!r} in {args.dir}/")
        sys.exit(1)

    switch_store = LocalSwitchStore(args.switch_dir)
    if args.manifest_id in switch_store.list_ids() and not args.force:
        print(
            f"A switch already exists for {args.manifest_id}. "
            f"Use --force to reset it (this clears attestations and resets the check-in timer)."
        )
        sys.exit(1)

    sw = DeadMansSwitch.from_manifest(manifest)
    switch_store.save(sw)
    print(f"Switch initialized for manifest {args.manifest_id}")
    print(f"  check-in every {sw.interval_days} days, {sw.grace_days} day grace period")
    print(f"  quorum threshold: {sw.quorum_threshold}")


def cmd_switch_status(args: argparse.Namespace) -> None:
    switch_store = LocalSwitchStore(args.switch_dir)
    try:
        sw = switch_store.load(args.manifest_id)
    except SwitchNotFoundError:
        print(f"No switch found for manifest {args.manifest_id!r}. Run `dlp switch-init` first.")
        sys.exit(1)

    state = sw.state()
    print(f"Manifest: {args.manifest_id}")
    print(f"State: {state.value}")
    if state == SwitchState.ACTIVE:
        print(f"Days until overdue: {sw.days_until_overdue():.1f}")
    elif state in (SwitchState.VERIFICATION, SwitchState.ACTIVATED):
        print(f"Confirmations needed: {sw.confirmations_needed()}")
        for a in sw.attestations:
            verdict = "unreachable" if a.confirms_unreachable else "reachable (aborts activation)"
            print(f"  trustee {a.trustee_id}: {verdict} (at {a.timestamp.isoformat()})")


def cmd_switch_checkin(args: argparse.Namespace) -> None:
    switch_store = LocalSwitchStore(args.switch_dir)
    try:
        sw = switch_store.load(args.manifest_id)
    except SwitchNotFoundError:
        print(f"No switch found for manifest {args.manifest_id!r}. Run `dlp switch-init` first.")
        sys.exit(1)

    sw.record_checkin()
    switch_store.save(sw)
    print(f"Check-in recorded for {args.manifest_id}. State: {sw.state().value}")


def cmd_switch_attest(args: argparse.Namespace) -> None:
    switch_store = LocalSwitchStore(args.switch_dir)
    try:
        sw = switch_store.load(args.manifest_id)
    except SwitchNotFoundError:
        print(f"No switch found for manifest {args.manifest_id!r}. Run `dlp switch-init` first.")
        sys.exit(1)

    confirms_unreachable = args.unreachable
    try:
        sw.record_attestation(args.trustee_id, confirms_unreachable=confirms_unreachable)
    except RuntimeError as e:
        print(f"Cannot record attestation: {e}")
        sys.exit(1)

    switch_store.save(sw)
    print(f"Attestation recorded for trustee {args.trustee_id}. State: {sw.state().value}")


def cmd_switch_tick(args: argparse.Namespace) -> None:
    manifest_store = LocalFileStore(args.dir)
    switch_store = LocalSwitchStore(args.switch_dir)

    if args.smtp_host:
        from .notify import SMTPEmailChannel

        if not (args.smtp_user and args.smtp_password and args.smtp_from):
            print(
                "--smtp-host requires --smtp-user, --smtp-password, and --smtp-from",
                file=sys.stderr,
            )
            sys.exit(1)
        channel = SMTPEmailChannel(
            host=args.smtp_host,
            port=args.smtp_port,
            username=args.smtp_user,
            password=args.smtp_password,
            from_address=args.smtp_from,
        )
    elif args.sms_account_sid:
        from .notify import TwilioSMSChannel

        if not (args.sms_auth_token and args.sms_from):
            print(
                "--sms-account-sid requires --sms-auth-token and --sms-from",
                file=sys.stderr,
            )
            sys.exit(1)
        channel = TwilioSMSChannel(
            account_sid=args.sms_account_sid,
            auth_token=args.sms_auth_token,
            from_number=args.sms_from,
        )
    else:
        channel = ConsoleChannel()

    monitor = SwitchMonitor(manifest_store, switch_store, NotificationService(channel))
    attempts = monitor.tick(args.manifest_id)

    if not attempts:
        print(f"Nothing new to notify for {args.manifest_id}.")
        return
    for a in attempts:
        status = "sent" if a.success else "FAILED"
        detail = f" ({a.detail})" if a.detail else ""
        print(f"[{status}] {a.kind} -> {a.recipient}{detail}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="dlp", description="Digital Legacy Protocol CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("keygen", help="generate an Ed25519 keypair").set_defaults(func=cmd_keygen)
    sub.add_parser("enckeygen", help="generate an X25519 keypair for hint encryption").set_defaults(
        func=cmd_enckeygen
    )
    sub.add_parser("demo", help="run a full end-to-end demo scenario").set_defaults(func=cmd_demo)

    p_verify = sub.add_parser("verify", help="validate a manifest file's structure and signature")
    p_verify.add_argument("manifest_path")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="print a human-readable summary of a manifest")
    p_inspect.add_argument("manifest_path")
    p_inspect.set_defaults(func=cmd_inspect)

    p_store_save = sub.add_parser("store-save", help="persist a manifest file to local storage")
    p_store_save.add_argument("manifest_path")
    p_store_save.add_argument("--dir", default=_DEFAULT_STORE_DIR)
    p_store_save.set_defaults(func=cmd_store_save)

    p_store_list = sub.add_parser("store-list", help="list manifest_ids in local storage")
    p_store_list.add_argument("--dir", default=_DEFAULT_STORE_DIR)
    p_store_list.set_defaults(func=cmd_store_list)

    p_store_load = sub.add_parser("store-load", help="print a stored manifest by id")
    p_store_load.add_argument("manifest_id")
    p_store_load.add_argument("--dir", default=_DEFAULT_STORE_DIR)
    p_store_load.set_defaults(func=cmd_store_load)

    p_switch_init = sub.add_parser(
        "switch-init", help="start monitoring a stored manifest's dead man's switch"
    )
    p_switch_init.add_argument("manifest_id")
    p_switch_init.add_argument(
        "--dir", default=_DEFAULT_STORE_DIR, help="manifest storage directory"
    )
    p_switch_init.add_argument("--switch-dir", default=_DEFAULT_SWITCH_DIR, dest="switch_dir")
    p_switch_init.add_argument("--force", action="store_true", help="reset an existing switch")
    p_switch_init.set_defaults(func=cmd_switch_init)

    p_switch_status = sub.add_parser("switch-status", help="show a manifest's switch state")
    p_switch_status.add_argument("manifest_id")
    p_switch_status.add_argument("--switch-dir", default=_DEFAULT_SWITCH_DIR, dest="switch_dir")
    p_switch_status.set_defaults(func=cmd_switch_status)

    p_switch_checkin = sub.add_parser(
        "switch-checkin", help="record that the owner is alive and checking in"
    )
    p_switch_checkin.add_argument("manifest_id")
    p_switch_checkin.add_argument("--switch-dir", default=_DEFAULT_SWITCH_DIR, dest="switch_dir")
    p_switch_checkin.set_defaults(func=cmd_switch_checkin)

    p_switch_attest = sub.add_parser(
        "switch-attest", help="record a trustee's attestation during verification"
    )
    p_switch_attest.add_argument("manifest_id")
    p_switch_attest.add_argument("trustee_id")
    attest_group = p_switch_attest.add_mutually_exclusive_group(required=True)
    attest_group.add_argument(
        "--unreachable", action="store_true", help="trustee confirms the owner cannot be reached"
    )
    attest_group.add_argument(
        "--reachable",
        dest="unreachable",
        action="store_false",
        help="trustee confirms the owner is fine — aborts activation",
    )
    p_switch_attest.add_argument("--switch-dir", default=_DEFAULT_SWITCH_DIR, dest="switch_dir")
    p_switch_attest.set_defaults(func=cmd_switch_attest)

    p_switch_tick = sub.add_parser(
        "switch-tick",
        help="send any notifications due for a manifest's current switch state (safe to run repeatedly, e.g. from cron)",
    )
    p_switch_tick.add_argument("manifest_id")
    p_switch_tick.add_argument(
        "--dir", default=_DEFAULT_STORE_DIR, help="manifest storage directory"
    )
    p_switch_tick.add_argument("--switch-dir", default=_DEFAULT_SWITCH_DIR, dest="switch_dir")
    p_switch_tick.add_argument(
        "--smtp-host",
        default=None,
        help="if set, sends real email via this SMTP server instead of printing to console (takes precedence over --sms-account-sid if both are given)",
    )
    p_switch_tick.add_argument("--smtp-port", type=int, default=587)
    p_switch_tick.add_argument("--smtp-user", default=None)
    p_switch_tick.add_argument("--smtp-password", default=None)
    p_switch_tick.add_argument("--smtp-from", default=None)
    p_switch_tick.add_argument(
        "--sms-account-sid",
        default=None,
        help="if set (and --smtp-host is not), sends real SMS via Twilio instead of printing to console",
    )
    p_switch_tick.add_argument("--sms-auth-token", default=None)
    p_switch_tick.add_argument(
        "--sms-from", default=None, help="Twilio-verified sending number, e.g. +15551230000"
    )
    p_switch_tick.set_defaults(func=cmd_switch_tick)

    p_web = sub.add_parser("web", help="launch the local web UI (requires the 'web' extra)")
    p_web.add_argument("--dir", default=_DEFAULT_STORE_DIR, help="manifest storage directory")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=5000)
    p_web.add_argument("--debug", action="store_true")
    p_web.set_defaults(func=cmd_web)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
