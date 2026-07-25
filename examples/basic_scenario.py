"""
A worked example: Ada wants her cold-storage Bitcoin wallet to go to her
son Marcus, verified by a 2-of-3 quorum of her sister, her lawyer, and her
oldest friend — none of whom individually has to be trusted with the whole
picture.

Run with: python examples/basic_scenario.py
"""

from datetime import datetime, timedelta, timezone

from dlp import ManifestBuilder, crypto, is_signature_valid, shamir, validate_manifest
from dlp.switch import DeadMansSwitch, SwitchState


def main() -> None:
    print("--- Ada sets up her digital legacy ---\n")

    # only Ada's private key is used below (to sign her own manifest) — the
    # trustees' private keys stay with them in real life, so we discard the
    # local copies here to make that explicit
    ada_priv, ada_pub = crypto.generate_keypair()
    _sister_priv, sister_pub = crypto.generate_keypair()
    _lawyer_priv, lawyer_pub = crypto.generate_keypair()
    _friend_priv, friend_pub = crypto.generate_keypair()

    manifest = (
        ManifestBuilder(owner_public_key=ada_pub, owner_display_name="Ada")
        .with_checkin(interval_days=60, grace_days=14, method="app_heartbeat")
        .add_trustee("sister", sister_pub, contact_hint="Ada's sister, Elena")
        .add_trustee("lawyer", lawyer_pub, contact_hint="Ada's estate lawyer")
        .add_trustee("friend", friend_pub, contact_hint="Ada's college roommate")
        .set_quorum_threshold(2)
        .add_beneficiary("marcus", contact_hint="Ada's son")
        .add_asset(
            asset_type="crypto_wallet",
            reference="cold storage — main BTC wallet",
            beneficiary_id="marcus",
            action="release_key",
            shares_distributed_to=["sister", "lawyer", "friend"],
        )
        .build_and_sign(ada_priv)
    )

    print(f"Manifest created: {manifest['manifest_id']}")
    print("Structurally valid: passes" if _try_validate(manifest) else "INVALID")
    print(f"Signature checks out: {is_signature_valid(manifest)}\n")

    print("--- The actual wallet key is split, never stored in the manifest ---\n")
    wallet_private_key = b"xprv9s21ZrQH143K...this-would-be-a-real-bip32-key"
    shares = shamir.split_secret(
        wallet_private_key,
        threshold=2,
        trustee_ids=["sister", "lawyer", "friend"],
    )
    print("Elena, the lawyer, and the friend each hold one share.")
    print("Any two of them together can reconstruct the key. Neither can alone.\n")

    print("--- Two years pass. Ada checks in regularly, nothing happens. ---\n")
    switch = DeadMansSwitch(
        manifest_id=manifest["manifest_id"],
        interval_days=60,
        grace_days=14,
        quorum_threshold=2,
        last_checkin=datetime.now(timezone.utc) - timedelta(days=10),
    )
    print(f"Switch state: {switch.state().value} (as expected)\n")

    print("--- Then Ada misses several check-ins in a row ---\n")
    switch.last_checkin = datetime.now(timezone.utc) - timedelta(days=100)
    print(f"Switch state: {switch.state().value}")
    print(f"Confirmations still needed: {switch.confirmations_needed()}\n")

    print("--- Elena and the lawyer independently confirm they can't reach Ada ---\n")
    switch.record_attestation("sister", confirms_unreachable=True)
    switch.record_attestation("lawyer", confirms_unreachable=True)
    print(f"Switch state: {switch.state().value}\n")

    if switch.state() == SwitchState.ACTIVATED:
        print("--- Reconstructing the wallet key from their two shares ---\n")
        reconstructed = shamir.reconstruct_secret([shares[0], shares[1]])  # sister + lawyer
        assert reconstructed == wallet_private_key
        print("Key reconstructed correctly. Marcus can now access the wallet.")
        print("\nNote: the friend's share was never needed here, and the friend")
        print("never had to learn anything about the wallet at all.")


def _try_validate(manifest) -> bool:
    try:
        validate_manifest(manifest)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    main()
