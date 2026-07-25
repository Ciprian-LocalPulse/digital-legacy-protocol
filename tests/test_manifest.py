import pytest

from dlp import crypto
from dlp.manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)


def _basic_signed_manifest(threshold=2, n_trustees=3):
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Test Owner")
    trustee_ids = [f"t{i}" for i in range(n_trustees)]
    for tid in trustee_ids:
        _, pub = crypto.generate_keypair()
        builder.add_trustee(tid, pub, contact_hint="hint")
    builder.set_quorum_threshold(threshold)
    builder.add_beneficiary("ben1", contact_hint="daughter")
    builder.add_asset(
        asset_type="crypto_wallet",
        reference="wallet #1",
        beneficiary_id="ben1",
        action="release_key",
        shares_distributed_to=trustee_ids,
    )
    return builder.build_and_sign(owner_priv), owner_pub


def test_build_and_sign_produces_valid_manifest():
    manifest, _owner_pub = _basic_signed_manifest()
    validate_manifest(manifest)  # should not raise
    assert is_signature_valid(manifest) is True


def test_tampering_invalidates_signature():
    manifest, _ = _basic_signed_manifest()
    manifest["assets"][0]["reference"] = "hacked wallet"
    assert is_signature_valid(manifest) is False


def test_quorum_threshold_below_two_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(1)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    with pytest.raises(ManifestValidationError):
        builder.build()


def test_quorum_threshold_exceeding_trustees_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    with pytest.raises(ManifestValidationError):
        builder.add_asset("file", "doc", "b1", "grant_access", ["t1"])
        builder.build()


def test_asset_with_unknown_beneficiary_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    # no beneficiary added at all
    builder.add_asset("file", "doc", "ghost-beneficiary", "grant_access", ["t1", "t2"])
    with pytest.raises(ManifestValidationError):
        builder.build()


def test_asset_with_fewer_shares_than_threshold_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.add_trustee("t3", "ed25519:z")
    builder.set_quorum_threshold(3)
    builder.add_beneficiary("b1")
    # only 2 shares distributed but threshold is 3 -> unreconstructable
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    with pytest.raises(ManifestValidationError):
        builder.build()


def test_invalid_asset_type_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    with pytest.raises(ManifestValidationError):
        builder.add_asset("not_a_real_type", "x", "b1", "grant_access", [])


def test_invalid_action_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    with pytest.raises(ManifestValidationError):
        builder.add_asset("file", "x", "b1", "not_a_real_action", [])


def test_build_without_quorum_threshold_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    with pytest.raises(ManifestValidationError):
        builder.build()  # no set_quorum_threshold call


def test_build_without_assets_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    with pytest.raises(ManifestValidationError):
        builder.build()


def test_supersedes_chain():
    manifest_v1, _owner_pub = _basic_signed_manifest()
    owner_priv2, owner_pub2 = crypto.generate_keypair()
    builder2 = ManifestBuilder(owner_public_key=owner_pub2, supersedes=manifest_v1["manifest_id"])
    builder2.add_trustee("t0", "ed25519:z")
    builder2.add_trustee("t1", "ed25519:w")
    builder2.set_quorum_threshold(2)
    builder2.add_beneficiary("b1")
    builder2.add_asset("file", "doc", "b1", "grant_access", ["t0", "t1"])
    manifest_v2 = builder2.build_and_sign(owner_priv2)
    assert manifest_v2["supersedes"] == manifest_v1["manifest_id"]


def test_invalid_checkin_method_rejected():
    _, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    with pytest.raises(ManifestValidationError):
        builder.with_checkin(90, 30, "carrier_pigeon")
