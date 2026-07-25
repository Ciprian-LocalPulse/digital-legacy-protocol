from dlp import crypto
from dlp.adapter import InMemoryDemoAdapter, default_verify
from dlp.manifest import ManifestBuilder


def _signed_manifest():
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    return builder.build_and_sign(owner_priv)


def test_default_verify_accepts_well_formed_signed_manifest():
    manifest = _signed_manifest()
    assert default_verify(manifest) is True


def test_default_verify_rejects_tampered_manifest():
    manifest = _signed_manifest()
    manifest["assets"][0]["reference"] = "tampered"
    assert default_verify(manifest) is False


def test_demo_adapter_activation_records_release():
    manifest = _signed_manifest()
    adapter = InMemoryDemoAdapter()
    asset_id = manifest["assets"][0]["asset_id"]
    result = adapter.on_activation(manifest, asset_id, b"reconstructed-secret")
    assert result.success is True
    assert len(adapter.activations) == 1


def test_demo_adapter_revocation_blocks_future_verification():
    manifest = _signed_manifest()
    adapter = InMemoryDemoAdapter()
    assert adapter.verify_manifest(manifest) is True
    adapter.on_revocation(manifest["manifest_id"])
    assert adapter.verify_manifest(manifest) is False
