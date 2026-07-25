import pytest

from dlp import crypto
from dlp.manifest import ManifestBuilder, ManifestValidationError
from dlp.storage import LocalFileStore, ManifestNotFoundError


def _signed_manifest(supersedes=None):
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, supersedes=supersedes)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    return builder.build_and_sign(owner_priv)


def test_save_and_load_roundtrip(tmp_path):
    store = LocalFileStore(tmp_path)
    manifest = _signed_manifest()
    store.save(manifest)
    loaded = store.load(manifest["manifest_id"])
    assert loaded == manifest


def test_load_missing_manifest_raises(tmp_path):
    store = LocalFileStore(tmp_path)
    with pytest.raises(ManifestNotFoundError):
        store.load("does-not-exist")


def test_delete_is_idempotent(tmp_path):
    store = LocalFileStore(tmp_path)
    manifest = _signed_manifest()
    store.save(manifest)
    store.delete(manifest["manifest_id"])
    store.delete(manifest["manifest_id"])  # should not raise the second time
    with pytest.raises(ManifestNotFoundError):
        store.load(manifest["manifest_id"])


def test_list_ids_returns_all_saved_manifests(tmp_path):
    store = LocalFileStore(tmp_path)
    m1 = _signed_manifest()
    m2 = _signed_manifest()
    store.save(m1)
    store.save(m2)
    ids = set(store.list_ids())
    assert ids == {m1["manifest_id"], m2["manifest_id"]}


def test_save_rejects_invalid_manifest(tmp_path):
    store = LocalFileStore(tmp_path)
    with pytest.raises(ManifestValidationError):
        store.save({"not": "a valid manifest"})


def test_path_traversal_in_manifest_id_rejected(tmp_path):
    store = LocalFileStore(tmp_path)
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")


def test_load_latest_in_chain_follows_supersedes(tmp_path):
    store = LocalFileStore(tmp_path)
    v1 = _signed_manifest()
    v2 = _signed_manifest(supersedes=v1["manifest_id"])
    v3 = _signed_manifest(supersedes=v2["manifest_id"])
    store.save(v1)
    store.save(v2)
    store.save(v3)
    latest = store.load_latest_in_chain(v1["manifest_id"])
    assert latest["manifest_id"] == v3["manifest_id"]


def test_load_latest_in_chain_with_no_updates_returns_itself(tmp_path):
    store = LocalFileStore(tmp_path)
    v1 = _signed_manifest()
    store.save(v1)
    latest = store.load_latest_in_chain(v1["manifest_id"])
    assert latest["manifest_id"] == v1["manifest_id"]


def test_directory_created_if_missing(tmp_path):
    nested = tmp_path / "does" / "not" / "exist" / "yet"
    _store = LocalFileStore(nested)  # constructor side effect is what's under test
    assert nested.exists()
