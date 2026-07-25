import json
import re

import pytest

from dlp.storage import LocalFileStore
from dlp.webapp import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(store_dir=str(tmp_path))
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def store_dir(tmp_path):
    return tmp_path


def _create_manifest(client, **overrides):
    data = {
        "owner_name": "Ada",
        "trustee_name": ["Elena", "Lawyer", "Friend"],
        "threshold": "2",
        "beneficiary_name": "Marcus",
        "asset_type": "crypto_wallet",
        "asset_action": "release_key",
        "asset_reference": "cold wallet #1",
    }
    data.update(overrides)
    return client.post("/create", data=data)


def _extract_manifest_id(html: str) -> str:
    match = re.search(r"manifest_id: <code>([a-f0-9-]+)</code>", html)
    assert match, "manifest_id not found in response"
    return match.group(1)


def test_index_empty_store(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "No manifests stored yet" in r.get_data(as_text=True)


def test_create_form_renders(client):
    r = client.get("/create")
    assert r.status_code == 200
    assert b"Owner display name" in r.data


def test_create_manifest_success(client):
    r = _create_manifest(client)
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "ed25519:" in body  # owner private key shown
    assert "x25519:" in body  # trustee encryption key shown
    assert "Elena" in body


def test_create_manifest_persists_to_store(client, store_dir):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    store = LocalFileStore(store_dir)
    manifest = store.load(manifest_id)
    assert manifest["owner"]["display_name"] == "Ada"
    assert len(manifest["quorum"]["trustees"]) == 3


def test_create_manifest_encrypts_trustee_hints(client, store_dir):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    store = LocalFileStore(store_dir)
    manifest = store.load(manifest_id)
    for t in manifest["quorum"]["trustees"]:
        assert t["contact_hint_encrypted"] is True
        assert t["contact_hint"].startswith("dlp-enc:")


def test_create_missing_owner_name_shows_error(client):
    r = _create_manifest(client, owner_name="")
    assert r.status_code == 200
    assert "required" in r.get_data(as_text=True)


def test_create_threshold_exceeding_trustees_shows_error(client):
    r = _create_manifest(client, threshold="10")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "quorum threshold" in body.lower()


def test_create_threshold_below_two_shows_error(client):
    r = _create_manifest(client, threshold="1")
    body = r.get_data(as_text=True)
    assert "quorum threshold" in body.lower()


def test_view_manifest(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    r = client.get(f"/manifest/{manifest_id}")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "valid" in body.lower()
    assert "Ada" in body


def test_view_missing_manifest_returns_404(client):
    r = client.get("/manifest/does-not-exist")
    assert r.status_code == 404


def test_view_manifest_path_traversal_rejected(client):
    r = client.get("/manifest/..%2F..%2Fetc%2Fpasswd")
    assert r.status_code == 404


def test_index_lists_created_manifest(client):
    _create_manifest(client)
    r = client.get("/")
    body = r.get_data(as_text=True)
    assert "Ada" in body
    assert "2 of 3" in body


def test_verify_form_renders(client):
    r = client.get("/verify")
    assert r.status_code == 200


def test_verify_valid_manifest(client, store_dir):
    create_resp = _create_manifest(client)
    manifest_id = _extract_manifest_id(create_resp.get_data(as_text=True))
    store = LocalFileStore(store_dir)
    manifest = store.load(manifest_id)

    r = client.post("/verify", data={"manifest_json": json.dumps(manifest)})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "valid" in body.lower()
    assert manifest_id in body


def test_verify_tampered_manifest(client, store_dir):
    create_resp = _create_manifest(client)
    manifest_id = _extract_manifest_id(create_resp.get_data(as_text=True))
    store = LocalFileStore(store_dir)
    manifest = store.load(manifest_id)
    manifest["assets"][0]["reference"] = "tampered"

    r = client.post("/verify", data={"manifest_json": json.dumps(manifest)})
    body = r.get_data(as_text=True)
    assert "INVALID" in body


def test_verify_garbage_input(client):
    r = client.post("/verify", data={"manifest_json": "not json at all"})
    assert r.status_code == 200
    assert "could not parse" in r.get_data(as_text=True).lower()


def test_multiple_manifests_all_listed(client):
    _create_manifest(client, owner_name="Ada")
    _create_manifest(client, owner_name="Bogdan")
    r = client.get("/")
    body = r.get_data(as_text=True)
    assert "Ada" in body
    assert "Bogdan" in body
