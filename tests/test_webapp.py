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


def test_manifest_view_shows_start_monitoring_before_switch_init(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    r = client.get(f"/manifest/{manifest_id}")
    assert "Start monitoring" in r.get_data(as_text=True)


def test_switch_init_creates_active_switch(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))

    r = client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "active" in body
    assert "Check in now" in body


def test_switch_init_missing_manifest_404s(client):
    r = client.post("/manifest/does-not-exist/switch/init")
    assert r.status_code == 404


def test_switch_checkin_before_init_404s(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    r = client.post(f"/manifest/{manifest_id}/switch/checkin")
    assert r.status_code == 404


def test_full_switch_lifecycle_through_web_ui(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))

    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)  # force well past overdue+grace
    switch_store.save(sw)

    r = client.get(f"/manifest/{manifest_id}")
    assert "verification" in r.get_data(as_text=True)

    manifest = st.LocalFileStore(store_dir).load(manifest_id)
    trustee_ids = [t["trustee_id"] for t in manifest["quorum"]["trustees"]]

    r = client.post(
        f"/manifest/{manifest_id}/switch/attest",
        data={"trustee_id": trustee_ids[0], "verdict": "unreachable"},
        follow_redirects=True,
    )
    assert "Confirmations needed: 1" in r.get_data(as_text=True)

    r = client.post(
        f"/manifest/{manifest_id}/switch/attest",
        data={"trustee_id": trustee_ids[1], "verdict": "unreachable"},
        follow_redirects=True,
    )
    assert "activated" in r.get_data(as_text=True)


def test_switch_checkin_resets_after_activation(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)
    switch_store.save(sw)

    r = client.post(f"/manifest/{manifest_id}/switch/checkin", follow_redirects=True)
    assert "active" in r.get_data(as_text=True)
    assert switch_store.load(manifest_id).state().value == "active"


def test_switch_attest_reachable_aborts_via_web(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)
    switch_store.save(sw)

    manifest = st.LocalFileStore(store_dir).load(manifest_id)
    trustee_id = manifest["quorum"]["trustees"][0]["trustee_id"]

    r = client.post(
        f"/manifest/{manifest_id}/switch/attest",
        data={"trustee_id": trustee_id, "verdict": "reachable"},
        follow_redirects=True,
    )
    assert "aborted" in r.get_data(as_text=True)


def test_switch_attest_too_early_does_not_crash(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    r = client.post(
        f"/manifest/{manifest_id}/switch/attest",
        data={"trustee_id": "t1", "verdict": "unreachable"},
        follow_redirects=True,
    )
    # silently ignored per design — still redirects to a normal 200 page, still "active"
    assert r.status_code == 200
    assert "active" in r.get_data(as_text=True)


def test_create_with_notification_addresses_stores_them(client, store_dir):
    from dlp.storage import LocalFileStore

    r = _create_manifest(
        client,
        owner_email="ada@example.com",
        trustee_email=["elena@example.com", "lawyer@example.com", "friend@example.com"],
        beneficiary_email="marcus@example.com",
    )
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    manifest = LocalFileStore(store_dir).load(manifest_id)

    assert manifest["owner"]["notification_address"] == "ada@example.com"
    assert manifest["beneficiaries"][0]["notification_address"] == "marcus@example.com"
    trustee_addresses = {t["notification_address"] for t in manifest["quorum"]["trustees"]}
    assert trustee_addresses == {"elena@example.com", "lawyer@example.com", "friend@example.com"}


def test_create_without_notification_addresses_leaves_them_none(client, store_dir):
    from dlp.storage import LocalFileStore

    r = _create_manifest(client)  # no email fields supplied at all
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    manifest = LocalFileStore(store_dir).load(manifest_id)

    assert manifest["owner"]["notification_address"] is None
    assert manifest["beneficiaries"][0]["notification_address"] is None
    assert all(t["notification_address"] is None for t in manifest["quorum"]["trustees"])


def test_switch_tick_reports_failed_without_addresses(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(client)  # no addresses
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)
    switch_store.save(sw)

    r = client.post(f"/manifest/{manifest_id}/switch/tick")
    body = r.get_data(as_text=True)
    assert "Notification results" in body
    assert "FAILED" in body


def test_switch_tick_sends_when_addresses_present(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(
        client,
        trustee_email=["elena@example.com", "lawyer@example.com", "friend@example.com"],
    )
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)
    switch_store.save(sw)

    r = client.post(f"/manifest/{manifest_id}/switch/tick")
    body = r.get_data(as_text=True)
    assert "[sent] attestation_request" in body
    assert "elena@example.com" in body


def test_switch_tick_idempotent_via_web(client, store_dir):
    import dlp.storage as st

    r = _create_manifest(client, trustee_email=["a@example.com", "b@example.com", "c@example.com"])
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    client.post(f"/manifest/{manifest_id}/switch/init", follow_redirects=True)

    switch_store = st.LocalSwitchStore(store_dir / "switches")
    sw = switch_store.load(manifest_id)
    sw.last_checkin = sw.last_checkin.replace(year=2020)
    switch_store.save(sw)

    client.post(f"/manifest/{manifest_id}/switch/tick")
    r2 = client.post(f"/manifest/{manifest_id}/switch/tick")
    assert "Nothing new to notify" in r2.get_data(as_text=True)


def test_switch_tick_missing_switch_404s(client):
    r = _create_manifest(client)
    manifest_id = _extract_manifest_id(r.get_data(as_text=True))
    r = client.post(f"/manifest/{manifest_id}/switch/tick")
    assert r.status_code == 404
