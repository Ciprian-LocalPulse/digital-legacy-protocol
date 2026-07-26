from datetime import datetime, timedelta, timezone

import pytest

from dlp.storage import LocalSwitchStore, SwitchNotFoundError
from dlp.switch import DeadMansSwitch


def _switch(manifest_id="m1", days_since_checkin=1):
    return DeadMansSwitch(
        manifest_id=manifest_id,
        interval_days=90,
        grace_days=30,
        quorum_threshold=2,
        last_checkin=datetime.now(timezone.utc) - timedelta(days=days_since_checkin),
    )


def test_save_and_load_roundtrip(tmp_path):
    store = LocalSwitchStore(tmp_path)
    sw = _switch()
    store.save(sw)
    loaded = store.load(sw.manifest_id)
    assert loaded.state() == sw.state()
    assert loaded.last_checkin == sw.last_checkin


def test_load_missing_switch_raises(tmp_path):
    store = LocalSwitchStore(tmp_path)
    with pytest.raises(SwitchNotFoundError):
        store.load("does-not-exist")


def test_save_preserves_attestations(tmp_path):
    store = LocalSwitchStore(tmp_path)
    sw = _switch(days_since_checkin=130)
    sw.record_attestation("t1", confirms_unreachable=True)
    store.save(sw)
    loaded = store.load(sw.manifest_id)
    assert len(loaded.attestations) == 1
    assert loaded.confirmations_needed() == sw.confirmations_needed()


def test_delete_is_idempotent(tmp_path):
    store = LocalSwitchStore(tmp_path)
    sw = _switch()
    store.save(sw)
    store.delete(sw.manifest_id)
    store.delete(sw.manifest_id)  # should not raise
    with pytest.raises(SwitchNotFoundError):
        store.load(sw.manifest_id)


def test_list_ids(tmp_path):
    store = LocalSwitchStore(tmp_path)
    store.save(_switch("m1"))
    store.save(_switch("m2"))
    assert set(store.list_ids()) == {"m1", "m2"}


def test_path_traversal_rejected(tmp_path):
    store = LocalSwitchStore(tmp_path)
    with pytest.raises(ValueError):
        store.load("../../etc/passwd")


def test_repeated_save_overwrites(tmp_path):
    store = LocalSwitchStore(tmp_path)
    sw = _switch()
    store.save(sw)
    sw.record_checkin()
    store.save(sw)
    loaded = store.load(sw.manifest_id)
    assert loaded.last_checkin == sw.last_checkin


def test_directory_created_if_missing(tmp_path):
    nested = tmp_path / "does" / "not" / "exist"
    _store = LocalSwitchStore(nested)
    assert nested.exists()
