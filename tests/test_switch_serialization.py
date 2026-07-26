from datetime import datetime, timedelta, timezone

from dlp.switch import Attestation, DeadMansSwitch, SwitchState


def _switch(days_since_checkin=0, interval=90, grace=30, threshold=2):
    now = datetime.now(timezone.utc)
    return DeadMansSwitch(
        manifest_id="m1",
        interval_days=interval,
        grace_days=grace,
        quorum_threshold=threshold,
        last_checkin=now - timedelta(days=days_since_checkin),
    )


def test_attestation_roundtrip():
    a = Attestation(
        trustee_id="t1", confirms_unreachable=True, timestamp=datetime.now(timezone.utc)
    )
    restored = Attestation.from_dict(a.to_dict())
    assert restored.trustee_id == a.trustee_id
    assert restored.confirms_unreachable == a.confirms_unreachable
    assert restored.timestamp == a.timestamp


def test_switch_roundtrip_preserves_state():
    sw = _switch(days_since_checkin=1)
    restored = DeadMansSwitch.from_dict(sw.to_dict())
    assert restored.state() == sw.state() == SwitchState.ACTIVE
    assert restored.last_checkin == sw.last_checkin


def test_switch_roundtrip_preserves_attestations():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    restored = DeadMansSwitch.from_dict(sw.to_dict())
    assert len(restored.attestations) == 1
    assert restored.attestations[0].trustee_id == "t1"
    assert restored.confirmations_needed() == sw.confirmations_needed()


def test_switch_roundtrip_preserves_activation():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t2", confirms_unreachable=True)
    assert sw.state() == SwitchState.ACTIVATED
    restored = DeadMansSwitch.from_dict(sw.to_dict())
    assert restored.state() == SwitchState.ACTIVATED


def test_switch_roundtrip_preserves_abort():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t2", confirms_unreachable=True)
    sw.record_attestation("t3", confirms_unreachable=False)
    assert sw.state() == SwitchState.ABORTED
    restored = DeadMansSwitch.from_dict(sw.to_dict())
    assert restored.state() == SwitchState.ABORTED


def test_switch_roundtrip_with_no_attestations_has_no_aborted_at():
    sw = _switch(days_since_checkin=1)
    d = sw.to_dict()
    assert d["aborted_at"] is None
    restored = DeadMansSwitch.from_dict(d)
    assert restored.state() == SwitchState.ACTIVE


def test_from_manifest_uses_manifest_checkin_and_quorum_config():
    manifest = {
        "manifest_id": "abc-123",
        "checkin": {"interval_days": 60, "grace_days": 14, "method": "app_heartbeat"},
        "quorum": {"threshold": 3, "trustees": []},
    }
    sw = DeadMansSwitch.from_manifest(manifest)
    assert sw.manifest_id == "abc-123"
    assert sw.interval_days == 60
    assert sw.grace_days == 14
    assert sw.quorum_threshold == 3
    assert sw.state() == SwitchState.ACTIVE


def test_from_manifest_accepts_explicit_time():
    manifest = {
        "manifest_id": "abc-123",
        "checkin": {"interval_days": 60, "grace_days": 14, "method": "app_heartbeat"},
        "quorum": {"threshold": 2, "trustees": []},
    }
    fixed_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sw = DeadMansSwitch.from_manifest(manifest, at=fixed_time)
    assert sw.last_checkin == fixed_time
