from datetime import datetime, timedelta, timezone

import pytest

from dlp.switch import DeadMansSwitch, SwitchState


def _switch(days_since_checkin=0, interval=90, grace=30, threshold=2):
    now = datetime.now(timezone.utc)
    return DeadMansSwitch(
        manifest_id="m1",
        interval_days=interval,
        grace_days=grace,
        quorum_threshold=threshold,
        last_checkin=now - timedelta(days=days_since_checkin),
    )


def test_fresh_checkin_is_active():
    sw = _switch(days_since_checkin=1)
    assert sw.state() == SwitchState.ACTIVE


def test_overdue_within_grace_period():
    sw = _switch(days_since_checkin=100)  # past 90-day interval, within +30 grace
    assert sw.state() == SwitchState.OVERDUE


def test_verification_after_grace_period_lapses():
    sw = _switch(days_since_checkin=130)  # past interval + grace
    assert sw.state() == SwitchState.VERIFICATION


def test_activation_requires_quorum_of_attestations():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    assert sw.state() == SwitchState.VERIFICATION  # only 1 of 2
    sw.record_attestation("t2", confirms_unreachable=True)
    assert sw.state() == SwitchState.ACTIVATED


def test_single_denial_aborts_activation():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t2", confirms_unreachable=True)
    assert sw.state() == SwitchState.ACTIVATED
    sw.record_attestation("t3", confirms_unreachable=False)
    assert sw.state() == SwitchState.ABORTED


def test_checkin_resets_everything():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t2", confirms_unreachable=True)
    assert sw.state() == SwitchState.ACTIVATED
    sw.record_checkin()
    assert sw.state() == SwitchState.ACTIVE
    assert sw.attestations == []


def test_attestation_before_verification_raises():
    sw = _switch(days_since_checkin=1)  # still active
    with pytest.raises(RuntimeError):
        sw.record_attestation("t1", confirms_unreachable=True)


def test_duplicate_attestation_from_same_trustee_only_counts_once():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t1", confirms_unreachable=True)  # same trustee again
    assert sw.confirmations_needed() == 1  # still needs a second, different trustee
    sw.record_attestation("t2", confirms_unreachable=True)
    assert sw.state() == SwitchState.ACTIVATED


def test_trustee_can_change_their_mind():
    sw = _switch(days_since_checkin=130, threshold=2)
    sw.record_attestation("t1", confirms_unreachable=True)
    sw.record_attestation("t1", confirms_unreachable=False)  # retracts
    assert sw.confirmations_needed() == 2  # back to needing both


def test_days_until_overdue_is_positive_when_active():
    sw = _switch(days_since_checkin=1, interval=90)
    assert sw.days_until_overdue() == pytest.approx(89, abs=0.1)


def test_days_until_overdue_is_negative_when_overdue():
    sw = _switch(days_since_checkin=100, interval=90)
    assert sw.days_until_overdue() < 0
