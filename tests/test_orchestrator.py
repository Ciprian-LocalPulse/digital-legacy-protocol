from datetime import datetime, timedelta, timezone

from dlp import ManifestBuilder, crypto
from dlp.notify import ConsoleChannel, NotificationChannel, NotificationError, NotificationService
from dlp.orchestrator import SwitchMonitor
from dlp.storage import LocalFileStore, LocalSwitchStore
from dlp.switch import DeadMansSwitch


class _FailingChannel(NotificationChannel):
    def send(self, recipient, subject, body):
        raise NotificationError("simulated delivery failure")


def _build_manifest(
    owner_address="ada@example.com",
    trustee_addresses=("elena@example.com", "lawyer@example.com"),
    beneficiary_address="marcus@example.com",
    threshold=2,
):
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(
        owner_public_key=owner_pub,
        owner_display_name="Ada",
        owner_notification_address=owner_address,
    )
    builder.with_checkin(interval_days=90, grace_days=30, method="signed_ping")
    trustee_ids = []
    for i, addr in enumerate(trustee_addresses):
        tid = f"t{i}"
        builder.add_trustee(tid, f"ed25519:key{i}", notification_address=addr)
        trustee_ids.append(tid)
    builder.set_quorum_threshold(threshold)
    builder.add_beneficiary("b1", notification_address=beneficiary_address)
    builder.add_asset("crypto_wallet", "cold wallet", "b1", "release_key", trustee_ids)
    return builder.build_and_sign(owner_priv), trustee_ids


def _setup(tmp_path, days_since_checkin=1, **manifest_kwargs):
    manifest, trustee_ids = _build_manifest(**manifest_kwargs)
    manifest_store = LocalFileStore(tmp_path / "manifests")
    manifest_store.save(manifest)
    switch_store = LocalSwitchStore(tmp_path / "switches")
    sw = DeadMansSwitch.from_manifest(
        manifest, at=datetime.now(timezone.utc) - timedelta(days=days_since_checkin)
    )
    switch_store.save(sw)
    channel = ConsoleChannel()
    monitor = SwitchMonitor(manifest_store, switch_store, NotificationService(channel))
    return manifest, trustee_ids, manifest_store, switch_store, channel, monitor


def test_tick_with_no_switch_returns_empty(tmp_path):
    manifest_store = LocalFileStore(tmp_path / "manifests")
    switch_store = LocalSwitchStore(tmp_path / "switches")
    channel = ConsoleChannel()
    monitor = SwitchMonitor(manifest_store, switch_store, NotificationService(channel))
    assert monitor.tick("nonexistent") == []


def test_active_state_sends_nothing(tmp_path):
    manifest, _, _, _, channel, monitor = _setup(tmp_path, days_since_checkin=1)
    attempts = monitor.tick(manifest["manifest_id"])
    assert attempts == []
    assert channel.sent == []


def test_overdue_notifies_owner(tmp_path):
    manifest, _, _, _, channel, monitor = _setup(tmp_path, days_since_checkin=95)
    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].kind == "checkin_reminder"
    assert attempts[0].success is True
    assert attempts[0].recipient == "ada@example.com"
    assert len(channel.sent) == 1


def test_verification_notifies_all_trustees(tmp_path):
    manifest, _trustee_ids, _, _, _channel, monitor = _setup(tmp_path, days_since_checkin=130)
    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 2
    assert all(a.kind == "attestation_request" and a.success for a in attempts)
    recipients = {a.recipient for a in attempts}
    assert recipients == {"elena@example.com", "lawyer@example.com"}


def test_activated_notifies_beneficiary(tmp_path):
    manifest, trustee_ids, _, switch_store, _channel, monitor = _setup(
        tmp_path, days_since_checkin=130
    )
    sw = switch_store.load(manifest["manifest_id"])
    sw.record_attestation(trustee_ids[0], confirms_unreachable=True)
    sw.record_attestation(trustee_ids[1], confirms_unreachable=True)
    switch_store.save(sw)

    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].kind == "activation_notice"
    assert attempts[0].recipient == "marcus@example.com"
    assert attempts[0].success is True


def test_aborted_notifies_owner(tmp_path):
    manifest, trustee_ids, _, switch_store, _channel, monitor = _setup(
        tmp_path, days_since_checkin=130
    )
    monitor.tick(manifest["manifest_id"])  # consume the verification notification first

    sw = switch_store.load(manifest["manifest_id"])
    sw.record_attestation(trustee_ids[0], confirms_unreachable=False)  # aborts
    switch_store.save(sw)

    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].kind == "abort_notice"
    assert attempts[0].recipient == "ada@example.com"
    assert attempts[0].success is True


def test_idempotent_does_not_renotify_same_state(tmp_path):
    manifest, _, _, _, channel, monitor = _setup(tmp_path, days_since_checkin=130)
    first = monitor.tick(manifest["manifest_id"])
    assert len(first) == 2
    second = monitor.tick(manifest["manifest_id"])
    assert second == []
    assert len(channel.sent) == 2  # not 4 — nothing extra sent on the second tick


def test_state_change_notifies_again_after_previous_state(tmp_path):
    manifest, trustee_ids, _, switch_store, channel, monitor = _setup(
        tmp_path, days_since_checkin=130
    )
    monitor.tick(manifest["manifest_id"])  # verification notifications sent
    assert len(channel.sent) == 2

    sw = switch_store.load(manifest["manifest_id"])
    sw.record_attestation(trustee_ids[0], confirms_unreachable=True)
    sw.record_attestation(trustee_ids[1], confirms_unreachable=True)
    switch_store.save(sw)

    monitor.tick(manifest["manifest_id"])  # new state (activated) -> new notification
    assert len(channel.sent) == 3


def test_missing_owner_address_reported_not_crashed(tmp_path):
    manifest, _, _, _, _channel, monitor = _setup(
        tmp_path, days_since_checkin=95, owner_address=None
    )
    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].success is False
    assert "notification_address" in attempts[0].detail


def test_missing_trustee_address_reported_per_trustee(tmp_path):
    manifest, _, _, _, _channel, monitor = _setup(
        tmp_path, days_since_checkin=130, trustee_addresses=(None, "lawyer@example.com")
    )
    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 2
    failed = [a for a in attempts if not a.success]
    succeeded = [a for a in attempts if a.success]
    assert len(failed) == 1
    assert len(succeeded) == 1
    assert succeeded[0].recipient == "lawyer@example.com"


def test_missing_beneficiary_address_reported(tmp_path):
    manifest, trustee_ids, _, switch_store, _channel, monitor = _setup(
        tmp_path, days_since_checkin=130, beneficiary_address=None
    )
    monitor.tick(manifest["manifest_id"])
    sw = switch_store.load(manifest["manifest_id"])
    sw.record_attestation(trustee_ids[0], confirms_unreachable=True)
    sw.record_attestation(trustee_ids[1], confirms_unreachable=True)
    switch_store.save(sw)

    attempts = monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].success is False
    assert "notification_address" in attempts[0].detail


def test_channel_failure_reported_not_raised(tmp_path):
    manifest, _trustee_ids, manifest_store, switch_store, _, _ = _setup(
        tmp_path, days_since_checkin=95
    )
    failing_monitor = SwitchMonitor(
        manifest_store, switch_store, NotificationService(_FailingChannel())
    )
    attempts = failing_monitor.tick(manifest["manifest_id"])
    assert len(attempts) == 1
    assert attempts[0].success is False
    assert "simulated delivery failure" in attempts[0].detail


def test_tick_updates_last_notified_state_in_storage(tmp_path):
    manifest, _, _, switch_store, _, monitor = _setup(tmp_path, days_since_checkin=95)
    monitor.tick(manifest["manifest_id"])
    reloaded = switch_store.load(manifest["manifest_id"])
    assert reloaded.last_notified_state == "overdue"
