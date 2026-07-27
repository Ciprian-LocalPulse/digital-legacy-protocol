import argparse
from datetime import datetime, timedelta, timezone

import pytest

from dlp import cli, crypto
from dlp.manifest import ManifestBuilder
from dlp.storage import LocalFileStore, LocalSwitchStore


def _write_manifest_to_store(store_dir, interval_days=90, grace_days=30, threshold=2):
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Switch Test Owner")
    builder.with_checkin(interval_days=interval_days, grace_days=grace_days, method="signed_ping")
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(threshold)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    manifest = builder.build_and_sign(owner_priv)
    LocalFileStore(store_dir).save(manifest)
    return manifest["manifest_id"]


def _backdate_switch(switch_dir, manifest_id, days: int):
    store = LocalSwitchStore(switch_dir)
    sw = store.load(manifest_id)
    sw.last_checkin = datetime.now(timezone.utc) - timedelta(days=days)
    store.save(sw)


def test_switch_init_creates_switch(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)

    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    out = capsys.readouterr().out
    assert "Switch initialized" in out
    assert manifest_id in LocalSwitchStore(switch_dir).list_ids()


def test_switch_init_missing_manifest_exits(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.cmd_switch_init(
            argparse.Namespace(
                manifest_id="nonexistent",
                dir=str(tmp_path / "m"),
                switch_dir=str(tmp_path / "s"),
                force=False,
            )
        )
    assert "No manifest found" in capsys.readouterr().out


def test_switch_init_refuses_to_overwrite_without_force(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    ns = argparse.Namespace(
        manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
    )
    cli.cmd_switch_init(ns)
    capsys.readouterr()

    with pytest.raises(SystemExit):
        cli.cmd_switch_init(ns)
    assert "already exists" in capsys.readouterr().out


def test_switch_init_force_resets(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=130)

    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=True
        )
    )
    sw = LocalSwitchStore(switch_dir).load(manifest_id)
    assert sw.state().value == "active"  # force reset it back to fresh


def test_switch_status_active(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()

    cli.cmd_switch_status(argparse.Namespace(manifest_id=manifest_id, switch_dir=str(switch_dir)))
    out = capsys.readouterr().out
    assert "State: active" in out
    assert "Days until overdue" in out


def test_switch_status_missing_exits(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.cmd_switch_status(
            argparse.Namespace(manifest_id="nonexistent", switch_dir=str(tmp_path))
        )
    assert "No switch found" in capsys.readouterr().out


def test_switch_checkin_resets_state(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=130)

    cli.cmd_switch_checkin(argparse.Namespace(manifest_id=manifest_id, switch_dir=str(switch_dir)))
    out = capsys.readouterr().out
    assert "State: active" in out
    assert LocalSwitchStore(switch_dir).load(manifest_id).state().value == "active"


def test_switch_attest_full_quorum_activates(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir, threshold=2)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=130)

    cli.cmd_switch_attest(
        argparse.Namespace(
            manifest_id=manifest_id, trustee_id="t1", unreachable=True, switch_dir=str(switch_dir)
        )
    )
    out1 = capsys.readouterr().out
    assert "State: verification" in out1

    cli.cmd_switch_attest(
        argparse.Namespace(
            manifest_id=manifest_id, trustee_id="t2", unreachable=True, switch_dir=str(switch_dir)
        )
    )
    out2 = capsys.readouterr().out
    assert "State: activated" in out2


def test_switch_attest_reachable_aborts(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir, threshold=2)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=130)

    cli.cmd_switch_attest(
        argparse.Namespace(
            manifest_id=manifest_id, trustee_id="t1", unreachable=False, switch_dir=str(switch_dir)
        )
    )
    out = capsys.readouterr().out
    assert "State: aborted" in out


def test_switch_attest_too_early_exits(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()

    with pytest.raises(SystemExit):
        cli.cmd_switch_attest(
            argparse.Namespace(
                manifest_id=manifest_id,
                trustee_id="t1",
                unreachable=True,
                switch_dir=str(switch_dir),
            )
        )
    assert "Cannot record attestation" in capsys.readouterr().out


def test_switch_attest_missing_switch_exits(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.cmd_switch_attest(
            argparse.Namespace(
                manifest_id="nonexistent",
                trustee_id="t1",
                unreachable=True,
                switch_dir=str(tmp_path),
            )
        )
    assert "No switch found" in capsys.readouterr().out


def test_main_parses_switch_status_command(monkeypatch, tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_to_store(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()

    monkeypatch.setattr(
        "sys.argv", ["dlp", "switch-status", manifest_id, "--switch-dir", str(switch_dir)]
    )
    cli.main()
    out = capsys.readouterr().out
    assert "State: active" in out


def _write_manifest_with_addresses(store_dir, **kwargs):
    from dlp.manifest import ManifestBuilder

    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(
        owner_public_key=owner_pub,
        owner_display_name="Ada",
        owner_notification_address=kwargs.get("owner_address", "ada@example.com"),
    )
    builder.with_checkin(interval_days=90, grace_days=30, method="signed_ping")
    builder.add_trustee("t1", "ed25519:x", notification_address="elena@example.com")
    builder.add_trustee("t2", "ed25519:y", notification_address="lawyer@example.com")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1", notification_address="marcus@example.com")
    builder.add_asset("crypto_wallet", "wallet", "b1", "release_key", ["t1", "t2"])
    manifest = builder.build_and_sign(owner_priv)
    LocalFileStore(store_dir).save(manifest)
    return manifest["manifest_id"]


def test_switch_tick_console_sends_notification(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_with_addresses(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=95)

    cli.cmd_switch_tick(
        argparse.Namespace(
            manifest_id=manifest_id,
            dir=str(manifest_dir),
            switch_dir=str(switch_dir),
            smtp_host=None,
            smtp_port=587,
            smtp_user=None,
            smtp_password=None,
            smtp_from=None,
        )
    )
    out = capsys.readouterr().out
    assert "[sent] checkin_reminder -> ada@example.com" in out


def test_switch_tick_idempotent(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_with_addresses(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()
    _backdate_switch(switch_dir, manifest_id, days=95)

    ns = argparse.Namespace(
        manifest_id=manifest_id,
        dir=str(manifest_dir),
        switch_dir=str(switch_dir),
        smtp_host=None,
        smtp_port=587,
        smtp_user=None,
        smtp_password=None,
        smtp_from=None,
    )
    cli.cmd_switch_tick(ns)
    capsys.readouterr()
    cli.cmd_switch_tick(ns)
    out = capsys.readouterr().out
    assert "Nothing new to notify" in out


def test_switch_tick_requires_smtp_credentials_together(tmp_path, capsys):
    manifest_dir = tmp_path / "manifests"
    switch_dir = tmp_path / "switches"
    manifest_id = _write_manifest_with_addresses(manifest_dir)
    cli.cmd_switch_init(
        argparse.Namespace(
            manifest_id=manifest_id, dir=str(manifest_dir), switch_dir=str(switch_dir), force=False
        )
    )
    capsys.readouterr()

    with pytest.raises(SystemExit):
        cli.cmd_switch_tick(
            argparse.Namespace(
                manifest_id=manifest_id,
                dir=str(manifest_dir),
                switch_dir=str(switch_dir),
                smtp_host="smtp.example.com",
                smtp_port=587,
                smtp_user=None,
                smtp_password=None,
                smtp_from=None,
            )
        )
