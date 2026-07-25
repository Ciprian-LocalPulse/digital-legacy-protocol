import argparse
import json

import pytest

from dlp import cli, crypto
from dlp.manifest import ManifestBuilder


def _write_sample_manifest(path) -> str:
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="CLI Test Owner")
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    manifest = builder.build_and_sign(owner_priv)
    path.write_text(json.dumps(manifest))
    return manifest["manifest_id"]


def test_cmd_keygen_prints_both_keys(capsys):
    cli.cmd_keygen(argparse.Namespace())
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["private_key"].startswith("ed25519:")
    assert parsed["public_key"].startswith("ed25519:")


def test_cmd_enckeygen_prints_x25519_keys(capsys):
    cli.cmd_enckeygen(argparse.Namespace())
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["private_key"].startswith("x25519:")
    assert parsed["public_key"].startswith("x25519:")


def test_cmd_verify_accepts_valid_manifest(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    _write_sample_manifest(manifest_path)
    cli.cmd_verify(argparse.Namespace(manifest_path=str(manifest_path)))
    out = capsys.readouterr().out
    assert "signature checks out" in out


def test_cmd_verify_rejects_tampered_manifest(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    _write_sample_manifest(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    manifest["assets"][0]["reference"] = "tampered"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(SystemExit):
        cli.cmd_verify(argparse.Namespace(manifest_path=str(manifest_path)))
    out = capsys.readouterr().out
    assert "SIGNATURE DOES NOT MATCH" in out


def test_cmd_verify_rejects_malformed_manifest(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    manifest_path.write_text(json.dumps({"not": "a manifest"}))
    with pytest.raises(SystemExit):
        cli.cmd_verify(argparse.Namespace(manifest_path=str(manifest_path)))
    out = capsys.readouterr().out
    assert "INVALID structure" in out


def test_cmd_inspect_prints_summary(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    _write_sample_manifest(manifest_path)
    cli.cmd_inspect(argparse.Namespace(manifest_path=str(manifest_path)))
    out = capsys.readouterr().out
    assert "CLI Test Owner" in out
    assert "Quorum: 2 of 2" in out


def test_cmd_demo_runs_without_error(capsys):
    cli.cmd_demo(argparse.Namespace())
    out = capsys.readouterr().out
    assert "matches original: True" in out
    assert "never required a single company" in out


def test_cmd_store_save_and_list(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    manifest_id = _write_sample_manifest(manifest_path)
    store_dir = tmp_path / "store"

    cli.cmd_store_save(argparse.Namespace(manifest_path=str(manifest_path), dir=str(store_dir)))
    save_out = capsys.readouterr().out
    assert manifest_id in save_out

    cli.cmd_store_list(argparse.Namespace(dir=str(store_dir)))
    list_out = capsys.readouterr().out
    assert manifest_id in list_out
    assert "CLI Test Owner" in list_out


def test_cmd_store_list_empty_dir(tmp_path, capsys):
    cli.cmd_store_list(argparse.Namespace(dir=str(tmp_path / "empty")))
    out = capsys.readouterr().out
    assert "no manifests stored" in out


def test_cmd_store_load_roundtrip(tmp_path, capsys):
    manifest_path = tmp_path / "m.json"
    manifest_id = _write_sample_manifest(manifest_path)
    store_dir = tmp_path / "store"

    cli.cmd_store_save(argparse.Namespace(manifest_path=str(manifest_path), dir=str(store_dir)))
    capsys.readouterr()

    cli.cmd_store_load(argparse.Namespace(manifest_id=manifest_id, dir=str(store_dir)))
    out = capsys.readouterr().out
    loaded = json.loads(out)
    assert loaded["manifest_id"] == manifest_id


def test_cmd_store_load_missing_id_exits(tmp_path, capsys):
    with pytest.raises(SystemExit):
        cli.cmd_store_load(argparse.Namespace(manifest_id="nonexistent", dir=str(tmp_path)))
    out = capsys.readouterr().out
    assert "No manifest found" in out


def test_main_parses_keygen_command(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["dlp", "keygen"])
    cli.main()
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["private_key"].startswith("ed25519:")


def test_main_requires_a_command(monkeypatch):
    monkeypatch.setattr("sys.argv", ["dlp"])
    with pytest.raises(SystemExit):
        cli.main()
