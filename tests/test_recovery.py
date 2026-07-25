import base64
import itertools

import pytest

from dlp import crypto, recovery


def _raw_priv_bytes():
    priv_str, _pub_str = crypto.generate_keypair()
    return base64.b64decode(priv_str.split(":", 1)[1])


def test_backup_and_recover_roundtrip():
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=2, trustee_ids=["t1", "t2", "t3"])
    subset = {"t1": backup.shares["t1"], "t2": backup.shares["t2"]}
    assert recovery.recover_owner_key(subset) == raw


def test_every_combination_of_threshold_shares_reconstructs():
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=2, trustee_ids=["t1", "t2", "t3"])
    for combo in itertools.combinations(["t1", "t2", "t3"], 2):
        subset = {tid: backup.shares[tid] for tid in combo}
        assert recovery.recover_owner_key(subset) == raw


def test_insufficient_shares_does_not_reconstruct_correctly():
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=3, trustee_ids=["t1", "t2", "t3", "t4"])
    subset = {"t1": backup.shares["t1"], "t2": backup.shares["t2"]}  # only 2 of required 3
    assert recovery.recover_owner_key(subset) != raw


def test_single_share_raises():
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=2, trustee_ids=["t1", "t2"])
    with pytest.raises(ValueError):
        recovery.recover_owner_key({"t1": backup.shares["t1"]})


def test_backup_rejects_empty_key():
    with pytest.raises(ValueError):
        recovery.backup_owner_key(b"", threshold=2, trustee_ids=["t1", "t2"])


def test_to_dict_preserves_index_and_data():
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=2, trustee_ids=["t1", "t2", "t3"])
    d = backup.to_dict()
    assert d["threshold"] == 2
    for tid in ("t1", "t2", "t3"):
        assert "index" in d["shares"][tid]
        assert "data" in d["shares"][tid]


def test_recovery_threshold_independent_of_manifest_quorum():
    # the whole point: recovering the owner's OWN key can require a
    # different (typically higher) threshold than activating the switch
    raw = _raw_priv_bytes()
    backup = recovery.backup_owner_key(raw, threshold=3, trustee_ids=["t1", "t2", "t3", "t4"])
    assert backup.threshold == 3
    full_set = {tid: backup.shares[tid] for tid in ("t1", "t2", "t3")}
    assert recovery.recover_owner_key(full_set) == raw
