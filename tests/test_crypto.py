import pytest

from dlp import crypto


def test_keypair_generation_produces_prefixed_keys():
    priv, pub = crypto.generate_keypair()
    assert priv.startswith("ed25519:")
    assert pub.startswith("ed25519:")
    assert priv != pub


def test_sign_and_verify_roundtrip():
    priv, pub = crypto.generate_keypair()
    manifest = {"dlp_version": "0.1", "manifest_id": "abc", "owner": {"public_key": pub}}
    manifest["signature"] = crypto.sign_manifest(manifest, priv)
    assert crypto.verify_manifest(manifest, pub) is True


def test_verify_fails_with_wrong_key():
    priv, _pub = crypto.generate_keypair()
    _other_priv, other_pub = crypto.generate_keypair()
    manifest = {"a": 1}
    manifest["signature"] = crypto.sign_manifest(manifest, priv)
    assert crypto.verify_manifest(manifest, other_pub) is False


def test_verify_fails_if_manifest_tampered_after_signing():
    priv, pub = crypto.generate_keypair()
    manifest = {"amount": 100}
    manifest["signature"] = crypto.sign_manifest(manifest, priv)
    manifest["amount"] = 999999  # tamper
    assert crypto.verify_manifest(manifest, pub) is False


def test_verify_returns_false_for_missing_signature():
    _priv, pub = crypto.generate_keypair()
    manifest = {"a": 1}
    assert crypto.verify_manifest(manifest, pub) is False


def test_canonicalize_excludes_signature_field():
    manifest_a = {"x": 1, "signature": "AAAA"}
    manifest_b = {"x": 1, "signature": "BBBB"}
    assert crypto.canonicalize(manifest_a) == crypto.canonicalize(manifest_b)


def test_canonicalize_is_order_independent():
    manifest_a = {"x": 1, "y": 2}
    manifest_b = {"y": 2, "x": 1}
    assert crypto.canonicalize(manifest_a) == crypto.canonicalize(manifest_b)


def test_invalid_key_prefix_rejected():
    with pytest.raises(ValueError):
        crypto._strip_prefix("not-a-valid-key")
