"""
Property-based tests for dlp.crypto (Ed25519 signing + canonical JSON
serialization). Ed25519 itself comes from the `cryptography` library, not
hand-rolled — the property here worth stress-testing isn't the elliptic
curve math (that's someone else's well-audited job), it's the thin layer
this project adds on top: canonicalization, and the sign/verify contract
holding for arbitrary manifest-shaped dictionaries, not just the fixed
examples in test_crypto.py.
"""

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from dlp import crypto

# JSON-safe values: keys and string values drawn from a printable subset
# so canonicalization has something realistic to chew on without needing
# full Unicode edge-case handling to be the point of this test file.
_json_safe_text = st.text(alphabet=string.ascii_letters + string.digits + " _-", max_size=30)
_json_scalar = st.one_of(
    _json_safe_text,
    st.integers(min_value=-(2**31), max_value=2**31),
    st.booleans(),
    st.none(),
)
_json_like_dict = st.dictionaries(
    keys=_json_safe_text.filter(lambda s: len(s) > 0),
    values=_json_scalar,
    max_size=8,
)


@given(manifest=_json_like_dict)
@settings(max_examples=150)
def test_sign_then_verify_holds_for_arbitrary_manifest_shapes(manifest):
    priv, pub = crypto.generate_keypair()
    manifest["signature"] = crypto.sign_manifest(manifest, priv)
    assert crypto.verify_manifest(manifest, pub) is True


@given(manifest=_json_like_dict, tamper_key=_json_safe_text.filter(lambda s: len(s) > 0))
@settings(max_examples=150)
def test_any_tamper_after_signing_invalidates_signature(manifest, tamper_key):
    priv, pub = crypto.generate_keypair()
    manifest["signature"] = crypto.sign_manifest(manifest, priv)
    manifest[tamper_key] = "tampered-value-injected-by-test"
    assert crypto.verify_manifest(manifest, pub) is False


@given(manifest=_json_like_dict)
@settings(max_examples=100)
def test_verify_fails_with_a_different_keypairs_public_key(manifest):
    priv_a, _pub_a = crypto.generate_keypair()
    _priv_b, pub_b = crypto.generate_keypair()
    manifest["signature"] = crypto.sign_manifest(manifest, priv_a)
    assert crypto.verify_manifest(manifest, pub_b) is False


@given(manifest=_json_like_dict)
@settings(max_examples=100)
def test_canonicalize_ignores_key_insertion_order(manifest):
    reversed_manifest = dict(reversed(list(manifest.items())))
    assert crypto.canonicalize(manifest) == crypto.canonicalize(reversed_manifest)


@given(manifest=_json_like_dict)
@settings(max_examples=100)
def test_canonicalize_excludes_signature_regardless_of_its_value(manifest):
    variant_a = dict(manifest)
    variant_a["signature"] = "AAAAAAAA"
    variant_b = dict(manifest)
    variant_b["signature"] = "completely-different-signature-value"
    assert crypto.canonicalize(variant_a) == crypto.canonicalize(variant_b)
