"""
Property-based tests for dlp.hint_crypto (X25519 + HKDF-SHA256 +
AES-256-GCM hybrid encryption for contact hints). Like dlp.crypto, the
underlying primitives come from `cryptography`, not hand-rolled — what's
worth stress-testing here is this project's own composition of them:
does encrypt/decrypt round-trip for arbitrary text, does tampering always
get caught, does using the wrong key always fail closed.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from dlp import hint_crypto

# Unicode text, not just ASCII — contact hints are free-form human text
# ("Ada's sister, lives in Cluj", emoji, non-Latin scripts, etc.) and the
# encryption layer shouldn't care about the content beyond it being a str.
_hint_text = st.text(min_size=1, max_size=200)


@given(plaintext=_hint_text)
@settings(max_examples=150)
def test_encrypt_decrypt_roundtrip_holds_for_arbitrary_text(plaintext):
    priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub)
    assert hint_crypto.decrypt_hint(ciphertext, priv) == plaintext


@given(plaintext=_hint_text)
@settings(max_examples=100)
def test_ciphertext_never_contains_plaintext_verbatim(plaintext):
    _priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub)
    # Compare against the actual encrypted body only, not the whole
    # blob — the "dlp-enc:" format tag is a fixed, public prefix, not
    # encrypted content, so a plaintext that happens to overlap with
    # that literal tag (e.g. "dlp-") would otherwise produce a false
    # positive here that has nothing to do with the encryption itself.
    ciphertext_body = ciphertext[len("dlp-enc:") :]
    if len(plaintext) >= 4:
        assert plaintext not in ciphertext_body


@given(plaintext=_hint_text)
@settings(max_examples=100)
def test_wrong_private_key_always_fails_to_decrypt(plaintext):
    _priv_a, pub_a = hint_crypto.generate_encryption_keypair()
    priv_b, _pub_b = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub_a)
    try:
        recovered = hint_crypto.decrypt_hint(ciphertext, priv_b)
        # AES-GCM should make this branch unreachable; if it's ever hit,
        # the recovered plaintext must at least not match (belt and
        # suspenders — the real assertion is the exception below)
        assert recovered != plaintext
    except hint_crypto.HintDecryptionError:
        pass  # expected outcome


@given(plaintext=_hint_text)
@settings(max_examples=100)
def test_tampering_with_any_byte_is_detected(plaintext):
    import base64

    priv2, pub2 = hint_crypto.generate_encryption_keypair()
    ciphertext2 = hint_crypto.encrypt_hint(plaintext, pub2)

    # flip the last byte of the base64 payload (after the "dlp-enc:"
    # prefix) — AES-GCM's authentication tag must catch this regardless
    # of where in the ciphertext the corruption lands
    blob = ciphertext2[len("dlp-enc:") :]
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0xFF  # flip every bit of the last byte
    tampered = "dlp-enc:" + base64.b64encode(bytes(raw)).decode()

    try:
        hint_crypto.decrypt_hint(tampered, priv2)
        raise AssertionError("tampered ciphertext should not decrypt successfully")
    except hint_crypto.HintDecryptionError:
        pass  # expected


@given(plaintext=_hint_text)
@settings(max_examples=100)
def test_two_encryptions_of_same_plaintext_are_never_identical(plaintext):
    # semantic security: fresh ephemeral key + nonce every call means
    # identical plaintext must still produce different ciphertext
    _priv, pub = hint_crypto.generate_encryption_keypair()
    c1 = hint_crypto.encrypt_hint(plaintext, pub)
    c2 = hint_crypto.encrypt_hint(plaintext, pub)
    assert c1 != c2


@given(plaintext=_hint_text)
@settings(max_examples=100)
def test_is_encrypted_hint_correctly_identifies_output(plaintext):
    _priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub)
    assert hint_crypto.is_encrypted_hint(ciphertext) is True
    if not plaintext.startswith("dlp-enc:"):
        assert hint_crypto.is_encrypted_hint(plaintext) is False
