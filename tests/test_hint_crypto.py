import pytest

from dlp import hint_crypto


def test_encrypt_decrypt_roundtrip():
    priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint("Ada's sister, Elena", pub)
    assert hint_crypto.decrypt_hint(ciphertext, priv) == "Ada's sister, Elena"


def test_ciphertext_is_not_plaintext():
    _priv, pub = hint_crypto.generate_encryption_keypair()
    plaintext = "my daughter Maria, lives in Cluj"
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub)
    assert plaintext not in ciphertext
    assert ciphertext.startswith("dlp-enc:")


def test_wrong_key_cannot_decrypt():
    _priv_a, pub_a = hint_crypto.generate_encryption_keypair()
    priv_b, _pub_b = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint("secret hint", pub_a)
    with pytest.raises(hint_crypto.HintDecryptionError):
        hint_crypto.decrypt_hint(ciphertext, priv_b)


def test_tampered_ciphertext_rejected():
    priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint("secret hint", pub)
    # flip a character deep in the blob to simulate tampering
    tampered = ciphertext[:-4] + ("A" if ciphertext[-4] != "A" else "B") + ciphertext[-3:]
    with pytest.raises(hint_crypto.HintDecryptionError):
        hint_crypto.decrypt_hint(tampered, priv)


def test_two_encryptions_of_same_plaintext_differ():
    # each call uses a fresh ephemeral key + nonce, so ciphertexts must differ
    # even for identical plaintext and recipient (semantic security)
    _priv, pub = hint_crypto.generate_encryption_keypair()
    c1 = hint_crypto.encrypt_hint("same hint", pub)
    c2 = hint_crypto.encrypt_hint("same hint", pub)
    assert c1 != c2


def test_is_encrypted_hint_detects_correctly():
    _priv, pub = hint_crypto.generate_encryption_keypair()
    ciphertext = hint_crypto.encrypt_hint("hint", pub)
    assert hint_crypto.is_encrypted_hint(ciphertext) is True
    assert hint_crypto.is_encrypted_hint("plain text hint") is False
    assert hint_crypto.is_encrypted_hint("") is False


def test_decrypt_rejects_unrecognized_blob():
    priv, _pub = hint_crypto.generate_encryption_keypair()
    with pytest.raises(hint_crypto.HintDecryptionError):
        hint_crypto.decrypt_hint("not-a-real-blob", priv)


def test_keypair_uses_x25519_prefix():
    priv, pub = hint_crypto.generate_encryption_keypair()
    assert priv.startswith("x25519:")
    assert pub.startswith("x25519:")


@pytest.mark.parametrize("plaintext", ["", "a", "a" * 500, "unicode: café, 日本語, 🔑"])
def test_various_plaintext_lengths_and_content(plaintext):
    priv, pub = hint_crypto.generate_encryption_keypair()
    if plaintext == "":
        pytest.skip("empty string is handled at the manifest-builder layer, not here")
    ciphertext = hint_crypto.encrypt_hint(plaintext, pub)
    assert hint_crypto.decrypt_hint(ciphertext, priv) == plaintext
