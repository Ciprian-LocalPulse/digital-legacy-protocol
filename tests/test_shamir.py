import os

import pytest

from dlp import shamir


def test_split_and_reconstruct_roundtrip():
    secret = b"a supposedly secret private key material 1234567890"
    shares = shamir.split_secret(secret, threshold=3, trustee_ids=["a", "b", "c", "d", "e"])
    assert len(shares) == 5
    # any 3 of 5 should reconstruct
    import itertools

    for combo in itertools.combinations(shares, 3):
        assert shamir.reconstruct_secret(list(combo)) == secret


def test_insufficient_shares_do_not_reconstruct_correctly():
    secret = os.urandom(32)
    shares = shamir.split_secret(secret, threshold=3, trustee_ids=["a", "b", "c"])
    # only 2 of 3 required-3 shares: should NOT match (overwhelmingly likely)
    wrong = shamir.reconstruct_secret(shares[:2])
    assert wrong != secret


def test_single_share_raises():
    secret = b"x"
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=["a", "b"])
    with pytest.raises(ValueError):
        shamir.reconstruct_secret(shares[:1])


def test_threshold_equals_n():
    secret = b"all trustees required"
    shares = shamir.split_secret(secret, threshold=3, trustee_ids=["a", "b", "c"])
    assert shamir.reconstruct_secret(shares) == secret


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        shamir.split_secret(b"", threshold=2, trustee_ids=["a", "b"])


def test_threshold_below_two_rejected():
    with pytest.raises(ValueError):
        shamir.split_secret(b"x", threshold=1, trustee_ids=["a", "b"])


def test_threshold_exceeds_trustees_rejected():
    with pytest.raises(ValueError):
        shamir.split_secret(b"x", threshold=5, trustee_ids=["a", "b"])


def test_shares_are_distinct():
    secret = b"distinct shares please"
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=["a", "b", "c"])
    datas = {s.data for s in shares}
    assert len(datas) == len(shares)


def test_share_serialization_roundtrip():
    secret = b"serialize me"
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=["a", "b"])
    restored = [shamir.Share.from_dict(s.to_dict()) for s in shares]
    assert shamir.reconstruct_secret(restored) == secret


def test_binary_secret_with_null_bytes():
    secret = bytes([0, 0, 255, 0, 128, 1, 0])
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=["a", "b", "c"])
    assert shamir.reconstruct_secret(shares[:2]) == secret


@pytest.mark.parametrize("length", [1, 16, 32, 64, 256])
def test_various_secret_lengths(length):
    secret = os.urandom(length)
    shares = shamir.split_secret(secret, threshold=3, trustee_ids=["a", "b", "c", "d"])
    assert shamir.reconstruct_secret(shares[:3]) == secret


def test_gf_arithmetic_sanity():
    # multiplication by 1 is identity
    for v in range(256):
        assert shamir.gf_mul(v, 1) == v
    # multiplication by 0 is 0
    for v in range(256):
        assert shamir.gf_mul(v, 0) == 0
    # a * b / b == a for b != 0
    for a in range(1, 256, 17):
        for b in range(1, 256, 23):
            assert shamir.gf_div(shamir.gf_mul(a, b), b) == a
