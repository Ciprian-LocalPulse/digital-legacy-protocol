"""
Shamir's Secret Sharing over GF(256).

Splits a secret (bytes) into N shares such that any M of them can
reconstruct the original secret, while M-1 shares reveal nothing at all
(information-theoretic security, not just computational).

This is a from-scratch implementation over the finite field GF(2^8) using
the AES field polynomial (x^8 + x^4 + x^3 + x + 1 = 0x11B), so it operates
byte-by-byte and needs no external crypto library.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# GF(256) arithmetic
# ---------------------------------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    """Precompute log/exp tables for GF(256) using generator 3."""

    p = 1

    for i in range(255):
        _EXP[i] = p
        _LOG[p] = i

        xtime = (p << 1) ^ 0x11B if p & 0x80 else (p << 1)
        p = (xtime ^ p) & 0xFF

    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def gf_mul(a: int, b: int) -> int:
    """Multiply two field elements."""

    if a == 0 or b == 0:
        return 0

    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a: int, b: int) -> int:
    """Divide two field elements."""

    if a == 0:
        return 0

    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")

    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def gf_pow(a: int, power: int) -> int:
    """Exponentiation in GF(256)."""

    if power == 0:
        return 1

    if a == 0:
        return 0

    return _EXP[(_LOG[a] * power) % 255]


# ---------------------------------------------------------------------------
# Polynomial evaluation
# ---------------------------------------------------------------------------


def _eval_poly(coeffs: list[int], x: int) -> int:
    """
    Evaluate a polynomial using Horner's method.

    coeffs[0] is the constant term (the secret byte).
    """

    result = 0

    for coeff in reversed(coeffs):
        result = gf_mul(result, x) ^ coeff

    return result


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Share:
    """
    A single Shamir share.

    Attributes:
        index:
            X-coordinate (1..254).

        trustee_id:
            Human-readable trustee identifier.

        data:
            One Y byte for every byte of the original secret.
    """

    index: int
    trustee_id: str
    data: bytes

    def to_dict(self) -> dict:
        """Serialize the share."""

        return {
            "index": self.index,
            "trustee_id": self.trustee_id,
            "data": self.data.hex(),
        }

    @staticmethod
    def from_dict(d: dict) -> "Share":
        """Deserialize a Share."""

        return Share(
            index=d["index"],
            trustee_id=d["trustee_id"],
            data=bytes.fromhex(d["data"]),
        )
        # ---------------------------------------------------------------------------
# Secret splitting
# ---------------------------------------------------------------------------


def split_secret(
    secret: bytes,
    threshold: int,
    trustee_ids: list[str],
) -> list[Share]:
    """
    Split a secret into N shares.

    Any `threshold` shares can reconstruct the original secret, while
    fewer than `threshold` reveal no information about it.
    """

    n = len(trustee_ids)

    if threshold < 2:
        raise ValueError(
            "threshold must be >= 2 "
            "(a threshold of 1 isn't secret sharing)"
        )

    if threshold > n:
        raise ValueError(
            "threshold cannot exceed the number of trustees"
        )

    if n >= 255:
        raise ValueError(
            "maximum 254 trustees supported "
            "(x-coordinates 1..254)"
        )

    if not secret:
        raise ValueError("secret must not be empty")

    xs = list(range(1, n + 1))

    # Repeat only in the astronomically unlikely event that two shares
    # become identical.
    while True:

        share_bytes: list[bytearray] = [
            bytearray()
            for _ in xs
        ]

        for secret_byte in secret:

            random_coeffs: list[int] = []

            for i in range(threshold - 1):

                while True:
                    r = os.urandom(1)[0]

                    # The highest-degree coefficient must never be zero.
                    # Otherwise the polynomial degree may collapse,
                    # weakening the threshold guarantees.
                    if i == threshold - 2 and r == 0:
                        continue

                    random_coeffs.append(r)
                    break

            coeffs = [secret_byte] + random_coeffs

            for idx, x in enumerate(xs):
                share_bytes[idx].append(
                    _eval_poly(coeffs, x)
                )

        shares = [
            Share(
                index=xs[i],
                trustee_id=trustee_ids[i],
                data=bytes(share_bytes[i]),
            )
            for i in range(n)
        ]

        # Extremely defensive check.
        datas = [share.data for share in shares]

        if len(datas) == len(set(datas)):
            return shares
            # ---------------------------------------------------------------------------
# Secret reconstruction
# ---------------------------------------------------------------------------


def reconstruct_secret(shares: list[Share]) -> bytes:
    """
    Reconstruct the original secret using Lagrange interpolation at x = 0.

    Passing fewer than the original threshold shares does not raise an
    exception. Instead, reconstruction produces random output, which is
    the expected information-theoretic property of Shamir's Secret Sharing.
    """

    if len(shares) < 2:
        raise ValueError("need at least 2 shares to reconstruct")

    lengths = {len(share.data) for share in shares}

    if len(lengths) != 1:
        raise ValueError(
            "all shares must encode secrets of the same length"
        )

    secret_len = lengths.pop()

    xs = [share.index for share in shares]

    if len(xs) != len(set(xs)):
        raise ValueError(
            "duplicate share indices — cannot interpolate"
        )

    out = bytearray(secret_len)

    for byte_pos in range(secret_len):

        ys = [
            share.data[byte_pos]
            for share in shares
        ]

        acc = 0

        for i, (xi, yi) in enumerate(zip(xs, ys)):

            numerator = 1
            denominator = 1

            for j, xj in enumerate(xs):

                if i == j:
                    continue

                # In characteristic two:
                # (0 - xj) == xj
                numerator = gf_mul(
                    numerator,
                    xj,
                )

                # (xi - xj) == (xi XOR xj)
                denominator = gf_mul(
                    denominator,
                    xi ^ xj,
                )

            basis = gf_div(
                numerator,
                denominator,
            )

            acc ^= gf_mul(
                yi,
                basis,
            )

        out[byte_pos] = acc

    return bytes(out)
