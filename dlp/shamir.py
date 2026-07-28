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
from typing import List

# --- GF(256) arithmetic -----------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    """Precompute log/exp tables for GF(256) using generator 3.

    Note: 2 is NOT a primitive element for the AES reduction polynomial
    (0x11B) — that's precisely why AES itself uses 3 as its generator.
    Using 2 here silently produces a table that cycles after only a few
    steps, which breaks multiplication for most byte values. Multiplying
    by 3 is doubling (xtime) XORed with the original value.
    """
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
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_div(a: int, b: int) -> int:
    if a == 0:
        return 0
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def gf_pow(a: int, power: int) -> int:
    if power == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * power) % 255]


# --- Polynomial evaluation ---------------------------------------------------


def _eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial (coeffs[0] is the secret / constant term) at x."""
    result = 0
    for coeff in reversed(coeffs):
        result = gf_mul(result, x) ^ coeff
    return result


# --- Public data structures --------------------------------------------------


@dataclass(frozen=True)
class Share:
    """A single share: an x-coordinate plus one byte of y per secret byte."""

    index: int  # x-coordinate, 1..255, never 0
    trustee_id: str
    data: bytes  # y-values, one per byte of the original secret

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "trustee_id": self.trustee_id,
            "data": self.data.hex(),
        }

   @staticmethod
    def from_dict(d: dict) -> Share:
        return Share(
            index=d["index"], trustee_id=d["trustee_id"], data=bytes.fromhex(d["data"])
        )


def split_secret(secret: bytes, threshold: int, trustee_ids: List[str]) -> List[Share]:
    """
    Split `secret` into len(trustee_ids) shares, any `threshold` of which
    reconstruct it.
    """
    n = len(trustee_ids)
    if threshold < 2:
        raise ValueError("threshold must be >= 2 (a threshold of 1 isn't secret sharing)")
    if threshold > n:
        raise ValueError("threshold cannot exceed the number of trustees")
    if n >= 255:
        raise ValueError("maximum 254 trustees supported (x-coordinates 1..254)")
    if not secret:
        raise ValueError("secret must not be empty")

    xs = list(range(1, n + 1))

    # Buclă de siguranță: se repetă doar dacă (prin absurd) apar share-uri duplicate
    while True:
        share_bytes: List[bytearray] = [bytearray() for _ in xs]

        for secret_byte in secret:
            random_coeffs = []
            for i in range(threshold - 1):
                while True:
                    r = os.urandom(1)[0]
                    # Coeficientul de grad maxim (ultimul din listă) NU are voie să fie 0.
                    # Pentru threshold=2, acesta este singurul coeficient aleatoriu.
                    if i == (threshold - 2) and r == 0:
                        continue
                    random_coeffs.append(r)
                    break

            coeffs = [secret_byte] + random_coeffs

            for i, x in enumerate(xs):
                share_bytes[i].append(_eval_poly(coeffs, x))

        shares = [
            Share(index=xs[i], trustee_id=trustee_ids[i], data=bytes(share_bytes[i]))
            for i in range(n)
        ]

        # Validare: asigură proprietatea matematică de distincție între perechi
        datas = [s.data for s in shares]
        if len(datas) == len(set(datas)):
            return shares


def reconstruct_secret(shares: List[Share]) -> bytes:
    """
    Reconstruct the original secret from >= threshold shares using
    Lagrange interpolation at x=0. Passing fewer shares than the original
    threshold silently returns garbage (by design — this module has no way
    to know the threshold after the fact; callers should track it in the
    manifest).
    """
    if len(shares) < 2:
        raise ValueError("need at least 2 shares to reconstruct")

    lengths = {len(s.data) for s in shares}
    if len(lengths) != 1:
        raise ValueError("all shares must encode secrets of the same length")
    secret_len = lengths.pop()

    xs = [s.index for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices — cannot interpolate")

    out = bytearray(secret_len)
    for byte_pos in range(secret_len):
        ys = [s.data[byte_pos] for s in shares]
        # Lagrange interpolation at x = 0
        acc = 0
        for i in range(len(xs)):
            xi, yi = xs[i], ys[i]
            num = 1
            den = 1
            for j in range(len(xs)):
                if i == j:
                    continue
                xj = xs[j]
                num = gf_mul(num, xj)  # (0 - xj) == xj in GF(256)
                den = gf_mul(den, xi ^ xj)  # (xi - xj) == xi ^ xj
            term = gf_mul(yi, gf_div(num, den))
            acc ^= term
        out[byte_pos] = acc

    return bytes(out)
