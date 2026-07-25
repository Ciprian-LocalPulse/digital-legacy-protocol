"""
Owner key recovery (spec v0.1 gap: if the owner loses their own private key
*before* activation, the old manifest can't be updated or revoked — only
reissued from scratch under a new key, silently orphaning the old one).

This module gives the owner an opt-in way to avoid that: split their own
Ed25519 private key with Shamir's Secret Sharing among the SAME trustees
who already hold asset shares, at a SEPARATE threshold the owner chooses.
This is deliberately not automatic — backing up your own signing key to
the people you also rely on for the dead man's switch is a real tradeoff
(those trustees could collude to reconstruct your key while you're still
alive), and the owner should decide that consciously, not have it happen
as a side effect of building a manifest.

If you don't want this tradeoff at all, don't call this module — losing
your key still just means reissuing a fresh manifest, exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from . import shamir


@dataclass(frozen=True)
class OwnerKeyBackup:
    """The result of splitting an owner's private key. `shares` maps
    trustee_id -> (index, hex_data). The index is the share's original
    x-coordinate and MUST be preserved — reconstruction is Lagrange
    interpolation, which needs to know which x each y-value belongs to,
    not just an arbitrary re-ordering of the shares that survived."""

    threshold: int
    shares: Dict[str, Tuple[int, str]]

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "shares": {
                tid: {"index": idx, "data": hexdata} for tid, (idx, hexdata) in self.shares.items()
            },
        }


def backup_owner_key(
    owner_private_key_raw_bytes: bytes, threshold: int, trustee_ids: List[str]
) -> OwnerKeyBackup:
    """Splits the owner's raw Ed25519 private key bytes (NOT the
    'ed25519:...' base64 string — strip that prefix and base64-decode it
    first) among trustee_ids. `threshold` can differ from the manifest's
    quorum threshold for activation; a common choice is to require MORE
    trustees to recover a live owner's key than to activate the switch
    after death, since the former is a much higher-stakes operation on a
    presumably-still-living person.
    """
    if len(owner_private_key_raw_bytes) == 0:
        raise ValueError("owner private key bytes must not be empty")
    shares = shamir.split_secret(owner_private_key_raw_bytes, threshold, trustee_ids)
    return OwnerKeyBackup(
        threshold=threshold,
        shares={s.trustee_id: (s.index, s.data.hex()) for s in shares},
    )


def recover_owner_key(shares_by_trustee: Dict[str, Tuple[int, str]]) -> bytes:
    """Reconstructs the owner's raw private key bytes from >= threshold
    shares, each supplied as (index, hex_data) exactly as stored in
    OwnerKeyBackup.shares. Callers are responsible for re-deriving the
    'ed25519:...' key string (base64-encode these bytes and add the
    prefix) and for verifying the recovered key actually matches the
    owner's known public key before trusting it — this function only does
    the arithmetic."""
    if len(shares_by_trustee) < 2:
        raise ValueError("need at least 2 shares to attempt recovery")
    shares = [
        shamir.Share(index=idx, trustee_id=tid, data=bytes.fromhex(hex_data))
        for tid, (idx, hex_data) in shares_by_trustee.items()
    ]
    return shamir.reconstruct_secret(shares)
