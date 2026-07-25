"""
Ed25519 signing and canonicalization helpers for DLP manifests.

Manifests are canonicalized with a deterministic JSON serialization
(sorted keys, no whitespace) before signing, so any two implementations
that hash the "same" manifest get the same bytes.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[str, str]:
    """Returns (private_key_b64, public_key_b64)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        "ed25519:" + base64.b64encode(priv_bytes).decode(),
        "ed25519:" + base64.b64encode(pub_bytes).decode(),
    )


def _strip_prefix(key_str: str) -> bytes:
    if not key_str.startswith("ed25519:"):
        raise ValueError("expected key string prefixed with 'ed25519:'")
    return base64.b64decode(key_str[len("ed25519:") :])


def canonicalize(manifest: Dict[str, Any]) -> bytes:
    """
    Deterministic serialization: sorted keys, compact separators, the
    'signature' field excluded (you can't sign a document containing its
    own signature).
    """
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(manifest: Dict[str, Any], private_key_b64: str) -> str:
    key_bytes = _strip_prefix(private_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    signature = private_key.sign(canonicalize(manifest))
    return base64.b64encode(signature).decode()


def verify_manifest(manifest: Dict[str, Any], public_key_b64: str) -> bool:
    signature_b64 = manifest.get("signature")
    if not signature_b64:
        return False
    try:
        key_bytes = _strip_prefix(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        public_key.verify(base64.b64decode(signature_b64), canonicalize(manifest))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False
