"""
Platform Adapter interface (spec section 8).

Any service — a bank, an exchange, a password manager, a hobby project —
implements this ABC to become DLP-aware. This module ships no real
integrations on purpose; it's the contract, plus a toy in-memory adapter
used by the tests and the CLI demo so people can see it work end to end.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict

from . import manifest as manifest_mod


@dataclass
class ActionResult:
    success: bool
    detail: str


class DLPAdapter(ABC):
    """Subclass this in your platform's codebase to honor DLP manifests."""

    @abstractmethod
    def verify_manifest(self, manifest: Dict[str, Any]) -> bool:
        """Check structural validity and signature. Reference impl provided
        below via `default_verify` — most adapters can just call that."""
        raise NotImplementedError

    @abstractmethod
    def on_activation(
        self, manifest: Dict[str, Any], asset_id: str, reconstructed_secret: bytes
    ) -> ActionResult:
        """Called once quorum has reconstructed the secret for one asset.
        This is where you'd actually transfer funds, unlock an account,
        deliver a message, etc."""
        raise NotImplementedError

    @abstractmethod
    def on_revocation(self, manifest_id: str) -> None:
        """Called when the owner supersedes or explicitly revokes a manifest.
        Adapters should stop honoring the old manifest_id immediately."""
        raise NotImplementedError


def default_verify(manifest: Dict[str, Any]) -> bool:
    """Structural + signature validation any adapter can reuse as-is."""
    try:
        manifest_mod.validate_manifest(manifest)
    except manifest_mod.ManifestValidationError:
        return False
    return manifest_mod.is_signature_valid(manifest)


class InMemoryDemoAdapter(DLPAdapter):
    """Reference/demo adapter — keeps everything in memory. Not for
    production use; it exists so the CLI and tests have something concrete
    to run against."""

    def __init__(self):
        self.revoked: set[str] = set()
        self.activations: list[tuple[str, str, bytes]] = []

    def verify_manifest(self, manifest: Dict[str, Any]) -> bool:
        if manifest["manifest_id"] in self.revoked:
            return False
        return default_verify(manifest)

    def on_activation(
        self, manifest: Dict[str, Any], asset_id: str, reconstructed_secret: bytes
    ) -> ActionResult:
        self.activations.append((manifest["manifest_id"], asset_id, reconstructed_secret))
        return ActionResult(
            success=True, detail=f"asset {asset_id} released (demo, in-memory only)"
        )

    def on_revocation(self, manifest_id: str) -> None:
        self.revoked.add(manifest_id)
