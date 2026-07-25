"""
Manifest construction and validation for the Digital Legacy Protocol.

A Manifest is the signed, portable document at the center of DLP. This
module handles building one, validating its shape, and signing/verifying
it via dlp.crypto.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import crypto

DLP_VERSION = "0.1"

REQUIRED_TOP_LEVEL = {
    "dlp_version",
    "manifest_id",
    "owner",
    "created_at",
    "updated_at",
    "checkin",
    "quorum",
    "assets",
    "beneficiaries",
}

VALID_ASSET_TYPES = {"crypto_wallet", "account_access", "file", "message", "custom"}
VALID_ACTIONS = {"release_key", "grant_access", "deliver_message", "execute_webhook"}
VALID_CHECKIN_METHODS = {"signed_ping", "email_confirm", "app_heartbeat"}


class ManifestValidationError(ValueError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ManifestBuilder:
    """Fluent builder for a DLP manifest. Call .build() to get the dict,
    or .build_and_sign(private_key) to get a signed one directly."""

    def __init__(
        self,
        owner_public_key: str,
        owner_display_name: Optional[str] = None,
        manifest_id: Optional[str] = None,
        supersedes: Optional[str] = None,
    ):
        self._manifest_id = manifest_id or str(uuid.uuid4())
        self._owner = {"public_key": owner_public_key, "display_name": owner_display_name}
        self._supersedes = supersedes
        self._checkin = {"interval_days": 90, "grace_days": 30, "method": "signed_ping"}
        self._trustees: List[Dict[str, Any]] = []
        self._threshold: Optional[int] = None
        self._assets: List[Dict[str, Any]] = []
        self._beneficiaries: List[Dict[str, Any]] = []
        self._created_at = _now_iso()

    def with_checkin(self, interval_days: int, grace_days: int, method: str) -> ManifestBuilder:
        if method not in VALID_CHECKIN_METHODS:
            raise ManifestValidationError(f"invalid checkin method: {method}")
        if interval_days <= 0 or grace_days < 0:
            raise ManifestValidationError("interval_days must be > 0, grace_days must be >= 0")
        self._checkin = {"interval_days": interval_days, "grace_days": grace_days, "method": method}
        return self

    def add_trustee(
        self, trustee_id: Optional[str], public_key: str, contact_hint: str = ""
    ) -> ManifestBuilder:
        self._trustees.append(
            {
                "trustee_id": trustee_id or str(uuid.uuid4()),
                "public_key": public_key,
                "contact_hint": contact_hint,
            }
        )
        return self

    def set_quorum_threshold(self, threshold: int) -> ManifestBuilder:
        self._threshold = threshold
        return self

    def add_beneficiary(
        self,
        beneficiary_id: Optional[str],
        public_key: Optional[str] = None,
        contact_hint: str = "",
    ) -> ManifestBuilder:
        self._beneficiaries.append(
            {
                "beneficiary_id": beneficiary_id or str(uuid.uuid4()),
                "public_key": public_key,
                "contact_hint": contact_hint,
            }
        )
        return self

    def add_asset(
        self,
        asset_type: str,
        reference: str,
        beneficiary_id: str,
        action: str,
        shares_distributed_to: List[str],
        asset_id: Optional[str] = None,
        extra_conditions: Optional[List[str]] = None,
    ) -> ManifestBuilder:
        if asset_type not in VALID_ASSET_TYPES:
            raise ManifestValidationError(f"invalid asset type: {asset_type}")
        if action not in VALID_ACTIONS:
            raise ManifestValidationError(f"invalid action: {action}")
        self._assets.append(
            {
                "asset_id": asset_id or str(uuid.uuid4()),
                "type": asset_type,
                "reference": reference,
                "share_scheme": "shamir",
                "shares_distributed_to": shares_distributed_to,
                "beneficiary_id": beneficiary_id,
                "conditions": ["quorum_reached"] + (extra_conditions or []),
                "action": action,
            }
        )
        return self

    def build(self) -> Dict[str, Any]:
        if self._threshold is None:
            raise ManifestValidationError("must call set_quorum_threshold before build()")
        if self._threshold > len(self._trustees):
            raise ManifestValidationError("quorum threshold exceeds number of trustees")
        if self._threshold < 2:
            raise ManifestValidationError("quorum threshold must be >= 2")
        if not self._assets:
            raise ManifestValidationError("manifest must declare at least one asset")

        manifest = {
            "dlp_version": DLP_VERSION,
            "manifest_id": self._manifest_id,
            "owner": self._owner,
            "created_at": self._created_at,
            "updated_at": _now_iso(),
            "supersedes": self._supersedes,
            "checkin": self._checkin,
            "quorum": {"threshold": self._threshold, "trustees": self._trustees},
            "assets": self._assets,
            "beneficiaries": self._beneficiaries,
        }
        validate_manifest(manifest)
        return manifest

    def build_and_sign(self, owner_private_key: str) -> Dict[str, Any]:
        manifest = self.build()
        manifest["signature"] = crypto.sign_manifest(manifest, owner_private_key)
        return manifest


def validate_manifest(manifest: Dict[str, Any]) -> None:
    """Raises ManifestValidationError on any structural problem."""
    missing = REQUIRED_TOP_LEVEL - manifest.keys()
    if missing:
        raise ManifestValidationError(f"manifest missing required fields: {missing}")

    if manifest["dlp_version"] != DLP_VERSION:
        raise ManifestValidationError(f"unsupported dlp_version: {manifest['dlp_version']}")

    quorum = manifest["quorum"]
    trustee_ids = {t["trustee_id"] for t in quorum["trustees"]}
    if quorum["threshold"] > len(trustee_ids):
        raise ManifestValidationError("quorum threshold exceeds number of distinct trustees")
    if quorum["threshold"] < 2:
        raise ManifestValidationError("quorum threshold must be >= 2")

    beneficiary_ids = {b["beneficiary_id"] for b in manifest["beneficiaries"]}

    for asset in manifest["assets"]:
        if asset["type"] not in VALID_ASSET_TYPES:
            raise ManifestValidationError(f"asset {asset['asset_id']} has invalid type")
        if asset["action"] not in VALID_ACTIONS:
            raise ManifestValidationError(f"asset {asset['asset_id']} has invalid action")
        if asset["beneficiary_id"] not in beneficiary_ids:
            raise ManifestValidationError(
                f"asset {asset['asset_id']} references unknown beneficiary_id"
            )
        unknown = set(asset["shares_distributed_to"]) - trustee_ids
        if unknown:
            raise ManifestValidationError(
                f"asset {asset['asset_id']} distributes shares to unknown trustee(s): {unknown}"
            )
        if len(asset["shares_distributed_to"]) < quorum["threshold"]:
            raise ManifestValidationError(
                f"asset {asset['asset_id']} has fewer shares distributed than the quorum threshold "
                f"— it could never be reconstructed"
            )


def is_signature_valid(manifest: Dict[str, Any]) -> bool:
    return crypto.verify_manifest(manifest, manifest["owner"]["public_key"])
