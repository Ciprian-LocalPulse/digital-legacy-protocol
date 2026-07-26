"""
Dead man's switch state machine.

This module tracks check-ins and trustee attestations for a single
manifest, and decides when quorum-based activation should fire. It is
deliberately storage-agnostic: give it timestamps, it gives you a state.
No database, no network calls — a Platform Adapter wires this to real
infrastructure (see dlp/adapter.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import List, Optional


class SwitchState(str, Enum):
    ACTIVE = "active"  # owner checking in normally
    OVERDUE = "overdue"  # missed check-in, inside grace period
    VERIFICATION = "verification"  # grace period lapsed, polling trustees
    ACTIVATED = "activated"  # quorum confirmed, assets should release
    ABORTED = "aborted"  # owner checked in during verification


@dataclass
class Attestation:
    trustee_id: str
    confirms_unreachable: bool
    timestamp: datetime

    def to_dict(self) -> dict:
        return {
            "trustee_id": self.trustee_id,
            "confirms_unreachable": self.confirms_unreachable,
            "timestamp": self.timestamp.isoformat(),
        }

    @staticmethod
    def from_dict(d: dict) -> Attestation:
        return Attestation(
            trustee_id=d["trustee_id"],
            confirms_unreachable=d["confirms_unreachable"],
            timestamp=datetime.fromisoformat(d["timestamp"]),
        )


@dataclass
class DeadMansSwitch:
    manifest_id: str
    interval_days: int
    grace_days: int
    quorum_threshold: int
    last_checkin: datetime
    attestations: List[Attestation] = field(default_factory=list)
    _aborted_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Serializes full state, including the internal _aborted_at
        field — this is persisted state, not a public API surface, so
        round-tripping it exactly matters more than hiding the
        underscore-prefixed attribute."""
        return {
            "manifest_id": self.manifest_id,
            "interval_days": self.interval_days,
            "grace_days": self.grace_days,
            "quorum_threshold": self.quorum_threshold,
            "last_checkin": self.last_checkin.isoformat(),
            "attestations": [a.to_dict() for a in self.attestations],
            "aborted_at": self._aborted_at.isoformat() if self._aborted_at else None,
        }

    @staticmethod
    def from_dict(d: dict) -> DeadMansSwitch:
        return DeadMansSwitch(
            manifest_id=d["manifest_id"],
            interval_days=d["interval_days"],
            grace_days=d["grace_days"],
            quorum_threshold=d["quorum_threshold"],
            last_checkin=datetime.fromisoformat(d["last_checkin"]),
            attestations=[Attestation.from_dict(a) for a in d.get("attestations", [])],
            _aborted_at=(datetime.fromisoformat(d["aborted_at"]) if d.get("aborted_at") else None),
        )

    @staticmethod
    def from_manifest(manifest: dict, at: Optional[datetime] = None) -> DeadMansSwitch:
        """Initializes a fresh switch from a manifest's checkin/quorum
        config, with last_checkin set to now (or the given time) — the
        natural starting point when an owner first activates monitoring
        for a manifest they've just signed."""
        return DeadMansSwitch(
            manifest_id=manifest["manifest_id"],
            interval_days=manifest["checkin"]["interval_days"],
            grace_days=manifest["checkin"]["grace_days"],
            quorum_threshold=manifest["quorum"]["threshold"],
            last_checkin=at or datetime.now(timezone.utc),
        )

    def record_checkin(self, at: Optional[datetime] = None) -> None:
        """Owner proves they're alive. Resets everything."""
        self.last_checkin = at or datetime.now(timezone.utc)
        self.attestations.clear()
        self._aborted_at = None

    def record_attestation(
        self, trustee_id: str, confirms_unreachable: bool, at: Optional[datetime] = None
    ) -> None:
        if self.state(at) not in (SwitchState.VERIFICATION, SwitchState.ACTIVATED):
            raise RuntimeError(
                "attestations are only meaningful once verification has started "
                "(owner must be overdue past the grace period first)"
            )
        # a trustee can update their attestation; only the latest counts
        self.attestations = [a for a in self.attestations if a.trustee_id != trustee_id]
        self.attestations.append(
            Attestation(
                trustee_id=trustee_id,
                confirms_unreachable=confirms_unreachable,
                timestamp=at or datetime.now(timezone.utc),
            )
        )
        if not confirms_unreachable:
            # any single "I've seen them, they're fine" aborts activation —
            # this is intentional friction against false positives, per spec section 7
            self._aborted_at = at or datetime.now(timezone.utc)

    def state(self, at: Optional[datetime] = None) -> SwitchState:
        now = at or datetime.now(timezone.utc)
        deadline = self.last_checkin + timedelta(days=self.interval_days)
        grace_deadline = deadline + timedelta(days=self.grace_days)

        if self._aborted_at is not None and self._aborted_at >= self.last_checkin:
            return SwitchState.ABORTED

        confirmations = sum(1 for a in self.attestations if a.confirms_unreachable)
        if now > grace_deadline and confirmations >= self.quorum_threshold:
            return SwitchState.ACTIVATED
        if now > grace_deadline:
            return SwitchState.VERIFICATION
        if now > deadline:
            return SwitchState.OVERDUE
        return SwitchState.ACTIVE

    def days_until_overdue(self, at: Optional[datetime] = None) -> float:
        now = at or datetime.now(timezone.utc)
        deadline = self.last_checkin + timedelta(days=self.interval_days)
        return (deadline - now).total_seconds() / 86400

    def confirmations_needed(self, at: Optional[datetime] = None) -> int:
        confirmed = sum(1 for a in self.attestations if a.confirms_unreachable)
        return max(0, self.quorum_threshold - confirmed)
