"""
Connects dlp.switch's state machine to dlp.notify's message delivery.

Before this module, the two pieces existed but nothing wired them
together: DeadMansSwitch computed the right state, NotificationService
knew how to send the right email, but nobody called one from the other.
A trustee had no way to learn they needed to attest except someone
manually running `dlp switch-attest` on their behalf after being told
out-of-band.

SwitchMonitor.tick() is the missing connector: given a manifest and its
switch state, it sends exactly the notifications appropriate for the
current state, exactly once per state (tracked via
DeadMansSwitch.last_notified_state), and persists that bookkeeping so a
repeated call — e.g. from a daily cron job — doesn't re-send the same
email every time it runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .notify import NotificationService
from .storage import LocalFileStore, LocalSwitchStore, SwitchNotFoundError
from .switch import SwitchState


@dataclass
class NotificationAttempt:
    recipient: str
    kind: str  # "checkin_reminder" | "attestation_request" | "activation_notice" | "abort_notice"
    success: bool
    detail: str = ""


class SwitchMonitor:
    """Ties a ManifestStore + a LocalSwitchStore + a NotificationService
    together. Call tick(manifest_id) periodically (a cron job, a
    scheduled task, a button in a web UI) — it figures out what, if
    anything, needs to be sent, sends it, and updates bookkeeping so the
    next call doesn't repeat itself unless the state has actually moved
    on."""

    def __init__(
        self,
        manifest_store: LocalFileStore,
        switch_store: LocalSwitchStore,
        notification_service: NotificationService,
    ):
        self._manifests = manifest_store
        self._switches = switch_store
        self._notify = notification_service

    def tick(self, manifest_id: str) -> List[NotificationAttempt]:
        """Returns the list of notification attempts made this call.
        Empty list means either nothing has changed since the last tick,
        or the manifest/switch don't have the contact info needed to
        notify anyone (both are valid, non-error outcomes)."""
        try:
            switch_state = self._switches.load(manifest_id)
        except SwitchNotFoundError:
            return []

        manifest = self._manifests.load(manifest_id)
        current = switch_state.state()
        attempts: List[NotificationAttempt] = []

        if current.value == switch_state.last_notified_state:
            return attempts  # already notified for this state; nothing new to do

        if current == SwitchState.OVERDUE:
            attempts.extend(self._notify_owner_overdue(manifest, switch_state))
        elif current == SwitchState.VERIFICATION:
            attempts.extend(self._notify_trustees_verification(manifest))
        elif current == SwitchState.ACTIVATED:
            attempts.extend(self._notify_beneficiaries_activated(manifest))
        elif current == SwitchState.ABORTED:
            attempts.extend(self._notify_owner_aborted(manifest))
        # ACTIVE needs no notification — it's the normal resting state,
        # reached either at switch-init or after a check-in resets things.

        switch_state.last_notified_state = current.value
        self._switches.save(switch_state)
        return attempts

    def _notify_owner_overdue(self, manifest: dict, switch_state) -> List[NotificationAttempt]:
        address = manifest["owner"].get("notification_address")
        if not address:
            return [
                NotificationAttempt(
                    recipient="(none)",
                    kind="checkin_reminder",
                    success=False,
                    detail="owner has no notification_address on this manifest",
                )
            ]
        try:
            self._notify.send_checkin_reminder(
                address,
                manifest["owner"].get("display_name") or "there",
                days_until_overdue=switch_state.days_until_overdue(),
            )
            return [NotificationAttempt(recipient=address, kind="checkin_reminder", success=True)]
        except Exception as e:
            return [
                NotificationAttempt(
                    recipient=address, kind="checkin_reminder", success=False, detail=str(e)
                )
            ]

    def _notify_trustees_verification(self, manifest: dict) -> List[NotificationAttempt]:
        attempts = []
        owner_name = manifest["owner"].get("display_name") or "the manifest owner"
        for trustee in manifest["quorum"]["trustees"]:
            address = trustee.get("notification_address")
            if not address:
                attempts.append(
                    NotificationAttempt(
                        recipient=f"trustee {trustee['trustee_id'][:8]}…",
                        kind="attestation_request",
                        success=False,
                        detail="trustee has no notification_address on this manifest",
                    )
                )
                continue
            hint = (
                "(hint is encrypted)"
                if trustee.get("contact_hint_encrypted")
                else (trustee.get("contact_hint") or "")
            )
            try:
                self._notify.send_attestation_request(address, hint, owner_name)
                attempts.append(
                    NotificationAttempt(recipient=address, kind="attestation_request", success=True)
                )
            except Exception as e:
                attempts.append(
                    NotificationAttempt(
                        recipient=address, kind="attestation_request", success=False, detail=str(e)
                    )
                )
        return attempts

    def _notify_beneficiaries_activated(self, manifest: dict) -> List[NotificationAttempt]:
        attempts = []
        beneficiaries_by_id = {b["beneficiary_id"]: b for b in manifest["beneficiaries"]}
        for asset in manifest["assets"]:
            beneficiary = beneficiaries_by_id.get(asset["beneficiary_id"])
            address = beneficiary.get("notification_address") if beneficiary else None
            if not address:
                attempts.append(
                    NotificationAttempt(
                        recipient=f"asset {asset['asset_id'][:8]}…",
                        kind="activation_notice",
                        success=False,
                        detail="beneficiary has no notification_address",
                    )
                )
                continue
            try:
                self._notify.send_activation_notice(address, asset["reference"])
                attempts.append(
                    NotificationAttempt(recipient=address, kind="activation_notice", success=True)
                )
            except Exception as e:
                attempts.append(
                    NotificationAttempt(
                        recipient=address, kind="activation_notice", success=False, detail=str(e)
                    )
                )
        return attempts

    def _notify_owner_aborted(self, manifest: dict) -> List[NotificationAttempt]:
        # Reassurance notice: a trustee reported the owner is fine, so
        # activation was aborted. The owner should know this happened,
        # both to reassure them and as a signal something looked wrong
        # enough that a trustee had to intervene.
        address = manifest["owner"].get("notification_address")
        if not address:
            return [
                NotificationAttempt(
                    recipient="(none)",
                    kind="abort_notice",
                    success=False,
                    detail="owner has no notification_address on this manifest",
                )
            ]
        try:
            self._notify.send_abort_notice(
                address, manifest["owner"].get("display_name") or "there"
            )
            return [NotificationAttempt(recipient=address, kind="abort_notice", success=True)]
        except Exception as e:
            return [
                NotificationAttempt(
                    recipient=address, kind="abort_notice", success=False, detail=str(e)
                )
            ]
