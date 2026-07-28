"""
Trustee and owner notification (spec gap: check-in reminders and
attestation requests are described in the spec and modeled correctly in
dlp.switch, but nothing actually delivers them to a real person).

This module defines a small NotificationChannel interface plus three
implementations:
  - SMTPEmailChannel: sends real email via any standard SMTP server
    (Gmail, SES, Postmark, your own mail server — anything that speaks
    SMTP over TLS with username/password auth).
  - TwilioSMSChannel: sends real SMS via Twilio's REST API. Chosen
    because Twilio's HTTP API is simple enough to implement with nothing
    but stdlib urllib (no SDK dependency) and is widely enough used that
    several other providers (and Twilio-compatible gateways) speak a
    near-identical API.
  - ConsoleChannel: prints to stdout instead of sending anything. Useful
    for local development, tests, and the CLI demo, where spinning up
    real mail or SMS infrastructure would be overkill.

NotificationService wraps any channel with the actual message content
DLP needs to send: check-in reminders to the owner, attestation requests
to trustees once verification starts, activation notices to
beneficiaries, and abort notices back to the owner.
"""

from __future__ import annotations

import base64
import json
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import List


class NotificationError(RuntimeError):
    """Raised when a channel fails to deliver a message. Deliberately a
    single exception type — callers deciding what to do about a failed
    delivery (retry, alert a human, fall back to another channel) need to
    know delivery failed, not necessarily why in fine-grained detail."""


class NotificationChannel(ABC):
    @abstractmethod
    def send(self, recipient: str, subject: str, body: str) -> None:
        """Raises NotificationError on failure. Returns normally on
        success — there is no partial-success state for a single
        message."""
        raise NotImplementedError


@dataclass
class SMTPEmailChannel(NotificationChannel):
    """Sends real email via SMTP over TLS. Works with Gmail (with an app
    password), Amazon SES, Postmark, Mailgun, or a self-hosted server —
    anything speaking standard SMTP+STARTTLS auth. No dependency beyond
    the Python standard library."""

    host: str
    port: int
    username: str
    password: str
    from_address: str
    use_tls: bool = True
    timeout_seconds: int = 15

    def send(self, recipient: str, subject: str, body: str) -> None:
        message = MIMEText(body, "plain", "utf-8")
        message["Subject"] = subject
        message["From"] = self.from_address
        message["To"] = recipient

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout_seconds) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_address, [recipient], message.as_string())
        except (smtplib.SMTPException, OSError) as e:
            raise NotificationError(f"failed to send email to {recipient}: {e}") from e


@dataclass
class TwilioSMSChannel(NotificationChannel):
    """Sends real SMS via Twilio's REST API
    (https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json).
    No SDK dependency — this is a handful of lines against a simple HTTP
    API, using HTTP Basic Auth with your Account SID and Auth Token
    exactly as Twilio's own docs describe.

    SMS has no concept of a subject line, so `subject` is prefixed onto
    the body rather than dropped, and the combined message is truncated
    to stay under a conservative single-segment length — long DLP
    notification bodies are not what SMS is for; use email for anything
    that needs the full text."""

    account_sid: str
    auth_token: str
    from_number: str
    timeout_seconds: int = 15
    max_length: int = 320  # roughly 2 GSM-7 segments; keeps messages affordable and readable

    def send(self, recipient: str, subject: str, body: str) -> None:
        full_text = f"{subject}\n{body}" if subject else body
        if len(full_text) > self.max_length:
            full_text = full_text[: self.max_length - 1].rstrip() + "…"

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self.account_sid}/Messages.json"
        form_data = urllib.parse.urlencode(
            {"To": recipient, "From": self.from_number, "Body": full_text}
        ).encode("utf-8")

        credentials = base64.b64encode(f"{self.account_sid}:{self.auth_token}".encode()).decode()
        req = urllib.request.Request(url, data=form_data, method="POST")
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            # url is hardcoded to https://api.twilio.com/..., never derived from manifest or user data
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # nosec B310
                resp.read()  # drain the response; Twilio's success payload isn't needed here
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("message", str(e))
            except (ValueError, AttributeError):
                detail = str(e)
            raise NotificationError(f"Twilio SMS to {recipient} failed ({e.code}): {detail}") from e
        except urllib.error.URLError as e:
            raise NotificationError(f"Twilio SMS to {recipient} unreachable: {e.reason}") from e


@dataclass
class ConsoleChannel(NotificationChannel):
    """Prints messages instead of sending them. Every call is also
    recorded in `.sent`, so tests can assert on exactly what would have
    gone out without needing real mail infrastructure."""

    sent: List[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.sent is None:
            self.sent = []

    def send(self, recipient: str, subject: str, body: str) -> None:
        entry = {"recipient": recipient, "subject": subject, "body": body}
        self.sent.append(entry)
        print(f"--- [DLP notification -> {recipient}] {subject} ---")
        print(body)
        print("--- end notification ---")


class NotificationService:
    """The actual message content for each situation DLP's dead man's
    switch cares about. Wraps any NotificationChannel — swap
    ConsoleChannel for SMTPEmailChannel (or your own channel) to go from
    a local demo to production without changing any of this text."""

    def __init__(self, channel: NotificationChannel):
        self._channel = channel

    def send_checkin_reminder(
        self, owner_email: str, owner_name: str, days_until_overdue: float
    ) -> None:
        subject = "Digital Legacy Protocol: check-in reminder"
        urgency = "very soon" if days_until_overdue < 7 else "in about a week"
        body = (
            f"Hi {owner_name},\n\n"
            f"This is a reminder from your Digital Legacy Protocol manifest: "
            f"your check-in window closes {urgency} "
            f"({days_until_overdue:.1f} days remaining).\n\n"
            f"If you're reading this, nothing needs to happen except your "
            f"normal check-in — no action is taken until you miss the "
            f"check-in AND the grace period AND a quorum of trustees "
            f"confirms they can't reach you.\n\n"
            f"— Digital Legacy Protocol"
        )
        self._channel.send(owner_email, subject, body)

    def send_attestation_request(
        self, trustee_email: str, trustee_contact_hint: str, owner_display_name: str
    ) -> None:
        subject = "Digital Legacy Protocol: your attestation is needed"
        body = (
            f"Hello,\n\n"
            f"You are listed as a trustee ({trustee_contact_hint}) for "
            f"{owner_display_name}'s Digital Legacy Protocol manifest. "
            f"{owner_display_name} has missed their check-in window, "
            f"including the grace period.\n\n"
            f"We need to know: to your knowledge, is {owner_display_name} "
            f"alive and able to check in?\n\n"
            f"This does not release anything by itself. A quorum of "
            f"trustees must independently confirm before any action is "
            f"taken, and any one trustee reporting the owner is fine "
            f"aborts the process.\n\n"
            f"Please respond through whatever channel your manifest "
            f"owner set up for attestation.\n\n"
            f"— Digital Legacy Protocol"
        )
        self._channel.send(trustee_email, subject, body)

    def send_activation_notice(self, beneficiary_email: str, asset_reference: str) -> None:
        subject = "Digital Legacy Protocol: an asset has been released to you"
        body = (
            f"Hello,\n\n"
            f"A Digital Legacy Protocol manifest has activated, and you "
            f"are the designated beneficiary for: {asset_reference}.\n\n"
            f"This happened because a quorum of trustees independently "
            f"confirmed the owner could not be reached, after their "
            f"check-in and grace period both lapsed.\n\n"
            f"— Digital Legacy Protocol"
        )
        self._channel.send(beneficiary_email, subject, body)

    def send_abort_notice(self, owner_email: str, owner_name: str) -> None:
        subject = "Digital Legacy Protocol: activation was aborted"
        body = (
            f"Hello {owner_name},\n\n"
            f"Your Digital Legacy Protocol switch entered verification "
            f"(you missed a check-in), but a trustee has confirmed you're "
            f"fine, so activation was aborted automatically.\n\n"
            f"If this is unexpected, please check in as soon as you can — "
            f"and consider whether your check-in interval is realistic "
            f"for how you actually use this.\n\n"
            f"— Digital Legacy Protocol"
        )
        self._channel.send(owner_email, subject, body)
