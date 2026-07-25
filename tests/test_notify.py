from unittest.mock import MagicMock, patch

import pytest

from dlp.notify import (
    ConsoleChannel,
    NotificationError,
    NotificationService,
    SMTPEmailChannel,
)


def test_console_channel_records_and_prints(capsys):
    channel = ConsoleChannel()
    channel.send("ada@example.com", "Test subject", "Test body")
    out = capsys.readouterr().out
    assert "Test subject" in out
    assert "Test body" in out
    assert len(channel.sent) == 1
    assert channel.sent[0]["recipient"] == "ada@example.com"


def test_console_channel_records_multiple_sends():
    channel = ConsoleChannel()
    channel.send("a@example.com", "Subject A", "Body A")
    channel.send("b@example.com", "Subject B", "Body B")
    assert len(channel.sent) == 2
    assert channel.sent[0]["recipient"] == "a@example.com"
    assert channel.sent[1]["recipient"] == "b@example.com"


@patch("smtplib.SMTP")
def test_smtp_channel_sends_via_starttls_and_login(mock_smtp_cls):
    import base64

    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    channel = SMTPEmailChannel(
        host="smtp.example.com",
        port=587,
        username="user",
        password="pass",
        from_address="dlp@example.com",
    )
    channel.send("trustee@example.com", "Subject", "Body")

    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("user", "pass")
    mock_server.sendmail.assert_called_once()
    args = mock_server.sendmail.call_args[0]
    assert args[0] == "dlp@example.com"
    assert args[1] == ["trustee@example.com"]
    assert "Subject" in args[2]
    # MIMEText base64-encodes the body when utf-8 charset is used — decode
    # the payload rather than expecting the raw text to appear in the envelope
    payload_line = args[2].strip().splitlines()[-1]
    assert base64.b64decode(payload_line).decode() == "Body"


@patch("smtplib.SMTP")
def test_smtp_channel_without_tls_skips_starttls(mock_smtp_cls):
    mock_server = MagicMock()
    mock_smtp_cls.return_value.__enter__.return_value = mock_server

    channel = SMTPEmailChannel(
        host="localhost",
        port=25,
        username="u",
        password="p",
        from_address="dlp@example.com",
        use_tls=False,
    )
    channel.send("x@example.com", "S", "B")
    mock_server.starttls.assert_not_called()


@patch("smtplib.SMTP")
def test_smtp_failure_raises_notification_error(mock_smtp_cls):
    import smtplib as smtplib_module

    mock_smtp_cls.side_effect = smtplib_module.SMTPConnectError(421, "connection refused")
    channel = SMTPEmailChannel(
        host="smtp.example.com",
        port=587,
        username="u",
        password="p",
        from_address="dlp@example.com",
    )
    with pytest.raises(NotificationError):
        channel.send("x@example.com", "S", "B")


def test_checkin_reminder_content():
    channel = ConsoleChannel()
    service = NotificationService(channel)
    service.send_checkin_reminder("ada@example.com", "Ada", days_until_overdue=3.0)
    assert len(channel.sent) == 1
    body = channel.sent[0]["body"]
    assert "Ada" in body
    assert "very soon" in body
    assert channel.sent[0]["recipient"] == "ada@example.com"


def test_checkin_reminder_long_deadline_uses_different_wording():
    channel = ConsoleChannel()
    service = NotificationService(channel)
    service.send_checkin_reminder("ada@example.com", "Ada", days_until_overdue=20.0)
    body = channel.sent[0]["body"]
    assert "about a week" in body


def test_attestation_request_content():
    channel = ConsoleChannel()
    service = NotificationService(channel)
    service.send_attestation_request("sister@example.com", "Ada's sister", "Ada")
    body = channel.sent[0]["body"]
    assert "Ada" in body
    assert "trustee" in body.lower()
    assert "does not release anything by itself" in body


def test_activation_notice_content():
    channel = ConsoleChannel()
    service = NotificationService(channel)
    service.send_activation_notice("marcus@example.com", "cold storage wallet")
    body = channel.sent[0]["body"]
    assert "cold storage wallet" in body
    assert "quorum" in body.lower()


def test_notification_service_works_with_smtp_channel_too():
    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__.return_value = mock_server
        channel = SMTPEmailChannel(
            host="smtp.example.com",
            port=587,
            username="u",
            password="p",
            from_address="dlp@example.com",
        )
        service = NotificationService(channel)
        service.send_checkin_reminder("ada@example.com", "Ada", days_until_overdue=5.0)
        mock_server.sendmail.assert_called_once()
