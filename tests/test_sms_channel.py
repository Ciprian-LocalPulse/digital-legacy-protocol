import base64
import json
import urllib.error
import urllib.parse
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from dlp.notify import NotificationError, NotificationService, TwilioSMSChannel


def _mock_urlopen_success():
    mock_resp = MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_resp.read.return_value = b'{"sid": "SMxxxx", "status": "queued"}'
    return mock_resp


@patch("urllib.request.urlopen")
def test_sms_sends_to_correct_twilio_url(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(
        account_sid="ACfake", auth_token="tokfake", from_number="+15551230000"
    )
    channel.send("+15559998888", "Alert", "body text")

    req = mock_urlopen.call_args[0][0]
    assert req.full_url == "https://api.twilio.com/2010-04-01/Accounts/ACfake/Messages.json"
    assert req.get_method() == "POST"


@patch("urllib.request.urlopen")
def test_sms_uses_http_basic_auth(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="ACfake", auth_token="tokfake", from_number="+1")
    channel.send("+1999", "", "hi")

    req = mock_urlopen.call_args[0][0]
    expected = "Basic " + base64.b64encode(b"ACfake:tokfake").decode()
    assert req.get_header("Authorization") == expected


@patch("urllib.request.urlopen")
def test_sms_body_contains_to_from_and_message(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+15551230000")
    channel.send("+15559998888", "", "please check in")

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    assert parsed["To"] == ["+15559998888"]
    assert parsed["From"] == ["+15551230000"]
    assert parsed["Body"] == ["please check in"]


@patch("urllib.request.urlopen")
def test_sms_prefixes_subject_when_present(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1")
    channel.send("+1999", "DLP Alert", "the body")

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    assert parsed["Body"] == ["DLP Alert\nthe body"]


@patch("urllib.request.urlopen")
def test_sms_omits_subject_line_when_blank(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1")
    channel.send("+1999", "", "just the body")

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    assert parsed["Body"] == ["just the body"]


@patch("urllib.request.urlopen")
def test_sms_truncates_long_messages(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1", max_length=20)
    channel.send("+1999", "", "a" * 100)

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    body = parsed["Body"][0]
    assert len(body) == 20
    assert body.endswith("…")


@patch("urllib.request.urlopen")
def test_sms_short_message_not_truncated(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1", max_length=320)
    channel.send("+1999", "", "short message")

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    assert parsed["Body"] == ["short message"]
    assert "…" not in parsed["Body"][0]


@patch("urllib.request.urlopen")
def test_sms_http_error_wrapped_with_twilio_message(mock_urlopen):
    error_body = json.dumps({"message": "The 'To' number is not a valid phone number."}).encode()
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="x", code=400, msg="Bad Request", hdrs=None, fp=BytesIO(error_body)
    )
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1")

    with pytest.raises(NotificationError) as exc_info:
        channel.send("+1invalid", "", "test")
    assert "not a valid phone number" in str(exc_info.value)
    assert "400" in str(exc_info.value)


@patch("urllib.request.urlopen")
def test_sms_http_error_without_json_body_falls_back_gracefully(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="x", code=500, msg="Internal Server Error", hdrs=None, fp=BytesIO(b"not json")
    )
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1")

    with pytest.raises(NotificationError):
        channel.send("+1999", "", "test")


@patch("urllib.request.urlopen")
def test_sms_network_error_raises_notification_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("connection refused")
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+1")

    with pytest.raises(NotificationError):
        channel.send("+1999", "", "test")


@patch("urllib.request.urlopen")
def test_sms_channel_works_with_notification_service(mock_urlopen):
    mock_urlopen.return_value = _mock_urlopen_success()
    channel = TwilioSMSChannel(account_sid="AC", auth_token="t", from_number="+15551230000")
    service = NotificationService(channel)

    service.send_checkin_reminder("+15559998888", "Ada", days_until_overdue=3.0)

    req = mock_urlopen.call_args[0][0]
    parsed = urllib.parse.parse_qs(req.data.decode())
    assert "Ada" in parsed["Body"][0]
    assert parsed["To"] == ["+15559998888"]
