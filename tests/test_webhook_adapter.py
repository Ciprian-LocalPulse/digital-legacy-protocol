import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest

from dlp.adapters.webhook import WebhookAdapter, sign_payload, verify_webhook_signature


class _CapturingHandler(BaseHTTPRequestHandler):
    """Records every POST it receives onto the class itself, and replies
    with whatever status code the test configured (default 200).

    http.server instantiates a fresh handler per request, so accumulating
    across requests within one test genuinely requires class-level state
    here, reset by the fixture before each test — this isn't the usual
    mutable-default-argument hazard."""

    received: ClassVar[list] = []
    respond_status: ClassVar[int] = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _CapturingHandler.received.append({"body": body, "headers": dict(self.headers)})
        self.send_response(_CapturingHandler.respond_status)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # keep test output quiet


@pytest.fixture
def local_webhook_server():
    """A real HTTP server on localhost, not a mock — the adapter's actual
    urllib code runs against it exactly as it would against a real
    third-party endpoint."""
    _CapturingHandler.received = []
    _CapturingHandler.respond_status = 200
    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/hook", _CapturingHandler
    server.shutdown()
    thread.join(timeout=2)


def _manifest_with_webhook_asset(url: str, action: str = "execute_webhook"):
    return {
        "dlp_version": "0.1",
        "manifest_id": "m1",
        "assets": [{"asset_id": "a1", "action": action, "reference": url}],
    }


def test_webhook_delivers_real_post_request(local_webhook_server):
    url, handler = local_webhook_server
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset(url)

    result = adapter.on_activation(manifest, "a1", b"final message content")

    assert result.success is True
    assert "200" in result.detail
    assert len(handler.received) == 1

    payload = json.loads(handler.received[0]["body"])
    assert payload["event"] == "dlp.activation"
    assert payload["manifest_id"] == "m1"
    assert payload["asset_id"] == "a1"


def test_webhook_payload_contains_correctly_encoded_secret(local_webhook_server):
    import base64

    url, handler = local_webhook_server
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset(url)

    adapter.on_activation(manifest, "a1", b"binary-ish \x00\x01 content")

    payload = json.loads(handler.received[0]["body"])
    decoded = base64.b64decode(payload["secret_base64"])
    assert decoded == b"binary-ish \x00\x01 content"


def test_webhook_signs_when_secret_configured(local_webhook_server):
    url, handler = local_webhook_server
    adapter = WebhookAdapter(signing_secret="shh-its-a-secret", allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset(url)

    adapter.on_activation(manifest, "a1", b"content")

    sig_header = handler.received[0]["headers"].get("X-Dlp-Signature")
    assert sig_header is not None
    body = handler.received[0]["body"]
    assert verify_webhook_signature(body, sig_header, "shh-its-a-secret") is True
    assert verify_webhook_signature(body, sig_header, "wrong-secret") is False


def test_webhook_omits_signature_when_no_secret_configured(local_webhook_server):
    url, handler = local_webhook_server
    adapter = WebhookAdapter(allow_insecure_http=True)  # no signing_secret
    manifest = _manifest_with_webhook_asset(url)

    adapter.on_activation(manifest, "a1", b"content")

    assert "X-Dlp-Signature" not in handler.received[0]["headers"]


def test_webhook_reports_non_200_response(local_webhook_server):
    url, handler = local_webhook_server
    handler.respond_status = 500
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset(url)

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "500" in result.detail


def test_webhook_unreachable_server_reported_gracefully():
    adapter = WebhookAdapter(allow_insecure_http=True, timeout_seconds=1)
    # nothing listening on this port
    manifest = _manifest_with_webhook_asset("http://127.0.0.1:1/nowhere")

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "unreachable" in result.detail


def test_http_url_rejected_by_default():
    adapter = WebhookAdapter()  # allow_insecure_http defaults False
    manifest = _manifest_with_webhook_asset("http://example.com/hook")

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "refusing to send secret material" in result.detail


def test_https_url_allowed_without_flag():
    # we can't actually reach a real https endpoint in tests, but we can
    # confirm it gets PAST the scheme check and fails only on connectivity
    adapter = WebhookAdapter(timeout_seconds=1)
    manifest = _manifest_with_webhook_asset("https://127.0.0.1:1/nowhere")

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "refusing to send" not in result.detail  # got past the http-only guard


def test_invalid_url_scheme_rejected():
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset("ftp://example.com/hook")

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "not a valid http(s) URL" in result.detail


def test_unsupported_action_rejected(local_webhook_server):
    url, _ = local_webhook_server
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset(url, action="release_key")

    result = adapter.on_activation(manifest, "a1", b"content")

    assert result.success is False
    assert "only supports action 'execute_webhook'" in result.detail


def test_missing_asset_reported():
    adapter = WebhookAdapter(allow_insecure_http=True)
    manifest = _manifest_with_webhook_asset("http://example.com/hook")

    result = adapter.on_activation(manifest, "nonexistent-asset", b"content")

    assert result.success is False
    assert "not found" in result.detail


def test_on_revocation_is_safe_noop():
    adapter = WebhookAdapter()
    assert adapter.on_revocation("some-manifest-id") is None


def test_verify_manifest_delegates_to_default_verify():
    from dlp import crypto
    from dlp.manifest import ManifestBuilder

    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    builder.add_asset("custom", "hook", "b1", "execute_webhook", ["t1", "t2"])
    manifest = builder.build_and_sign(owner_priv)

    adapter = WebhookAdapter()
    assert adapter.verify_manifest(manifest) is True
    manifest["assets"][0]["reference"] = "tampered"
    assert adapter.verify_manifest(manifest) is False


def test_sign_payload_is_deterministic():
    body = b'{"a": 1}'
    sig1 = sign_payload(body, "secret")
    sig2 = sign_payload(body, "secret")
    assert sig1 == sig2
    assert sig1.startswith("sha256=")


def test_sign_payload_differs_by_secret():
    body = b'{"a": 1}'
    assert sign_payload(body, "secret1") != sign_payload(body, "secret2")


def test_sign_payload_differs_by_body():
    assert sign_payload(b"body1", "secret") != sign_payload(b"body2", "secret")
