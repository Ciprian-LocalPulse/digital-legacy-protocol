import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from dlp.adapters.github import GitHubAdapter, GitHubAdapterError


def _mock_response(payload: dict, status: int = 200):
    """Builds a fake urlopen() context manager returning the given JSON."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def _sample_manifest_with_asset(action: str, reference: str):
    return {
        "assets": [
            {
                "asset_id": "asset-1",
                "type": "message",
                "reference": reference,
                "action": action,
            }
        ]
    }


@patch("urllib.request.urlopen")
def test_deliver_message_creates_private_gist(mock_urlopen):
    mock_urlopen.return_value = _mock_response(
        {"html_url": "https://gist.github.com/example/abc123"}
    )
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset("deliver_message", "final letter to Marcus")

    result = adapter.on_activation(manifest, "asset-1", b"I love you, take care of the dog.")

    assert result.success is True
    assert "gist.github.com" in result.detail

    sent_request = mock_urlopen.call_args[0][0]
    assert sent_request.full_url == "https://api.github.com/gists"
    body = json.loads(sent_request.data)
    assert body["public"] is False
    assert "I love you, take care of the dog." in body["files"]["asset-1.txt"]["content"]


@patch("urllib.request.urlopen")
def test_deliver_message_sets_auth_headers(mock_urlopen):
    mock_urlopen.return_value = _mock_response({"html_url": "https://gist.github.com/x"})
    adapter = GitHubAdapter(personal_access_token="secret-token-123")
    manifest = _sample_manifest_with_asset("deliver_message", "ref")

    adapter.on_activation(manifest, "asset-1", b"content")

    sent_request = mock_urlopen.call_args[0][0]
    assert sent_request.get_header("Authorization") == "Bearer secret-token-123"
    assert sent_request.get_header("X-github-api-version") == "2022-11-28"


def test_deliver_message_rejects_non_utf8_content():
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset("deliver_message", "ref")
    invalid_utf8 = b"\xff\xfe\x00\x01"

    result = adapter.on_activation(manifest, "asset-1", invalid_utf8)

    assert result.success is False
    assert "UTF-8" in result.detail


@patch("urllib.request.urlopen")
def test_grant_access_adds_collaborator(mock_urlopen):
    mock_urlopen.return_value = _mock_response({})
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset(
        "grant_access", "Ciprian-LocalPulse/digital-legacy-protocol:marcus99"
    )

    result = adapter.on_activation(manifest, "asset-1", b"unused for this action")

    assert result.success is True
    assert "marcus99" in result.detail
    sent_request = mock_urlopen.call_args[0][0]
    assert sent_request.full_url == (
        "https://api.github.com/repos/Ciprian-LocalPulse/digital-legacy-protocol/collaborators/marcus99"
    )
    assert sent_request.get_method() == "PUT"


def test_grant_access_rejects_malformed_reference():
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset("grant_access", "not-a-valid-reference")

    result = adapter.on_activation(manifest, "asset-1", b"")

    assert result.success is False
    assert "expects asset.reference formatted as" in result.detail


def test_unsupported_action_reported_clearly():
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset("release_key", "some wallet")

    result = adapter.on_activation(manifest, "asset-1", b"secret key material")

    assert result.success is False
    assert "does not support action" in result.detail


def test_missing_asset_id_reported_clearly():
    adapter = GitHubAdapter(personal_access_token="fake-token")
    manifest = _sample_manifest_with_asset("deliver_message", "ref")

    result = adapter.on_activation(manifest, "does-not-exist", b"content")

    assert result.success is False
    assert "not found" in result.detail


@patch("urllib.request.urlopen")
def test_http_error_wrapped_with_github_message(mock_urlopen):
    error_body = json.dumps({"message": "Bad credentials"}).encode()
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://api.github.com/gists",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=BytesIO(error_body),
    )
    adapter = GitHubAdapter(personal_access_token="invalid-token")
    manifest = _sample_manifest_with_asset("deliver_message", "ref")

    result = adapter.on_activation(manifest, "asset-1", b"content")

    assert result.success is False
    assert "Bad credentials" in result.detail
    assert "401" in result.detail


@patch("urllib.request.urlopen")
def test_network_error_raises_adapter_error(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.URLError("connection refused")
    adapter = GitHubAdapter(personal_access_token="fake-token")

    with pytest.raises(GitHubAdapterError):
        adapter._request("GET", "/user")


@patch("urllib.request.urlopen")
def test_check_token_valid_true_on_success(mock_urlopen):
    mock_urlopen.return_value = _mock_response({"login": "someuser"})
    adapter = GitHubAdapter(personal_access_token="fake-token")
    assert adapter.check_token_valid() is True


@patch("urllib.request.urlopen")
def test_check_token_valid_false_on_failure(mock_urlopen):
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="x", code=401, msg="Unauthorized", hdrs=None, fp=BytesIO(b"{}")
    )
    adapter = GitHubAdapter(personal_access_token="bad-token")
    assert adapter.check_token_valid() is False


def test_verify_manifest_delegates_to_default_verify():
    from dlp import crypto
    from dlp.manifest import ManifestBuilder

    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub)
    builder.add_trustee("t1", "ed25519:x")
    builder.add_trustee("t2", "ed25519:y")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1")
    builder.add_asset("file", "doc", "b1", "grant_access", ["t1", "t2"])
    manifest = builder.build_and_sign(owner_priv)

    adapter = GitHubAdapter(personal_access_token="fake-token")
    assert adapter.verify_manifest(manifest) is True

    manifest["assets"][0]["reference"] = "tampered"
    assert adapter.verify_manifest(manifest) is False


def test_on_revocation_is_a_safe_noop():
    adapter = GitHubAdapter(personal_access_token="fake-token")
    assert adapter.on_revocation("some-manifest-id") is None


@pytest.mark.live_network
def test_real_github_api_connectivity_best_effort():
    """Opportunistic real test against api.github.com — not mocked. Skips
    gracefully on rate limiting or lack of network rather than failing
    the suite, since public CI runners commonly share IPs that hit
    GitHub's unauthenticated rate limit."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        "https://api.github.com/zen", headers={"User-Agent": "digital-legacy-protocol-test"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            assert len(body) > 0
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        pytest.skip(f"real GitHub API unreachable in this environment: {e}")
