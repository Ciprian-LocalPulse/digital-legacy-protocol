"""
A real DLPAdapter for GitHub. No mocking, no simulation — this makes
actual authenticated HTTPS calls to api.github.com using nothing but the
Python standard library (urllib), so it has zero new dependencies beyond
what dlp already needs.

Two of the four spec actions map naturally onto things GitHub's API can
actually do:

  - "deliver_message": create a private Gist containing the reconstructed
    secret/message, then return its URL. Useful for a manifest whose
    "asset" is really a final message, a set of instructions, or a
    small file the owner wants delivered on activation.
  - "grant_access": add a beneficiary as a collaborator on a private
    repository. Useful for an owner who wants a specific repo to become
    accessible to someone else after they're gone — code, a personal
    wiki, anything living in a GitHub repo.

"release_key" and "execute_webhook" aren't things GitHub's API is a
natural fit for, so this adapter reports failure clearly for those
rather than pretending to support them.

Requires a GitHub Personal Access Token (classic, or fine-grained with
`gist` and `repo` scopes as needed) supplied by the caller — this
adapter never generates or stores one itself.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..adapter import ActionResult, DLPAdapter, default_verify

_API_BASE = "https://api.github.com"
_USER_AGENT = (
    "digital-legacy-protocol/0.4 (+https://github.com/Ciprian-LocalPulse/digital-legacy-protocol)"
)


class GitHubAdapterError(RuntimeError):
    """Raised when a GitHub API call fails — bad token, rate limit, repo
    not found, etc. Wraps the underlying urllib error with GitHub's own
    error message when one is available, since that's usually far more
    useful than the raw HTTP status code alone."""


@dataclass
class GitHubAdapter(DLPAdapter):
    personal_access_token: str
    api_base: str = _API_BASE
    timeout_seconds: int = 15

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> Dict[str, Any]:
        url = f"{self.api_base}{path}"
        if not url.startswith(("https://", "http://")):
            # api_base is developer-configured, not derived from manifest
            # data, so this is defense in depth rather than a response to
            # a realistic attack path — but it's a one-line guard against
            # urllib.request.urlopen's willingness to open file:// and
            # other unexpected schemes (bandit B310), so there's no reason
            # not to have it.
            raise GitHubAdapterError(f"refusing to request non-http(s) URL: {url!r}")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.personal_access_token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", _USER_AGENT)
        if data is not None:
            req.add_header("Content-Type", "application/json")

        try:
            # scheme validated above (raises before reaching here otherwise)
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:  # nosec B310
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("message", str(e))
            except (ValueError, AttributeError):
                detail = str(e)
            raise GitHubAdapterError(
                f"GitHub API {method} {path} failed ({e.code}): {detail}"
            ) from e
        except urllib.error.URLError as e:
            raise GitHubAdapterError(f"GitHub API {method} {path} unreachable: {e.reason}") from e

    # -- DLPAdapter interface -------------------------------------------------

    def verify_manifest(self, manifest: Dict[str, Any]) -> bool:
        return default_verify(manifest)

    def on_activation(
        self, manifest: Dict[str, Any], asset_id: str, reconstructed_secret: bytes
    ) -> ActionResult:
        asset = next((a for a in manifest["assets"] if a["asset_id"] == asset_id), None)
        if asset is None:
            return ActionResult(success=False, detail=f"asset {asset_id} not found in manifest")

        action = asset["action"]
        if action == "deliver_message":
            return self._deliver_as_gist(asset, reconstructed_secret)
        if action == "grant_access":
            return self._grant_repo_access(asset)
        return ActionResult(
            success=False,
            detail=f"GitHubAdapter does not support action '{action}' — "
            f"only deliver_message (via Gist) and grant_access (via repo collaborator) are implemented",
        )

    def on_revocation(self, manifest_id: str) -> None:
        # This adapter is stateless — it doesn't track which manifests it
        # has acted on, so there's nothing to undo here. A production
        # adapter with its own database would use this hook to, e.g.,
        # cancel a pending collaborator invitation.
        return None

    # -- action implementations ------------------------------------------------

    def _deliver_as_gist(self, asset: Dict[str, Any], content: bytes) -> ActionResult:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return ActionResult(
                success=False,
                detail="deliver_message content is not valid UTF-8 text — Gists can't hold arbitrary binary data",
            )
        filename = f"{asset['asset_id']}.txt"
        try:
            result = self._request(
                "POST",
                "/gists",
                {
                    "description": f"Digital Legacy Protocol — {asset['reference']}",
                    "public": False,
                    "files": {filename: {"content": text}},
                },
            )
        except GitHubAdapterError as e:
            return ActionResult(success=False, detail=str(e))
        return ActionResult(success=True, detail=f"created private gist: {result.get('html_url')}")

    def _grant_repo_access(self, asset: Dict[str, Any]) -> ActionResult:
        # convention: asset["reference"] is "owner/repo:beneficiary-github-username"
        reference = asset["reference"]
        if ":" not in reference or "/" not in reference.split(":")[0]:
            return ActionResult(
                success=False,
                detail=(
                    "grant_access via GitHubAdapter expects asset.reference formatted as "
                    "'owner/repo:beneficiary-github-username', got: " + reference
                ),
            )
        repo_part, username = reference.rsplit(":", 1)
        owner, repo = repo_part.split("/", 1)
        try:
            self._request(
                "PUT",
                f"/repos/{owner}/{repo}/collaborators/{username}",
                {"permission": "pull"},
            )
        except GitHubAdapterError as e:
            return ActionResult(success=False, detail=str(e))
        return ActionResult(
            success=True, detail=f"invited {username} as a collaborator on {owner}/{repo}"
        )

    # -- convenience, not part of the DLPAdapter interface ---------------------

    def check_token_valid(self) -> bool:
        """A quick way to verify the configured token works at all,
        before relying on it during an actual activation event."""
        try:
            self._request("GET", "/user")
            return True
        except GitHubAdapterError:
            return False
