"""
A generic DLPAdapter for the 'execute_webhook' action — the one spec
action that dlp.adapters.github deliberately doesn't attempt (GitHub's
API has no natural mapping for "call an arbitrary URL"). This adapter is
the opposite: it does nothing else.

Any automation platform that can receive an HTTP POST — Zapier, a
self-hosted script, IFTTT via webhook triggers, a Discord/Slack incoming
webhook, your own server — can be the target. The adapter's only job is
to deliver the reconstructed secret and manifest metadata reliably,
authenticably, and over an encrypted transport.

Authentication: if a signing_secret is configured, every request carries
an HMAC-SHA256 signature (in the `X-DLP-Signature` header, same
convention as GitHub/Stripe webhook signing) computed over the exact
request body, so the receiver can verify the request really came from an
adapter holding that secret and wasn't forged or tampered with in
transit. verify_webhook_signature() is provided for receivers to check
this without re-deriving the HMAC construction themselves.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import urllib.error
import urllib.request
from base64 import b64encode
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ..adapter import ActionResult, DLPAdapter, default_verify

_USER_AGENT = "digital-legacy-protocol-webhook/0.6"


class WebhookAdapterError(RuntimeError):
    pass


def sign_payload(body: bytes, secret: str) -> str:
    """Returns the value to send in the X-DLP-Signature header."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_webhook_signature(body: bytes, signature_header: str, secret: str) -> bool:
    """For the RECEIVING end of a webhook: given the raw request body
    exactly as received and the X-DLP-Signature header value, returns
    whether it's authentic. Uses constant-time comparison to avoid
    leaking the correct signature one byte at a time via timing."""
    expected = sign_payload(body, secret)
    return hmac.compare_digest(expected, signature_header)


@dataclass
class WebhookAdapter(DLPAdapter):
    signing_secret: Optional[str] = None
    timeout_seconds: int = 15
    allow_insecure_http: bool = False
    """If False (default), URLs must use https:// — an activation payload
    contains reconstructed secret material, and sending that over
    unencrypted HTTP would defeat most of the point of everything else
    this protocol does to protect it. Set True only for local development
    against http://localhost."""

    def verify_manifest(self, manifest: Dict[str, Any]) -> bool:
        return default_verify(manifest)

    def on_activation(
        self, manifest: Dict[str, Any], asset_id: str, reconstructed_secret: bytes
    ) -> ActionResult:
        asset = next((a for a in manifest["assets"] if a["asset_id"] == asset_id), None)
        if asset is None:
            return ActionResult(success=False, detail=f"asset {asset_id} not found in manifest")

        if asset["action"] != "execute_webhook":
            return ActionResult(
                success=False,
                detail=(
                    f"WebhookAdapter only supports action 'execute_webhook', got '{asset['action']}' "
                    f"— use a different adapter for this asset"
                ),
            )

        url = asset["reference"]
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http"):
            return ActionResult(
                success=False, detail=f"asset.reference is not a valid http(s) URL: {url!r}"
            )
        if parsed.scheme == "http" and not self.allow_insecure_http:
            return ActionResult(
                success=False,
                detail=(
                    f"refusing to send secret material to a plain http:// URL ({url}) — "
                    f"set allow_insecure_http=True only for local development"
                ),
            )

        payload = {
            "event": "dlp.activation",
            "dlp_version": manifest["dlp_version"],
            "manifest_id": manifest["manifest_id"],
            "asset_id": asset_id,
            "asset_reference": asset["reference"],
            "secret_base64": b64encode(reconstructed_secret).decode("ascii"),
        }
        body = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", _USER_AGENT)
        if self.signing_secret:
            req.add_header("X-DLP-Signature", sign_payload(body, self.signing_secret))

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            return ActionResult(success=False, detail=f"webhook returned HTTP {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            return ActionResult(success=False, detail=f"webhook unreachable: {e.reason}")

        return ActionResult(success=True, detail=f"webhook delivered, responded with HTTP {status}")

    def on_revocation(self, manifest_id: str) -> None:
        # Stateless, same as GitHubAdapter — nothing to undo on this end.
        # A receiver-side system tracking manifest_ids could choose to act
        # on a revocation notice, but that's out of scope for the sender.
        return None
