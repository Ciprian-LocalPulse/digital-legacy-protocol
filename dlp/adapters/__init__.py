"""
Real DLPAdapter implementations for third-party services, as opposed to
dlp.adapter.InMemoryDemoAdapter (which exists only to prove the interface
works, not to talk to anything real).

Each adapter here is a genuine, network-calling implementation against a
real service's real API. They're kept in their own subpackage — separate
from the core dlp package — because they pull in service-specific
assumptions (API shapes, auth schemes, rate limits) that have no business
being part of the protocol's core dependency surface.
"""

from .github import GitHubAdapter
from .webhook import WebhookAdapter, sign_payload, verify_webhook_signature

__all__ = ["GitHubAdapter", "WebhookAdapter", "sign_payload", "verify_webhook_signature"]
