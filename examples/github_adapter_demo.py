"""
A worked example using the real GitHubAdapter — this actually calls
api.github.com if you provide a token, unlike examples/basic_scenario.py
which is entirely offline.

Requires a GitHub Personal Access Token with `gist` scope (classic token,
or fine-grained with Gists: read/write) set as the GITHUB_TOKEN
environment variable. Without one, this script explains what it would
have done and exits cleanly rather than failing.

    export GITHUB_TOKEN=ghp_your_token_here
    python examples/github_adapter_demo.py
"""

import os
import sys

from dlp import ManifestBuilder, crypto, shamir
from dlp.adapters.github import GitHubAdapter


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN environment variable not set.")
        print("This example would otherwise:")
        print("  1. Build and sign a manifest with a 'deliver_message' asset")
        print("  2. Split a final message with Shamir's Secret Sharing")
        print("  3. Simulate quorum reconstruction of that message")
        print("  4. Actually call the real GitHub API to create a private")
        print("     Gist containing the reconstructed message")
        print("\nSet GITHUB_TOKEN and re-run to see it happen for real.")
        sys.exit(0)

    print("--- Building a manifest with a deliver_message asset ---\n")
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Demo Owner")
    builder.add_trustee("t1", "ed25519:placeholder1")
    builder.add_trustee("t2", "ed25519:placeholder2")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1", contact_hint="demo beneficiary")
    builder.add_asset(
        asset_type="message",
        reference="a final message, delivered via GitHub Gist",
        beneficiary_id="b1",
        action="deliver_message",
        shares_distributed_to=["t1", "t2"],
    )
    manifest = builder.build_and_sign(owner_priv)
    asset_id = manifest["assets"][0]["asset_id"]
    print(f"Manifest built: {manifest['manifest_id']}\n")

    print("--- Splitting the message and simulating quorum reconstruction ---\n")
    message = b"This is a demo message from the Digital Legacy Protocol GitHub adapter example."
    shares = shamir.split_secret(message, threshold=2, trustee_ids=["t1", "t2"])
    reconstructed = shamir.reconstruct_secret(shares[:2])
    assert reconstructed == message
    print("Message reconstructed from 2-of-2 shares.\n")

    print("--- Calling the real GitHub API to create a private Gist ---\n")
    adapter = GitHubAdapter(personal_access_token=token)
    if not adapter.check_token_valid():
        print("GITHUB_TOKEN is set but doesn't seem to be valid — check the token and its scopes.")
        sys.exit(1)

    result = adapter.on_activation(manifest, asset_id, reconstructed)
    if result.success:
        print(f"Success: {result.detail}")
    else:
        print(f"GitHub API call failed: {result.detail}")
        sys.exit(1)


if __name__ == "__main__":
    main()
