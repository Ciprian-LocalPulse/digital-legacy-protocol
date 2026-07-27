"""
A worked example for WebhookAdapter — unlike the GitHub adapter demo,
this one needs no external account or token: it stands up a tiny local
HTTP server to receive the webhook, so you can see the whole flow work
end to end with nothing but `python examples/webhook_adapter_demo.py`.

In real use, you'd point the adapter at Zapier, a Discord/Slack incoming
webhook, or your own server instead of localhost.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from dlp import ManifestBuilder, crypto, shamir
from dlp.adapters.webhook import WebhookAdapter, verify_webhook_signature

SIGNING_SECRET = "demo-shared-secret-change-me"


class ReceivingHandler(BaseHTTPRequestHandler):
    """Stands in for whatever real service would receive this webhook —
    verifies the signature, then prints what it got."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        signature = self.headers.get("X-DLP-Signature", "")

        print("--- webhook receiver got a POST ---")
        if verify_webhook_signature(body, signature, SIGNING_SECRET):
            print("signature: VALID (this really came from a holder of the shared secret)")
        else:
            print("signature: INVALID — would reject this in a real receiver")

        payload = json.loads(body)
        print(f"event: {payload['event']}")
        print(f"manifest_id: {payload['manifest_id']}")
        print(f"asset_id: {payload['asset_id']}")

        import base64

        secret = base64.b64decode(payload["secret_base64"])
        print(f"decoded secret content: {secret!r}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"received")

    def log_message(self, *args):
        pass  # keep stdout clean for the demo output above


def main() -> None:
    print("--- Starting a local webhook receiver on 127.0.0.1 ---\n")
    server = HTTPServer(("127.0.0.1", 0), ReceivingHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    webhook_url = f"http://127.0.0.1:{port}/dlp-webhook"

    print("--- Building a manifest with an execute_webhook asset ---\n")
    owner_priv, owner_pub = crypto.generate_keypair()
    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Demo Owner")
    builder.add_trustee("t1", "ed25519:placeholder1")
    builder.add_trustee("t2", "ed25519:placeholder2")
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("b1", contact_hint="automation system")
    builder.add_asset(
        asset_type="custom",
        reference=webhook_url,
        beneficiary_id="b1",
        action="execute_webhook",
        shares_distributed_to=["t1", "t2"],
    )
    manifest = builder.build_and_sign(owner_priv)
    asset_id = manifest["assets"][0]["asset_id"]
    print(f"Manifest built, targeting webhook: {webhook_url}\n")

    print("--- Splitting and reconstructing a secret, as if quorum had activated ---\n")
    secret = b"trigger: unlock the shared family photo archive"
    shares = shamir.split_secret(secret, threshold=2, trustee_ids=["t1", "t2"])
    reconstructed = shamir.reconstruct_secret(shares[:2])
    assert reconstructed == secret

    print("--- Delivering via WebhookAdapter (real HTTP POST, signed) ---\n")
    adapter = WebhookAdapter(signing_secret=SIGNING_SECRET, allow_insecure_http=True)
    result = adapter.on_activation(manifest, asset_id, reconstructed)

    print()
    print(f"Adapter result: success={result.success}, detail={result.detail!r}")

    server.shutdown()
    thread.join(timeout=2)


if __name__ == "__main__":
    main()
