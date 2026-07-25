"""
Minimal web UI for Digital Legacy Protocol (spec gap: the reference
implementation was CLI/library-only, which means anyone not comfortable
with a terminal couldn't use it at all).

This is deliberately small: server-rendered Jinja2 templates, no
JavaScript build step, no client-side framework. Key generation and
manifest signing happen server-side in this process — that's the right
call for a local single-user tool, and the wrong call for a multi-tenant
hosted service. If you're deploying this for real, multiple people, over
a network: private keys must never touch a server you don't fully trust,
which likely means moving key generation and signing to the browser via
WebCrypto, or to a separate device entirely. This reference UI does not
attempt that — see the warning banner on the create-manifest page.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Optional

from flask import Flask, render_template, request

from .. import crypto, hint_crypto
from ..manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)
from ..storage import LocalFileStore, ManifestNotFoundError


def create_app(store_dir: str = ".dlp_store") -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STORE_DIR"] = store_dir

    def _store() -> LocalFileStore:
        return LocalFileStore(app.config["STORE_DIR"])

    @app.route("/")
    def index():
        store = _store()
        manifests = []
        for manifest_id in store.list_ids():
            m = store.load(manifest_id)
            manifests.append(
                {
                    "id": m["manifest_id"],
                    "owner": m["owner"].get("display_name") or "(unnamed)",
                    "trustees": len(m["quorum"]["trustees"]),
                    "threshold": m["quorum"]["threshold"],
                    "assets": len(m["assets"]),
                }
            )
        return render_template("index.html", manifests=manifests, store_dir=app.config["STORE_DIR"])

    @app.route("/create", methods=["GET"])
    def create_form():
        return render_template("create.html", error=None)

    @app.route("/create", methods=["POST"])
    def create_submit():
        try:
            owner_name = request.form.get("owner_name", "").strip()
            threshold = int(request.form["threshold"])
            trustee_names = [n.strip() for n in request.form.getlist("trustee_name") if n.strip()]
            beneficiary_name = request.form.get("beneficiary_name", "").strip()
            asset_reference = request.form.get("asset_reference", "").strip()
            asset_type = request.form.get("asset_type", "crypto_wallet")
            asset_action = request.form.get("asset_action", "release_key")

            if not owner_name or not trustee_names or not beneficiary_name or not asset_reference:
                raise ValueError("all fields are required")
            if threshold < 2 or threshold > len(trustee_names):
                raise ValueError(
                    f"quorum threshold must be between 2 and the number of trustees "
                    f"({len(trustee_names)})"
                )

            owner_priv, owner_pub = crypto.generate_keypair()
            trustees = []
            for name in trustee_names:
                sign_priv, sign_pub = crypto.generate_keypair()
                enc_priv, enc_pub = hint_crypto.generate_encryption_keypair()
                trustees.append(
                    {
                        "trustee_id": str(uuid.uuid4()),
                        "name": name,
                        "signing_private_key": sign_priv,
                        "signing_public_key": sign_pub,
                        "encryption_private_key": enc_priv,
                        "encryption_public_key": enc_pub,
                    }
                )

            builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name=owner_name)
            for t in trustees:
                builder.add_trustee(
                    t["trustee_id"],
                    t["signing_public_key"],
                    contact_hint=t["name"],
                    encryption_public_key=t["encryption_public_key"],
                )
            builder.set_quorum_threshold(threshold)

            trustee_ids = [t["trustee_id"] for t in trustees]
            beneficiary_id = str(uuid.uuid4())
            builder.add_beneficiary(beneficiary_id, contact_hint=beneficiary_name)

            builder.add_asset(
                asset_type=asset_type,
                reference=asset_reference,
                beneficiary_id=beneficiary_id,
                action=asset_action,
                shares_distributed_to=trustee_ids,
            )
            manifest = builder.build_and_sign(owner_priv)
            _store().save(manifest)

            return render_template(
                "created.html",
                manifest=manifest,
                owner_private_key=owner_priv,
                trustees=trustees,
            )
        except (ValueError, ManifestValidationError, KeyError) as e:
            return render_template("create.html", error=str(e))

    @app.route("/manifest/<manifest_id>")
    def view_manifest(manifest_id: str):
        import json

        try:
            manifest = _store().load(manifest_id)
        except (ManifestNotFoundError, ValueError):
            return render_template("not_found.html", manifest_id=manifest_id), 404
        return render_template(
            "manifest.html",
            manifest=manifest,
            manifest_json=json.dumps(manifest, indent=2, sort_keys=True),
            signature_valid=is_signature_valid(manifest),
        )

    @app.route("/verify", methods=["GET", "POST"])
    def verify():
        result: Optional[dict] = None
        if request.method == "POST":
            import json

            try:
                manifest = json.loads(request.form["manifest_json"])
                validate_manifest(manifest)
                result = {
                    "structurally_valid": True,
                    "signature_valid": is_signature_valid(manifest),
                    "manifest_id": manifest.get("manifest_id"),
                    "error": None,
                }
            except ManifestValidationError as e:
                result = {"structurally_valid": False, "signature_valid": False, "error": str(e)}
            except Exception as e:
                result = {
                    "structurally_valid": False,
                    "signature_valid": False,
                    "error": f"could not parse as a manifest: {e}",
                }
        return render_template("verify.html", result=result)

    return app
