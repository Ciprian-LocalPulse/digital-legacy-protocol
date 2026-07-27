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

from flask import Flask, redirect, render_template, request, url_for

from .. import crypto, hint_crypto
from ..manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)
from ..notify import ConsoleChannel, NotificationService
from ..orchestrator import SwitchMonitor
from ..storage import (
    LocalFileStore,
    LocalSwitchStore,
    ManifestNotFoundError,
    SwitchNotFoundError,
)
from ..switch import DeadMansSwitch


def create_app(store_dir: str = ".dlp_store") -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STORE_DIR"] = store_dir

    def _store() -> LocalFileStore:
        return LocalFileStore(app.config["STORE_DIR"])

    def _switch_store() -> LocalSwitchStore:
        return LocalSwitchStore(str(Path(app.config["STORE_DIR"]) / "switches"))

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
            owner_email = request.form.get("owner_email", "").strip() or None
            threshold = int(request.form["threshold"])
            trustee_names = [n.strip() for n in request.form.getlist("trustee_name") if n.strip()]
            trustee_emails_raw = request.form.getlist("trustee_email")
            beneficiary_name = request.form.get("beneficiary_name", "").strip()
            beneficiary_email = request.form.get("beneficiary_email", "").strip() or None
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
            # trustee_email is submitted in lockstep with trustee_name (see
            # create.html's submit handler) — pad defensively in case a
            # client posts mismatched lists by hand rather than through the form
            trustee_emails = (trustee_emails_raw + [""] * len(trustee_names))[: len(trustee_names)]

            owner_priv, owner_pub = crypto.generate_keypair()
            trustees = []
            for name, email in zip(trustee_names, trustee_emails):
                sign_priv, sign_pub = crypto.generate_keypair()
                enc_priv, enc_pub = hint_crypto.generate_encryption_keypair()
                trustees.append(
                    {
                        "trustee_id": str(uuid.uuid4()),
                        "name": name,
                        "email": email.strip() or None,
                        "signing_private_key": sign_priv,
                        "signing_public_key": sign_pub,
                        "encryption_private_key": enc_priv,
                        "encryption_public_key": enc_pub,
                    }
                )

            builder = ManifestBuilder(
                owner_public_key=owner_pub,
                owner_display_name=owner_name,
                owner_notification_address=owner_email,
            )
            for t in trustees:
                builder.add_trustee(
                    t["trustee_id"],
                    t["signing_public_key"],
                    contact_hint=t["name"],
                    encryption_public_key=t["encryption_public_key"],
                    notification_address=t["email"],
                )
            builder.set_quorum_threshold(threshold)

            trustee_ids = [t["trustee_id"] for t in trustees]
            beneficiary_id = str(uuid.uuid4())
            builder.add_beneficiary(
                beneficiary_id,
                contact_hint=beneficiary_name,
                notification_address=beneficiary_email,
            )

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

        sw = None
        try:
            sw = _switch_store().load(manifest_id)
        except SwitchNotFoundError:
            pass

        return render_template(
            "manifest.html",
            manifest=manifest,
            manifest_json=json.dumps(manifest, indent=2, sort_keys=True),
            signature_valid=is_signature_valid(manifest),
            switch=sw,
            switch_state=sw.state().value if sw else None,
            tick_results=None,
        )

    @app.route("/manifest/<manifest_id>/switch/init", methods=["POST"])
    def switch_init(manifest_id: str):
        try:
            manifest = _store().load(manifest_id)
        except ManifestNotFoundError:
            return render_template("not_found.html", manifest_id=manifest_id), 404
        sw = DeadMansSwitch.from_manifest(manifest)
        _switch_store().save(sw)
        return redirect(url_for("view_manifest", manifest_id=manifest_id))

    @app.route("/manifest/<manifest_id>/switch/checkin", methods=["POST"])
    def switch_checkin(manifest_id: str):
        store = _switch_store()
        try:
            sw = store.load(manifest_id)
        except SwitchNotFoundError:
            return render_template("not_found.html", manifest_id=manifest_id), 404
        sw.record_checkin()
        store.save(sw)
        return redirect(url_for("view_manifest", manifest_id=manifest_id))

    @app.route("/manifest/<manifest_id>/switch/attest", methods=["POST"])
    def switch_attest(manifest_id: str):
        store = _switch_store()
        try:
            sw = store.load(manifest_id)
        except SwitchNotFoundError:
            return render_template("not_found.html", manifest_id=manifest_id), 404
        trustee_id = request.form.get("trustee_id", "")
        confirms_unreachable = request.form.get("verdict") == "unreachable"
        try:
            sw.record_attestation(trustee_id, confirms_unreachable=confirms_unreachable)
        except RuntimeError:
            pass  # too early to attest — silently ignored, the button shouldn't be visible then anyway
        else:
            store.save(sw)
        return redirect(url_for("view_manifest", manifest_id=manifest_id))

    @app.route("/manifest/<manifest_id>/switch/tick", methods=["POST"])
    def switch_tick(manifest_id: str):
        import json

        try:
            manifest = _store().load(manifest_id)
        except (ManifestNotFoundError, ValueError):
            return render_template("not_found.html", manifest_id=manifest_id), 404

        switch_store = _switch_store()
        try:
            sw = switch_store.load(manifest_id)
        except SwitchNotFoundError:
            return render_template("not_found.html", manifest_id=manifest_id), 404

        # Console-only in this reference UI: notifications print to the
        # server's own console rather than sending real email. This UI is
        # documented as local/single-user (see spec section 14) — wiring
        # real SMTP credentials into a web form would mean typing an email
        # password into a browser field, which is a worse idea than it
        # sounds. Use `dlp switch-tick --smtp-host ...` for real delivery.
        monitor = SwitchMonitor(_store(), switch_store, NotificationService(ConsoleChannel()))
        tick_results = monitor.tick(manifest_id)

        sw = switch_store.load(manifest_id)
        return render_template(
            "manifest.html",
            manifest=manifest,
            manifest_json=json.dumps(manifest, indent=2, sort_keys=True),
            signature_valid=is_signature_valid(manifest),
            switch=sw,
            switch_state=sw.state().value,
            tick_results=tick_results,
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
