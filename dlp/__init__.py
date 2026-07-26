"""
Digital Legacy Protocol (DLP) — reference implementation.

An open protocol for declaring, verifying, and honoring instructions about
what happens to a person's digital assets after death or incapacity —
without any single company acting as the sole judge of whether that has
happened. See spec/SPEC.md for the full protocol description.

Quick start:

    from dlp import ManifestBuilder, crypto, shamir

    owner_priv, owner_pub = crypto.generate_keypair()
    t1_priv, t1_pub = crypto.generate_keypair()
    t2_priv, t2_pub = crypto.generate_keypair()
    t3_priv, t3_pub = crypto.generate_keypair()

    builder = ManifestBuilder(owner_public_key=owner_pub, owner_display_name="Ada")
    builder.add_trustee("t1", t1_pub).add_trustee("t2", t2_pub).add_trustee("t3", t3_pub)
    builder.set_quorum_threshold(2)
    builder.add_beneficiary("ben1", contact_hint="daughter")
    builder.add_asset(
        asset_type="crypto_wallet", reference="cold wallet #1",
        beneficiary_id="ben1", action="release_key",
        shares_distributed_to=["t1", "t2", "t3"],
    )
    signed = builder.build_and_sign(owner_priv)
"""

from . import adapter, crypto, hint_crypto, notify, recovery, shamir, storage, switch
from .manifest import (
    ManifestBuilder,
    ManifestValidationError,
    is_signature_valid,
    validate_manifest,
)

__all__ = [
    "ManifestBuilder",
    "ManifestValidationError",
    "adapter",
    "crypto",
    "hint_crypto",
    "is_signature_valid",
    "notify",
    "recovery",
    "shamir",
    "storage",
    "switch",
    "validate_manifest",
]

__version__ = "0.4.0"
