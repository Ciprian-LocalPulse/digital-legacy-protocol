"""
Property-based tests for dlp.shamir, using Hypothesis to generate
hundreds of secrets, thresholds, and trustee counts per run rather than
relying only on the fixed examples in test_shamir.py.

This exists specifically because dlp.shamir is hand-rolled GF(256)
arithmetic and Lagrange interpolation, not a call into a vetted external
library — the kind of code where an off-by-one or a sign error can be
easy to miss by eye and easy for a fuzzer to find. The bug this project
already caught and fixed (see CHANGELOG 0.2.0, the owner-key-recovery
index-tracking defect) was exactly this class of mistake; these tests
are, among other things, an attempt to make sure nothing similar is
still lurking uncaught.
"""

import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dlp import shamir

# Keep generated cases small enough that itertools.combinations over all
# subsets of shares stays fast — this module already tests every subset
# combinatorially, so trustee counts don't need to be large to be useful.
_secrets = st.binary(min_size=1, max_size=64)
_small_trustee_counts = st.integers(min_value=2, max_value=6)
# Used specifically where a test asserts reconstruction must NOT match
# the original secret: for very short secrets (esp. 1 byte), an
# under-threshold reconstruction interpolates the wrong polynomial but
# has a real, non-negligible chance (~1/256 per byte) of landing on the
# same byte value purely by coincidence — not a bug, just how many
# possible wrong answers there are for one byte. Requiring 4+ bytes here
# makes that coincidence astronomically unlikely instead of hedging the
# assertion itself.
_secrets_long_enough_to_rule_out_collision = st.binary(min_size=4, max_size=64)


@given(secret=_secrets, n=_small_trustee_counts)
@settings(max_examples=200)
def test_any_threshold_subset_reconstructs_correctly(secret, n):
    """For every (secret, n), and for every valid threshold 2..n, every
    subset of exactly `threshold` shares must reconstruct the original
    secret — not just the first `threshold` shares in generation order."""
    trustee_ids = [f"t{i}" for i in range(n)]
    for threshold in range(2, n + 1):
        shares = shamir.split_secret(secret, threshold, trustee_ids)
        for combo in itertools.combinations(shares, threshold):
            assert shamir.reconstruct_secret(list(combo)) == secret


@given(secret=_secrets_long_enough_to_rule_out_collision, n=_small_trustee_counts, data=st.data())
@settings(max_examples=100)
def test_below_threshold_subset_does_not_reconstruct(secret, n, data):
    """The flip side of the reconstruction property: strictly fewer than
    `threshold` shares must NOT reconstruct the original secret. This is
    the actual security property Shamir's scheme promises — not just
    "works with enough shares" but "reveals nothing with too few".

    A single share is a special case: dlp.shamir.reconstruct_secret()
    refuses it outright with ValueError (see test_shamir.py's
    test_single_share_raises) rather than returning a wrong answer, so
    that case is checked separately from "2+ shares, still below
    threshold, must silently produce the wrong secret" — both are
    correct behavior, just different behavior."""
    threshold = data.draw(st.integers(min_value=2, max_value=n))
    shares = shamir.split_secret(secret, threshold, [f"t{i}" for i in range(n)])
    under_threshold = data.draw(st.integers(min_value=1, max_value=threshold - 1))
    subset = data.draw(
        st.lists(
            st.sampled_from(shares), min_size=under_threshold, max_size=under_threshold, unique=True
        )
    )

    if under_threshold < 2:
        with pytest.raises(ValueError):
            shamir.reconstruct_secret(subset)
        return

    # 2+ shares but still below threshold: reconstruction "succeeds"
    # mechanically but must not recover the real secret — this is the
    # actual information-theoretic security property being verified.
    # Overwhelmingly likely to differ; a match here would indicate a real
    # security break in the field arithmetic, not test flakiness.
    if len(secret) > 0:
        assert shamir.reconstruct_secret(subset) != secret


@given(secret=_secrets, n=_small_trustee_counts)
@settings(max_examples=100)
def test_shares_are_pairwise_distinct(secret, n):
    shares = shamir.split_secret(secret, 2, [f"t{i}" for i in range(n)])
    datas = [s.data for s in shares]
    assert len(datas) == len(set(datas))


@given(a=st.integers(min_value=0, max_value=255), b=st.integers(min_value=0, max_value=255))
@settings(max_examples=500)
def test_gf_mul_commutative(a, b):
    assert shamir.gf_mul(a, b) == shamir.gf_mul(b, a)


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
)
@settings(max_examples=300)
def test_gf_mul_associative(a, b, c):
    assert shamir.gf_mul(shamir.gf_mul(a, b), c) == shamir.gf_mul(a, shamir.gf_mul(b, c))


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
)
@settings(max_examples=300)
def test_gf_mul_distributes_over_xor(a, b, c):
    # GF(256) addition is XOR; multiplication must distribute over it
    # exactly as in any field: a*(b XOR c) == (a*b) XOR (a*c)
    assert shamir.gf_mul(a, b ^ c) == shamir.gf_mul(a, b) ^ shamir.gf_mul(a, c)


@given(a=st.integers(min_value=1, max_value=255), b=st.integers(min_value=1, max_value=255))
@settings(max_examples=500)
def test_gf_div_inverts_mul(a, b):
    assert shamir.gf_div(shamir.gf_mul(a, b), b) == a


@given(a=st.integers(min_value=0, max_value=255))
@settings(max_examples=256)
def test_gf_mul_identity(a):
    assert shamir.gf_mul(a, 1) == a


@given(a=st.integers(min_value=0, max_value=255))
@settings(max_examples=256)
def test_gf_mul_zero(a):
    assert shamir.gf_mul(a, 0) == 0


@given(secret=st.binary(min_size=4, max_size=32))
@settings(max_examples=100)
def test_threshold_equal_to_n_requires_all_shares(secret):
    # min_size=4 here (not 1, like the other properties in this file) is
    # deliberate: with a threshold-of-n scheme, reconstructing from only
    # n-1 shares interpolates the WRONG polynomial rather than failing
    # outright, and for a single-byte secret there's a genuine ~1/256
    # chance that wrong interpolation coincidentally produces the same
    # byte value — a real property of GF(256), not a bug, but it would
    # make this specific assertion flaky for very short secrets. At 4+
    # bytes the same coincidence would need to hold across every byte
    # simultaneously (roughly 1-in-4-billion), which is what "must not
    # reconstruct" can safely assert without hedging.
    n = 4
    shares = shamir.split_secret(secret, n, [f"t{i}" for i in range(n)])
    assert shamir.reconstruct_secret(shares) == secret
    # any single share missing must fail to reconstruct correctly
    for i in range(n):
        subset = shares[:i] + shares[i + 1 :]
        assert shamir.reconstruct_secret(subset) != secret
