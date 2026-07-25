# Contributing to Digital Legacy Protocol

Thanks for taking a look. This project is small on purpose, but the problem it addresses is not — so contributions of all sizes are useful, not just code.

## Ways to contribute

### 1. Critique the spec
`spec/SPEC.md` is a v0.1 draft. If you can find a scenario it handles badly — a jurisdiction where trustee quorum has no legal standing, a beneficiary with no public key and no smartphone, a platform whose ToS makes any of this impossible — open an issue. Spec critique from people who are *not* engineers is especially valuable; this is meant to work for families, not just developers.

### 2. Build a platform adapter
If you maintain or work at a service that could plausibly honor DLP manifests (password managers, crypto exchanges, email providers, anything), implement `dlp.adapter.DLPAdapter` for it. It doesn't need to be production-ready to be a useful contribution — even a proof-of-concept adapter for a small self-hosted service demonstrates the interface works outside the reference implementation's own test suite.

### 3. Improve the reference implementation
The code in `dlp/` should stay dependency-light and auditable — right now it only depends on the `cryptography` package. Before adding a new dependency, ask in an issue first.

Things that are always welcome:
- More edge-case tests, especially anything that tries to break the Shamir reconstruction or the quorum state machine
- Property-based tests (e.g. via `hypothesis`) for `dlp/shamir.py`
- Language ports — a TypeScript or Rust implementation of the manifest format and canonicalization would let non-Python platforms verify manifests without shelling out to Python

### 4. Report security issues privately
See [SECURITY.md](SECURITY.md). Please do not open a public issue for anything that could let someone forge a manifest, bypass quorum, or extract a secret from fewer than the threshold number of shares.

## Development setup

```bash
git clone https://github.com/Ciprian-LocalPulse/digital-legacy-protocol
cd digital-legacy-protocol
pip install -e ".[dev]"
pytest tests/ -v --cov=dlp
```

Before opening a PR:

```bash
black dlp/ tests/
ruff check dlp/ tests/
pytest tests/ -v
python -m dlp.cli demo   # should complete without errors
```

## Code style

- Type hints on all public functions.
- No bare `except:` — catch specific exceptions.
- Docstrings that explain *why*, not just *what* — this codebase deals with cryptography and inheritance, where the reasoning behind a decision matters more than usual.
- Keep `dlp/shamir.py` dependency-free (no external crypto libraries) so it stays easy to audit line by line.

## Pull request process

1. Fork, branch, make your change.
2. Add or update tests — PRs that touch `shamir.py`, `crypto.py`, or `switch.py` without accompanying tests will be asked for them.
3. Run the full check list above.
4. Open the PR with a plain description of *why*, not just *what*. "Fixes off-by-one in grace period calculation" is more useful than "update switch.py".

## Governance

There's no formal governance structure yet — this is an early-stage open protocol with one primary maintainer. If the project grows, decision-making will move to a more structured RFC process modeled on how IETF or W3C specs evolve. Suggestions on how to structure that are welcome as issues.
