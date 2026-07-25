"""Minimal local web UI for Digital Legacy Protocol. Requires the optional
'web' extra: pip install -e ".[web]" — kept separate from the core package
so the CLI/library stay dependency-light for anyone who doesn't need a
browser interface."""

from .app import create_app

__all__ = ["create_app"]
