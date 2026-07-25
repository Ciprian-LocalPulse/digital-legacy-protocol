"""
Manifest storage (spec v0.1 gap: no storage layer exists at all — a
manifest is just a Python dict or a JSON file someone remembers to keep).

This module defines a small ManifestStore interface plus one real,
tested implementation (local filesystem, one JSON file per manifest) so
the reference implementation can actually persist something end to end.
It is explicitly NOT meant to be the only backend: a real deployment
would want a database-backed store, an IPFS-pinned store, or a store
replicated across the trustees' own devices so no single server going
down loses the manifest. Implement ManifestStore for any of those the
same way you'd implement DLPAdapter.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from . import manifest as manifest_mod


class ManifestNotFoundError(KeyError):
    pass


class ManifestStore(ABC):
    """Storage contract. All methods operate on manifest dicts, not
    signed bytes — callers are expected to have already verified a
    manifest (see dlp.manifest.is_signature_valid) before writing it, and
    to re-verify after reading it back if the store isn't fully trusted."""

    @abstractmethod
    def save(self, manifest: Dict[str, Any]) -> None:
        """Writes or overwrites a manifest by its manifest_id."""
        raise NotImplementedError

    @abstractmethod
    def load(self, manifest_id: str) -> Dict[str, Any]:
        """Raises ManifestNotFoundError if no such manifest exists."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, manifest_id: str) -> None:
        """No-op (does not raise) if the manifest doesn't exist — deleting
        something already gone is not an error."""
        raise NotImplementedError

    @abstractmethod
    def list_ids(self) -> List[str]:
        raise NotImplementedError

    def load_latest_in_chain(self, manifest_id: str) -> Dict[str, Any]:
        """Follows `supersedes` links forward: given any manifest_id in a
        chain of updates, walks forward to find the most recent version.
        Relies on a linear scan of list_ids(), which is fine for the
        local file store and any store with a small number of manifests;
        a database-backed store would want to index `supersedes` instead."""
        current = self.load(manifest_id)
        all_ids = set(self.list_ids())
        # find whether anything in the store supersedes `current`
        changed = True
        while changed:
            changed = False
            for other_id in all_ids:
                if other_id == current["manifest_id"]:
                    continue
                candidate = self.load(other_id)
                if candidate.get("supersedes") == current["manifest_id"]:
                    current = candidate
                    changed = True
                    break
        return current


class LocalFileStore(ManifestStore):
    """One JSON file per manifest, named <manifest_id>.json, inside a
    directory. Good for local development, the CLI, and single-machine
    demos. Not concurrency-safe across multiple processes writing at
    once — a real deployment needs a database or object store with
    proper locking, not this."""

    def __init__(self, directory: str | Path):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, manifest_id: str) -> Path:
        # manifest_id is always a UUID (see ManifestBuilder), so no path
        # traversal risk from untrusted input reaching here — but assert
        # the shape anyway rather than trusting that invariant blindly
        if "/" in manifest_id or "\\" in manifest_id or ".." in manifest_id:
            raise ValueError(f"unsafe manifest_id: {manifest_id!r}")
        return self._dir / f"{manifest_id}.json"

    def save(self, manifest: Dict[str, Any]) -> None:
        manifest_mod.validate_manifest(manifest)  # refuse to persist garbage
        path = self._path_for(manifest["manifest_id"])
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True))

    def load(self, manifest_id: str) -> Dict[str, Any]:
        path = self._path_for(manifest_id)
        if not path.exists():
            raise ManifestNotFoundError(manifest_id)
        return json.loads(path.read_text())

    def delete(self, manifest_id: str) -> None:
        path = self._path_for(manifest_id)
        path.unlink(missing_ok=True)

    def list_ids(self) -> List[str]:
        return [p.stem for p in self._dir.glob("*.json")]
