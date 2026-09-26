"""On-disk cache for per-scan graph snapshots.

Snapshots live under PH_DATA_DIR/graphs/<scan_id>/snapshot.json. A cached snapshot from an
older SNAPSHOT_VERSION is treated as absent so it is transparently rebuilt. Writes are atomic
(temp file + replace) so a crash mid-write never leaves a half-snapshot behind.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path

from .schema import SNAPSHOT_VERSION, GraphSnapshot

_log = logging.getLogger("posturehound")
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")

# Snapshots are large (tens of MB for a big tenant) and parsed on every cold graph load, so
# prefer orjson when available (~2x faster than stdlib json); fall back transparently.
try:
    import orjson as _orjson

    def _loads(raw: bytes):
        return _orjson.loads(raw)
except Exception:  # orjson not installed on this interpreter
    def _loads(raw: bytes):
        return json.loads(raw)


def _safe(scan_id: str) -> str:
    return _SAFE.sub("_", scan_id or "unknown")


def graphs_dir() -> Path:
    from .. import store
    return store.DATA_DIR / "graphs"


def snapshot_dir(scan_id: str) -> Path:
    return graphs_dir() / _safe(scan_id)


def snapshot_path(scan_id: str) -> Path:
    return snapshot_dir(scan_id) / "snapshot.json"


def read_snapshot(scan_id: str) -> GraphSnapshot | None:
    """Load a cached snapshot, or None if missing / stale / unreadable."""
    p = snapshot_path(scan_id)
    try:
        if not p.exists():
            return None
        d = _loads(p.read_bytes())
    except Exception:
        # A present-but-unreadable snapshot is corruption, not a cold cache: log it (the caller
        # transparently rebuilds from raw).
        _log.warning("corrupt graph snapshot for scan %s; rebuilding", scan_id, exc_info=True)
        return None
    if int(d.get("version", 0)) != SNAPSHOT_VERSION:
        return None
    try:
        return GraphSnapshot.from_dict(d)
    except Exception:
        _log.warning("unreadable graph snapshot for scan %s; rebuilding", scan_id, exc_info=True)
        return None


def write_snapshot(scan_id: str, snap: GraphSnapshot) -> Path:
    d = snapshot_dir(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    p = d / "snapshot.json"
    fd, tmp = tempfile.mkstemp(dir=str(d), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(snap.to_json())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return p


def delete_snapshot(scan_id: str) -> None:
    """Remove a scan's cached graph (used when the scan itself is deleted)."""
    import shutil
    d = snapshot_dir(scan_id)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)
