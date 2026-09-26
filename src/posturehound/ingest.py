"""Ingest layer: read AzureHound collection output into a list of typed records.

AzureHound emits ``{"meta": {...}, "data": [ {"kind": "...", "data": {...}}, ... ]}``.
Relationship records (members, owners, role assignments, KV access policies, app
roles) are represented as their own ``kind`` entries. Field mappings should be
validated against the target AzureHound version (see docs/DATA_MODEL.md, OQ-1).
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Decompressed-size safety limits for ZIP uploads.  The outer HTTP layer caps
# the *compressed* size via MAX_UPLOAD_BYTES; these guard against ZIP bombs
# where a small archive expands to many gigabytes.
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        import sys
        print(f"Warning: {name} is not a valid integer; using default {default}", file=sys.stderr)
        return default

_MAX_DECOMPRESSED_MB = _int_env("PH_MAX_DECOMPRESSED_MB", 2048)
_MAX_DECOMPRESSED_BYTES = _MAX_DECOMPRESSED_MB * 1024 * 1024
_MAX_ZIP_ENTRIES = _int_env("PH_MAX_ZIP_ENTRIES", 50)


@dataclass
class IngestResult:
    records: list[dict[str, Any]]
    meta: dict[str, Any]
    summary: dict[str, Any]
    warnings: list[str]


class IngestError(Exception):
    pass


def _coerce_records(obj: Any) -> list[dict[str, Any]]:
    """Extract the list of {kind, data} records from a parsed object."""
    if isinstance(obj, dict) and isinstance(obj.get("data"), list):
        return obj["data"]
    if isinstance(obj, list):
        return obj
    raise IngestError("Unrecognised collection structure: expected an object with a 'data' array.")


def _read_text(raw: bytes) -> str:
    return raw.decode("utf-8-sig", errors="replace")


_MAX_FILE_BYTES = 512 * 1024 * 1024  # 512 MB per file


def parse_bytes(raw: bytes, *, source: str = "<bytes>") -> IngestResult:
    """Parse raw collection bytes. Supports JSON object, JSON array, and NDJSON."""
    if len(raw) > _MAX_FILE_BYTES:
        raise IngestError(
            f"{source}: file too large ({len(raw) // 1_048_576} MB). "
            f"Maximum supported size is {_MAX_FILE_BYTES // 1_048_576} MB."
        )
    warnings: list[str] = []
    text = _read_text(raw).strip()
    meta: dict[str, Any] = {}
    records: list[dict[str, Any]]

    if not text:
        raise IngestError("Empty collection.")

    # Try strict JSON first.
    try:
        obj = json.loads(text)
        records = _coerce_records(obj)
        if isinstance(obj, dict):
            meta = obj.get("meta", {}) or {}
    except json.JSONDecodeError:
        # Fall back to NDJSON (one record per line).
        records = []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]", "{", "}"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                warnings.append(f"{source}: skipped malformed line {i}")

    return _finalise(records, meta, warnings, source)


def parse_file(path: str | Path) -> IngestResult:
    p = Path(path)
    if not p.exists():
        raise IngestError(f"File not found: {p}")
    if p.suffix.lower() == ".zip":
        return _parse_zip(p)
    return parse_bytes(p.read_bytes(), source=p.name)


def parse_many(blobs: list[tuple[bytes, str]]) -> IngestResult:
    """Parse and merge several collection blobs into one result.

    AzureHound can emit its Entra (e.g. ``ad.json``) and Resource-Manager (e.g.
    ``rm.json``) collections as separate files. They describe different halves of
    the same tenant and must be combined into a single graph to see cross-plane
    escalation paths. Records are concatenated; the graph builder deduplicates
    nodes by id, so overlapping objects across files are merged, not duplicated.
    """
    if not blobs:
        raise IngestError("No files provided.")
    all_records: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    warnings: list[str] = []
    sources: list[str] = []
    for raw, name in blobs:
        if name.lower().endswith(".zip"):
            try:
                zf_ctx = zipfile.ZipFile(io.BytesIO(raw))
            except zipfile.BadZipFile as e:
                raise IngestError(f"Invalid or corrupt ZIP file '{name}': {e}") from e
            with zf_ctx as zf:
                json_entries = [m for m in zf.namelist()
                                if m.lower().endswith((".json", ".ndjson"))]
                if len(json_entries) > _MAX_ZIP_ENTRIES:
                    warnings.append(
                        f"{name}: ZIP contains {len(json_entries)} JSON entries; "
                        f"processing the first {_MAX_ZIP_ENTRIES} only."
                    )
                    json_entries = json_entries[:_MAX_ZIP_ENTRIES]
                decompressed_total = 0
                for m in json_entries:
                    info = zf.getinfo(m)
                    decompressed_total += info.file_size
                    if decompressed_total > _MAX_DECOMPRESSED_BYTES:
                        raise IngestError(
                            f"ZIP decompressed content exceeds the {_MAX_DECOMPRESSED_MB} MB "
                            f"safety limit. Raise it with PH_MAX_DECOMPRESSED_MB."
                        )
                    if info.file_size > _MAX_DECOMPRESSED_BYTES:
                        raise IngestError(
                            f"A single ZIP entry ({m}) would decompress to "
                            f"{info.file_size // (1024*1024)} MB, exceeding the "
                            f"{_MAX_DECOMPRESSED_MB} MB limit."
                        )
                    res = parse_bytes(zf.read(m), source=m)
                    all_records.extend(res.records)
                    meta = meta or res.meta
                    warnings.extend(res.warnings)
        else:
            res = parse_bytes(raw, source=name)
            all_records.extend(res.records)
            meta = meta or res.meta
            warnings.extend(res.warnings)
        sources.append(name)
    result = _finalise(all_records, meta, warnings, ", ".join(sources))
    result.summary["files"] = sources
    return result


def _parse_zip(p: Path) -> IngestResult:
    return parse_many([(p.read_bytes(), p.name)])


def _finalise(
    records: list[dict[str, Any]], meta: dict[str, Any], warnings: list[str], source: str
) -> IngestResult:
    clean: list[dict[str, Any]] = []
    by_kind: dict[str, int] = {}
    skipped = 0
    for rec in records:
        if not isinstance(rec, dict) or "kind" not in rec:
            skipped += 1
            continue
        kind = rec.get("kind")
        if not isinstance(kind, str):
            skipped += 1
            continue
        if "data" not in rec or not isinstance(rec["data"], dict):
            rec["data"] = {}
            warnings.append(f"{source}: record kind={kind} had no/invalid data block")
        clean.append(rec)
        by_kind[kind] = by_kind.get(kind, 0) + 1

    version = meta.get("version")
    if version is not None and not isinstance(version, int):
        warnings.append(f"{source}: unexpected meta.version type {type(version).__name__}")

    summary = {
        "source": source,
        "total_records": len(clean),
        "skipped_records": skipped,
        "by_kind": dict(sorted(by_kind.items())),
        "meta_version": version,
    }
    if not clean:
        raise IngestError("No valid records found in collection.")
    return IngestResult(records=clean, meta=meta, summary=summary, warnings=warnings)
