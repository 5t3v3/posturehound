"""Embedded Kùzu (Cypher) backend for the attack graph.

Loads a GraphSnapshot into an on-disk Kùzu database (one generic Node table + one Rel table)
via bulk COPY, and runs arbitrary Cypher for the ad-hoc query feature. Kùzu has no wheel on
some interpreters (e.g. CPython 3.14); callers must gate on `kuzu_available()` and fall back
to the networkx queries when it is False.

Untrusted input: raw Cypher from the UI is read-only by construction here (the DB is rebuilt
per scan and thrown away), but callers should still forbid DDL/DML verbs before running it.
"""
from __future__ import annotations

import csv
import shutil
import tempfile
from pathlib import Path

from .persist import snapshot_dir
from .schema import GraphSnapshot

# Cypher verbs that mutate schema or data - rejected for the ad-hoc query box.
_FORBIDDEN_VERBS = (
    "create", "merge", "delete", "set", "remove", "drop", "alter",
    "copy", "detach", "load", "install", "attach",
)


def kuzu_available() -> bool:
    try:
        import kuzu  # noqa: F401
        return True
    except Exception:
        return False


def is_read_only_cypher(query: str) -> bool:
    """True if the query contains no schema/data-mutating verb (word-boundary match)."""
    import re
    low = query.lower()
    return not any(re.search(rf"\b{v}\b", low) for v in _FORBIDDEN_VERBS)


class KuzuGraph:
    """A per-scan Kùzu database built from a snapshot; supports read-only Cypher."""

    def __init__(self, db_path: Path):
        import kuzu
        self._db = kuzu.Database(str(db_path))
        self._conn = kuzu.Connection(self._db)

    # ---- construction -------------------------------------------------
    @classmethod
    def build(cls, snap: GraphSnapshot, db_path: Path) -> "KuzuGraph":
        import kuzu
        if db_path.exists():
            shutil.rmtree(db_path, ignore_errors=True)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db = kuzu.Database(str(db_path))
        conn = kuzu.Connection(db)
        conn.execute(
            "CREATE NODE TABLE Node(id STRING, kind STRING, label STRING, "
            "tier0 BOOLEAN, critical BOOLEAN, eligible BOOLEAN, PRIMARY KEY(id))")
        conn.execute(
            "CREATE REL TABLE Rel(FROM Node TO Node, type STRING, primitive STRING, "
            "derived BOOLEAN, cnt INT64)")
        with tempfile.TemporaryDirectory() as td:
            npath = Path(td) / "nodes.csv"
            rpath = Path(td) / "rels.csv"
            with npath.open("w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["id", "kind", "label", "tier0", "critical", "eligible"])
                for n in snap.nodes:
                    w.writerow([n.id, n.kind, n.label,
                                str(n.tier0).lower(), str(n.critical).lower(),
                                str(n.eligible).lower()])
            with rpath.open("w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["from", "to", "type", "primitive", "derived", "cnt"])
                for e in snap.edges:
                    w.writerow([e.source, e.target, e.type, e.primitive or "",
                                str(e.derived).lower(), e.count])
            conn.execute(f'COPY Node FROM "{npath}" (HEADER=true)')
            conn.execute(f'COPY Rel FROM "{rpath}" (HEADER=true)')
        return cls(db_path)

    # ---- query --------------------------------------------------------
    def run_cypher(self, query: str, *, read_only: bool = True) -> dict:
        """Run Cypher and return {columns, rows, elements}. elements holds any Node/Rel
        values found in the result, as Cytoscape elements (for graph-shaped queries)."""
        if read_only and not is_read_only_cypher(query):
            raise ValueError("Only read-only Cypher is allowed here.")
        res = self._conn.execute(query)
        columns = res.get_column_names()
        rows: list[list] = []
        nodes: dict[str, dict] = {}
        edges: dict[str, dict] = {}
        while res.has_next():
            row = res.get_next()
            out_row = []
            for val in row:
                self._collect(val, nodes, edges)
                out_row.append(self._scalarize(val))
            rows.append(out_row)
        return {
            "columns": columns,
            "rows": rows,
            "elements": {"nodes": list(nodes.values()), "edges": list(edges.values())},
        }

    # ---- result extraction -------------------------------------------
    def _collect(self, val, nodes: dict, edges: dict) -> None:
        """Recursively pull Node/Rel/path values out of a Cypher result cell."""
        if isinstance(val, dict):
            if "_id" in val and "_label" in val and "_src" not in val:
                nodes[val.get("id") or str(val["_id"])] = {"data": {
                    "id": val.get("id"), "label": val.get("label") or val.get("id"),
                    "kind": val.get("kind"), "tier0": bool(val.get("tier0")),
                    "critical": bool(val.get("critical")), "eligible": bool(val.get("eligible")),
                }}
            elif "_src" in val and "_dst" in val:
                key = f'{val.get("_src")}|{val.get("type")}|{val.get("_dst")}'
                edges[key] = {"data": {
                    "id": key, "type": val.get("type"), "primitive": val.get("primitive"),
                    "derived": bool(val.get("derived")),
                    # _src/_dst are internal ids; the UI resolves endpoints from returned nodes.
                    "_src": str(val.get("_src")), "_dst": str(val.get("_dst")),
                }}
            elif "_nodes" in val or "_rels" in val:      # a path value
                for n in val.get("_nodes", []):
                    self._collect(n, nodes, edges)
                for r in val.get("_rels", []):
                    self._collect(r, nodes, edges)
        elif isinstance(val, list):
            for item in val:
                self._collect(item, nodes, edges)

    def _scalarize(self, val):
        if isinstance(val, dict):
            return val.get("id") or val.get("label") or "<node>" if "_id" in val else str(val)
        return val


def kuzu_db_path(scan_id: str) -> Path:
    return snapshot_dir(scan_id) / "kuzu"


def graph_for_cypher(snap: GraphSnapshot, scan_id: str, *, rebuild: bool = False) -> "KuzuGraph | None":
    """Return a KuzuGraph for a scan, building it from the snapshot if needed. None if Kùzu
    is unavailable on this interpreter."""
    if not kuzu_available():
        return None
    db_path = kuzu_db_path(scan_id)
    if rebuild or not db_path.exists() or not any(db_path.iterdir()):
        return KuzuGraph.build(snap, db_path)
    try:
        return KuzuGraph(db_path)
    except Exception:
        return KuzuGraph.build(snap, db_path)
