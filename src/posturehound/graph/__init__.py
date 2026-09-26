"""Native graph engine for PostureHound.

An in-house attack graph built directly from PostureHound's own normalized model.
networkx is the always-available source of truth and query backend; Kùzu (embedded,
Cypher) is used as an optional accelerated/ad-hoc-query backend when its wheel is
installed (see queries.py).

Public surface:
    build_snapshot(graph)        -> GraphSnapshot   (from an in-memory Graph)
    snapshot_for_scan(scan_id)   -> GraphSnapshot   (cached; rebuilt from stored raw)
    GraphSnapshot, GraphNode, GraphEdge             (schema)
"""
from .schema import GraphEdge, GraphNode, GraphSnapshot
from .build import build_snapshot, persist_snapshot, snapshot_for_scan

__all__ = [
    "GraphEdge",
    "GraphNode",
    "GraphSnapshot",
    "build_snapshot",
    "persist_snapshot",
    "snapshot_for_scan",
]
