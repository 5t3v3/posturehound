"""Build a GraphSnapshot from the deterministic model, and load/cache it per scan.

networkx MultiDiGraph -> flat, deduped, sorted GraphSnapshot. Parallel edges (the same
primitive between two nodes at many RBAC scopes) collapse to a single edge with a count,
which is all path-finding and visualization need. Edge endpoints that networkx auto-created
as bare nodes (scope strings used as derive.py destinations) get a synthetic placeholder so
the graph stays referentially whole for Cytoscape and path queries.
"""
from __future__ import annotations

from . import primitives
from .schema import (
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    TIER0_CRITICAL_TAG,
    TIER0_ELIGIBLE_TAG,
    TIER0_TAG,
    _scalar_props,
)

# Evidence keys worth carrying into the snapshot for the provenance panel (skip bulky/opaque ones).
_EVIDENCE_KEYS = ("reason", "role", "scope", "target", "target_role", "via", "path")


def _compact_evidence(ev: dict | None) -> dict:
    out: dict = {}
    for k in _EVIDENCE_KEYS:
        v = (ev or {}).get(k)
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, list) and len(v) <= 12:
            out[k] = [str(x) for x in v]
    return out


def _context_weight(g, e, base: float) -> "tuple[float, str]":
    """Context-aware edge difficulty (PRD v2.1 Workstream E3). Today: a PIM EligibleForRole edge's
    weight depends on the target role's collected activation policy, no MFA + no approval makes
    self-activation trivial (weight 1.0), MFA + approval makes it hard (3.0). Deterministic for
    the same input. Returns (weight, reason); reason is '' when unadjusted."""
    if e.type.value != "EligibleForRole":
        return base, ""
    role = g.node(e.dst)
    pol = (role.props.get("pim_policy") if role and role.props else None) or {}
    if not pol:
        return base, ""
    mfa = pol.get("activationRequiresMfa")
    appr = pol.get("activationRequiresApproval")
    if mfa is False and not appr:
        return 1.0, "no MFA on activation"
    if mfa and appr:
        return 3.0, "MFA and approval required on activation"
    if mfa:
        return 2.0, "MFA required on activation"
    return base, ""


def build_snapshot(g, *, scan_id: str | None = None) -> GraphSnapshot:
    """Flatten an in-memory model.Graph into a serializable GraphSnapshot."""
    nodes: list[GraphNode] = []
    node_ids: set[str] = set()
    for n in g.nodes():                       # already sorted by id
        tags = set(n.tags or ())
        nodes.append(GraphNode(
            id=n.id,
            kind=n.kind.value,
            label=n.name or n.id,
            tier0=TIER0_TAG in tags,
            critical=TIER0_CRITICAL_TAG in tags,
            eligible=TIER0_ELIGIBLE_TAG in tags,
            tags=sorted(tags),
            props=_scalar_props(n.props),
        ))
        node_ids.add(n.id)

    # Dedup edges to one per (source, type, primitive, target); tally the collapsed count.
    merged: dict[str, GraphEdge] = {}
    referenced: set[str] = set()
    for e in g.edges():                       # already sorted
        k = primitives.knowledge_for(e.primitive, e.type.value)
        weight, weight_reason = _context_weight(g, e, k["weight"])
        ge = GraphEdge(
            source=e.src,
            target=e.dst,
            type=e.type.value,
            primitive=e.primitive,
            derived=bool(e.derived),
            weight=weight,
            weight_reason=weight_reason,
            why=k["why"],
            conditions=k["conditions"],
            evidence=_compact_evidence(e.evidence),
        )
        referenced.add(e.src)
        referenced.add(e.dst)
        existing = merged.get(ge.key)
        if existing is None:
            merged[ge.key] = ge
        else:
            existing.count += 1
            # A derived assertion for the pair wins the flag (attack-relevant); keep the
            # first concrete evidence we saw (parallel edges differ only by scope).
            existing.derived = existing.derived or ge.derived
            if not existing.evidence and ge.evidence:
                existing.evidence = ge.evidence

    # Synthetic placeholders for endpoints networkx created without a node payload
    # (scope strings, etc.) so every edge has both ends present.
    for missing in sorted(referenced - node_ids):
        nodes.append(GraphNode(id=missing, kind="AZUnknown", label=missing))
    nodes.sort(key=lambda n: n.id)

    edges = sorted(merged.values(), key=lambda e: e.key)
    return GraphSnapshot(
        scan_id=scan_id,
        tenant_id=getattr(g, "tenant_id", None),
        nodes=nodes,
        edges=edges,
    )


def persist_snapshot(scan_id: str, g) -> GraphSnapshot:
    """Build and cache a scan's graph from the already-derived in-memory graph, at scan time.

    Preferred over snapshot_for_scan (which rebuilds from raw): the scan pipeline already holds
    the derived graph, so this avoids re-parsing + re-deriving on first view. Also builds the
    Kùzu DB when available. Best-effort on Kùzu; the JSON snapshot always lands.
    """
    from . import persist
    snap = build_snapshot(g, scan_id=scan_id)
    persist.write_snapshot(scan_id, snap)
    try:
        from . import kuzu_store
        if kuzu_store.kuzu_available():
            kuzu_store.graph_for_cypher(snap, scan_id, rebuild=True)
    except Exception:
        pass
    return snap


def snapshot_for_scan(scan_id: str, *, rebuild: bool = False) -> GraphSnapshot | None:
    """Return a scan's snapshot, from cache when possible, else rebuilt from stored raw.

    Returns None when the scan has no stored raw collection to rebuild from.
    """
    from . import persist

    if not rebuild:
        cached = persist.read_snapshot(scan_id)
        if cached is not None:
            return cached

    # Rebuild from the stored raw collection (lazy imports: heavy modules, and this
    # path is only hit on a cold cache).
    from .. import ingest, store
    from ..derive import derive
    from ..normalize import build_graph

    blobs = store.get_raw_blobs(scan_id)
    if not blobs:
        return None
    ing = ingest.parse_many(blobs)
    g = build_graph(ing)
    # Add the escalation/abuse edges and Tier-0 tagging. build_graph alone yields only the
    # raw graph; derive() is what makes it an attack graph (mirrors engine._assess).
    derive(g)
    snap = build_snapshot(g, scan_id=scan_id)
    persist.write_snapshot(scan_id, snap)
    return snap
