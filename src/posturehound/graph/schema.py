"""Serializable attack-graph snapshot.

A GraphSnapshot is the on-disk, backend-agnostic representation of one scan's attack
graph: the same nodes and edges the deterministic engine builds in model.Graph, flattened
to plain dicts so they can be persisted, loaded into Kùzu, or queried with networkx without
re-running a scan. Everything is emitted in a stable, sorted order so the same tenant always
produces a byte-identical snapshot (matching PostureHound's determinism guarantee).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Snapshot format version - bump when the node/edge shape changes so stale caches
# are transparently rebuilt instead of misread.
# v2: edges carry weight/why/conditions/evidence; nodes carry value.
# v3: Tier-0 tightened to the curated high-impact role set - old caches must rebuild.
# v4: RBAC edge keys include the role, so multiple roles at one scope no longer collapse.
SNAPSHOT_VERSION = 4

# Node tags that mark a high-value target. Kept in one place so the UI, the queries,
# and the snapshot all agree on what "Tier-0" means.
TIER0_TAG = "tier0"
TIER0_CRITICAL_TAG = "tier0_critical"
TIER0_ELIGIBLE_TAG = "tier0_eligible"

# Only scalar props are carried into the snapshot (nested structures bloat it and are
# not needed for display/queries); each value is also length-capped.
_MAX_PROP_LEN = 200


def _scalar_props(props: dict[str, Any] | None) -> dict[str, Any]:
    """Filter a node's props to display-safe scalars, sorted for determinism."""
    out: dict[str, Any] = {}
    for k in sorted((props or {}).keys()):
        v = props[k]
        if isinstance(v, bool) or isinstance(v, (int, float)):
            out[k] = v
        elif isinstance(v, str):
            if len(v) <= _MAX_PROP_LEN:
                out[k] = v
    return out


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: str                       # NodeKind value, e.g. "AZUser"
    label: str                      # display name
    tier0: bool = False
    critical: bool = False          # tier0_critical
    eligible: bool = False          # tier0_eligible (PIM shadow admin)
    value: int = 0                  # impact/importance (populated later; 0 = unset)
    tags: list[str] = field(default_factory=list)
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "tier0": self.tier0,
            "critical": self.critical,
            "eligible": self.eligible,
            "value": self.value,
            "tags": self.tags,
            "props": self.props,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GraphNode":
        return cls(
            id=d["id"],
            kind=d.get("kind", "AZUnknown"),
            label=d.get("label", d["id"]),
            tier0=bool(d.get("tier0")),
            critical=bool(d.get("critical")),
            eligible=bool(d.get("eligible")),
            value=int(d.get("value", 0)),
            tags=list(d.get("tags") or []),
            props=dict(d.get("props") or {}),
        )


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    type: str                       # EdgeType value, e.g. "CanAddSecret"
    primitive: str | None = None    # abuse primitive label, when the edge is derived
    derived: bool = False           # True for escalation/abuse edges (attack-relevant)
    count: int = 1                  # how many raw assignments collapsed into this edge
    weight: float = 1.0             # traversal difficulty (lower = easier); for cost-aware paths
    why: str = ""                   # plain explanation of the abuse (provenance panel)
    conditions: list[str] = field(default_factory=list)   # extra prerequisites
    evidence: dict[str, Any] = field(default_factory=dict)  # concrete scope/role/reason

    @property
    def key(self) -> str:
        """Stable, unique edge id. A snapshot dedups to one edge per src+type+primitive+target,
        PLUS the RBAC role - a node can hold several distinct RBAC roles (e.g. Contributor AND
        User Access Administrator) at the SAME scope, and collapsing those loses the privileged
        one (and its Tier-0 justification)."""
        base = f"{self.source}|{self.type}|{self.primitive or ''}|{self.target}"
        if self.type == "HasRBACRole":
            role = (self.evidence or {}).get("role")
            if role:
                return base + "|" + str(role)
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "primitive": self.primitive,
            "derived": self.derived,
            "count": self.count,
            "weight": self.weight,
            "why": self.why,
            "conditions": self.conditions,
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GraphEdge":
        return cls(
            source=d["source"],
            target=d["target"],
            type=d.get("type", ""),
            primitive=d.get("primitive"),
            derived=bool(d.get("derived")),
            count=int(d.get("count", 1)),
            weight=float(d.get("weight", 1.0)),
            why=d.get("why", ""),
            conditions=list(d.get("conditions") or []),
            evidence=dict(d.get("evidence") or {}),
        )


@dataclass
class GraphSnapshot:
    scan_id: str | None
    tenant_id: str | None
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    version: int = SNAPSHOT_VERSION

    # ---- summary ------------------------------------------------------
    def counts(self) -> dict[str, int]:
        kinds: dict[str, int] = {}
        for n in self.nodes:
            kinds[n.kind] = kinds.get(n.kind, 0) + 1
        edge_kinds: dict[str, int] = {}
        for e in self.edges:
            edge_kinds[e.type] = edge_kinds.get(e.type, 0) + 1
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "tier0": sum(1 for n in self.nodes if n.tier0),
            "attack_edges": sum(1 for e in self.edges if e.derived),
            "node_kinds": dict(sorted(kinds.items())),
            "edge_kinds": dict(sorted(edge_kinds.items())),
        }

    # ---- serialization ------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "scan_id": self.scan_id,
            "tenant_id": self.tenant_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self) -> str:
        # sort_keys for byte-stable output; the node/edge lists are already sorted by build.
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GraphSnapshot":
        return cls(
            scan_id=d.get("scan_id"),
            tenant_id=d.get("tenant_id"),
            nodes=[GraphNode.from_dict(n) for n in d.get("nodes", [])],
            edges=[GraphEdge.from_dict(e) for e in d.get("edges", [])],
            version=int(d.get("version", 0)),
        )
