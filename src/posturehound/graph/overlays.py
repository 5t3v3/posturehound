"""User overlays applied over the immutable per-scan graph at query time.

An overlay is analyst state that changes how the graph is interpreted without mutating the
persisted snapshot: today, custom Tier-0 targets; the same assembly point is where remediation
marks and saved views will hang in the next wave. Keeping it in one place means the API and any
future consumer build the overlay the same way.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Overlay:
    tier0: set[str] = field(default_factory=set)          # extra high-value targets
    # Reserved for the next wave (what-if remediation): edges/nodes to treat as removed.
    remediated_edges: set[str] = field(default_factory=set)
    remediated_nodes: set[str] = field(default_factory=set)


def load_overlay(scan_id: str) -> Overlay:
    """Assemble the overlay for a specific scan from persisted per-scan user state."""
    from .. import store
    return Overlay(tier0=set(store.get_custom_tier0(scan_id)))
