"""Attack-graph queries over a GraphSnapshot (networkx backend).

This is the always-available query workhorse for the interactive explorer. It answers the
fixed MVP questions - node search, 1-hop expansion, shortest attack paths to Tier-0, and a
path between two nodes - and returns Cytoscape-ready elements. Path-finding runs over the
DERIVED (escalation/abuse) edges only, since those are what make an attack path; expansion
shows all relationships for context.

Kùzu provides ad-hoc Cypher separately (see kuzu_store.py); these fixed queries stay on
networkx so they work identically on every Python (including 3.14, where Kùzu has no wheel).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .schema import GraphEdge, GraphNode, GraphSnapshot

# Never ship an unbounded subgraph to the browser; the UI renders subgraphs, not the whole
# ~60k-edge graph. A query that would exceed this is truncated and flagged.
DEFAULT_NODE_CAP = 600

# Edge types the attack graph traverses for path-finding - kept identical to scoring's
# _ESCALATION_EDGES so the explorer's paths match the findings exactly. Crucially this
# includes MemberOf/Owns (positioning), without which membership-into-a-Tier-0-group paths
# were missing and everything looked like a 1-2 hop graph.
_ABUSE_TYPES = {
    "CanAddSecret", "CanAddMember", "CanAddOwner", "CanGrantRole", "CanGrantAppRole",
    "CanEscalateRBAC", "CanStealManagedIdentity", "CanResetPassword", "CanReachKVSecret",
    "CanGetStorageKey", "CanExecAKS", "CanReadStorageBlob", "CanPushContainer",
    "EligibleForRole",
}
_POSITIONING_TYPES = {"MemberOf": 0.5, "Owns": 0.5}   # traversed to get into position; cheap
_TRAVERSABLE_TYPES = _ABUSE_TYPES | set(_POSITIONING_TYPES)

# Edge types that mean "source HOLDS / can exercise target" (principal -> role/group/target).
# A role node is a sink - nothing escalates out of it - so the blast radius of a role is what
# its holders can do: the reach you inherit by obtaining the role.
_HOLDING_TYPES = {"EffectiveRole", "HasEntraRole", "EligibleForRole",
                  "HasRBACRole", "HasAppRole", "MemberOf", "Owns"}


def _scope_label(scope: str) -> str:
    """Human label for an ARM scope string (subscription GUID / management group)."""
    if not scope:
        return "broad scope"
    low = scope.lower()
    parts = scope.strip("/").split("/")
    if "managementgroups" in low:
        return "management group " + parts[-1]
    if len(parts) >= 2 and parts[0].lower() == "subscriptions":
        return "subscription " + parts[1]
    return scope[:48]

# Prebuilt attack-path queries offered in the explorer.
PRESETS = [
    {"name": "shortest-to-tier0", "label": "Shortest paths to Tier-0",
     "desc": "Every principal's shortest escalation path to a Tier-0 target."},
    {"name": "sp-to-tier0", "label": "Service principals → Tier-0",
     "desc": "Non-human identities (SPs) that can escalate to Tier-0."},
    {"name": "guests-to-tier0", "label": "Guests / external → Tier-0",
     "desc": "Guest (external) accounts that can escalate to Tier-0."},
    {"name": "disabled-to-tier0", "label": "Disabled accounts → Tier-0",
     "desc": "Disabled accounts that still hold a path to Tier-0."},
    {"name": "stale-privileged", "label": "Stale privileged (disabled Tier-0)",
     "desc": "Disabled accounts that are themselves Tier-0 - dormant but dangerous."},
    {"name": "app-consent", "label": "Dangerous app permissions",
     "desc": "App permission grants that lead to role escalation (CanGrantRole / CanGrantAppRole)."},
    {"name": "mi-abuse", "label": "Managed-identity abuse",
     "desc": "Compute that can mint tokens as an assigned managed identity."},
    {"name": "kv-readers", "label": "Key Vault secret readers",
     "desc": "Principals with data-plane access to read Key Vault secrets."},
    {"name": "storage-keys", "label": "Storage key access",
     "desc": "Principals that can list storage account keys."},
    {"name": "owners", "label": "Ownership edges",
     "desc": "Owner / take-ownership relationships."},
    # ---- abuse-primitive views (one edge class each) ----
    {"name": "crown-jewels", "label": "All Tier-0 assets",
     "desc": "Every crown-jewel (Tier-0) asset in the tenant, with any onward path to another."},
    {"name": "pim-eligible", "label": "PIM-eligible → Tier-0 (shadow admins)",
     "desc": "Principals eligible to activate a privileged role via PIM without holding it."},
    {"name": "reset-password", "label": "Password-reset abuse",
     "desc": "Principals that can reset another account's password / MFA (CanResetPassword)."},
    {"name": "add-secret", "label": "Credential injection (AddSecret)",
     "desc": "Principals that can add a credential to an app/SP and authenticate as it."},
    {"name": "add-member", "label": "Group-membership injection",
     "desc": "Principals that can add members to a privileged group (CanAddMember)."},
    {"name": "rbac-escalation", "label": "Azure RBAC self-escalation",
     "desc": "Principals that can grant themselves any Azure role (CanEscalateRBAC)."},
    {"name": "aks-exec", "label": "AKS cluster admin / exec",
     "desc": "Principals that can obtain cluster-admin and run code in AKS (CanExecAKS)."},
    {"name": "container-push", "label": "Container image push (supply chain)",
     "desc": "Principals that can push images to a registry downstream workloads pull."},
    {"name": "blob-access", "label": "Storage blob data access",
     "desc": "Principals with direct data-plane access to storage blobs (CanReadStorageBlob)."},
    {"name": "foreign-apps", "label": "External / multi-tenant apps",
     "desc": "Service principals owned by another tenant, and any Tier-0 reach they hold."},
]


@dataclass
class Subgraph:
    node_ids: set[str] = field(default_factory=set)
    edges: list[GraphEdge] = field(default_factory=list)
    path_edge_keys: set[str] = field(default_factory=set)   # edges to highlight
    paths: list[list[str]] = field(default_factory=list)    # ordered node-id hop lists
    truncated: bool = False
    message: str = ""


class AttackGraph:
    """Query facade over one scan's snapshot."""

    def __init__(self, snap: GraphSnapshot, extra_tier0: set[str] | None = None, overlay=None):
        self.snap = snap
        self._node: dict[str, GraphNode] = {n.id: n for n in snap.nodes}
        self._edge_by_key: dict[str, GraphEdge] = {e.key: e for e in snap.edges}
        self._out: dict[str, list[GraphEdge]] = {}
        self._in: dict[str, list[GraphEdge]] = {}
        # Fold the overlay (custom Tier-0, and - next wave - remediated edges/nodes) in.
        t0extra = set(extra_tier0 or ())
        rem_edges: set[str] = set()
        rem_nodes: set[str] = set()
        if overlay is not None:
            t0extra |= set(overlay.tier0)
            rem_edges = set(overlay.remediated_edges)
            rem_nodes = set(overlay.remediated_nodes)
        # DiGraph of attack edges for path-finding (first edge per pair, snapshot-sorted),
        # carrying the traversal weight so cost-aware ("easiest") paths work. Remediated
        # edges/nodes are treated as removed.
        self.attack = nx.DiGraph()
        for e in snap.edges:
            self._out.setdefault(e.source, []).append(e)
            self._in.setdefault(e.target, []).append(e)
            if (e.type in _TRAVERSABLE_TYPES and e.key not in rem_edges
                    and e.source not in rem_nodes and e.target not in rem_nodes
                    and not self.attack.has_edge(e.source, e.target)):
                w = _POSITIONING_TYPES.get(e.type, float(e.weight))
                self.attack.add_edge(e.source, e.target, edge=e, weight=w)
        # Tier-0 = the derived set, plus any user-defined high-value targets that exist here.
        self._custom_tier0 = {t for t in t0extra if t in self._node}
        self.tier0_ids = {n.id for n in snap.nodes if n.tier0} | self._custom_tier0

    def is_tier0(self, node_id: str) -> bool:
        return node_id in self.tier0_ids

    # ---- helpers ------------------------------------------------------
    def has(self, node_id: str) -> bool:
        return node_id in self._node

    def _edge_between(self, src: str, dst: str) -> GraphEdge | None:
        if self.attack.has_edge(src, dst):
            return self.attack[src][dst]["edge"]
        for e in self._out.get(src, []):
            if e.target == dst:
                return e
        return None

    def _path_edges(self, path: list[str]) -> list[GraphEdge]:
        out = []
        for a, b in zip(path, path[1:]):
            e = self._edge_between(a, b)
            if e:
                out.append(e)
        return out

    # ---- queries ------------------------------------------------------
    def meta(self) -> dict:
        m = self.snap.counts()
        m["tier0"] = len(self.tier0_ids)   # reflect custom Tier-0, not just the baked-in flags
        # Distinct relationship types the path engine can traverse - powers the explorer's
        # optional "Via" filter so a user can constrain a path to specific primitives.
        m["edge_types"] = sorted({
            (data["edge"].type.value if hasattr(data["edge"].type, "value")
             else str(data["edge"].type))
            for _, _, data in self.attack.edges(data=True)
        })
        return m

    def search(self, q: str, limit: int = 50) -> list[GraphNode]:
        ql = (q or "").strip().lower()
        if not ql:
            return []
        hits = [n for n in self.snap.nodes
                if ql in n.label.lower() or ql in n.id.lower()]
        # Best matches first: exact/startswith label, then Tier-0, then alphabetical.
        hits.sort(key=lambda n: (
            0 if n.label.lower() == ql else 1 if n.label.lower().startswith(ql) else 2,
            not n.tier0, n.label.lower(), n.id))
        return hits[:limit]

    def expand(self, node_id: str, direction: str = "both",
               limit: int = DEFAULT_NODE_CAP) -> Subgraph:
        sg = Subgraph()
        if not self.has(node_id):
            sg.message = "Node not found in this scan's graph."
            return sg
        sg.node_ids.add(node_id)
        cand: list[GraphEdge] = []
        if direction in ("out", "both"):
            cand += self._out.get(node_id, [])
        if direction in ("in", "both"):
            cand += self._in.get(node_id, [])
        # Stable order; derived (attack) edges first so a capped expand keeps the interesting ones.
        cand.sort(key=lambda e: (not e.derived, e.key))
        for e in cand:
            if len(sg.node_ids) >= limit:
                sg.truncated = True
                break
            sg.node_ids.add(e.source)
            sg.node_ids.add(e.target)
            sg.edges.append(e)
        if sg.truncated:
            sg.message = f"Showing the first {limit} neighbours; narrow the view to see more."
        return sg

    def _lengths(self, source: str, mode: str, graph=None) -> dict[str, float]:
        g = graph if graph is not None else self.attack
        if mode == "easiest":
            return nx.single_source_dijkstra_path_length(g, source, weight="weight")
        return nx.single_source_shortest_path_length(g, source)

    def _filtered_attack(self, via):
        """The attack graph restricted to the given relationship-type names, or the full graph
        when `via` is empty. Powers the explorer's optional 'Via' filter across every trace."""
        allow = {str(v).strip().lower() for v in via if str(v).strip()} if via else None
        if not allow:
            return self.attack, None

        def _keep_edge(u, v):
            e = self.attack[u][v]["edge"]
            t = (e.type.value if hasattr(e.type, "value") else str(e.type)).lower()
            return t in allow
        return nx.subgraph_view(self.attack, filter_edge=_keep_edge), allow

    def _best_path(self, source: str, target: str, mode: str, graph=None) -> list[str]:
        g = graph if graph is not None else self.attack
        if mode == "easiest":
            return nx.dijkstra_path(g, source, target, weight="weight")
        return nx.shortest_path(g, source, target)

    def paths_to_tier0(self, source: str, max_paths: int = 25,
                       mode: str = "hops", via=None) -> Subgraph:
        sg = Subgraph()
        if not self.has(source):
            sg.message = "Node not found in this scan's graph."
            return sg
        graph, allow = self._filtered_attack(via)
        is_t0 = source in self.tier0_ids
        if source not in graph or graph.out_degree(source) == 0:
            sg.node_ids.add(source)
            if allow:
                sg.message = "This node has no outbound edges of the selected relationship type(s)."
            else:
                sg.message = ("This is a Tier-0 asset with no outbound escalation edges." if is_t0
                              else "This node has no outbound escalation edges.")
            return sg
        # Rank Tier-0 targets by distance - hop count, or (mode='easiest') summed edge weight
        # so the most *likely* route wins over the merely shortest. No hop limit. A Tier-0 node
        # shows onward paths to OTHER Tier-0 assets (lateral movement), excluding itself.
        lengths = self._lengths(source, mode, graph=graph)
        targets = sorted((lengths[t], t) for t in self.tier0_ids if t in lengths and t != source)
        dest = "other Tier-0 assets" if is_t0 else "Tier-0"
        if not targets:
            sg.node_ids.add(source)
            if allow:
                sg.message = "No path to a Tier-0 asset using the selected relationship type(s)."
            else:
                sg.message = ("This is a Tier-0 asset with no onward paths to other Tier-0 assets." if is_t0
                              else "No escalation path to a Tier-0 asset.")
            return sg
        for _cost, tgt in targets[:max_paths]:
            path = self._best_path(source, tgt, mode, graph=graph)
            sg.paths.append(path)
            for n in path:
                sg.node_ids.add(n)
            for e in self._path_edges(path):
                sg.edges.append(e)
                sg.path_edge_keys.add(e.key)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        extra = len(targets) - max_paths
        how = "easiest" if mode == "easiest" else "shortest"
        sg.message = (f"{len(sg.paths)} {how} path(s) to {dest}"
                      + (f" (+{extra} more target(s) not shown)" if extra > 0 else "")
                      + (f" · via {', '.join(sorted(allow))}" if allow else "") + ".")
        return sg

    def _impact_key(self, nid: str, dist: dict[str, int]):
        """Rank a reachable node: Tier-0 first, then onward reach (centrality), then nearer, name."""
        node = self._node.get(nid)
        return (
            nid not in self.tier0_ids,
            -(self.attack.out_degree(nid) if nid in self.attack else 0),
            dist.get(nid, 1 << 30),
            (node.label.lower() if node else nid),
        )

    def _holders_of(self, node_id: str) -> list[str]:
        """Principals that hold / can exercise this node (sources of a holding edge into it)."""
        seen: dict[str, None] = {}
        for e in self._in.get(node_id, []):
            if e.type in _HOLDING_TYPES and e.source != node_id:
                seen.setdefault(e.source, None)
        return list(seen.keys())

    def blast_radius(self, source: str, cap: int = DEFAULT_NODE_CAP) -> Subgraph:
        """Everything `source` can reach downstream: the forward shortest-path tree over the
        attack graph - the damage that follows if this identity is compromised. Reachable nodes
        are ranked by impact (Tier-0 first, then onward reach / centrality), so when the view is
        capped the most damaging targets are always the ones kept.

        A role (or any node with no outbound escalation edges) is a sink: nothing escalates *out*
        of it. For such a node the blast radius is instead what its HOLDERS can do - the reach you
        inherit by obtaining the role - so a Tier-0 role still shows 'what else can be done'."""
        sg = Subgraph()
        if not self.has(source):
            sg.message = "Node not found in this scan's graph."
            return sg
        if source not in self.attack or self.attack.out_degree(source) == 0:
            holders = self._holders_of(source)
            if holders:
                return self._blast_from_holders(source, holders, cap)
            sg.node_ids.add(source)
            sg.message = "This node has no outbound escalation edges and no holders - nothing downstream."
            return sg
        paths = nx.single_source_shortest_path(self.attack, source)   # node -> shortest path
        reachable = [n for n in paths if n != source]
        t0_reached = sum(1 for n in reachable if n in self.tier0_ids)
        dist = {n: len(p) for n, p in paths.items()}
        reachable.sort(key=lambda n: self._impact_key(n, dist))
        sg.node_ids.add(source)
        for nid in reachable:
            if len(sg.node_ids) >= cap:
                sg.truncated = True
                break
            chain = paths[nid]
            for x in chain:
                sg.node_ids.add(x)
            sg.paths.append(chain)
            for e in self._path_edges(chain):
                sg.edges.append(e)
                sg.path_edge_keys.add(e.key)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        src = self._node.get(source)
        name = src.label if src else source
        sg.message = (f"Blast radius of {name}: reaches {len(reachable)} node(s), "
                      f"{t0_reached} Tier-0" + (" (view truncated)" if sg.truncated else "") + ".")
        return sg

    def all_relationships(self, source: str, cap: int = DEFAULT_NODE_CAP) -> Subgraph:
        """The node's DIRECT relationships over EVERY relationship type - not just the
        escalation edges the attack views use, but membership, ownership, role/app-role
        holdings, managed identities, Key Vault access, containment, PIM eligibility, and
        the derived abuse edges too. Exactly one hop: the source node plus every node it is
        directly connected to, and the edges between them. No transitive reach.

        This is the 'show me everything this node is directly connected to' view, distinct
        from blast_radius (escalation reach → Tier-0) and expand (one hop, escalation-only)."""
        sg = Subgraph()
        if not self.has(source):
            sg.message = "Node not found in this scan's graph."
            return sg
        sg.node_ids.add(source)
        # One hop only: every edge leaving the source, over the full outgoing adjacency
        # (all edge types). Derived (abuse) edges first, then by key, so the cap - if ever
        # hit - drops the least-interesting direct edges rather than the abuse ones.
        direct_edges = sorted(self._out.get(source, []),
                              key=lambda x: (not x.derived, x.key))
        total_direct = len(direct_edges)
        kept: list[GraphEdge] = []
        for e in direct_edges:
            if e.target not in sg.node_ids and len(sg.node_ids) >= cap:
                continue                    # neighbour would exceed the cap - skip its edge
            sg.node_ids.add(e.target)
            kept.append(e)
        sg.edges = sorted(kept, key=lambda e: e.key)
        sg.truncated = len(kept) < total_direct
        src = self._node.get(source)
        name = src.label if src else source
        sg.message = (f"{name}: {total_direct} direct relationship(s) across all edge types"
                      + (f" (showing {len(kept)})" if sg.truncated else "") + ".")
        return sg

    def _blast_from_holders(self, node_id: str, holders: list[str], cap: int) -> Subgraph:
        """Blast radius of a sink (a role/target): the combined onward reach of everything that
        holds it. Shows who holds it (holding edges into the node) plus what those holders can do."""
        sg = Subgraph()
        sg.node_ids.add(node_id)
        # Who holds it - draw the holding edges so the panel reads "N principals hold X".
        for e in self._in.get(node_id, []):
            if e.type in _HOLDING_TYPES and e.source in set(holders):
                sg.edges.append(e)
                sg.node_ids.add(e.source)
        # Union the holders' forward reach, keeping each target's shortest path from any holder.
        reach: dict[str, tuple[int, list[str]]] = {}
        for h in holders:
            if h not in self.attack:
                continue
            for tgt, p in nx.single_source_shortest_path(self.attack, h).items():
                if tgt == h:
                    continue
                if tgt not in reach or len(p) < reach[tgt][0]:
                    reach[tgt] = (len(p), p)
        reachable = [t for t in reach if t != node_id]
        t0_reached = sum(1 for n in reachable if n in self.tier0_ids)
        dist = {t: reach[t][0] for t in reach}
        reachable.sort(key=lambda n: self._impact_key(n, dist))
        for nid in reachable:
            if len(sg.node_ids) >= cap:
                sg.truncated = True
                break
            chain = reach[nid][1]
            for x in chain:
                sg.node_ids.add(x)
            sg.paths.append(chain)
            for e in self._path_edges(chain):
                sg.edges.append(e)
                sg.path_edge_keys.add(e.key)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        n = self._node.get(node_id)
        name = n.label if n else node_id
        what = "role" if (n and n.kind == "AZRole") else "asset"
        sg.message = (f"Blast radius of {name}: held by {len(holders)} principal(s); "
                      f"holding this {what} reaches {len(reachable)} node(s), {t0_reached} Tier-0"
                      + (" (view truncated)" if sg.truncated else "") + ".")
        return sg

    def path(self, source: str, target: str, mode: str = "hops", via=None) -> Subgraph:
        """Best path from source to target. `via` (optional list of relationship-type names)
        restricts the path to ONLY those edge types, so a user can ask e.g. 'how does A reach B
        using only CanGrantRole / CanStealManagedIdentity'."""
        sg = Subgraph()
        if not self.has(source) or not self.has(target):
            sg.message = "Source or target not found in this scan's graph."
            return sg
        graph, allow = self._filtered_attack(via)
        try:
            path = self._best_path(source, target, mode, graph=graph)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            sg.node_ids.update({source, target})
            sg.message = ("No path between these nodes using the selected relationship type(s)."
                          if allow else "No escalation path between these nodes.")
            return sg
        sg.paths.append(path)
        for n in path:
            sg.node_ids.add(n)
        for e in self._path_edges(path):
            sg.edges.append(e)
            sg.path_edge_keys.add(e.key)
        how = "easiest" if mode == "easiest" else "shortest"
        sg.message = f"{how.capitalize()} path found ({len(path) - 1} hop(s))."
        if allow:
            sg.message += f" · via {', '.join(sorted(allow))}"
        return sg

    def reachable_from(self, source: str, via=None, cap: int = DEFAULT_NODE_CAP) -> Subgraph:
        """Everything reachable FROM `source` over the escalation graph, to ANY node (not only
        Tier-0), as a forward shortest-path DAG. With `via` it is restricted to the selected
        relationship types - the 'From → everything, via these primitives' objective, the
        counterpart to paths_to_tier0's 'From → Tier-0'."""
        from collections import deque
        sg = Subgraph()
        if not self.has(source):
            sg.message = "Node not found in this scan's graph."
            return sg
        graph, allow = self._filtered_attack(via)
        if source not in graph or graph.out_degree(source) == 0:
            sg.node_ids.add(source)
            sg.message = ("This node has no outbound edges of the selected relationship type(s)."
                          if allow else "This node has no outbound escalation edges.")
            return sg
        # Forward BFS hop-distances, nearest-first order.
        dist = {source: 0}
        order = [source]
        dq = deque([source])
        while dq:
            u = dq.popleft()
            for v in graph.successors(u):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    order.append(v)
                    dq.append(v)
        kept = set()
        for n in order:
            if len(kept) >= cap:
                sg.truncated = True
                break
            kept.add(n)
        # DAG edges: every edge (u,v) that advances one hop, both endpoints retained.
        for u in kept:
            for v in graph.successors(u):
                if v in kept and dist.get(v) == dist[u] + 1:
                    e = self._edge_between(u, v)
                    if e:
                        sg.edges.append(e)
                        sg.path_edge_keys.add(e.key)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        sg.node_ids = set(kept)
        src = self._node.get(source)
        name = src.label if src else source
        reached = len(dist) - 1
        sg.message = (f"{reached} node(s) reachable from {name}"
                      + (f" (showing {len(kept) - 1})" if sg.truncated else "")
                      + (f" · via {', '.join(sorted(allow))}" if allow else "") + ".")
        return sg

    def _shortest_dag(self, match=None, *, cap: int = 1500, targets=None) -> "tuple[Subgraph, int]":
        """Shared engine for every 'reach Tier-0' preset. Reverse multi-source BFS from the
        objective set (`targets`, defaulting to all Tier-0 nodes) gives each node its
        hop-distance to an objective; then, for each source (all of them, or only those
        matching `match`), it expands the FULL shortest-path DAG toward the objective - every
        edge (u,v) with dist[v]==dist[u]-1, branching on ties. This is the fix that makes a
        source which reaches several objectives at the same distance show ALL of those edges,
        not the single one a succ-pointer happened to keep. Returns the subgraph and the number
        of matched sources."""
        from collections import deque
        sg = Subgraph()
        base = self.tier0_ids if targets is None else targets
        tset = {t for t in base if t in self.attack}
        if not tset:
            if targets is None:
                sg.message = "No Tier-0 targets in the attack graph. Mark some high-value nodes as Tier-0."
            else:
                sg.message = "Target is not reachable in the attack graph."
            return sg, 0
        rev = self.attack.reverse(copy=False)
        dist: dict[str, int] = {t: 0 for t in tset}
        dq = deque(tset)
        while dq:
            u = dq.popleft()
            for v in rev.successors(u):          # v -> u exists in the attack graph
                if v not in dist:
                    dist[v] = dist[u] + 1
                    dq.append(v)
        sources = [n for n, d in dist.items()
                   if d > 0 and (match is None or match(self._node.get(n)))]
        sources.sort(key=lambda n: (dist[n],
                                    (self._node.get(n).label.lower() if self._node.get(n) else n)))
        matched = 0
        for s in sources:
            if len(sg.node_ids) >= cap:
                sg.truncated = True
                break
            matched += 1
            stack = [s]
            local = {s}
            sg.node_ids.add(s)
            head: list[str] = []
            while stack:
                u = stack.pop()
                if dist.get(u, 0) == 0:
                    continue                     # Tier-0 target reached - sink
                if len(sg.node_ids) >= cap:
                    sg.truncated = True
                    break
                for v in self.attack.successors(u):
                    if dist.get(v, 1 << 30) != dist[u] - 1:
                        continue                 # keep only hops that advance toward Tier-0
                    e = self._edge_between(u, v)
                    if e:
                        sg.edges.append(e)
                        sg.path_edge_keys.add(e.key)
                    sg.node_ids.add(v)
                    if v not in local:
                        local.add(v)
                        stack.append(v)
                    if not head:
                        head = [u, v]
            if head:
                sg.paths.append(head)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        return sg, matched

    def overview(self, cap: int = 1500) -> Subgraph:
        """Every attack path to Tier-0 in one view: the shortest-path DAG from all principals
        that can reach any Tier-0 target (all tied shortest routes, not a single forest edge
        per node)."""
        sg, matched = self._shortest_dag(None, cap=cap)
        if sg.node_ids or matched:
            sg.message = (f"{matched} source(s) can escalate to Tier-0 - showing every "
                          f"shortest attack path." + (" (truncated)" if sg.truncated else ""))
        return sg

    def _tier0_reasons(self, node_id: str) -> list[dict]:
        """Why this node is Tier-0: the role(s) it holds or the broad-scope RBAC it has, each
        with a plain description. Empty for non-Tier-0 nodes."""
        n = self._node.get(node_id)
        if n is None or node_id not in self.tier0_ids:
            return []
        from . import primitives as P
        from .. import constants as C
        reasons: list[dict] = []
        if node_id in self._custom_tier0:
            reasons.append({"label": "Marked Tier-0 by an analyst", "desc": P.CUSTOM_TIER0_DESC})
        if n.kind == "AZRole":
            info = P.tier0_role_info(n.label)
            if info:
                reasons.append({"label": "Tier-0 Entra role: " + n.label, "desc": info})
        seen: set[str] = set()
        for e in self._out.get(node_id, []):
            if e.type in ("EffectiveRole", "HasEntraRole"):
                role = self._node.get(e.target)
                rn = role.label if role else e.target
                info = P.tier0_role_info(rn)
                if info and rn.lower() not in seen:
                    seen.add(rn.lower())
                    via = ""
                    path = e.evidence.get("path") if isinstance(e.evidence, dict) else None
                    if isinstance(path, list) and path:
                        via = " (" + "; ".join(str(x) for x in path[:3]) + ")"
                    reasons.append({"label": "Holds " + rn + via, "desc": info})
        for e in self._out.get(node_id, []):
            if e.type == "HasRBACRole" and isinstance(e.evidence, dict):
                role = (e.evidence.get("role") or "").lower()
                scope = e.evidence.get("scope") or ""
                if role in C.RBAC_ESCALATION_ROLES and C.is_at_broad_scope(scope):
                    reasons.append({"label": role.title() + " at " + _scope_label(scope),
                                    "desc": P.RBAC_BROAD_TIER0_DESC})
                    break
        if not reasons:
            reasons.append({"label": "Tier-0 asset",
                            "desc": "Holds a privileged role or a broad-scope RBAC assignment "
                                    "that grants control of the tenant or a subscription."})
        return reasons

    def node_detail(self, node_id: str) -> dict | None:
        """Full collected detail for one node: kind, flags, tags, all props, degree, the abuse
        primitives it can perform, how many Tier-0 targets it reaches, how many principals can
        reach it, and its nearest Tier-0 distance. Powers the details panel."""
        n = self._node.get(node_id)
        if n is None:
            return None
        reaches_count = 0
        nearest = None
        if node_id in self.attack:
            # Count Tier-0 reachable from here, EXCLUDING the node itself - so a Tier-0 node
            # correctly reports its onward reach to *other* Tier-0 assets instead of a flat 0.
            lengths = nx.single_source_shortest_path_length(self.attack, node_id)
            t0 = [lengths[t] for t in self.tier0_ids if t in lengths and t != node_id]
            reaches_count = len(t0)
            nearest = min(t0) if t0 else None
        attackers = len(nx.ancestors(self.attack, node_id)) if node_id in self.attack else 0
        # Outgoing abuse primitives this node can perform, with counts.
        out_prims: dict[str, int] = {}
        for e in self._out.get(node_id, []):
            if e.derived:
                out_prims[e.primitive or e.type] = out_prims.get(e.primitive or e.type, 0) + 1
        return {
            "id": n.id, "kind": n.kind, "label": n.label,
            "tier0": node_id in self.tier0_ids, "critical": n.critical, "eligible": n.eligible,
            "custom_tier0": node_id in self._custom_tier0,
            "tags": n.tags, "props": n.props,
            "out_degree": len(self._out.get(node_id, [])),
            "in_degree": len(self._in.get(node_id, [])),
            "reaches_tier0": reaches_count > 0,
            "reaches_tier0_count": reaches_count,
            "nearest_tier0_hops": nearest,
            "attackers_count": attackers,
            "out_primitives": dict(sorted(out_prims.items(), key=lambda kv: (-kv[1], kv[0]))),
            "tier0_reasons": self._tier0_reasons(node_id),
        }

    # ---- predefined queries + path listing ----------------------------
    def paths_list(self, limit: int = 300) -> list[dict]:
        """One row per principal that can reach Tier-0: nearest target + hop count. Drives the
        left-side path list; clicking a row traces that principal's paths."""
        from collections import deque
        tset = {t for t in self.tier0_ids if t in self.attack}
        if not tset:
            return []
        rev = self.attack.reverse(copy=False)
        dist = {t: 0 for t in tset}
        nearest = {t: t for t in tset}
        dq = deque(tset)
        while dq:
            u = dq.popleft()
            for v in rev.successors(u):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    nearest[v] = nearest[u]
                    dq.append(v)
        # How many distinct Tier-0 targets each source can reach (breadth of impact).
        reaches: dict[str, int] = {}
        for t in tset:
            for anc in nx.ancestors(self.attack, t):
                reaches[anc] = reaches.get(anc, 0) + 1
        rows = []
        for nid, d in dist.items():
            if d == 0:
                continue
            node = self._node.get(nid)
            tgt = self._node.get(nearest[nid])
            rows.append({
                "source": nid, "source_label": node.label if node else nid,
                "source_kind": node.kind if node else "AZUnknown",
                "target_label": tgt.label if tgt else nearest[nid], "hops": d,
                "reaches": reaches.get(nid, 1),
            })
        # Most impactful first (reaches the most Tier-0), then nearest, then name.
        rows.sort(key=lambda r: (-r["reaches"], r["hops"], r["source_label"].lower()))
        return rows[:limit]

    def _paths_from_matching(self, predicate, label: str) -> Subgraph:
        """Full shortest-path DAG to Tier-0, restricted to sources matching a predicate.
        Shares the engine with overview() so every 'reach Tier-0' preset shows all tied
        shortest routes (the fix for the missing SP→Tier-0-group edges), not one per node."""
        sg, matched = self._shortest_dag(predicate, cap=DEFAULT_NODE_CAP)
        # _shortest_dag treats every Tier-0 node as a sink (distance 0), so a MATCHING account
        # that already holds Tier-0 AND can pivot to OTHER Tier-0 assets is dropped as a source
        # (e.g. a disabled Owner that can add credentials to Tier-0 SPs). Add those back with
        # their shortest path to the nearest OTHER Tier-0 - the most severe case, not the least.
        added = False
        for nid in self.tier0_ids:
            if nid in sg.node_ids or nid not in self.attack:
                continue
            n = self._node.get(nid)
            if not predicate(n):
                continue
            lengths = nx.single_source_shortest_path_length(self.attack, nid)
            tgts = sorted((lengths[t], t) for t in self.tier0_ids if t in lengths and t != nid)
            if not tgts:
                continue                              # holds Tier-0 but reaches no OTHER Tier-0
            path = nx.shortest_path(self.attack, nid, tgts[0][1])
            sg.paths.append(path)
            for x in path:
                sg.node_ids.add(x)
            for e in self._path_edges(path):
                sg.edges.append(e)
                sg.path_edge_keys.add(e.key)
            matched += 1
            added = True
        if added:                                     # de-dup edges the extra paths may repeat
            seen: dict[str, GraphEdge] = {}
            for e in sg.edges:
                seen.setdefault(e.key, e)
            sg.edges = sorted(seen.values(), key=lambda e: e.key)
        if matched or not sg.message:
            sg.message = f"{matched} {label} can reach Tier-0."
        return sg

    def paths_to(self, target: str, cap: int = DEFAULT_NODE_CAP) -> Subgraph:
        """Every principal that can reach `target`, with all tied shortest routes to it - the
        reverse of paths_to_tier0 for an arbitrary node chosen as the sole objective. Used by
        the explorer when only a 'To' is set (no 'From'): show everything that leads to it."""
        sg = Subgraph()
        if not self.has(target):
            sg.message = "Target not found in this scan's graph."
            return sg
        sg, matched = self._shortest_dag(None, cap=cap, targets={target})
        sg.node_ids.add(target)                          # keep the objective even if isolated
        tn = self._node.get(target)
        name = tn.label if tn else target
        if matched:
            sg.message = f"{matched} principal(s) can reach {name}."
        elif not sg.message:
            sg.message = f"Nothing can reach {name}."
        return sg

    def _edges_by_type(self, types: set[str], label: str,
                       cap: int = 500, edge_cap: int = 900) -> Subgraph:
        # Bound BOTH nodes and edges - some relations (storage-key / managed-identity access)
        # are near-complete many-to-many and produce thousands of edges, an unreadable hairball.
        # Order edges so the most consequential survive the cap: those landing on a Tier-0
        # target first, then ones whose source can itself reach Tier-0, then the rest.
        sg = Subgraph()
        matching = [e for e in self.snap.edges if e.type in types]
        total = len(matching)
        # Keep the most consequential edges under the cap: those landing on a Tier-0 target
        # first (cheap check), then the rest, stable by key.
        matching.sort(key=lambda e: (0 if e.target in self.tier0_ids else 1, e.key))
        for e in matching:
            if len(sg.node_ids) >= cap or len(sg.edges) >= edge_cap:
                sg.truncated = True
                break
            sg.edges.append(e)
            sg.path_edge_keys.add(e.key)
            sg.paths.append([e.source, e.target])
            sg.node_ids.add(e.source)
            sg.node_ids.add(e.target)
        shown = f"showing {len(sg.edges)} of {total}" if sg.truncated else f"{len(sg.edges)}"
        sg.message = f"{shown} {label}." + (" (view capped)" if sg.truncated else "")
        return sg

    def _highlight_nodes(self, predicate, label: str, cap: int = DEFAULT_NODE_CAP) -> Subgraph:
        """Show nodes matching a predicate, each with its shortest onward path to Tier-0 (if any).
        Unlike _paths_from_matching, a matching node is shown even when it reaches no Tier-0 -
        useful for 'these assets exist and are dangerous in themselves' presets."""
        sg = Subgraph()
        matched = [nid for nid, n in self._node.items() if predicate(n)]
        for nid in matched:
            if len(sg.node_ids) >= cap:
                sg.truncated = True
                break
            sg.node_ids.add(nid)
            if nid in self.attack:
                lengths = nx.single_source_shortest_path_length(self.attack, nid)
                tgts = sorted((lengths[t], t) for t in self.tier0_ids if t in lengths and t != nid)
                if tgts:
                    path = nx.shortest_path(self.attack, nid, tgts[0][1])
                    sg.paths.append(path)
                    for x in path:
                        sg.node_ids.add(x)
                    for e in self._path_edges(path):
                        sg.edges.append(e)
                        sg.path_edge_keys.add(e.key)
        seen: dict[str, GraphEdge] = {}
        for e in sg.edges:
            seen.setdefault(e.key, e)
        sg.edges = sorted(seen.values(), key=lambda e: e.key)
        sg.message = f"{len(matched)} {label}." + (" (truncated)" if sg.truncated else "")
        return sg

    @staticmethod
    def _is_guest(n) -> bool:
        return bool(n) and n.kind == "AZUser" and (
            "guest" in (n.tags or []) or str(n.props.get("userType", "")).lower() == "guest")

    def run_preset(self, name: str) -> Subgraph:
        if name == "sp-to-tier0":
            return self._paths_from_matching(lambda n: bool(n) and n.kind == "AZServicePrincipal",
                                             "service principals")
        if name == "guests-to-tier0":
            return self._paths_from_matching(self._is_guest, "guest / external accounts")
        if name == "disabled-to-tier0":
            return self._paths_from_matching(lambda n: bool(n) and n.props.get("accountEnabled") is False,
                                             "disabled accounts")
        if name == "stale-privileged":
            return self._highlight_nodes(
                lambda n: bool(n) and n.props.get("accountEnabled") is False and n.id in self.tier0_ids,
                "disabled Tier-0 account(s)")
        if name == "app-consent":
            return self._edges_by_type({"CanGrantRole", "CanGrantAppRole"},
                                       "dangerous app-permission grant paths")
        if name == "mi-abuse":
            return self._edges_by_type({"CanStealManagedIdentity"}, "managed-identity abuse paths")
        if name == "kv-readers":
            return self._edges_by_type({"CanReachKVSecret"}, "Key Vault secret-read paths")
        if name == "storage-keys":
            return self._edges_by_type({"CanGetStorageKey"}, "storage-key access paths")
        if name == "owners":
            return self._edges_by_type({"Owns", "CanAddOwner"}, "ownership edges")
        if name == "crown-jewels":
            return self._highlight_nodes(lambda n: bool(n) and n.id in self.tier0_ids,
                                         "Tier-0 asset(s)")
        if name == "pim-eligible":
            return self._edges_by_type({"EligibleForRole"}, "PIM eligibility edges")
        if name == "reset-password":
            return self._edges_by_type({"CanResetPassword"}, "password-reset abuse paths")
        if name == "add-secret":
            return self._edges_by_type({"CanAddSecret"}, "credential-injection paths")
        if name == "add-member":
            return self._edges_by_type({"CanAddMember"}, "group-membership injection paths")
        if name == "rbac-escalation":
            return self._edges_by_type({"CanEscalateRBAC"}, "Azure RBAC self-escalation paths")
        if name == "aks-exec":
            return self._edges_by_type({"CanExecAKS"}, "AKS cluster exec paths")
        if name == "container-push":
            return self._edges_by_type({"CanPushContainer"}, "container image-push paths")
        if name == "blob-access":
            return self._edges_by_type({"CanReadStorageBlob"}, "storage blob data-access paths")
        if name == "foreign-apps":
            return self._highlight_nodes(
                lambda n: bool(n) and n.kind == "AZServicePrincipal" and "foreign_tenant" in (n.tags or ()),
                "external / multi-tenant service principal(s)")
        return self.overview()   # "shortest-to-tier0" and default

    def edge_detail(self, edge_key: str) -> dict | None:
        """Provenance for one edge: the abuse primitive, why it exists, difficulty, conditions,
        and the concrete evidence (role/scope/reason). Powers the edge provenance panel."""
        e = self._edge_by_key.get(edge_key)
        if e is None:
            return None
        s = self._node.get(e.source)
        t = self._node.get(e.target)
        return {
            "id": e.key, "type": e.type, "primitive": e.primitive, "derived": e.derived,
            "weight": e.weight, "why": e.why, "conditions": e.conditions,
            "evidence": e.evidence, "count": e.count,
            "source": {"id": e.source, "label": s.label if s else e.source,
                       "kind": s.kind if s else "AZUnknown"},
            "target": {"id": e.target, "label": t.label if t else e.target,
                       "kind": t.kind if t else "AZUnknown", "tier0": e.target in self.tier0_ids},
        }

    # ---- rendering ----------------------------------------------------
    def to_elements(self, sg: Subgraph) -> dict:
        """Cytoscape.js elements for a subgraph."""
        nodes = []
        for nid in sorted(sg.node_ids):
            n = self._node.get(nid) or GraphNode(id=nid, kind="AZUnknown", label=nid)
            on_path = any(nid in p for p in sg.paths)
            nodes.append({"data": {
                "id": n.id, "label": n.label, "kind": n.kind,
                "tier0": nid in self.tier0_ids, "critical": n.critical, "eligible": n.eligible,
                "onPath": on_path,
            }})
        edges = []
        for e in sg.edges:
            edges.append({"data": {
                "id": e.key, "source": e.source, "target": e.target,
                # Always a string (never null) so the Cytoscape label mapping has a data field to
                # bind to - a null here floods the console with "no mapping for property label".
                "type": e.type, "primitive": e.primitive or "", "derived": e.derived,
                "count": e.count, "onPath": e.key in sg.path_edge_keys,
            }})
        return {
            "nodes": nodes, "edges": edges,
            "paths": sg.paths, "truncated": sg.truncated, "message": sg.message,
        }
