"""Single source of truth for attack-path computation over the derived identity graph.

Every consumer builds on the primitives here, so the CLI, the report, the web UI and the
graph explorer all agree on three things that used to be re-defined (and drift) in each
call site:

  * what an *escalation edge* is (`ESCALATION_EDGES` / `escalation_adjacency`);
  * what counts as a high-value *target* (`holds_tier0` vs `is_tier0_target`, `is_sink`);
  * how a path is *traversed* (`shortest_path` BFS, `k_shortest_paths` Yen's algorithm,
    `blast_radius` reachability).

Nothing here is heuristic or AI-driven: a path only ever contains nodes and edges that
exist in the collection, so it is exact and reproducible. The scoring layer narrates and
ranks these paths; it never invents them.

Tier-0 vocabulary (the distinction the UI and the explorer must share):
  * ``holds_tier0(n)``  - the node *is* a Tier-0 crown jewel (standing privilege: a Global
    Administrator, an Owner-at-root group, an SP with a Tier-0 role). It is the END of a
    path, the thing an attacker wants to become.
  * ``is_tier0_target(n)`` - the node is a worthwhile *objective* to route a path to: a
    Tier-0 holder, a PIM-eligible shadow admin (one self-activation away), or a principal
    that can itself reach Tier-0. A stepping stone as well as a destination.
"""
from __future__ import annotations

from collections import deque

from .model import EdgeType, Graph, NodeKind

# ── Edge vocabulary ─────────────────────────────────────────────────────────────
# Escalation edges used for reachability / path analysis. MEMBER_OF and OWNS are
# relationships traversed to get into position, not abuse primitives in their own right.
ESCALATION_EDGES: "set[EdgeType]" = {
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
    EdgeType.CAN_STEAL_MANAGED_IDENTITY, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_GET_STORAGE_KEY, EdgeType.CAN_EXEC_AKS,
    EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_PUSH_CONTAINER,
    EdgeType.ELIGIBLE_FOR_ROLE,
    EdgeType.CONTROLS_TENANT,   # a critical Tier-0 role -> synthetic TenantControl (takeover)
    # Graph application-permission primitives (Workstream D): takeover / control-weakening / exfil.
    EdgeType.CAN_CONTROL_TENANT, EdgeType.CAN_WEAKEN_CONTROLS, EdgeType.CAN_EXFILTRATE_DATA,
    EdgeType.MEMBER_OF, EdgeType.OWNS,
}
TRAVERSAL_EDGES: "set[EdgeType]" = {EdgeType.MEMBER_OF, EdgeType.OWNS}
# Edges by which a principal already HOLDS a role / group / scope (not an escalation, a
# standing grant). blast_radius seeds from these so a principal's own privileges count.
HOLDING_EDGES: "set[EdgeType]" = {EdgeType.HAS_ENTRA_ROLE, EdgeType.EFFECTIVE_ROLE,
                                  EdgeType.MEMBER_OF, EdgeType.HAS_RBAC_ROLE}
# Abuse primitives: the escalation edges that are a real attack move, not plumbing.
ABUSE_EDGES: "set[EdgeType]" = ESCALATION_EDGES - TRAVERSAL_EDGES

# The two planes an abuse edge can live on. A single finding's path never mixes them: an
# Azure RBAC grant and an Entra role grant are different attacks on different control planes.
AZURE_PLANE_EDGES: "set[EdgeType]" = {
    EdgeType.CAN_ESCALATE_RBAC, EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_GET_STORAGE_KEY,
    EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_STEAL_MANAGED_IDENTITY,
    EdgeType.CAN_EXEC_AKS, EdgeType.CAN_PUSH_CONTAINER,
}
ENTRA_PLANE_EDGES: "set[EdgeType]" = {
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.ELIGIBLE_FOR_ROLE,
}
# Edges drawn in the attack-graph visualization: abuse primitives plus the plumbing
# (MemberOf/Owns/EffectiveRole) that connects them into a readable graph.
VIZ_EDGES: "set[EdgeType]" = ABUSE_EDGES | {
    EdgeType.MEMBER_OF, EdgeType.OWNS, EdgeType.EFFECTIVE_ROLE,
}

# Resource kinds that are sensitive data / credential sinks: valid path objectives even
# though they are not Tier-0 identities. A container registry is a supply-chain sink; the
# synthetic DataSink / SecurityControls nodes (Workstream D) are objectives for the data-plane
# and control-weakening Graph primitives.
SINK_KINDS: "set[NodeKind]" = {NodeKind.KEY_VAULT, NodeKind.STORAGE, NodeKind.AKS,
                               NodeKind.CONTAINER_REGISTRY, NodeKind.DATA_SINK,
                               NodeKind.SECURITY_CONTROLS}

# Tags that make a node a path OBJECTIVE (something worth routing a path to).
TARGET_TAGS: "set[str]" = {"tier0", "tier0_critical", "can_reach_tier0", "tier0_eligible"}
# Tags that count as "privileged reach" when sizing a principal's blast radius. Distinct
# from TARGET_TAGS: blast radius counts any privileged node reached, not only Tier-0 ones.
PRIVILEGED_REACH_TAGS: "set[str]" = {"tier0", "privileged", "dangerous_app_role",
                                     "tier0_eligible"}


# ── Target classification (the Tier-0 split the UI and explorer share) ───────────
# Three discriminating tags (PRD v2.1 Workstream A), assigned in derive._tag_tier0:
#   tier0_target         - the node IS a crown-jewel objective (a Tier-0 role / object): the
#                          END of a path, never an entry point.
#   holds_tier0          - a principal that HOLDS a Tier-0 role or broad Azure scope.
#   holds_critical_tier0 - a principal holding a CRITICAL Tier-0 role (Global Administrator /
#                          Privileged Role Administrator): already tenant-level, never an entry.
# The legacy "tier0" tag remains on both objects and holders for backward compatibility.
_PRINCIPAL_KINDS = (NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)


def is_tier0_target(node) -> bool:
    """The node is a crown-jewel objective (a Tier-0 role, TenantControl, or a user-picked
    Tier-0 object): the END of an attack path, never an entry point."""
    return bool(node and "tier0_target" in node.tags)


def is_tier0_critical(node) -> bool:
    """The node is a *critical* crown jewel (Global Administrator / Privileged Role Admin)."""
    return bool(node and "tier0_critical" in node.tags)


def holds_tier0(node) -> bool:
    """A principal that holds a Tier-0 role or broad Azure scope (Owner/UAA at sub/MG)."""
    return bool(node and "holds_tier0" in node.tags)


def holds_critical_tier0(node) -> bool:
    """A principal holding a critical Tier-0 role: already tenant-level, never an entry."""
    return bool(node and "holds_critical_tier0" in node.tags)


def is_sink(node) -> bool:
    """The node is a sensitive data / credential sink (Key Vault, Storage, AKS, ACR)."""
    return bool(node and node.kind in SINK_KINDS)


def is_attack_target(node) -> bool:
    """A valid terminal objective for an (entry -> target) attack path: a crown-jewel Tier-0
    target or a data/credential sink. A merely can-reach-tier0 principal is a stepping stone,
    not a terminal objective, so it is excluded here."""
    return is_tier0_target(node) or is_sink(node)


# `is_path_objective` kept as an alias of the terminal-objective test for older call sites.
is_path_objective = is_attack_target


def is_entry_point(node) -> bool:
    """A principal that can START an attack path: not itself a crown-jewel target and not a
    holder of a critical Tier-0 role. Holders of NON-critical Tier-0 roles (Cloud Application
    Administrator, Application Administrator) and of broad Azure scope REMAIN entry points -
    they are a foothold, not the objective (PRD v2.1 A1)."""
    return bool(node and node.kind in _PRINCIPAL_KINDS
                and "tier0_target" not in node.tags
                and "holds_critical_tier0" not in node.tags)


# ── Adjacency ────────────────────────────────────────────────────────────────────
def escalation_adjacency(g: Graph) -> "dict[str, list[tuple[str, str]]]":
    """node id -> list of (neighbour id, primitive label) over escalation edges, self-loops
    excluded (a self-loop can never advance a loopless path)."""
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in g.edges():
        if e.type in ESCALATION_EDGES and e.src != e.dst:
            adj.setdefault(e.src, []).append((e.dst, e.primitive or e.type.value))
    return adj


def typed_adjacency(g: Graph) -> "dict[str, list[tuple[str, str, EdgeType]]]":
    """As `escalation_adjacency`, but each entry also carries the EdgeType, so a caller can
    restrict a first hop to a particular capability (plane anchoring)."""
    adj: dict[str, list[tuple[str, str, EdgeType]]] = {}
    for e in g.edges():
        if e.type in ESCALATION_EDGES and e.src != e.dst:
            adj.setdefault(e.src, []).append((e.dst, e.primitive or e.type.value, e.type))
    return adj


# ── Traversal primitives ─────────────────────────────────────────────────────────
def shortest_path(g: Graph, src: str, dst: str, *,
                  adj: "dict[str, list[tuple[str, str]]] | None" = None,
                  max_depth: int = 8,
                  blocked_nodes: "set[str] | None" = None,
                  blocked_edges: "set[tuple[str, str]] | None" = None) -> "list[str] | None":
    """BFS for the shortest (fewest-hop) escalation path from `src` to `dst`.

    Returns the node-id sequence [src, ..., dst] (length 1 when src == dst), or None when
    `dst` is unreachable within `max_depth` hops. Hop labels are not returned; recover them
    from the adjacency if needed. Pass a prebuilt `adj` to avoid rebuilding it per call.
    `blocked_nodes` / `blocked_edges` remove nodes / (u,v) edges from the search - used by
    choke-point cut analysis to test what a removal severs."""
    if src == dst:
        return [src]
    if adj is None:
        adj = escalation_adjacency(g)
    return _bfs_with_blocks(adj, src, dst, blocked_nodes or set(),
                            blocked_edges or set(), max_depth)


def _bfs_with_blocks(adj, src, dst, blocked_nodes, blocked_edges, max_depth):
    """Shortest path src->dst skipping any node in `blocked_nodes` and any (u,v) edge in
    `blocked_edges`. Helper for Yen's algorithm."""
    if src == dst:
        return [src]
    pred: dict[str, str] = {}
    depth = {src: 0}
    q = deque([src])
    while q:
        cur = q.popleft()
        if depth[cur] >= max_depth:
            continue
        for nxt, _prim in adj.get(cur, []):
            if nxt in depth or nxt in blocked_nodes or (cur, nxt) in blocked_edges:
                continue
            depth[nxt] = depth[cur] + 1
            pred[nxt] = cur
            if nxt == dst:
                chain = [dst]
                while chain[-1] != src:
                    chain.append(pred[chain[-1]])
                chain.reverse()
                return chain
            q.append(nxt)
    return None


def k_shortest_paths(g: Graph, src: str, dst: str, k: int = 3, *,
                     adj: "dict[str, list[tuple[str, str]]] | None" = None,
                     max_depth: int = 8) -> "list[list[str]]":
    """Up to `k` loopless shortest escalation paths from `src` to `dst`, by hop count
    (Yen's algorithm). Each path is a node-id sequence; the list is ordered shortest-first
    and the paths are distinct. Empty when `dst` is unreachable.

    Used wherever "show the alternate routes" or "which single edge severs this" matters -
    the Attack Paths tab's `alt_paths`, and choke-point cut analysis."""
    if k <= 0:
        return []
    if adj is None:
        adj = escalation_adjacency(g)
    first = _bfs_with_blocks(adj, src, dst, set(), set(), max_depth)
    if first is None:
        return []
    accepted: list[list[str]] = [first]
    candidates: list[list[str]] = []
    seen = {tuple(first)}
    while len(accepted) < k:
        prev = accepted[-1]
        for i in range(len(prev) - 1):
            spur = prev[i]
            root = prev[:i + 1]
            blocked_edges: set[tuple[str, str]] = set()
            for p in accepted + candidates:
                if len(p) > i and p[:i + 1] == root:
                    blocked_edges.add((p[i], p[i + 1]))
            # Nodes of the root path (except the spur) cannot reappear - keeps paths loopless.
            blocked_nodes = set(root[:-1])
            spur_path = _bfs_with_blocks(adj, spur, dst, blocked_nodes, blocked_edges,
                                         max_depth - i)
            if spur_path is None:
                continue
            total = root[:-1] + spur_path
            if tuple(total) not in seen and len(total) - 1 <= max_depth:
                candidates.append(total)
        if not candidates:
            break
        candidates.sort(key=len)
        nxt = candidates.pop(0)
        seen.add(tuple(nxt))
        accepted.append(nxt)
    return accepted


def reachable_privileged(g: Graph, start: str, *,
                         priv_tags: "set[str] | None" = None) -> "set[str]":
    """Privileged / Tier-0 nodes reachable from `start` over escalation edges (the count a
    blast-radius *score* uses). `priv_tags` defaults to `PRIVILEGED_REACH_TAGS`."""
    tags = priv_tags if priv_tags is not None else PRIVILEGED_REACH_TAGS
    seen: set[str] = set()
    reached_priv: set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        for e in g.out_edges(cur):
            if e.type not in ESCALATION_EDGES or e.dst in seen or e.dst == cur:
                continue
            seen.add(e.dst)
            node = g.node(e.dst)
            if node and (node.tags & tags):
                reached_priv.add(e.dst)
            stack.append(e.dst)
    return reached_priv


def blast_radius(g: Graph, node_id: str) -> dict:
    """Structured blast radius (PRD v2.1 Workstream B): "what falls if this is compromised".

    Unlike `reachable_privileged` (a count of privileged nodes), this seeds from the roles,
    groups and scopes the principal ALREADY HOLDS (HasEntraRole/EffectiveRole/MemberOf/
    HasRBACRole) and then walks escalation edges, so a standing Global Administrator - whose
    only outbound edges are holdings, not escalations - is correctly tenant-wide rather than
    reporting a blast radius of zero.

    Returns:
      node_id, name, kind
      reachable          - sorted list of every node id reachable (held or escalated to)
      reachable_count
      tier0_reached      - sorted crown-jewel target ids in `reachable`
      tenant_takeover    - true when a critical Tier-0 role is held or reached
      counts_by_kind     - {kind: n} over reachable nodes
      effective_scope    - when takeover, the tenant-wide totals (all subs/KVs/storage/...)
      message            - set only for the empty case (no roles and no escalation)
    """
    node = g.node(node_id)
    if node is None:
        return {"node_id": node_id, "reachable": [], "reachable_count": 0,
                "tier0_reached": [], "tenant_takeover": False, "counts_by_kind": {},
                "message": "Unknown node."}

    # Frontier = the node plus everything it already holds (standing privilege).
    frontier = {node_id}
    for e in g.out_edges(node_id):
        if e.type in HOLDING_EDGES and e.dst != node_id:
            frontier.add(e.dst)

    reachable: set[str] = set()
    seen = set(frontier)
    stack = list(frontier)
    while stack:
        cur = stack.pop()
        for e in g.out_edges(cur):
            if e.type in ESCALATION_EDGES and e.dst not in seen and e.dst != cur:
                seen.add(e.dst)
                reachable.add(e.dst)
                stack.append(e.dst)
    reachable |= (frontier - {node_id})          # the held roles/groups are part of the fallout

    if not reachable:
        return {"node_id": node_id, "name": node.name, "kind": node.kind.value,
                "reachable": [], "reachable_count": 0, "tier0_reached": [],
                "tenant_takeover": False, "counts_by_kind": {},
                "message": "No roles held and no escalation edges: nothing further is reachable."}

    tier0_reached = sorted(n for n in reachable if is_tier0_target(g.node(n)))
    takeover = holds_critical_tier0(node) or any(
        is_tier0_critical(g.node(n)) or (g.node(n) and g.node(n).kind == NodeKind.TENANT_CONTROL)
        for n in reachable)
    counts: dict[str, int] = {}
    for n in reachable:
        kn = g.node(n)
        if kn:
            counts[kn.kind.value] = counts.get(kn.kind.value, 0) + 1

    result = {
        "node_id": node_id, "name": node.name, "kind": node.kind.value,
        "reachable": sorted(reachable), "reachable_count": len(reachable),
        "tier0_reached": tier0_reached, "tenant_takeover": takeover,
        "counts_by_kind": counts,
    }
    if takeover:
        result["effective_scope"] = _tenant_wide_scope(g)
    return result


def _tenant_wide_scope(g: Graph) -> dict:
    """Everything in the collection, since tenant takeover means control of all of it. The
    label makes clear the reach is via Global Administrator, not a per-edge escalation."""
    counts: dict[str, int] = {}
    ids_by_kind: dict[str, list[str]] = {}
    for n in g.nodes():
        counts[n.kind.value] = counts.get(n.kind.value, 0) + 1
        ids_by_kind.setdefault(n.kind.value, []).append(n.id)
    return {"label": "tenant-wide (via Global Administrator)",
            "counts_by_kind": counts, "total": sum(counts.values()),
            "ids_by_kind": ids_by_kind}


def path_hops(g: Graph, node_ids: "list[str]",
              adj: "dict[str, list[tuple[str, str]]] | None" = None) -> "list[dict]":
    """Decorate a node-id sequence (from `shortest_path` / `k_shortest_paths`) into ordered
    hop dicts {from, via, to} using the primitive label on each traversed edge."""
    if len(node_ids) < 2:
        return []
    if adj is None:
        adj = escalation_adjacency(g)
    hops: list[dict] = []
    for a, b in zip(node_ids, node_ids[1:]):
        prim = next((p for (d, p) in adj.get(a, []) if d == b), "")
        hops.append({"from": a, "from_name": g.display(a), "via": prim,
                     "to": b, "to_name": g.display(b)})
    return hops


# ── What-if remediation (PRD v2.1 Workstream E1) ────────────────────────────────
# Apply a set of removals (a permission grant, role/RBAC assignment, ownership or membership) to a
# COPY of the *pre-derive* graph, then re-derive and re-assess, so a user can see the recomputed
# attack paths / blast radius / exposure / grade WITHOUT touching the tenant. Deterministic only;
# the AI layer never runs here.
def _apply_removal(g: Graph, rem: dict) -> None:
    kind = (rem or {}).get("kind")
    if kind == "app_role":
        n = g.node(rem.get("node"))
        if n is not None:
            ars = n.props.get("_granted_app_roles") or []
            n.props["_granted_app_roles"] = [a for a in ars if a.get("value") != rem.get("value")]
        return

    def _match(e) -> bool:
        t = e.type.value
        if kind == "member":
            return t == "MemberOf" and e.src == rem.get("src") and e.dst == rem.get("dst")
        if kind == "ownership":
            return t == "Owns" and e.src == rem.get("src") and e.dst == rem.get("dst")
        if kind == "entra_role":
            return t in ("HasEntraRole", "EffectiveRole") and e.src == rem.get("node") and e.dst == rem.get("role")
        if kind == "rbac":
            return t == "HasRBACRole" and e.src == rem.get("node") and (
                rem.get("scope") in (None, "") or (e.evidence or {}).get("scope") == rem.get("scope"))
        if kind == "edge":
            return e.src == rem.get("src") and e.dst == rem.get("dst") and (
                rem.get("type") in (None, "", t))
        return False

    victims = [(u, v, k) for u, v, k, d in g.g.edges(keys=True, data=True)
               if d.get("edge") is not None and _match(d["edge"])]
    for u, v, k in victims:
        g.g.remove_edge(u, v, k)


def simulate(g: Graph, removals: "list[dict]") -> dict:
    """Return a full assessment computed on a copy of `g` with `removals` applied. `g` must be a
    PRE-derive graph (build_graph output); this re-derives after the removals so the change
    propagates (a removed app-role grant drops its derived edges, its tags and the findings that
    keyed on it). Deterministic; no AI."""
    import copy

    from . import engine
    g2 = copy.deepcopy(g)
    for rem in removals or []:
        _apply_removal(g2, rem)
    return engine._assess(g2)
