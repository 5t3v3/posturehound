"""Scoring and analytics over the derived graph.

All numbers here are deterministic and engine-computed. Any future AI layer
narrates these values but does not produce them.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .model import Category, EdgeType, Graph, NodeKind, Severity
from .rules.base import AssessmentResult

# Escalation edge types used for reachability/path analysis.
_ESCALATION_EDGES = {
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
    EdgeType.CAN_STEAL_MANAGED_IDENTITY, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_GET_STORAGE_KEY, EdgeType.CAN_EXEC_AKS,
    # Data-plane exfiltration and supply-chain image poisoning. These are DERIVED as
    # abuse edges (derive.py) but were omitted here, so every path through them -
    # storage-blob reads, ACR image pushes - was computed and then thrown away.
    EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_PUSH_CONTAINER,
    # PIM self-activation: a principal ELIGIBLE for a role can activate it at will
    # (often with no approval). Traversing this edge is what makes a shadow admin -
    # eligible-for-Global-Admin - a real path to the Tier-0 role, not just a tag.
    EdgeType.ELIGIBLE_FOR_ROLE,
    EdgeType.MEMBER_OF, EdgeType.OWNS,
}

# MemberOf / Owns are RELATIONSHIPS the BFS traverses to get into position; they are not
# abuse primitives in their own right. When deciding what a finding's OWN attack IS (the
# structural anchor), they must be excluded, or "an actor who also owns a Tier-0 group"
# hijacks e.g. a Key-Vault-read finding into an unrelated group-ownership path.
_TRAVERSAL_EDGES = {EdgeType.MEMBER_OF, EdgeType.OWNS}
_ABUSE_EDGES = _ESCALATION_EDGES - _TRAVERSAL_EDGES

# Resource kinds that are sensitive data/credential sinks (path objectives even
# when they are not Tier-0 identities). CONTAINER_REGISTRY is a supply-chain sink:
# push access to it poisons every downstream deployment.
_SINK_KINDS = {NodeKind.KEY_VAULT, NodeKind.STORAGE, NodeKind.AKS,
               NodeKind.CONTAINER_REGISTRY}

# ── Path anchoring: a finding's path must begin with the finding's OWN capability ──
#
# A finding's maximum-impact path must open with the specific move the finding is ABOUT,
# not the principal's single highest-impact *unrelated* capability. Left unconstrained, the
# search surfaced whatever reached a Tier-0 user (usually an Entra password-reset), so a Key
# Vault finding showed a password-reset, an Azure-RBAC finding showed an Entra move, and so
# on - the path contradicted the description.
#
# The anchor is DECLARED PER RULE (`_RULE_ATTACK_EDGES`), because the rule is the only thing
# that knows which capability it detected. A finding's *category* is NOT a reliable proxy:
# "AZ-RBAC-004 Guest principal holds an Azure RBAC role" is categorised under Guest yet is an
# Azure-plane finding, and an Applications finding can be an Entra role-grant OR an Azure
# storage-key. Anchoring by category therefore always leaves gaps that surface as new
# findings in new scans; anchoring by rule does not. `_CATEGORY_SEED_EDGES` remains ONLY as a
# coarse fallback for AI-generated findings, which carry no rule id.
#
# Rules NOT listed are EXPOSURE/hygiene findings ("this account is over-privileged / has
# standing credentials / is orphaned"), whose honest path IS the principal's worst reach -
# so they are intentionally left unanchored. The invariant is enforced by
# tests/test_path_anchor_invariant.py: every anchored rule's declared edges must be
# plane-consistent, and a principal holding both an in-class and a bigger out-of-class
# capability must anchor to the in-class one.
#
# Azure control/data-plane edges - what an Azure RBAC role (Owner/Contributor/UAA/resource
# role) actually grants. EXCLUDES the Entra-identity edges (password reset, Entra role grant,
# app-secret add, PIM eligibility), which come from a *separate* Entra role a principal may
# also hold, not from the Azure grant the finding is about.
_AZURE_PLANE_EDGES: "set[EdgeType]" = {
    EdgeType.CAN_ESCALATE_RBAC, EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_GET_STORAGE_KEY,
    EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_STEAL_MANAGED_IDENTITY,
    EdgeType.CAN_EXEC_AKS, EdgeType.CAN_PUSH_CONTAINER,
}
# Entra identity-plane edges - the moves an Entra role / app permission / group control
# grants. The mirror of the Azure plane; the two never belong on the same finding's anchor.
_ENTRA_PLANE_EDGES: "set[EdgeType]" = {
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.ELIGIBLE_FOR_ROLE,
}

_KV_READ = {EdgeType.CAN_REACH_KV_SECRET}
_STOR_KEY = {EdgeType.CAN_GET_STORAGE_KEY}

# Every capability rule declares the escalation edge(s) its finding represents. This is the
# authoritative anchor (rule id first, category only as an AI fallback).
_RULE_ATTACK_EDGES: "dict[str, set[EdgeType]]" = {
    # Azure RBAC - escalate on the Azure plane.
    "AZ-RBAC-001": _AZURE_PLANE_EDGES, "AZ-RBAC-002": _AZURE_PLANE_EDGES,
    "AZ-RBAC-003": _AZURE_PLANE_EDGES, "AZ-RBAC-005": _AZURE_PLANE_EDGES,
    "AZ-RBAC-008": _AZURE_PLANE_EDGES, "AZ-RBAC-011": _AZURE_PLANE_EDGES,
    "AZ-RBAC-004": _AZURE_PLANE_EDGES,                     # miscategorised (Guest) but Azure-plane
    # Compute / managed-identity - the specific run-code / push / steal move.
    "AZ-RBAC-006": {EdgeType.CAN_STEAL_MANAGED_IDENTITY},  # run-command -> IMDS -> steal MI
    "AZ-RBAC-007": {EdgeType.CAN_EXEC_AKS},                # AKS cluster-admin creds
    "AZ-RBAC-009": {EdgeType.CAN_PUSH_CONTAINER},          # push images to a container registry
    "AZ-RBAC-010": {EdgeType.CAN_STEAL_MANAGED_IDENTITY},  # code exec on VM -> IMDS -> steal MI
    # Key Vault data-plane reads.
    "AZ-KV-001": _KV_READ, "AZ-KV-003": _KV_READ, "AZ-KV-004": _KV_READ,
    "AZ-KV-007": _KV_READ, "AZ-KV-010": _KV_READ,
    # Storage data-plane.
    "AZ-STOR-002": _STOR_KEY, "AZ-STOR-004": _STOR_KEY,
    "AZ-STOR-003": {EdgeType.CAN_READ_STORAGE_BLOB},
    # Entra - role grant / app-role grant.
    "AZ-APP-001": {EdgeType.CAN_GRANT_ROLE}, "AZ-APP-002": {EdgeType.CAN_GRANT_ROLE},
    "AZ-APP-009": {EdgeType.CAN_GRANT_ROLE}, "AZ-APP-016": {EdgeType.CAN_GRANT_ROLE},
    # Entra - add credentials to an app (impersonate it).
    "AZ-APP-003": {EdgeType.CAN_ADD_SECRET}, "AZ-APP-007": {EdgeType.CAN_ADD_SECRET},
    # Entra - add members to privileged groups.
    "AZ-APP-010": {EdgeType.CAN_ADD_MEMBER}, "AZ-APP-011": {EdgeType.CAN_ADD_MEMBER},
    "AZ-GRP-003": {EdgeType.CAN_ADD_MEMBER},
    # Entra - password reset / PIM eligibility.
    "AZ-IDENT-008": {EdgeType.CAN_RESET_PASSWORD}, "AZ-IDENT-009": {EdgeType.CAN_RESET_PASSWORD},
    "AZ-IDENT-010": {EdgeType.ELIGIBLE_FOR_ROLE},
}
# AI-generated findings carry no rule id, so they declare their anchor directly: the
# specialist emits `attack_primitive` (the single first escalation move in its scenario),
# which maps to the same edge sets the rules use. This is the AI parallel of _RULE_ATTACK_EDGES
# - the finding's author (here the model) declares the capability, so the path
# matches the description. Critically, an Azure RBAC self-escalation and an Entra role grant
# are DIFFERENT primitives on different planes, which mitre_technique/category cannot distinguish.
_PRIMITIVE_ATTACK_EDGES: "dict[str, set[EdgeType]]" = {
    "azure_rbac_escalation": {EdgeType.CAN_ESCALATE_RBAC},
    "key_vault_secret_read": _KV_READ,
    "storage_key_theft": _STOR_KEY,
    "storage_blob_read": {EdgeType.CAN_READ_STORAGE_BLOB},
    "managed_identity_theft": {EdgeType.CAN_STEAL_MANAGED_IDENTITY},
    "aks_exec": {EdgeType.CAN_EXEC_AKS},
    "container_push": {EdgeType.CAN_PUSH_CONTAINER},
    "entra_role_grant": {EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE},
    "app_credential_add": {EdgeType.CAN_ADD_SECRET},
    "group_member_add": {EdgeType.CAN_ADD_MEMBER},
    "password_reset": {EdgeType.CAN_RESET_PASSWORD},
    "pim_activation": {EdgeType.ELIGIBLE_FOR_ROLE},
    "none": set(),                                          # pure exposure -> worst-reach
}
# Coarse plane fallback for AI findings that predate `attack_primitive` (older scans).
_CATEGORY_SEED_EDGES: "dict[str, set[EdgeType]]" = {
    Category.KEYVAULT.value: _KV_READ,
    Category.STORAGE.value: {EdgeType.CAN_GET_STORAGE_KEY, EdgeType.CAN_READ_STORAGE_BLOB},
    Category.COMPUTE.value: {EdgeType.CAN_EXEC_AKS, EdgeType.CAN_PUSH_CONTAINER,
                             EdgeType.CAN_STEAL_MANAGED_IDENTITY},
    Category.MANAGED_IDENTITY.value: {EdgeType.CAN_STEAL_MANAGED_IDENTITY},
    Category.RBAC.value: _AZURE_PLANE_EDGES,
}


@dataclass
class PostureScore:
    grade: str
    score: int  # 0-100, higher is better
    severity_counts: dict[str, int]
    methodology: str


@dataclass
class Analytics:
    blast_radius: dict[str, int]  # principal id -> reachable privileged count
    max_impact: dict | None
    choke_points: list[dict] = field(default_factory=list)
    tier0: list[dict] = field(default_factory=list)
    cross_subscription: dict = field(default_factory=dict)  # bridges + sub-to-sub links


_SEV_WEIGHTS = {"Critical": 40, "High": 20, "Medium": 8, "Low": 3, "Info": 1}

# Scoring model - rank-decayed severity with exponential mapping.
#
# The previous model was `100 - min(sum(weight x entity_factor), 100)`. Because the
# sum grows linearly with finding count, it hit the 100 cap on any real tenant: five
# High findings scored exactly 0/F, and a tenant twice as bad scored 0/F as well. The
# headline number carried no information and remediating dozens of findings moved it
# by nothing, so there was no feedback loop.
#
# This model fixes that in two steps:
#   1. Rank decay - findings are sorted worst-first and the Nth contributes
#      weight x DECAY^N. The worst problems dominate, additional findings of the same
#      kind add progressively less, and the total converges instead of running away.
#   2. Exponential mapping - score = 100 * exp(-effective / SCALE), which is strictly
#      monotonic and never truly bottoms out, so improvement is always visible.
_RANK_DECAY = 0.75    # each successive finding contributes 75% of the previous rank
_SCORE_SCALE = 93.0   # calibrated so one Critical ≈ 65 (C) and one High ≈ 81 (B)
_ENTITY_FACTOR_MAX = 2.0
_ENTITY_FACTOR_STEP = 0.10

_METHODOLOGY = (
    "Rank-decayed severity score. Each finding is weighted by severity "
    "(Critical 40, High 20, Medium 8) times an entity factor (1.0-2.0, scaling with "
    "affected-entity count). Findings are ranked worst-first and the Nth contributes "
    "75%^N of its weight, so the most severe issues dominate and breadth has "
    "diminishing effect. The score is 100 x exp(-total/93), which stays sensitive at "
    "every level - fixing findings always moves the number. Best-practice findings and "
    "attack paths (shown in their own tab) are counted but not penalised."
)


def _entity_factor(count: int) -> float:
    """Scale a finding's weight by how many entities it affects (capped)."""
    return min(1.0 + (max(count, 1) - 1) * _ENTITY_FACTOR_STEP, _ENTITY_FACTOR_MAX)


def _score_from_weights(weights: list[float]) -> tuple[int, str]:
    """Rank-decay the per-finding weights, map to 0-100, and grade it."""
    import math
    effective = sum(w * (_RANK_DECAY ** i)
                    for i, w in enumerate(sorted(weights, reverse=True)))
    raw = 100.0 * math.exp(-effective / _SCORE_SCALE)
    # Floor at 1 when anything was penalised: a literal 0 reads as a broken metric,
    # and it would also erase the difference between "bad" and "catastrophic".
    score = 100 if not weights else max(1, min(100, round(raw)))
    grade = ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
             else "D" if score >= 40 else "F")
    return score, grade


def rescore_from_findings(findings: list[dict]) -> dict:
    """Recompute posture score from a list of finding dicts (post-AI, final result).

    Returns a dict with the same keys as PostureScore so it can replace result["score"]
    after AI findings are merged in.
    """
    counts: dict[str, int] = {s: 0 for s in _SEV_WEIGHTS}
    weights: list[float] = []
    for f in findings:
        sev = f.get("severity", "Info")
        # path_consolidation findings are displayed separately in the Attack Paths tab.
        # They are excluded from BOTH severity_counts and the score: charging the score
        # for findings the badges deliberately hide made the grade unexplainable from
        # the numbers on screen.
        if f.get("source") == "path_consolidation":
            continue
        if sev in counts:
            counts[sev] += 1
        if f.get("best_practice"):
            continue
        count = max(len(f.get("entities") or []), f.get("affected_count") or 1, 1)
        weights.append(_SEV_WEIGHTS.get(sev, 1) * _entity_factor(count))
    score, grade = _score_from_weights(weights)
    return {"grade": grade, "score": score, "severity_counts": counts, "methodology": _METHODOLOGY}


def compute_score(result: AssessmentResult) -> PostureScore:
    counts = {s.value: 0 for s in Severity}
    weights: list[float] = []
    for f in result.findings:
        counts[f.severity.value] += 1
        if f.best_practice:
            continue  # hygiene findings count toward severity_counts but don't penalise the score
        count = max(f.count, 1)  # guard: count should never be < 1
        weights.append(f.severity.weight * _entity_factor(count))
    score, grade = _score_from_weights(weights)
    return PostureScore(grade=grade, score=score, severity_counts=counts,
                        methodology=_METHODOLOGY)


def _reachable_privileged(g: Graph, start: str) -> set[str]:
    """BFS over escalation edges; count privileged/Tier-0 nodes reachable."""
    seen: set[str] = set()
    stack = [start]
    reached_priv: set[str] = set()
    while stack:
        cur = stack.pop()
        for e in g.out_edges(cur):
            if e.type not in _ESCALATION_EDGES:
                continue
            if e.dst in seen or e.dst == cur:
                continue
            seen.add(e.dst)
            node = g.node(e.dst)
            if node and (node.tags & {"tier0", "privileged", "dangerous_app_role",
                                      "tier0_eligible"}):
                reached_priv.add(e.dst)
            stack.append(e.dst)
    return reached_priv


def compute_analytics(g: Graph) -> Analytics:
    principals = g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)
    blast: dict[str, int] = {}
    for p in principals:
        reach = _reachable_privileged(g, p.id)
        # A principal that can reach privilege without already being fully Tier-0 is interesting.
        if reach:
            blast[p.id] = len(reach)

    # Maximum-impact: the (non-Tier-0-by-default) entry point reaching the most privilege.
    max_impact = None
    if blast:
        top = max(blast.items(), key=lambda kv: kv[1])
        node = g.node(top[0])
        max_impact = {
            "principal_id": top[0],
            "principal": node.name if node else top[0],
            "kind": node.kind.value if node else "?",
            "reachable_privileged_count": top[1],
            "already_tier0": bool(node and "tier0" in node.tags),
        }

    # Choke points (heuristic MVP): privileged/escalation nodes that the most
    # entry points depend on to reach privilege. Counts in-edges of escalation type.
    choke_counts: dict[str, int] = {}
    for e in g.edges():
        if e.type in _ESCALATION_EDGES:
            node = g.node(e.dst)
            if node and (node.tags & {"tier0", "privileged", "dangerous_app_role"}):
                choke_counts[e.dst] = choke_counts.get(e.dst, 0) + 1
    choke_points = [
        {"id": nid, "name": g.display(nid), "paths_through": cnt}
        for nid, cnt in sorted(choke_counts.items(), key=lambda kv: -kv[1])[:10]
    ]

    tier0 = [{"id": n.id, "name": n.name, "kind": n.kind.value,
              "critical": "tier0_critical" in n.tags}
             for n in g.nodes() if "tier0" in n.tags]

    # Cross-subscription reach is computed ONCE over the full escalation graph and used
    # as a lens on everything downstream (bridges, max-impact paths, per-finding blast).
    reach = compute_subscription_reach(g)

    return Analytics(blast_radius=blast, max_impact=max_impact,
                     choke_points=choke_points, tier0=tier0,
                     cross_subscription=compute_cross_subscription(g, blast, reach))


# ── Maximum-impact paths ──────────────────────────────────────────────────────
# Every finding is an attack with a worst outcome. The "maximum-impact path" is the
# highest-value target reachable from the finding's own principals over the real
# escalation graph, plus the ordered path to it. It is deterministic and grounded:
# the path only ever contains nodes and edges that exist in the collection, so it is
# exact and reproducible on the identity graph. The AI cartographer narrates and prioritises
# these paths; it never invents them.
_PRINCIPAL_KINDS = (NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)


def _impact_score(g: Graph, nid: str, blast: "dict[str, int]") -> int:
    """Rank a node as an attack objective. Tier-0 (identity crown jewels) dominate,
    then privileged roles, then data/credential sinks; ties broken by how much
    further the node itself reaches (its own blast radius)."""
    n = g.node(nid)
    if not n:
        return 0
    if "tier0_critical" in n.tags:
        base = 1000
    elif "tier0" in n.tags:
        base = 500
    elif "tier0_eligible" in n.tags:   # PIM shadow admin - one self-activation from Tier-0
        base = 450
    elif n.tags & {"privileged", "dangerous_app_role"}:
        base = 200
    elif n.kind in (NodeKind.MANAGEMENT_GROUP, NodeKind.SUBSCRIPTION):
        # Owner/UAA on a subscription or management group is control of an entire cloud
        # scope - every resource within it (Key Vaults, storage, compute). A real attack
        # objective, so a "principal holds Owner on subscription X" finding shows the path
        # to X instead of a bare single node. Scored above a single data sink and below a
        # privileged identity, keeping the tool's identity-first ranking (the breadth of the
        # scope is surfaced separately via subscription_reach). Capped blast (<=49) keeps it
        # from ever crossing into the privileged tier.
        base = 150
    elif n.kind == NodeKind.RESOURCE_GROUP:
        base = 120                          # a finer cloud scope than a full subscription
    elif n.kind in _SINK_KINDS:
        base = 100
    else:
        base = 0
    # Blast radius is a TIE-BREAKER within a tier, never a tier-jumper: a Tier-0 target
    # must always outrank a merely-privileged one no matter how broad the latter's reach.
    # The smallest gap between tiers is 50 (Tier-0 500 vs Tier-0-eligible 450), so the
    # blast contribution is capped below it - otherwise a broad non-Tier-0 group could
    # outscore a directly reachable Tier-0 admin and falsely report reaches_tier0=False.
    return base + min(blast.get(nid, 0), 49)


def _escalation_adjacency(g: Graph) -> "dict[str, list[tuple[str, str]]]":
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in g.edges():
        if e.type in _ESCALATION_EDGES and e.src != e.dst:
            adj.setdefault(e.src, []).append((e.dst, e.primitive or e.type.value))
    return adj


def _node_brief(g: Graph, nid: str) -> dict:
    n = g.node(nid)
    return {
        "id": nid,
        "name": (n.name if n and n.name else nid),
        "kind": (n.kind.value if n else "Unknown"),
        "tier0": bool(n and "tier0" in n.tags),
        "critical": bool(n and "tier0_critical" in n.tags),
    }


def _steal_via_resource(g: Graph, src: str, dst: str) -> "tuple[dict, str] | None":
    """For a managed-identity-theft edge src->dst, return (resource_brief, how) - the
    compute resource whose identity is stolen and the mechanism - so a path can show the
    VM/app the code runs on. None when the edge isn't a steal edge or the resource is
    unresolved."""
    for e in g.out_edges(src, EdgeType.CAN_STEAL_MANAGED_IDENTITY):
        if e.dst != dst:
            continue
        rid = e.evidence.get("via_resource_id")
        if rid and g.node(rid):
            return _node_brief(g, rid), (e.evidence.get("how") or "run code on the resource")
        return None
    return None


def _best_path_from(g: Graph, start: str, adj: "dict[str, list[tuple[str, str]]]",
                    blast: "dict[str, int]", *, max_depth: int = 8,
                    seed_adj: "dict[str, list[tuple[str, str]]] | None" = None) -> "dict | None":
    """BFS from `start` over escalation edges; return the highest-impact reachable
    target and the shortest ordered hop path to it, or None if nothing of value is
    reachable.

    When `seed_adj` is supplied, the FIRST hop out of `start` is restricted to it (the
    finding's own capability edges), so the path begins with this finding's attack step
    rather than the principal's unrelated worst capability. Every hop after the first
    uses the full escalation adjacency, so a seeded first move still escalates onward."""
    from collections import deque
    pred: dict[str, tuple[str, str]] = {}
    depth: dict[str, int] = {start: 0}
    q = deque([start])
    while q:
        cur = q.popleft()
        if depth[cur] >= max_depth:
            continue
        neighbors = (seed_adj.get(cur, []) if (seed_adj is not None and cur == start)
                     else adj.get(cur, []))
        for dst, prim in neighbors:
            if dst in depth:
                continue
            depth[dst] = depth[cur] + 1
            pred[dst] = (cur, prim)
            q.append(dst)
    # Pick the reachable node (excluding the entry itself) with the greatest impact,
    # nearest first on ties, then by name for determinism.
    best_tid, best_key = None, None
    for nid, dep in depth.items():
        if nid == start:
            continue
        sc = _impact_score(g, nid, blast)
        if sc <= 0:
            continue
        key = (sc, -dep, g.display(nid))
        if best_key is None or key > best_key:
            best_key, best_tid = key, nid
    if best_tid is None:
        return None
    chain: list[dict] = []
    cur = best_tid
    while cur in pred:
        prev, prim = pred[cur]
        hop = {"from": _node_brief(g, prev), "via": prim, "to": _node_brief(g, cur)}
        # A managed-identity theft edge collapses the compute resource (VM / Function App /
        # AKS) the attacker runs code on into a direct principal->MI edge. Surface that
        # resource so the path matches the finding's scenario ("execute code on a VM"),
        # instead of jumping straight to the identity with the VM nowhere in sight.
        _via = _steal_via_resource(g, prev, cur)
        if _via:
            hop["via_resource"], hop["via_how"] = _via
        chain.append(hop)
        cur = prev
    chain.reverse()
    tgt = _node_brief(g, best_tid)
    return {
        "entry": _node_brief(g, start),
        "target": tgt,
        "hops": chain,
        "length": len(chain),
        "reaches_tier0": tgt["tier0"],
        "impact": _impact_score(g, best_tid, blast),
    }


def _object_entity_anchor(g: Graph, f: dict) -> "set[EdgeType] | None":
    """Derive a finding's anchor from its OWN structure - no text, no declaration.

    Most findings list BOTH the actors and the objects they attack (e.g. "8 engineers can
    add credentials to these 13 service principals" carries the 8 users AND the SPs). The
    objects are the entities that RECEIVE an escalation edge from another entity in the
    finding but never SEND one - the "victims". The edge type(s) reaching those objects are
    the finding's literal attack, so we anchor to them. This is the single most reliable
    signal because it is read straight off the finding's own entities and the real graph,
    and it needs nothing from the AI or a keyword list. Returns None when the finding does
    not carry its objects (then the caller falls back to the declared primitive / plane)."""
    ids = {(e.get("id") if isinstance(e, dict) else e) for e in (f.get("entities") or [])}
    ids = {i for i in ids if i and g.node(i)}
    if len(ids) < 2:
        return None
    sends: set[str] = set()
    recv: dict[str, set[EdgeType]] = {}
    for src in ids:
        for e in g.out_edges(src):
            # Anchor only on ABUSE edges - a MemberOf/Owns relationship between two of the
            # finding's entities is not the finding's attack primitive.
            if e.type in _ABUSE_EDGES and e.dst in ids and e.dst != src:
                sends.add(src)
                recv.setdefault(e.dst, set()).add(e.type)
    types: set[EdgeType] = set()
    for dst, etypes in recv.items():
        if dst not in sends:                       # a pure object (received, never sent)
            types |= etypes
    return types or None


def _finding_principal_ids(g: Graph, f: dict) -> list[str]:
    """The graph node ids this finding is *about*, entry points first. Principals
    (users/groups/SPs) lead; other referenced nodes (resources, roles) follow so a
    finding with no principal still gets a single-node plot."""
    principals: list[str] = []
    others: list[str] = []
    seen: set[str] = set()

    def _add(nid):
        if not nid or nid in seen:
            return
        seen.add(nid)
        n = g.node(nid)
        if n and n.kind in _PRINCIPAL_KINDS:
            principals.append(nid)
        elif n:
            others.append(nid)

    for ent in f.get("entities") or []:
        _add(ent.get("id") if isinstance(ent, dict) else ent)
    for hop in f.get("escalation_chain") or []:
        if isinstance(hop, dict):
            _add(hop.get("from_id") or (hop.get("from") or {}).get("id"))
            _add(hop.get("to_id") or (hop.get("to") or {}).get("id"))
    return principals + others


def _subject_principal_ids(g: Graph, f: dict) -> list[str]:
    """The principals the finding is ABOUT (its subjects), with relational-context helpers
    removed so they can never become the path's entry.

    A finding often lists helper principals only to explain what they can do TO the subject
    ("Dileesh can reset Aaron Drake's password"). Those helpers carry their own, often
    higher-impact, edges, and the max-impact search would otherwise anchor the path on THEM,
    showing an attack that has nothing to do with the finding (the recurring "path shows a
    different person doing a different thing" bug).

    Subjects are chosen in order of reliability:
      1. The AI's EXPLICIT per-entity `relation` tag ("subject" / "context"). The specialist
         that wrote the finding declares who it is about, so this is authoritative.
      2. A structural fallback when the AI did not tag: a principal is context when its
         role_in_finding names ANOTHER principal in the finding (the subject's role describes
         its OWN standing; a helper's role describes what it can do to the subject).
    Never returns empty - falls back to all principals when it cannot separate them, and
    always keeps the non-principal nodes (resources/roles) for single-node plots."""
    ordered = _finding_principal_ids(g, f)
    ppl = [nid for nid in ordered if g.node(nid) and g.node(nid).kind in _PRINCIPAL_KINDS]
    others = [nid for nid in ordered if nid not in set(ppl)]
    if len(ppl) < 2:
        return ordered
    ents = {e["id"]: e for e in (f.get("entities") or []) if isinstance(e, dict) and e.get("id")}

    # 1. Explicit AI declaration wins.
    rel = {nid: ents.get(nid, {}).get("relation") for nid in ppl}
    subj_tagged = [nid for nid in ppl if rel.get(nid) == "subject"]
    ctx_tagged = {nid for nid in ppl if rel.get(nid) == "context"}
    if subj_tagged:
        return subj_tagged + others                       # the AI named the subjects outright
    if ctx_tagged:
        return [nid for nid in ppl if nid not in ctx_tagged] + others  # AI named the helpers

    # 2. Structural fallback: a principal whose role names another principal is context.
    roles = {nid: (ents.get(nid, {}).get("role_in_finding") or "").lower() for nid in ppl}
    names = {nid: (g.node(nid).name or "") for nid in ppl}
    subjects = []
    for nid in ppl:
        role = roles.get(nid, "")
        names_another = any(nm and len(nm) >= 3 and nm.lower() in role
                            for onid, nm in names.items() if onid != nid)
        if not names_another:
            subjects.append(nid)
    subjects = subjects or ppl              # never strip every principal
    return subjects + others


def compute_max_impact_paths(g: Graph, findings: "list[dict]",
                             blast: "dict[str, int] | None" = None,
                             reach: "dict[str, set[str]] | None" = None) -> dict:
    """Attach a `max_impact_path` to every finding and return the deduplicated,
    impact-ranked attack map for the whole tenant.

    Guarantees coverage: a finding whose principal reaches Tier-0 gets the full
    escalation path; one whose principal reaches nothing (or is itself the crown
    jewel, or is a bare exposed resource) still gets a single-node path so it can be
    plotted. Nothing is silently dropped.

    Cross-subscription blast radius is woven in as a lens: every finding also carries the
    number and names of subscriptions its principals can reach over the full escalation
    graph (`subscription_reach`/`subscription_reach_count`), so a report can amplify a
    finding that crosses subscription boundaries wherever it appears - never as a separate
    menu."""
    if blast is None:
        blast = {p.id: len(_reachable_privileged(g, p.id))
                 for p in g.nodes_of_kind(*_PRINCIPAL_KINDS)}
    if reach is None:
        reach = compute_subscription_reach(g)
    _, _sub_name = _subscription_resolver(g)
    adj = _escalation_adjacency(g)
    # Per-edge-type adjacency, used to build a finding's seed (first-hop) adjacency when
    # its category anchors the path to a specific capability (see _CATEGORY_SEED_EDGES).
    typed_adj: dict[str, list[tuple[str, str, EdgeType]]] = {}
    for e in g.edges():
        if e.type in _ESCALATION_EDGES and e.src != e.dst:
            typed_adj.setdefault(e.src, []).append(
                (e.dst, e.primitive or e.type.value, e.type))
    amap: list[dict] = []
    for f in findings:
        entries = _subject_principal_ids(g, f)
        # Anchor priority: a deterministic rule declares its edge (_RULE_ATTACK_EDGES); an AI
        # finding declares `attack_primitive`; older AI findings fall back to a coarse category
        # plane. Exposure findings declare nothing / "none" -> worst-reach. This is the single
        # rule for every finding: anchor to the capability its AUTHOR declared, never a proxy.
        rid = f.get("rule_id")
        prim = f.get("attack_primitive")
        if rid and rid in _RULE_ATTACK_EDGES:
            seeds = _RULE_ATTACK_EDGES[rid]           # curated rule declaration wins
        elif f.get("_anchor_from_primitive") and prim and _PRIMITIVE_ATTACK_EDGES.get(prim):
            # The coherence gate reviewed this path and re-declared its primitive: honour it
            # over the structural anchor (otherwise the gate's correction is discarded).
            seeds = _PRIMITIVE_ATTACK_EDGES[prim]
        else:
            # For every other finding, derive the anchor from the finding's OWN structure
            # first (the edge reaching its object entities - the literal actor->object
            # attack), then the AI's declared primitive, then a coarse category plane for
            # AI findings only. Exposure rules with no object entities -> worst-reach.
            seeds = (_object_entity_anchor(g, f)
                     or (_PRIMITIVE_ATTACK_EDGES.get(prim) if prim else None)
                     or (None if rid else _CATEGORY_SEED_EDGES.get(f.get("category") or "")))
        best: dict | None = None
        # A curated rule declares an authoritative edge; an AI finding's declared primitive
        # can be wrong OR dead-end (e.g. "azure_rbac_escalation" whose CanEscalateRBAC only
        # reaches a management group), so for AI findings we may retry on the subjects' own
        # capabilities. A rule's seeds are never second-guessed.
        ai_anchored = not (rid and rid in _RULE_ATTACK_EDGES) and not f.get("_anchor_from_primitive")

        def _anchored(seed_set):
            b = None
            for eid in entries:  # noqa: B023 - defined and called within this iteration only, never deferred
                first = [(d, p) for (d, p, t) in typed_adj.get(eid, []) if t in seed_set]
                if not first:
                    continue
                cand = _best_path_from(g, eid, adj, blast, seed_adj={eid: first})
                if cand is None:
                    continue
                if b is None or (cand["impact"], -cand["length"]) > (b["impact"], -b["length"]):
                    b = cand
            return b

        anchored_intent = bool(seeds)
        if seeds:
            best = _anchored(seeds)
            # Declared anchor found no real path: anchor on what the SUBJECTS can actually
            # do (their own abuse edges) rather than forcing a wrong/empty path - but never
            # on another principal's capability, since `entries` is already the subjects.
            if best is None and ai_anchored:
                own = {t for eid in entries for (_, _, t) in typed_adj.get(eid, []) if t in _ABUSE_EDGES}
                if own:
                    best = _anchored(own)

        if best is None:
            for eid in entries:
                # Anchored intent but no path: fall back to the node's own objective, NEVER an
                # unconstrained walk that could surface an unrelated cross-plane escalation on
                # the same principal (the "path contradicts the description" bug). Only a
                # finding with NO declared anchor (an exposure/worst-reach finding) does the
                # unconstrained search.
                cand = None if anchored_intent else _best_path_from(g, eid, adj, blast)
                if cand is None:
                    # No onward escalation (or an anchored finding whose capability isn't a
                    # first move here) - the node itself is the objective.
                    cand = {
                        "entry": _node_brief(g, eid), "target": _node_brief(g, eid),
                        "hops": [], "length": 0,
                        "reaches_tier0": _node_brief(g, eid)["tier0"],
                        "impact": _impact_score(g, eid, blast),
                    }
                if best is None or (cand["impact"], -cand["length"]) > (best["impact"], -best["length"]):
                    best = cand
        if best is None:
            continue
        # Subscriptions this finding's principals can reach (full-graph, MG-expanded).
        f_subs: set[str] = set()
        for eid in entries:
            f_subs |= reach.get(eid, set())
        sub_names = sorted({_sub_name(s) for s in f_subs})
        f["max_impact_path"] = best
        f["max_impact_reaches_tier0"] = best["reaches_tier0"]
        f["subscription_reach"] = sub_names
        f["subscription_reach_count"] = len(f_subs)
        # The tenant-wide max-impact MAP is a list of escalation PATHS, so it only holds
        # entries that actually move (entry != target, length >= 1). A length-0 fallback
        # means the principal is already its own objective (a Tier-0 admin, or a resource
        # sink with no onward escalation) - real as per-finding context on f, but shown in
        # the map it reads as "entry point and objective are the same" for many rows. Keep
        # it on the finding; leave it out of the map.
        if best["length"] > 0 and best["entry"]["id"] != best["target"]["id"]:
            amap.append({
                "finding": f.get("title"), "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "entry": best["entry"], "target": best["target"],
                "hops": best["hops"], "length": best["length"],
                "reaches_tier0": best["reaches_tier0"], "impact": best["impact"],
                "subscription_reach_count": len(f_subs),
                "subscription_reach": sub_names[:12],
            })
    # Deduplicate the tenant-wide map by (entry, target); keep the shortest, most
    # severe representative. Rank by impact, then Tier-0, then severity.
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    best_by_pair: dict[tuple, dict] = {}
    for p in amap:
        key = (p["entry"]["id"], p["target"]["id"])
        cur = best_by_pair.get(key)
        if cur is None or (sev_rank.get(p["severity"], 5), p["length"]) < (
                sev_rank.get(cur["severity"], 5), cur["length"]):
            best_by_pair[key] = p
    # Cross-subscription reach is a severity amplifier: among paths of equal impact and
    # Tier-0 status, the one that spans more subscriptions ranks higher.
    ranked = sorted(best_by_pair.values(),
                    key=lambda p: (-p["impact"], not p["reaches_tier0"],
                                   -p.get("subscription_reach_count", 0),
                                   sev_rank.get(p["severity"], 5), p["length"]))
    return {
        "paths": ranked,
        "count": len(ranked),
        "tier0_count": sum(1 for p in ranked if p["reaches_tier0"]),
        "cross_subscription_count": sum(1 for p in ranked
                                        if p.get("subscription_reach_count", 0) >= 2),
    }


_SUB_RE = None  # lazily compiled


def _subscription_resolver(g: Graph):
    """Return `(scope_subs, sub_name)` helpers that resolve an RBAC scope string to the
    set of subscription ids it grants over, management-group scopes expanded transitively
    to every descendant subscription. This is the single primitive that turns a role
    placement into a concrete cross-subscription blast radius."""
    import re
    global _SUB_RE
    if _SUB_RE is None:
        _SUB_RE = re.compile(r"/subscriptions/[0-9a-fA-F-]{36}", re.I)

    mg_children: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type == EdgeType.CONTAINS:
            parent = g.node(e.src)
            if parent and parent.kind == NodeKind.MANAGEMENT_GROUP:
                mg_children.setdefault(e.src, []).append(e.dst)

    def _descendants(mg_id: str, seen: "set[str] | None" = None) -> "set[str]":
        seen = seen if seen is not None else set()
        if mg_id in seen:
            return set()
        seen.add(mg_id)
        out: set[str] = set()
        for cid in mg_children.get(mg_id, []):
            c = g.node(cid)
            if not c:
                continue
            if c.kind == NodeKind.SUBSCRIPTION:
                out.add(cid)
            elif c.kind == NodeKind.MANAGEMENT_GROUP:
                out |= _descendants(cid, seen)
        return out

    mg_desc = {mg.id: _descendants(mg.id) for mg in g.nodes_of_kind(NodeKind.MANAGEMENT_GROUP)}
    mg_by_key: dict[str, set[str]] = {}
    for mid, subs in mg_desc.items():
        mg_by_key[mid.lower()] = subs
        tail = mid.lower().rsplit("managementgroups/", 1)[-1]
        if tail:
            mg_by_key.setdefault("managementgroups/" + tail, subs)

    def _sub_name(sid: str) -> str:
        n = g.node(sid)
        return n.name if (n and n.name) else sid.rsplit("/", 1)[-1]

    def _scope_subs(scope: str) -> set[str]:
        low = (scope or "").lower()
        if "managementgroups/" in low:
            if low in mg_by_key:
                return mg_by_key[low]
            tail = "managementgroups/" + low.rsplit("managementgroups/", 1)[-1]
            return mg_by_key.get(tail, set())
        m = _SUB_RE.search(scope or "")
        return {m.group(0)} if m else set()

    return _scope_subs, _sub_name


def compute_subscription_reach(g: Graph, scope_subs=None) -> "dict[str, set[str]]":
    """Per-node set of subscription ids reachable by compromising that node, computed
    over the FULL escalation graph - the way an attacker actually crosses subscription
    boundaries.

    Cross-subscription reach is NOT just the RBAC a node holds directly. A user who is a
    member of a group with Owner in two subscriptions bridges them; so does a principal
    that owns a service principal with cross-subscription RBAC, one PIM-eligible for a
    role that spans subscriptions, or one that can add a secret to / reset the password of
    such a principal. This walks every escalation primitive (group membership, ownership,
    PIM self-activation, add-secret, reset-password, managed-identity theft, ...) and, for
    each node, unions the subscriptions granted by every RBAC assignment held by anything
    it can escalate to. Management-group roles expand to all descendant subscriptions.

    Returns `{node_id: {subscription_id, ...}}`, present only for nodes that reach at
    least one subscription. Deterministic and grounded: reach only ever flows along edges
    that exist in the collection."""
    if scope_subs is None:
        scope_subs, _ = _subscription_resolver(g)

    # Subscriptions each node grants over via RBAC it holds DIRECTLY.
    direct: dict[str, set[str]] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_RBAC_ROLE:
            continue
        subs = scope_subs(e.evidence.get("scope") or "")
        if subs:
            direct.setdefault(e.src, set()).update(subs)

    # Escalation adjacency (destinations only): u -> v means compromising u yields v.
    adj: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type in _ESCALATION_EDGES and e.src != e.dst:
            adj.setdefault(e.src, []).append(e.dst)

    # Monotone fixpoint: reach[u] gains every subscription reachable from its escalation
    # successors, plus what u holds directly. Bounded passes (escalation depth is small),
    # early-exit once stable; correct in the presence of membership/ownership cycles.
    reach: dict[str, set[str]] = {n: set(s) for n, s in direct.items()}
    nodes = set(adj) | set(direct)
    for _ in range(16):
        changed = False
        for u in nodes:
            succ = adj.get(u)
            if not succ:
                continue
            ru = reach.get(u)
            for v in succ:
                rv = reach.get(v)
                if not rv:
                    continue
                if ru is None:
                    ru = set()
                    reach[u] = ru
                before = len(ru)
                ru |= rv
                if len(ru) > before:
                    changed = True
        if not changed:
            break
    return {n: s for n, s in reach.items() if s}


def _footprint_subscription_reach(g: Graph, scope_subs) -> "dict[str, set[str]]":
    """Per-node subscriptions of STANDING access - RBAC held directly plus RBAC inherited
    through group membership or ownership. Unlike compute_subscription_reach it deliberately
    does NOT follow escalation primitives (CanResetPassword, CanAddSecret, CanGrantRole,
    PIM self-activation, managed-identity theft): those are attack PATHS to another
    principal's access, not the node's own cross-subscription footprint. A cross-sub bridge
    is about standing reach - 'I already hold access in these subscriptions' - so it is
    built on this, which keeps escalation-only reach (e.g. an SP that can add a secret to a
    tier-0 SP) out of the bridge list, where it belongs to Attack Paths instead."""
    direct: dict[str, set[str]] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_RBAC_ROLE:
            continue
        subs = scope_subs(e.evidence.get("scope") or "")
        if subs:
            direct.setdefault(e.src, set()).update(subs)
    _FOOT = {EdgeType.MEMBER_OF, EdgeType.OWNS}
    adj: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type in _FOOT and e.src != e.dst:
            adj.setdefault(e.src, []).append(e.dst)
    foot: dict[str, set[str]] = {n: set(s) for n, s in direct.items()}
    nodes = set(adj) | set(direct)
    for _ in range(16):
        changed = False
        for u in nodes:
            for v in adj.get(u, ()):  # inherit the subscriptions the group/owned SP holds
                rv = foot.get(v)
                if not rv:
                    continue
                ru = foot.setdefault(u, set())
                before = len(ru)
                ru |= rv
                if len(ru) > before:
                    changed = True
        if not changed:
            break
    return {n: s for n, s in foot.items() if s}


def compute_cross_subscription(g: Graph, blast: "dict[str, int]",
                               reach: "dict[str, set[str]] | None" = None) -> dict:
    """Map the tenant's cross-subscription attack surface.

    A *bridge* is a principal with STANDING access to two or more subscriptions - held
    directly, or inherited through group membership or ownership - so compromising it
    directly touches every subscription in its footprint. Footprint reach (not the full
    escalation reach) defines a bridge: an SP that can only *escalate* to an admin who
    spans 41 subscriptions is an attack path, not a bridge, and belongs in Attack Paths.
    Members whose entire footprint comes from a bridging group are represented by that
    group (counted, not listed) so the list names the actionable target. The escalation
    `reach`/`blast` are still used to mark whether a bridge additionally reaches Tier-0."""
    scope_subs, _sub_name = _subscription_resolver(g)
    if reach is None:
        reach = compute_subscription_reach(g, scope_subs)
    footprint = _footprint_subscription_reach(g, scope_subs)

    # Subscriptions each principal holds DIRECTLY (to separate direct bridges from ones
    # that only bridge indirectly), the roles held, and whether any came via an MG scope.
    direct_subs: dict[str, set[str]] = {}
    direct_roles: dict[str, set[str]] = {}
    direct_mg: set[str] = set()
    for e in g.edges():
        if e.type != EdgeType.HAS_RBAC_ROLE:
            continue
        scope = e.evidence.get("scope") or ""
        subs = scope_subs(scope)
        if not subs:
            continue
        direct_subs.setdefault(e.src, set()).update(subs)
        role = e.evidence.get("role")
        if role:
            direct_roles.setdefault(e.src, set()).add(role)
        if "managementgroups/" in scope.lower():
            direct_mg.add(e.src)

    _ROLE_RANK = {"owner": 0, "user access administrator": 1,
                  "role based access control administrator": 1, "contributor": 2}
    _PRINCIPAL = {NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL}

    # Only principals with STANDING footprint across >=2 subscriptions are bridges (a
    # resource, single-sub, or escalation-only principal is not). Names can collide across
    # subscriptions, so disambiguate on id.
    per = {pid: subs for pid, subs in footprint.items()
           if len(subs) >= 2 and (g.node(pid) and g.node(pid).kind in _PRINCIPAL)}
    name_counts: dict[str, int] = {}
    for subs in per.values():
        for sid in subs:
            name_counts[_sub_name(sid)] = name_counts.get(_sub_name(sid), 0) + 1

    def _disp(sid: str) -> str:
        nm = _sub_name(sid)
        if name_counts.get(nm, 0) > 1:
            return f"{nm} ({sid.rsplit('/', 1)[-1][:8]})"
        return nm

    # Groups that hold cross-subscription RBAC DIRECTLY confer that reach to every member,
    # so each member shows up in `per` as its own bridge. Listing all of them (228 of 708
    # rows on real data) is noise that repeats one mechanism per member and buries the
    # actionable target - the group. Collapse a member whose cross-subscription reach is
    # FULLY explained by the bridging group(s) it belongs to into that group (counted, not
    # listed); keep principals that hold cross-sub RBAC themselves or that bridge by
    # combining grants no single group provides.
    bridge_groups = {gid for gid in per
                     if (g.node(gid) and g.node(gid).kind == NodeKind.GROUP
                         and len(direct_subs.get(gid, set())) >= 2)}
    inherited_members: dict[str, int] = {}   # group id -> members collapsed into it

    bridges: list[dict] = []
    link_agg: dict[tuple, dict] = {}
    for pid, subs in per.items():
        node = g.node(pid)
        held = direct_subs.get(pid, set())
        is_group = bool(node and node.kind == NodeKind.GROUP)
        # A principal that holds no cross-sub RBAC itself and whose entire reach is covered
        # by bridging groups it is a direct member of is represented by those groups.
        if not is_group and len(held) < 2:
            member_of_bridges = {e.dst for e in g.out_edges(pid, EdgeType.MEMBER_OF)} & bridge_groups
            covered: set[str] = set()
            for gid in member_of_bridges:
                covered |= footprint.get(gid, set())
            if member_of_bridges and subs <= covered:
                for gid in member_of_bridges:
                    inherited_members[gid] = inherited_members.get(gid, 0) + 1
                continue

        ids = sorted(subs)
        # Reach beyond what the principal holds directly means the bridge is formed by an
        # indirect primitive (membership, ownership, PIM, escalation), not a role on it.
        indirect = bool(subs - held)
        reaches_t0 = bool(blast.get(pid)) or bool(node and (node.tags & {"tier0", "can_reach_tier0"}))
        br = {
            "id": pid, "name": (node.name if node else pid),
            "kind": (node.kind.value if node else "?"),
            "subscriptions": [_disp(s) for s in ids], "subscription_count": len(ids),
            "roles": sorted(direct_roles.get(pid, set())),
            "via_management_group": pid in direct_mg,
            "indirect": indirect,
            "reaches_tier0": reaches_t0, "blast_radius": blast.get(pid, 0),
            # Group bridges carry their membership: that count is the real blast radius of
            # the group's cross-subscription reach.
            "member_count": (sum(1 for _ in g.in_edges(pid, EdgeType.MEMBER_OF))
                             if is_group else None),
        }
        bridges.append(br)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                key = (ids[i], ids[j])
                agg = link_agg.setdefault(key, {"a": _disp(ids[i]), "b": _disp(ids[j]),
                                                "principals": [], "max_blast": 0})
                agg["principals"].append(br["name"])
                agg["max_blast"] = max(agg["max_blast"], br["blast_radius"])
    # Fold the collapsed-member tally onto the group bridges so the UI can say
    # "confers cross-sub reach to N members".
    for br in bridges:
        if br["member_count"] is not None:
            br["inherited_bridge_members"] = inherited_members.get(br["id"], 0)

    # Rank by BRIDGE TYPE first, so the actionable leverage points lead: a group that
    # confers cross-sub reach to its whole membership (fix once, fix all members) ranks
    # above a principal holding cross-sub RBAC directly, which ranks above one that only
    # bridges by combining grants no single group provides. Within a type, Tier-0 first,
    # then widest span / blast / most members.
    def _btype(b):
        if b["member_count"] is not None:
            return 0                       # group - the conferring mechanism
        if not b["indirect"]:
            return 1                       # holds cross-sub RBAC directly
        return 2                           # combines grants from several sources
    bridges.sort(key=lambda b: (
        _btype(b),
        0 if b["reaches_tier0"] else 1,
        -b["subscription_count"], -(b["member_count"] or 0), -b["blast_radius"],
        min((_ROLE_RANK.get(r.lower(), 9) for r in b["roles"]), default=9),
        b["name"],
    ))
    links = [{"a": v["a"], "b": v["b"], "principal_count": len(v["principals"]),
              "principals": sorted(set(v["principals"]))[:8], "max_blast": v["max_blast"]}
             for v in link_agg.values()]
    links.sort(key=lambda l: (-l["principal_count"], -l["max_blast"]))

    all_subs = {s for subs in per.values() for s in subs}
    return {
        "subscription_count": len(all_subs),
        "bridge_count": len(bridges),
        "link_count": len(links),
        "bridges": bridges[:100],
        "links": links[:100],
    }


# Edge types worth visualising as escalation/abuse relationships.
_VIZ_EDGES = {
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
    EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_STEAL_MANAGED_IDENTITY, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_GET_STORAGE_KEY, EdgeType.CAN_EXEC_AKS,
    EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_PUSH_CONTAINER,
    EdgeType.ELIGIBLE_FOR_ROLE,
    EdgeType.EFFECTIVE_ROLE, EdgeType.MEMBER_OF, EdgeType.OWNS,
}

_TARGET_TAGS = {"tier0", "tier0_critical", "can_reach_tier0", "tier0_eligible"}


def compute_attack_paths(g: Graph, *, max_depth: int = 8, max_total: int = 800,
                         per_entry_targets: int = 15, routes_per_pair: int = 3,
                         per_entry_visits: int = 6000) -> dict:
    """Enumerate escalation paths from non-privileged entry points to a node that
    holds or can reach Tier-0, or to a sensitive data/credential sink.

    Complete-or-honest, not a silent sampler: traversal does NOT stop at an
    intermediate target (a Tier-0 stepping stone can reach a higher crown jewel, e.g.
    a group holding Privileged Authentication Administrator that can then reset a
    Global Admin's password), the per-entry limit counts DISTINCT TARGETS rather than
    raw paths (so an entry reaching ten targets is not cut off after six paths to
    two), genuinely distinct routes to the same (entry,target) are preserved
    (`route_count` + `alt_paths`), and `truncated` is set whenever ANY bound - depth,
    per-entry, or the global cap - actually drops a branch. Hard visit/total budgets
    keep it bounded on very large tenants; hitting them sets `truncated`."""
    adj: dict[str, list[tuple[str, str]]] = {}
    for e in g.edges():
        if e.type in _ESCALATION_EDGES and e.src != e.dst:
            adj.setdefault(e.src, []).append((e.dst, e.primitive or e.type.value))

    def is_target(nid: str) -> bool:
        n = g.node(nid)
        return bool(n and ((n.tags & _TARGET_TAGS) or n.kind in _SINK_KINDS))

    principals = g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)
    entries = [p for p in principals if p.id in adj and "tier0" not in p.tags]
    # Walk the entries already known to reach Tier-0 FIRST, so if the global cap does
    # bite it drops low-value entries, never the high-value ones.
    entries.sort(key=lambda p: (0 if "can_reach_tier0" in p.tags else 1, p.name))

    routes: dict[tuple, list[dict]] = {}   # (entry,target) -> stored routes
    extra_routes: dict[tuple, int] = {}    # routes seen beyond routes_per_pair
    truncated = False
    total = 0

    for entry in entries:
        if total >= max_total:
            truncated = True
            break
        targets_here: set[str] = set()
        visits = 0
        stack = [(entry.id, [entry.id], [])]
        entry_done = False
        while stack and not entry_done:
            if total >= max_total:
                truncated = True
                break
            if visits >= per_entry_visits:
                truncated = True
                break
            visits += 1
            cur, nodes, hops = stack.pop()
            depth = len(nodes) - 1
            for dst, prim in adj.get(cur, []):
                if dst in nodes:                    # cycle guard within this path
                    continue
                new_hops = hops + [{"from": cur, "to": dst, "from_name": g.display(cur),
                                    "to_name": g.display(dst), "primitive": prim}]
                if is_target(dst) and dst != entry.id:
                    # Per-entry DISTINCT-TARGET cap, enforced HERE (not once per node
                    # pop). A single node can fan out to hundreds of sink targets
                    # (CanReachKVSecret → every vault); checking only at the top of the
                    # while-loop let the first entry blow the whole global budget in one
                    # pop and starved every other entry - so all paths came from one
                    # principal and distinct escalation entries (e.g. the IDP chain)
                    # never appeared. Stop this entry once it has its quota of targets
                    # and move to the next, so the budget spreads across many entries.
                    if dst not in targets_here and len(targets_here) >= per_entry_targets:
                        truncated = True
                        entry_done = True
                        break
                    tgt = g.node(dst)
                    key = (entry.id, dst)
                    lst = routes.setdefault(key, [])
                    if len(lst) < routes_per_pair:
                        lst.append({
                            "id": f"{entry.id}->{dst}:{len(new_hops)}",
                            "entry": entry.name, "entry_id": entry.id,
                            "entry_kind": entry.kind.value,
                            "target": tgt.name, "target_id": dst, "target_kind": tgt.kind.value,
                            "target_sink": tgt.kind in _SINK_KINDS,
                            "length": len(new_hops), "hops": new_hops,
                            "critical": "tier0_critical" in tgt.tags or "tier0" in tgt.tags,
                        })
                        total += 1
                        targets_here.add(dst)
                        if total >= max_total:
                            truncated = True
                            entry_done = True
                            break
                    else:
                        extra_routes[key] = extra_routes.get(key, 0) + 1
                        targets_here.add(dst)
                # Keep expanding past a target too - respect the depth cap, and be
                # honest when it cuts a branch that might have reached further.
                if depth + 1 <= max_depth:
                    stack.append((dst, nodes + [dst], new_hops))
                else:
                    truncated = True
        if total >= max_total:
            truncated = True
            break

    # One representative (shortest) route per (entry,target); keep the distinct
    # alternates so "cut this edge to sever access" can actually be answered.
    result: list[dict] = []
    for key, lst in routes.items():
        lst.sort(key=lambda p: p["length"])
        primary = lst[0]
        if len(lst) > 1:
            primary["alt_paths"] = [{"length": p["length"], "hops": p["hops"]} for p in lst[1:]]
        primary["route_count"] = len(lst) + extra_routes.get(key, 0)
        result.append(primary)

    result.sort(key=lambda p: (p["length"], not p["critical"], p["entry"]))
    return {"paths": result, "truncated": truncated, "total_found": len(result)}


def compute_attack_graph(g: Graph, analytics: Analytics, *, max_nodes: int = 160,
                         max_edges: int = 320) -> dict:
    """Export a pruned subgraph for the attack-path visualization.

    EDGE-centric, not node-centric: the point of the graph is the escalation EDGES that
    reach privilege (a service principal that can add itself to a Tier-0 group, a
    principal that can grant a role, ...), so selection keeps the endpoints of the
    highest-value abuse edges rather than the highest-scoring isolated nodes. The old
    node-importance cap kept the 55+ Tier-0 dots and pruned the entry principals feeding
    them, which silently deleted exactly the SP→Tier-0 edges the user is looking for
    (e.g. an SP --CanAddMember--> [RBAC] Privileged Group).
    """
    choke_ids = {c["id"] for c in analytics.choke_points}
    tier0_ids = {t["id"] for t in analytics.tier0}
    entry_ids = set(analytics.blast_radius)

    def _is_priv(nid: str) -> bool:
        n = g.node(nid)
        return nid in tier0_ids or bool(n and (n.tags & {"tier0", "dangerous_app_role", "can_reach_tier0"}))

    # Escalation primitives (the actual abuse) rank above plumbing (MemberOf/EFFECTIVE_ROLE/Owns).
    _ABUSE = {EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
              EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
              EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_STEAL_MANAGED_IDENTITY,
              EdgeType.CAN_RESET_PASSWORD, EdgeType.CAN_GET_STORAGE_KEY, EdgeType.CAN_EXEC_AKS,
              EdgeType.CAN_READ_STORAGE_BLOB, EdgeType.CAN_PUSH_CONTAINER, EdgeType.ELIGIBLE_FOR_ROLE}

    edges = [e for e in g.edges() if e.type in _VIZ_EDGES and e.src != e.dst]

    def escore(e) -> int:
        s = 0
        if _is_priv(e.dst): s += 6          # the edge REACHES privilege - the money edge
        if e.type in _ABUSE: s += 3         # a real abuse primitive, not plumbing
        if e.src in entry_ids: s += 2       # from a non-privileged entry point
        if e.dst in tier0_ids: s += 2
        if e.dst in choke_ids or e.src in choke_ids: s += 1
        return s

    edges.sort(key=escore, reverse=True)

    # Greedily keep the highest-value edges, adding both endpoints, until the node budget
    # is spent - so every kept edge is fully drawable and the graph stays connected around
    # the real attack paths.
    keep: set[str] = set()
    kept_edges = []
    for e in edges:
        if len(kept_edges) >= max_edges:
            break
        new = {e.src, e.dst} - keep
        if len(keep) + len(new) > max_nodes and new:
            continue
        keep |= {e.src, e.dst}
        kept_edges.append(e)

    # Spend any leftover budget on Tier-0 / choke nodes not yet drawn, so crown jewels
    # with no kept edge still appear as targets.
    for nid in list(tier0_ids) + list(choke_ids):
        if len(keep) >= max_nodes:
            break
        keep.add(nid)

    nodes = []
    for nid in keep:
        n = g.node(nid)
        if not n:
            continue
        nodes.append({
            "id": nid, "name": n.name, "kind": n.kind.value,
            "tier0": "tier0" in n.tags, "tier0_critical": "tier0_critical" in n.tags,
            "entry": nid in entry_ids and "tier0" not in n.tags,
            "choke": nid in choke_ids,
            "dangerous": "dangerous_app_role" in n.tags,
        })
    node_ids = {n["id"] for n in nodes}
    viz_edges = []
    seen = set()
    for e in kept_edges:
        if e.src in node_ids and e.dst in node_ids:
            key = (e.src, e.dst, e.type.value)
            if key in seen:
                continue
            seen.add(key)
            viz_edges.append({"src": e.src, "dst": e.dst, "type": e.type.value,
                              "primitive": e.primitive or e.type.value, "derived": e.derived})
    total_abuse = sum(1 for e in edges if _is_priv(e.dst))
    return {"nodes": nodes, "edges": viz_edges,
            "edges_truncated": max(0, total_abuse - len(viz_edges)),
            "max_impact_id": (analytics.max_impact or {}).get("principal_id")}
