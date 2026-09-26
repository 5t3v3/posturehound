"""Deterministic fact extraction - the ground truth the AI reasons over.

This module is the boundary between "exact and scalable" and "judgement and
narrative." It never guesses: every fact here is derived mechanically from the
graph (which itself was built from AzureHound's real schema and re-derived
escalation primitives in derive.py). The AI finding-generator is only allowed to
reference entity ids and edge facts that appear in this pack, so it can reason
like a security architect without being able to invent a principal, a
permission, or a relationship that isn't actually in the tenant.

Design constraints:
  - Bounded size regardless of tenant size (caps + counts-when-truncated), so a
    multi-GB collection still produces a fact pack an LLM can reason over.
  - Every entity referenced carries a stable `id` plus enough evidence (name,
    kind, the exact permission/role/scope, source record) to stand on its own
    in a finding without the model needing to re-derive it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

from . import constants as C
from .model import EdgeType, Graph, NodeKind

# Caps keep the fact pack bounded.  With domain-specific packs each specialist
# only receives sections relevant to them, so higher caps are affordable -
# the cross-specialist cap competition that previously forced 120 is gone.
MAX_PER_BUCKET = 500


def _ent(g: Graph, node_id: str | None) -> dict[str, Any] | None:
    if not node_id:
        return None
    n = g.node(node_id)
    if not n:
        return {"id": node_id, "name": node_id[:200], "kind": "Unknown"}
    name = (n.name or "")[:200].strip()
    return {"id": n.id, "name": name, "kind": n.kind.value}


def _cap(items: list, n: int = MAX_PER_BUCKET) -> tuple[list, int]:
    return items[:n], max(0, len(items) - n)


@dataclass
class FactPack:
    tenant_id: str | None
    counts: dict[str, int]
    tier0_principals: list[dict] = field(default_factory=list)
    escalation_edges: list[dict] = field(default_factory=list)
    over_permissive_apps: list[dict] = field(default_factory=list)
    credential_exposure: list[dict] = field(default_factory=list)
    guest_and_foreign: list[dict] = field(default_factory=list)
    keyvault_exposure: list[dict] = field(default_factory=list)
    storage_exposure: list[dict] = field(default_factory=list)
    compute_identity_exposure: list[dict] = field(default_factory=list)
    hygiene_issues: list[dict] = field(default_factory=list)
    pim_eligible_shadow_admins: list[dict] = field(default_factory=list)
    container_exposure: list[dict] = field(default_factory=list)
    # Live Azure Resource Graph + Microsoft Graph findings (v2 Track B) - network,
    # database, container, cache, AI-service and Conditional-Access exposure that
    # AzureHound cannot see. Populated from the deterministic ARG/IDG findings so
    # the AI specialists reason over the tenant's full attack surface, not just the
    # identity graph. Empty when no Reader service principal is configured.
    external_exposure: list[dict] = field(default_factory=list)
    # Complete role-assignment inventories (not pre-filtered to known-bad).
    # The AI needs full visibility to detect non-standard posture - anomalies that
    # no individual rule can enumerate, like "47 users have Contributor on production".
    subscription_rbac_all: list[dict] = field(default_factory=list)   # every RBAC assignment at sub/MG scope
    entra_role_all: list[dict] = field(default_factory=list)           # every Entra role assignment
    service_principal_inventory: list[dict] = field(default_factory=list)  # all SPs ranked by permission count
    # Breadth / anomaly-detection signals - statistical aggregations
    broad_access_signals: dict = field(default_factory=dict)
    # Management-group hierarchy: MG id -> every descendant subscription id, resolved
    # transitively through nested MGs. This is what turns "Owner at MG scope" into a
    # quantified blast radius ("Owner over these 12 subscriptions"), which is the
    # single most important cross-subscription primitive in Azure RBAC.
    mg_descendant_subscriptions: dict[str, list[str]] = field(default_factory=dict)
    # Cross-subscription bridges: principals that can reach two or more subscriptions over
    # the FULL escalation graph - directly, or inherited through a group, an owned service
    # principal, a PIM-eligible role, or any escalation chain. This is the cross-subscription
    # attack surface as an attacker actually crosses it, not just direct multi-sub RBAC.
    # Every specialist that reasons about privilege sees it, so cross-subscription blast
    # radius is a severity amplifier woven through the whole analysis, never a side view.
    cross_subscription_bridges: list[dict] = field(default_factory=list)
    truncated: dict[str, int] = field(default_factory=dict)
    entity_index: dict[str, dict] = field(default_factory=dict)  # every id referenced anywhere above
    # Uncapped raw inventories. The Phase-1 Python anomaly scanners read these for
    # 100% coverage at zero cost; they are never placed in to_prompt_dict().
    raw_sp_list:        list[dict] = field(default_factory=list, repr=False)
    raw_rbac_list:      list[dict] = field(default_factory=list, repr=False)
    raw_entra_list:     list[dict] = field(default_factory=list, repr=False)
    raw_group_list:     list[dict] = field(default_factory=list, repr=False)
    raw_app_grant_list: list[dict] = field(default_factory=list, repr=False)
    # Complete multi-hop attack paths from non-privileged principals to tier-0 targets.
    # Built by _build_attack_paths() - the graph traversal flat-list scanning cannot do.
    raw_attack_paths:    list[dict] = field(default_factory=list, repr=False)
    attack_paths_capped: bool       = field(default=False)

    def register(self, ent: dict | None) -> dict | None:
        if ent:
            self.entity_index[ent["id"]] = ent
        return ent

    # Sections each domain pack includes.  Specialists get their domain pack
    # so they see all data relevant to them without sharing caps with others.
    _DOMAIN_SECTIONS: ClassVar[dict[str, list[str]]] = {
        "attack_paths": [
            "tier0_principals", "escalation_edges", "pim_eligible_shadow_admins",
            "guest_and_foreign", "entra_role_all", "hygiene_issues",
            "cross_subscription_bridges",
        ],
        # Live external exposure (v2 Track B) meets identity: the resource-exposure
        # specialist reasons over internet-facing resources plus who can reach them.
        "external": [
            "external_exposure", "tier0_principals", "broad_access_signals",
            "subscription_rbac_all", "guest_and_foreign", "cross_subscription_bridges",
        ],
        "applications": [
            "over_permissive_apps", "credential_exposure", "service_principal_inventory",
            "compute_identity_exposure", "guest_and_foreign", "cross_subscription_bridges",
        ],
        "identity": [
            "tier0_principals", "entra_role_all", "hygiene_issues",
            "pim_eligible_shadow_admins", "guest_and_foreign", "cross_subscription_bridges",
            # pim_risk and hygiene both reason about a principal that is PIM-eligible AND
            # holds a direct escalation primitive (CAN_ADD_SECRET / CAN_ADD_OWNER, ...);
            # without the edges here that pattern was structurally invisible to them.
            "escalation_edges",
        ],
        # Tenant-configuration baseline. Same identity core as `identity`, PLUS the live
        # Track-B controls (Conditional Access, security defaults, legacy auth) that arrive
        # as IDG-*/ARG-* rows in external_exposure - so the "absent controls" specialist can
        # actually reason over whether the expected controls are present when they WERE
        # collected, instead of being told they are always uncollectable.
        "tenant_config": [
            "tier0_principals", "entra_role_all", "hygiene_issues",
            "pim_eligible_shadow_admins", "guest_and_foreign", "external_exposure",
        ],
        # Automation / DevOps surface reasons about service principals: automation SPNs,
        # federated-credential subjects, Run-As identities, plus the managed identities on
        # compute. It needs the application/credential/SP sections (where FIC subjects and
        # Graph permissions live), NOT the storage/keyvault slice it used to get.
        "devops": [
            "over_permissive_apps", "credential_exposure", "service_principal_inventory",
            "compute_identity_exposure", "subscription_rbac_all", "cross_subscription_bridges",
        ],
        "resources": [
            "keyvault_exposure", "storage_exposure", "compute_identity_exposure",
            "container_exposure", "subscription_rbac_all", "cross_subscription_bridges",
        ],
        "rbac": [
            "subscription_rbac_all", "entra_role_all", "broad_access_signals",
            "tier0_principals", "cross_subscription_bridges",
        ],
        "breadth": [
            "broad_access_signals", "entra_role_all", "subscription_rbac_all",
            "service_principal_inventory", "large_privileged_groups_detail",
        ],
    }

    def to_prompt_dict(self, domain: "str | None" = None) -> dict:
        """Compact dict for the LLM prompt.

        When `domain` is provided, returns only the sections relevant to that
        domain so each specialist sees ALL the data it needs without competing
        for cap space with unrelated specialists.  When None, returns every
        section (used by Opus which needs the full picture).
        """
        all_sections: dict = {
            "tier0_principals": self.tier0_principals,
            "escalation_edges": self.escalation_edges,
            "over_permissive_apps": self.over_permissive_apps,
            "credential_exposure": self.credential_exposure,
            "guest_and_foreign": self.guest_and_foreign,
            "keyvault_exposure": self.keyvault_exposure,
            "storage_exposure": self.storage_exposure,
            "compute_identity_exposure": self.compute_identity_exposure,
            "hygiene_issues": self.hygiene_issues,
            "pim_eligible_shadow_admins": self.pim_eligible_shadow_admins,
            "container_exposure": self.container_exposure,
            "external_exposure": self.external_exposure,
            "subscription_rbac_all": self.subscription_rbac_all,
            "entra_role_all": self.entra_role_all,
            "service_principal_inventory": self.service_principal_inventory,
            "broad_access_signals": self.broad_access_signals,
            "cross_subscription_bridges": self.cross_subscription_bridges,
            # alias used by breadth domain
            "large_privileged_groups_detail": self.broad_access_signals.get("large_privileged_groups", []),
        }

        keys = self._DOMAIN_SECTIONS.get(domain, list(all_sections)) if domain else list(all_sections)
        d = {"tenant_id": self.tenant_id, "counts": self.counts}
        for k in keys:
            if k in all_sections:
                d[k] = all_sections[k]
        if self.truncated:
            d["truncated_buckets"] = {k: v for k, v in self.truncated.items() if k in keys}
        else:
            d["truncated_buckets"] = {}
        return d

    def known_ids(self) -> set[str]:
        return set(self.entity_index)

    def name_to_id_map(self) -> dict[str, str]:
        """{lowercased entity name -> id} for names that map to exactly ONE entity, so a
        finding that references a real entity by NAME (not its fact-pack id) can be recovered
        during grounding. Ambiguous names (shared by multiple entities) are omitted so a name
        collision never resolves to the wrong node. Cached."""
        cached = getattr(self, "_name_to_id", None)
        if cached is not None:
            return cached
        counts: dict[str, int] = {}
        first: dict[str, str] = {}
        for eid, info in self.entity_index.items():
            nm = (info.get("name") or "").strip().lower()
            if not nm:
                continue
            counts[nm] = counts.get(nm, 0) + 1
            first.setdefault(nm, eid)
        m = {nm: first[nm] for nm, c in counts.items() if c == 1}
        object.__setattr__(self, "_name_to_id", m)
        return m


# Escalation primitives worth surfacing individually (these are exactly the
# things a red-teamer / architect looks for: how does a low-priv identity end
# up with Tier-0, or steal another identity's access).
_ESCALATION_EDGE_TYPES = {
    EdgeType.CAN_ADD_SECRET: "Can add a credential to a service principal it controls",
    EdgeType.CAN_ADD_OWNER: "Can add itself/another principal as owner",
    EdgeType.CAN_ADD_MEMBER: "Can add itself to a privileged group",
    EdgeType.CAN_GRANT_ROLE: "Can grant directory roles to any principal",
    EdgeType.CAN_GRANT_APP_ROLE: "Can grant dangerous Graph application permissions",
    EdgeType.CAN_ESCALATE_RBAC: "Can grant itself Azure RBAC roles (User Access Administrator path)",
    EdgeType.CAN_REACH_KV_SECRET: "Can read Key Vault secrets/keys/certificates",
    EdgeType.CAN_STEAL_MANAGED_IDENTITY: "Can obtain a managed identity's token via the host resource",
    EdgeType.CAN_RESET_PASSWORD: "Can reset another principal's password",
    EdgeType.CAN_GET_STORAGE_KEY: "Can retrieve storage account keys (full data-plane access)",
    EdgeType.CAN_EXEC_AKS: "Can execute commands inside an AKS cluster (cluster-admin equivalent)",
    EdgeType.CAN_READ_STORAGE_BLOB: "Can read blob data directly via Entra token (bypasses shared-key controls)",
    EdgeType.CAN_PUSH_CONTAINER: "Can push container images to a registry (supply-chain attack vector)",
}

# Identity-plane primitives: the ones that move an attacker between PRINCIPALS and are
# the reason the attack_paths specialists exist. The remaining entries above are
# resource-plane sinks (Key Vault / storage / AKS / registry) which also reach the
# resources specialists via keyvault_exposure, storage_exposure and container_exposure.
# Because the sinks are far more numerous, a cap applied without this distinction spent
# ~67% of the 5,000-edge window on them and evicted identity primitives the specialists
# cannot get anywhere else.
_IDENTITY_ESCALATION_TYPES = frozenset({
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_OWNER, EdgeType.CAN_ADD_MEMBER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE,
    EdgeType.CAN_ESCALATE_RBAC, EdgeType.CAN_RESET_PASSWORD,
    EdgeType.CAN_STEAL_MANAGED_IDENTITY,
})
_IDENTITY_ESCALATION_PRIMITIVES = frozenset(t.value for t in _IDENTITY_ESCALATION_TYPES)


# Edge types that form traversable attack-path steps.
# These are the derived abuse edges (CAN_*) produced by derive.py plus
# MEMBER_OF for group-mediated privilege inheritance.
# Edge exploitability weights for path severity scoring.
# Score = max_edge_weight - 0.3*(hops-1) + guest_bonus + disabled_bonus.
# High-weight edges represent direct primitives (reset password, grant role);
# low-weight edges require chaining (group membership on its own does nothing).
_PATH_EDGE_WEIGHTS: "dict[str, float]" = {
    "CanResetPassword":        5.0,  # immediate account takeover
    "CanEscalateRBAC":         5.0,  # re-grant any role to self
    "CanGrantRole":            5.0,  # assign Global Administrator or any Entra role
    "CanAddSecret":            4.5,  # add credential → impersonate service principal
    "CanStealManagedIdentity": 4.5,  # steal VM/resource managed identity token
    "CanAddOwner":             4.0,  # become owner → full control of app/SP
    "CanGrantAppRole":         3.5,  # grant app role → expand SP permissions
    "CanAddMember":            2.5,  # add self to group → inherit group privileges
    "MemberOf":                1.5,  # already a member (static, needs a follow-on edge)
}

_PATH_EDGE_TYPES = frozenset({
    EdgeType.CAN_ADD_SECRET,            # A controls B's credentials → can auth as B
    EdgeType.CAN_ADD_OWNER,             # A makes itself/anyone owner of B
    EdgeType.CAN_ADD_MEMBER,            # A adds itself to privileged group B
    EdgeType.CAN_GRANT_ROLE,            # A can assign any Entra role to any principal
    EdgeType.CAN_GRANT_APP_ROLE,        # A can grant dangerous Graph app permissions
    EdgeType.CAN_ESCALATE_RBAC,         # A grants itself Owner/UAA via UAA path
    EdgeType.CAN_RESET_PASSWORD,        # A resets tier-0 user B's password
    EdgeType.CAN_STEAL_MANAGED_IDENTITY,# A steals MI B's token via its host resource
    EdgeType.MEMBER_OF,                 # A is a member of group B (transitive coverage)
})


def _build_attack_paths(g: "Graph", fp: "FactPack",
                        max_hops: int = 6, max_paths: int = 2000) -> "list[dict]":
    """Reverse BFS from all tier-0 targets - find non-privileged principals that
    can reach tier-0 within max_hops steps via the derived abuse edges.

    This is the graph traversal capability that flat-list scanning cannot provide:
    multi-hop paths like User→MEMBER_OF→Group→CAN_GRANT_ROLE→GlobalAdminRole are
    found deterministically without AI assistance.
    """
    from collections import deque

    # Group member count lookup - built from raw_group_list which is populated before this runs.
    # Used to add blast-radius bonus: a path through a 500-member group is more severe than
    # one through a 2-member group because more principals are implicitly affected.
    _group_mc: "dict[str, int]" = {grp["id"]: grp["member_count"] for grp in fp.raw_group_list}

    # Seed the BFS with all tier-0-tagged principals PLUS the role nodes they hold
    # (via EFFECTIVE_ROLE), so CAN_GRANT_ROLE paths to role nodes are captured.
    tier0_ids: "set[str]" = set()
    for n in g.nodes():
        if "tier0" in n.tags:
            tier0_ids.add(n.id)
            for e in g.out_edges(n.id, EdgeType.EFFECTIVE_ROLE):
                tier0_ids.add(e.dst)   # role node - CAN_GRANT_ROLE points here
    if not tier0_ids:
        return []

    paths: "list[dict]" = []
    seen:  "set[tuple]" = set()     # (src_id, target_id) pairs already recorded

    for target_id in tier0_ids:
        if len(paths) >= max_paths:
            break
        target_node = g.node(target_id)
        if not target_node:
            continue
        target_name = target_node.name or target_id

        # BFS queue: (current_node_id, forward_path_list)
        # forward_path_list: hops in FORWARD direction (src → … → target)
        queue: "deque" = deque([(target_id, [])])
        visited: "set[str]" = {target_id}

        while queue:
            curr_id, path_to_target = queue.popleft()
            if len(path_to_target) >= max_hops:
                continue

            for e in g.in_edges(curr_id):
                if e.type not in _PATH_EDGE_TYPES:
                    continue
                up_id = e.src
                if up_id in visited:
                    continue
                visited.add(up_id)

                up_node = g.node(up_id)
                if not up_node:
                    continue

                curr_node  = g.node(curr_id)
                curr_name  = (curr_node.name if curr_node else curr_id) or curr_id
                hop = {
                    "from_id":   up_id,
                    "from_name": up_node.name or up_id,
                    "from_kind": up_node.kind.value,
                    "edge":      e.type.value,
                    "to_id":     curr_id,
                    "to_name":   curr_name,
                    "to_kind":   curr_node.kind.value if curr_node else "Unknown",
                }
                new_path = [hop] + path_to_target   # prepend: keeps forward order

                # Record path when source is a non-tier0 user or SP.
                # When the first hop is group membership (User→MemberOf→Group→...),
                # use the GROUP as the effective source - all members share the same
                # dedup key, collapsing N per-member findings into one group-level one.
                if "tier0" not in up_node.tags and up_node.kind in (
                    NodeKind.USER, NodeKind.SERVICE_PRINCIPAL,
                ):
                    if (e.type == EdgeType.MEMBER_OF
                            and curr_node is not None
                            and curr_node.kind == NodeKind.GROUP
                            and "tier0" not in curr_node.tags
                            and path_to_target):
                        eff_src_id   = curr_id
                        eff_src_node = curr_node
                        eff_path     = path_to_target   # strip the MemberOf hop
                    else:
                        eff_src_id   = up_id
                        eff_src_node = up_node
                        eff_path     = new_path

                    src_key = (eff_src_id, target_id)
                    if src_key not in seen and len(paths) < max_paths:
                        seen.add(src_key)
                        nc = len(eff_path)
                        is_guest    = eff_src_node.props.get("userType") == "Guest"
                        is_disabled = eff_src_node.props.get("accountEnabled") is False

                        # Edge-weighted severity: worst edge on the path minus a hop
                        # penalty.  A 6-hop CanResetPassword path is still Critical;
                        # a 3-hop chain of pure MemberOf edges is only Medium.
                        _max_w  = max(
                            (_PATH_EDGE_WEIGHTS.get(h["edge"], 2.0) for h in eff_path),
                            default=2.0,
                        )
                        _score  = _max_w - 0.3 * (nc - 1)
                        if nc == 1:
                            _score = max(_score, 4.0)  # 1 hop to tier-0 is Critical regardless of edge
                        if is_guest:
                            _score += 0.5   # external party → higher urgency
                        if is_disabled:
                            _score += 0.3   # dormant account with path = oversight risk
                        # Blast radius: for group sources use the group's own member count;
                        # for user/SP sources find the largest intermediate group on the path.
                        if eff_src_node.kind == NodeKind.GROUP:
                            _max_group_mc = _group_mc.get(eff_src_id, 0)
                        else:
                            _max_group_mc = max(
                                (_group_mc.get(h["from_id"], 0)
                                 for h in eff_path if h.get("from_kind") == "AZGroup"),
                                default=0,
                            )
                        if _max_group_mc >= 50:
                            _score += 0.5
                        elif _max_group_mc >= 10:
                            _score += 0.2
                        sev = ("Critical" if _score >= 4.0
                               else "High" if _score >= 2.5
                               else "Medium")
                        _top_edge = max(
                            eff_path, key=lambda _h: _PATH_EDGE_WEIGHTS.get(_h["edge"], 2.0)
                        )["edge"]

                        # Ensure all entities on this path are grounding-registered
                        for h in eff_path:
                            fp.register(_ent(g, h["from_id"]))
                            fp.register(_ent(g, h["to_id"]))

                        # Build a clean chain string: A -[EdgeA]→ B -[EdgeB]→ C
                        parts = [eff_path[0]["from_name"]]
                        for h in eff_path:
                            parts.append(f"-[{h['edge']}]→ {h['to_name']}")
                        path_str = " ".join(parts)

                        paths.append({
                            "src_id":       eff_src_id,
                            "src_name":     eff_src_node.name or eff_src_id,
                            "src_kind":     eff_src_node.kind.value,
                            "src_is_guest": is_guest,
                            "src_enabled":  not is_disabled,
                            "dst_id":       target_id,
                            "dst_name":     target_name,
                            "hop_count":    nc,
                            "path":         path_str,
                            "hops":         eff_path,
                            "severity":          sev,
                            "path_score":        round(_score, 2),
                            "top_edge":          _top_edge,
                            "max_group_mc":      _max_group_mc,
                        })

                # Continue BFS through non-tier0 intermediaries (groups, SPs, etc.)
                if "tier0" not in up_node.tags:
                    queue.append((up_id, new_path))

    # Sort: guests + Critical first, then by hop count (shortest path most actionable)
    _sev = {"Critical": 0, "High": 1, "Medium": 2}
    paths.sort(key=lambda p: (
        0 if p.get("src_is_guest") else 1,
        _sev.get(p["severity"], 3),
        p["hop_count"],
    ))
    if len(paths) >= max_paths:
        fp.attack_paths_capped = True
    return paths


def build_fact_pack(g: Graph) -> FactPack:
    counts = {k.value: len(g.nodes_of_kind(k)) for k in NodeKind if g.nodes_of_kind(k)}
    fp = FactPack(tenant_id=g.tenant_id, counts=counts)

    # ---- Tier-0 principals: who already holds the keys, and how -----------
    t0 = [n for n in g.nodes() if "tier0" in n.tags]
    items = []
    for n in t0:
        # Resolve role names through the role node, dedupe, and DISCLOSE the cap. The
        # previous version emitted the raw evidence value (a GUID for Entra roles) and
        # truncated an undeduplicated list to 5 - so a Global Admin holding 12 Tier-0
        # roles rendered as ["Owner","Owner","Owner","Owner","Owner"], hiding the rest.
        via_all: list[str] = []
        for e in g.out_edges(n.id):
            if e.type not in (EdgeType.HAS_ENTRA_ROLE, EdgeType.HAS_RBAC_ROLE):
                continue
            dst = g.node(e.dst)
            resolved = (e.evidence.get("role")
                        or (dst.name if dst and dst.name and dst.kind == NodeKind.ROLE else None)
                        or e.evidence.get("roleTemplateId"))
            if resolved:
                via_all.append(str(resolved))
        via = sorted(set(via_all))
        ent = fp.register(_ent(g, n.id))
        # Tri-state: None means "never collected", which must not read as "cloud-only".
        _synced = n.props.get("onPremisesSyncEnabled")
        items.append({**ent,
                      "tier0_via": via[:8],
                      "tier0_via_distinct_total": len(via),
                      "tier0_via_withheld": max(0, len(via) - 8),
                      "account_type": n.props.get("userType"), "enabled": n.props.get("accountEnabled"),
                      "guest": n.props.get("userType") == "Guest",
                      "synced_from_onprem": None if _synced is None else bool(_synced)})
    fp.tier0_principals, trunc = _cap(items)
    if trunc:
        fp.truncated["tier0_principals"] = trunc

    # ---- Escalation edges: the exact primitives an attacker would chain ----
    esc = []
    for e in g.edges():
        if e.type not in _ESCALATION_EDGE_TYPES:
            continue
        src, dst = fp.register(_ent(g, e.src)), fp.register(_ent(g, e.dst))
        if not src or not dst:
            continue
        esc.append({
            "src": src, "dst": dst, "primitive": e.type.value,
            "meaning": _ESCALATION_EDGE_TYPES[e.type],
            "dst_is_tier0": "tier0" in (g.node(e.dst).tags if g.node(e.dst) else set()),
            "evidence": {k: v for k, v in (e.evidence or {}).items() if k in
                         ("role", "scope", "permissions", "resource", "value", "identityType")},
        })
    # Prioritise edges that actually reach Tier-0 - those are the ones that matter most.
    # Order: Tier-0 destinations first, then identity primitives ahead of resource-plane
    # sinks, so a cap can only ever drop the least consequential rows.
    esc.sort(key=lambda x: (
        not x["dst_is_tier0"],
        x.get("primitive") not in _IDENTITY_ESCALATION_PRIMITIVES,
    ))
    fp.escalation_edges, trunc = _cap(esc, 5000)  # attack paths must stay near-complete
    if trunc:
        fp.truncated["escalation_edges"] = trunc

    # ---- Over-permissive service principals / apps -------------------------
    apps = []
    for n in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        dangerous = [r.get("value") for r in (n.props.get("_granted_app_roles") or []) if r.get("value")]
        owners = [e.src for e in g.in_edges(n.id, EdgeType.OWNS)]
        has_secret = bool(n.props.get("passwordCredentials")) or bool(n.props.get("keyCredentials"))
        has_federated = bool(n.props.get("federatedIdentityCredentials"))
        is_foreign = "foreign_tenant" in n.tags
        is_managed_identity = n.props.get("servicePrincipalType") == "ManagedIdentity"
        # Delegated (on-behalf-of) OAuth2 grants - the illicit-consent surface that an
        # app-role-only view misses. Tenant-wide (admin-consented) grants apply to every
        # user, so a dangerous delegated scope there is a real escalation vector. Surfaced
        # here so the entitlement/delegation specialist can reason over the actual scopes,
        # not just the deterministic rule (AZ-APP-017) that also reads them.
        deleg = n.props.get("_delegated_grants") or []
        deleg_scopes = sorted({s.strip() for gr in deleg
                               for s in (gr.get("scope") or "").split() if s.strip()})
        admin_consented = any((gr.get("consent_type") or "").lower() == "allprincipals" for gr in deleg)
        if not (dangerous or (owners and (has_secret or has_federated)) or is_foreign or deleg_scopes):
            continue
        ent = fp.register(_ent(g, n.id))
        apps.append({**ent, "dangerous_graph_permissions": dangerous[:10],
                     "owners": [fp.register(_ent(g, o)) for o in owners[:5]],
                     "has_client_secret_or_cert": has_secret, "has_federated_credential": has_federated,
                     "multi_tenant_or_foreign": is_foreign, "is_managed_identity": is_managed_identity,
                     "delegated_scopes": deleg_scopes[:20],
                     "delegated_admin_consented": admin_consented,
                     "account_enabled": n.props.get("accountEnabled")})
    fp.over_permissive_apps, trunc = _cap(apps)
    if trunc:
        fp.truncated["over_permissive_apps"] = trunc

    # ---- Credential exposure (long-lived secrets, federated creds) --------
    cred = []
    for n in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL, NodeKind.APP):
        feds = n.props.get("federatedIdentityCredentials") or []
        pwds = n.props.get("passwordCredentials") or []
        if not (feds or pwds):
            continue
        ent = fp.register(_ent(g, n.id))
        cred.append({**ent,
                     "federated_credentials": [{"issuer": f.get("issuer"), "subject": f.get("subject")}
                                                for f in feds[:5]],
                     "password_credential_count": len(pwds)})
    fp.credential_exposure, trunc = _cap(cred)
    if trunc:
        fp.truncated["credential_exposure"] = trunc

    # ---- Guest & cross-tenant exposure --------------------------------------
    guests = []
    for n in g.nodes_of_kind(NodeKind.USER):
        if n.props.get("userType") == "Guest":
            # HAS_ENTRA_ROLE edges carry evidence {"roleTemplateId": ...} - never a
            # "role" key - so reading evidence["role"] alone produced [None, ...] for
            # every guest. The guard below still passed (a list of Nones is truthy) but
            # the rendered list was always empty, hiding e.g. a guest holding Billing
            # Administrator. Resolve through the role node, as tier0_via/entra_role_all do.
            roles = []
            for e in g.out_edges(n.id, EdgeType.HAS_ENTRA_ROLE):
                dst = g.node(e.dst)
                resolved = (e.evidence.get("role")
                            or (dst.name if dst and dst.name else None)
                            or e.evidence.get("roleTemplateId"))
                if resolved:
                    roles.append(resolved)
            groups = [e.dst for e in g.out_edges(n.id, EdgeType.MEMBER_OF)]
            if roles or groups or "tier0" in n.tags:
                ent = fp.register(_ent(g, n.id))
                guests.append({**ent, "roles": sorted(set(roles))[:5],
                               "role_count": len(set(roles)),
                               "member_of_count": len(groups), "tier0": "tier0" in n.tags})
    fp.guest_and_foreign, trunc = _cap(guests)
    if trunc:
        fp.truncated["guest_and_foreign"] = trunc

    # ---- Key Vault exposure --------------------------------------------------
    kv = []
    for n in g.nodes_of_kind(NodeKind.KEY_VAULT):
        props = n.props.get("properties") or n.props
        accessors = [e.src for e in g.in_edges(n.id, EdgeType.KV_ACCESS)] + \
                    [e.src for e in g.in_edges(n.id, EdgeType.CAN_REACH_KV_SECRET)]
        # Tri-state, not boolean. Azure omits these flags when off, so `is False` was
        # always False and the pack affirmatively told the AI
        # "purge_protection_disabled": false for 144 vaults that have NO purge protection
        # and "legacy_access_policy_model": false for 18 vaults that ARE on it - the
        # dangerous direction of absent-data-as-fact, on exactly the fields the data-plane
        # and misconfiguration prompts ask about.
        _soft = props.get("enableSoftDelete")
        _purge = props.get("enablePurgeProtection")
        _rbac_auth = props.get("enableRbacAuthorization")
        soft_delete_disabled = _soft is False
        purge_protection_disabled = True if _purge is None else (_purge is False)
        legacy_access = True if _rbac_auth is None else (_rbac_auth is False)
        if not accessors and not soft_delete_disabled and not purge_protection_disabled and not legacy_access:
            continue
        ent = fp.register(_ent(g, n.id))
        kv.append({**ent,
                    "legacy_access_policy_model": legacy_access,
                    "purge_protection_disabled": purge_protection_disabled,
                    "soft_delete_disabled": soft_delete_disabled,
                    "accessor_count": len(set(accessors)),
                    "accessors": [fp.register(_ent(g, a)) for a in list(dict.fromkeys(accessors))[:8]]})
    fp.keyvault_exposure, trunc = _cap(kv)
    if trunc:
        fp.truncated["keyvault_exposure"] = trunc

    # ---- Storage exposure ------------------------------------------------
    stor = []
    for n in g.nodes_of_kind(NodeKind.STORAGE):
        props = n.props.get("properties") or n.props
        key_accessors = [e.src for e in g.in_edges(n.id, EdgeType.CAN_GET_STORAGE_KEY)]
        blob_accessors = [e.src for e in g.in_edges(n.id, EdgeType.CAN_READ_STORAGE_BLOB)]
        public_blob = props.get("allowBlobPublicAccess") is True
        _acls = props.get("networkAcls") or {}
        _net_action = _acls.get("defaultAction") or ("none configured"
                                                     if "networkAcls" in props else None)
        _shared_key = props.get("allowSharedKeyAccess")
        # Report a misconfigured account even when nobody currently holds a role on it:
        # "open to all networks with shared keys enabled" is a finding regardless.
        if not (key_accessors or blob_accessors or public_blob
                or str(_net_action or "").lower() in ("allow", "none configured")
                or _shared_key is not False):
            continue
        ent = fp.register(_ent(g, n.id))
        # Dedupe and DISCLOSE the cap, as keyvault_exposure already does. Emitting a
        # bare 8-item sample with no count told the AI "8 principals can retrieve this
        # account's keys" for every account, when the real median was 24 and 70% of the
        # 7,786 principal→account listKeys relationships were hidden.
        key_uniq = list(dict.fromkeys(key_accessors))
        blob_uniq = list(dict.fromkeys(blob_accessors))
        stor.append({**ent, "allows_public_blob_access": public_blob,
                     "network_default_action": _net_action,
                     "shared_key_access": _shared_key,
                     "min_tls_version": props.get("minimumTlsVersion"),
                     "key_accessor_count": len(key_uniq),
                     "blob_accessor_count": len(blob_uniq),
                     "key_accessors": [fp.register(_ent(g, a)) for a in key_uniq[:8]],
                     "blob_data_role_accessors": [fp.register(_ent(g, a)) for a in blob_uniq[:8]]})
    fp.storage_exposure, trunc = _cap(stor)
    if trunc:
        fp.truncated["storage_exposure"] = trunc

    # ---- Container registry exposure (push = supply-chain attack vector) ----
    cont = []
    for n in g.nodes_of_kind(NodeKind.CONTAINER_REGISTRY):
        pushers = [e.src for e in g.in_edges(n.id, EdgeType.CAN_PUSH_CONTAINER)]
        if not pushers:
            continue
        ent = fp.register(_ent(g, n.id))
        cont.append({**ent,
                     "pusher_count": len(set(pushers)),
                     "pushers": [fp.register(_ent(g, p)) for p in list(dict.fromkeys(pushers))[:8]]})
    fp.container_exposure, trunc = _cap(cont)
    if trunc:
        fp.truncated["container_exposure"] = trunc

    # ---- Compute / managed-identity exposure (VM, AKS, Automation, etc.) --
    comp = []
    for e in g.edges():
        if e.type != EdgeType.HAS_MANAGED_IDENTITY:
            continue
        host, ident = fp.register(_ent(g, e.src)), fp.register(_ent(g, e.dst))
        if not host or not ident:
            continue
        stealers = [s.src for s in g.in_edges(e.src, EdgeType.CAN_STEAL_MANAGED_IDENTITY)]
        ident_privs = [r.evidence.get("role") for r in g.out_edges(ident["id"], EdgeType.HAS_RBAC_ROLE)]
        comp.append({"host": host, "managed_identity": ident,
                     "identity_type": e.evidence.get("identityType"),
                     "identity_rbac_roles": [r for r in ident_privs if r][:5],
                     "who_can_steal_this_identity": [fp.register(_ent(g, s)) for s in stealers[:5]]})
    fp.compute_identity_exposure, trunc = _cap(comp)
    if trunc:
        fp.truncated["compute_identity_exposure"] = trunc

    # ---- Hygiene (stale/disabled-but-privileged, sync, classic admins) ----
    hyg = []
    for n in g.nodes_of_kind(NodeKind.USER):
        if n.props.get("accountEnabled") is False and (
            "tier0" in n.tags
            or g.out_edges(n.id, EdgeType.HAS_RBAC_ROLE)
            or g.out_edges(n.id, EdgeType.HAS_ENTRA_ROLE)
        ):
            hyg.append({**fp.register(_ent(g, n.id)), "issue": "disabled_but_privileged"})
    for n in g.nodes_of_kind(NodeKind.SUBSCRIPTION):
        for ca in n.props.get("classicAdministrators") or []:
            sub_ent = fp.register(_ent(g, n.id))
            ca_ent = {"id": f"classic:{n.id}:{ca.get('emailAddress')}", "name": ca.get("emailAddress"),
                      "kind": "ClassicAdministrator", "issue": "legacy_classic_admin",
                      "role": ca.get("role"), "subscription": sub_ent}
            fp.register(ca_ent)
            hyg.append(ca_ent)
    fp.hygiene_issues, trunc = _cap(hyg)
    if trunc:
        fp.truncated["hygiene_issues"] = trunc

    # ---- PIM-eligible shadow admins (eligible, not currently active) --------
    shadow = []
    for n in g.nodes():
        if "tier0_eligible" not in n.tags:
            continue
        via = [e.evidence.get("roleTemplateId") for e in g.out_edges(n.id, EdgeType.ELIGIBLE_FOR_ROLE)]
        ent = fp.register(_ent(g, n.id))
        shadow.append({**ent, "eligible_for_tier0_via": [v for v in via if v][:5],
                       "note": "Not currently an active holder of this role - can self-activate via PIM "
                                "without a standing assignment ever appearing."})
    fp.pim_eligible_shadow_admins, trunc = _cap(shadow)
    if trunc:
        fp.truncated["pim_eligible_shadow_admins"] = trunc

    # ---- Complete RBAC inventory at subscription / MG scope -----------------
    # Every assignment (not filtered) - the AI needs the full list to reason
    # about breadth, outliers, and non-standard posture.
    rbac_all: list[dict] = []
    for e in g.edges():
        if e.type != EdgeType.HAS_RBAC_ROLE:
            continue
        scope = e.evidence.get("scope") or ""
        # Keep only subscription-level and above (skip resource-group and below).
        # Delegate to C.is_at_broad_scope rather than re-deriving this: the local
        # version compared path segments case-SENSITIVELY against "subscriptions" /
        # "managementGroups", but AzureHound emits ARM paths in upper case
        # (/SUBSCRIPTIONS/..., /PROVIDERS/MICROSOFT.MANAGEMENT/MANAGEMENTGROUPS/...).
        # On a real 85,693-assignment tenant that matched just 981 rows - 1.1% - and
        # dropped every one of the 554 management-group assignments, which are the
        # single most important cross-subscription primitive (an MG role applies to all
        # child subscriptions at once).
        if not (scope in ("/", "") or C.is_at_broad_scope(scope)):
            continue
        src_node = g.node(e.src)
        role = e.evidence.get("role") or ""
        if not src_node or not role:
            continue
        rbac_all.append({
            "principal_id": e.src,
            "principal_name": src_node.name or e.src,
            "principal_kind": src_node.kind.value,
            "role": role,
            "scope": scope,
            "is_tier0_principal": "tier0" in src_node.tags,
            # Carry the principal's account state so the scanner can flag a DISABLED
            # account that retains broad Azure-RBAC access (a dormant re-enable path the
            # Entra-only disabled_with_role signal missed entirely).
            "enabled": src_node.props.get("accountEnabled"),
        })
    # Register every principal so grounding validation accepts their IDs in findings.
    for r in rbac_all:
        fp.register({"id": r["principal_id"], "name": r["principal_name"], "kind": r["principal_kind"]})
    fp.raw_rbac_list = rbac_all                         # full uncapped list for the scanners

    # ---- Prompt-facing view: one row per (principal, role), not per assignment ----
    # This section used to be `_cap(sorted_by_role_name, 3000)`. Sorting alphabetically
    # by role and then truncating meant the 3,000 delivered rows were entirely the
    # alphabetically-first role: on a real tenant, 3,000 Contributor rows covering 3 of
    # 140 principals, with ZERO of the 24,142 Owner and 12,020 User Access Administrator
    # assignments - while the prompt told the model this was "EVERY RBAC assignment".
    #
    # Collapsing per (principal, role) removes the need for a cap at all: 75,437
    # assignments become ~240 rows carrying strictly more information, because the
    # scope COUNT is the fact that matters ("Owner on 38 subscriptions") and the
    # duplicated principal/role strings were most of the byte weight.
    _agg: dict[tuple, dict] = {}
    for r in rbac_all:
        key = (r["principal_id"], r["role"])
        row = _agg.setdefault(key, {
            "principal_id":   r["principal_id"],
            "principal_name": r["principal_name"],
            "principal_kind": r["principal_kind"],
            "role":           r["role"],
            "is_tier0_principal": r["is_tier0_principal"],
            "_scopes": set(), "_mgs": set(),
        })
        if "managementgroups" in (r["scope"] or "").lower():
            row["_mgs"].add(r["scope"])
        else:
            row["_scopes"].add(r["scope"])

    _ROLE_RISK = {"owner": 0, "user access administrator": 1,
                  "role based access control administrator": 1, "contributor": 2}
    rbac_rollup: list[dict] = []
    for row in _agg.values():
        subs, mgs = row.pop("_scopes"), row.pop("_mgs")
        rbac_rollup.append({
            **row,
            "management_group_scopes": sorted(mgs)[:10],
            "management_group_count":  len(mgs),
            "subscription_scopes":     sorted(subs)[:10],
            "subscription_count":      len(subs),
        })
    # Risk-sort so that if a cap ever does bite, it drops the least dangerous rows.
    rbac_rollup.sort(key=lambda x: (
        _ROLE_RISK.get(x["role"].lower(), 9),
        0 if x["management_group_count"] else 1,
        -(x["management_group_count"] + x["subscription_count"]),
        0 if x["principal_kind"] in ("AZUser", "AZServicePrincipal") else 1,
        x["principal_name"],
    ))
    fp.subscription_rbac_all, trunc = _cap(rbac_rollup, 3000)
    if trunc:
        fp.truncated["subscription_rbac_all"] = trunc

    # ---- Complete Entra role assignment inventory ----------------------------
    entra_all: list[dict] = []
    for e in g.edges():
        if e.type != EdgeType.HAS_ENTRA_ROLE:
            continue
        src_node = g.node(e.src)
        dst_node = g.node(e.dst)
        role = (e.evidence.get("role") or
                (dst_node.name if dst_node and dst_node.name else None) or
                e.evidence.get("roleTemplateId") or "")
        if not src_node or not role:
            continue
        entra_all.append({
            "principal_id": e.src,
            "principal_name": src_node.name or e.src,
            "principal_kind": src_node.kind.value,
            "role": role,
            "is_tier0_principal": "tier0" in src_node.tags,
            "enabled": src_node.props.get("accountEnabled"),
            "guest": src_node.props.get("userType") == "Guest",
        })
    entra_all.sort(key=lambda x: x["role"])
    for r in entra_all:
        fp.register({"id": r["principal_id"], "name": r["principal_name"], "kind": r["principal_kind"]})
    fp.raw_entra_list = entra_all                       # full uncapped list for Haiku
    fp.entra_role_all, trunc = _cap(entra_all, 2000)
    if trunc:
        fp.truncated["entra_role_all"] = trunc

    # ---- Service principal inventory ranked by permission count -------------
    # TENANT-OWNED SPs only, sorted by risk so the AI sees the outliers first -
    # not pre-filtered to known-bad permissions.
    # Microsoft first-party and external SPs are excluded here because their
    # appRoles list the permissions they *define*, not ones they've been *granted*.
    # Foreignness comes from the `foreign_tenant` tag (normalize.py), which compares
    # appOwnerOrganizationId against THIS tenant's GUID. Testing mere presence of that
    # field - as this once did - also excluded tenant-owned SPs, which carry it set to
    # the home tenant GUID; that silently dropped hundreds of real SPs (including
    # credentialed SSO/federation apps) from the inventory the scanners call complete.
    sp_inventory: list[dict] = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in sp.tags:
            continue  # MS-owned or another tenant's SP - not tenant-created
        perms = [r.get("value") for r in (sp.props.get("_granted_app_roles") or []) if r.get("value")]
        cred_count = (len(sp.props.get("passwordCredentials") or []) +
                      len(sp.props.get("keyCredentials") or []))
        fed_creds = sp.props.get("federatedIdentityCredentials") or []
        owners = [e.src for e in g.in_edges(sp.id, EdgeType.OWNS)]
        # appRoleAssignmentRequired: when True only explicitly assigned users can sign in.
        # When False (the default) any tenant user - including ex-employees whose accounts
        # haven't been disabled - can authenticate through the app.
        assignment_required = sp.props.get("appRoleAssignmentRequired")
        sp_inventory.append({
            "id": sp.id,
            "name": sp.name or sp.id,
            "permission_count": len(perms),
            "permissions": perms[:15],
            "credential_count": cred_count,
            "federated_credential_count": len(fed_creds),
            "owner_count": len(owners),
            "is_managed_identity": sp.props.get("servicePrincipalType") == "ManagedIdentity",
            "enabled": sp.props.get("accountEnabled"),
            "is_tier0": "tier0" in sp.tags,
            "user_assignment_required": bool(assignment_required),
        })
    sp_inventory.sort(key=lambda x: (-x["permission_count"], -x["credential_count"]))
    for sp_item in sp_inventory:
        fp.register({"id": sp_item["id"], "name": sp_item["name"],
                     "kind": NodeKind.SERVICE_PRINCIPAL.value})
    fp.raw_sp_list = sp_inventory                       # full uncapped list for Haiku
    fp.service_principal_inventory, trunc = _cap(sp_inventory, 1243)
    if trunc:
        fp.truncated["service_principal_inventory"] = trunc

    # ---- Broad access signals (anomaly / baseline-deviation context) --------
    # These are NOT filtered to known-bad patterns. They give the AI the numbers
    # it needs to detect non-standard posture: "everyone in a group that has
    # Contributor", "300 users have Directory.Read.All", etc.

    # 1. Groups with many members that hold any privileged access
    large_priv_groups: list[dict] = []
    _PRIV_EDGE_TYPES = {
        EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_OWNER, EdgeType.CAN_ADD_MEMBER,
        EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
        EdgeType.CAN_REACH_KV_SECRET, EdgeType.CAN_STEAL_MANAGED_IDENTITY,
        EdgeType.CAN_RESET_PASSWORD, EdgeType.CAN_GET_STORAGE_KEY,
        EdgeType.HAS_ENTRA_ROLE, EdgeType.HAS_RBAC_ROLE,
    }
    for grp in g.nodes_of_kind(NodeKind.GROUP):
        members = [e.src for e in g.in_edges(grp.id, EdgeType.MEMBER_OF)]
        if len(members) < 5:
            continue
        priv_edges = [e for e in g.out_edges(grp.id) if e.type in _PRIV_EDGE_TYPES]
        if not priv_edges:
            continue
        privileges = []
        for e in priv_edges[:8]:
            ev = {k: v for k, v in (e.evidence or {}).items()
                  if k in ("role", "scope", "permissions", "value")}
            privileges.append({"primitive": e.type.value, "target": _ent(g, e.dst), "evidence": ev})
        ent = fp.register(_ent(g, grp.id))
        # Dynamic membership is signalled by a non-empty membershipRule (AzureHound does NOT
        # emit a "membershipType" key - reading it left is_dynamic ALWAYS False, so no dynamic
        # privileged group was ever flagged). normalize also tags the node dynamic_membership.
        is_dynamic = bool((grp.props.get("membershipRule") or "").strip()) or "dynamic_membership" in grp.tags
        large_priv_groups.append({
            **ent,
            "member_count": len(members),
            "is_dynamic_membership": is_dynamic,
            "membership_rule": grp.props.get("membershipRule"),
            "privileges": privileges,
            "is_tier0": "tier0" in grp.tags,
        })
    large_priv_groups.sort(key=lambda x: -x["member_count"])

    # 2. RBAC role spread: per role, how many distinct principals hold it at
    #    subscription or management-group scope - a high count is anomalous
    rbac_role_spread: dict[str, int] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_RBAC_ROLE:
            continue
        scope = e.evidence.get("scope") or ""
        role = e.evidence.get("role") or ""
        if not role:
            continue
        # Only count broad scopes (subscription level or above, not resource-group level).
        # Same case-sensitivity trap as the rbac_all filter above - use the shared helper.
        if not (scope in ("/", "") or C.is_at_broad_scope(scope)):
            continue
        rbac_role_spread[role] = rbac_role_spread.get(role, 0) + 1
    # Sort by count desc, top 30 roles
    rbac_role_spread_sorted = dict(
        sorted(rbac_role_spread.items(), key=lambda x: -x[1])[:30]
    )

    # 3. Entra role spread: per role, how many principals hold it
    #    Resolve role template IDs to human-readable names via the destination ROLE node.
    entra_role_spread: dict[str, int] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_ENTRA_ROLE:
            continue
        role = e.evidence.get("role") or ""
        if not role:
            # Fall back to the destination node's name (the AZRole node) if the
            # evidence only carries the GUID roleTemplateId.
            dst_node = g.node(e.dst)
            role = (dst_node.name if dst_node and dst_node.name else
                    e.evidence.get("roleTemplateId") or "")
        if role:
            entra_role_spread[role] = entra_role_spread.get(role, 0) + 1
    entra_role_spread_sorted = dict(
        sorted(entra_role_spread.items(), key=lambda x: -x[1])[:30]
    )

    # 4. Broadly-assigned Graph app permissions: per permission, how many TENANT-OWNED SPs hold it.
    #    MS first-party / other-tenant SPs are excluded - their appRoles list what they
    #    *define*, not what they've been *granted*. Counting them would inflate every number.
    #    Uses the `foreign_tenant` tag, not the raw presence of appOwnerOrganizationId,
    #    which would also exclude tenant-owned SPs (see the SP inventory note above).
    graph_perm_spread: dict[str, list[str]] = {}  # permission → list of SP names
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in sp.tags:
            continue  # skip MS-owned / other-tenant SPs
        for ar in sp.props.get("_granted_app_roles") or []:
            v = ar.get("value")
            if v:
                graph_perm_spread.setdefault(v, []).append(sp.name or sp.id)
    # Convert to {perm: {count, sample_sps}} for the AI
    graph_perm_spread_sorted = {
        perm: {"count": len(names), "sample_sps": names[:5]}
        for perm, names in sorted(graph_perm_spread.items(), key=lambda x: -len(x[1]))[:30]
    }

    # 5. App-role grants to users/groups: which app roles have been granted to
    #    many users or to large groups - "everyone has access to this app's admin role"
    app_role_grant_spread: list[dict] = []
    _app_role_counts: dict[tuple, list] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_APP_ROLE:
            continue
        role_val = e.evidence.get("value") or e.evidence.get("roleId") or ""
        key = (e.dst, role_val)
        _app_role_counts.setdefault(key, []).append(e.src)
    for (sp_id, role_val), grantees in sorted(
        _app_role_counts.items(), key=lambda x: -len(x[1])
    )[:20]:
        if len(grantees) < 3:
            continue
        sp_ent = fp.register(_ent(g, sp_id))
        if not sp_ent:
            continue
        app_role_grant_spread.append({
            "sp": sp_ent, "role_value": role_val,
            "grantee_count": len(grantees),
            "sample_grantees": [fp.register(_ent(g, g_id)) for g_id in grantees[:5]],
        })

    # ---- Management-group hierarchy -> descendant subscriptions ---------------
    # Transitive closure over CONTAINS so a role at a top-level MG resolves to every
    # subscription beneath it, including through nested management groups.
    _mg_children: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type != EdgeType.CONTAINS:
            continue
        parent = g.node(e.src)
        if parent and parent.kind == NodeKind.MANAGEMENT_GROUP:
            _mg_children.setdefault(e.src, []).append(e.dst)

    def _descendant_subs(mg_id: str, seen: "set[str] | None" = None) -> "set[str]":
        seen = seen if seen is not None else set()
        if mg_id in seen:
            return set()          # guard against a cyclic/self-referential hierarchy
        seen.add(mg_id)
        found: "set[str]" = set()
        for child_id in _mg_children.get(mg_id, []):
            child = g.node(child_id)
            if child is None:
                continue
            if child.kind == NodeKind.SUBSCRIPTION:
                found.add(child_id)
            elif child.kind == NodeKind.MANAGEMENT_GROUP:
                found |= _descendant_subs(child_id, seen)
        return found

    fp.mg_descendant_subscriptions = {
        mg.id: sorted(_descendant_subs(mg.id))
        for mg in g.nodes_of_kind(NodeKind.MANAGEMENT_GROUP)
    }
    _mg_reach = {
        (g.node(mg_id).name if g.node(mg_id) else mg_id): len(subs)
        for mg_id, subs in fp.mg_descendant_subscriptions.items() if subs
    }

    fp.broad_access_signals = {
        "large_privileged_groups": large_priv_groups[:40],
        "rbac_role_spread_at_broad_scope": rbac_role_spread_sorted,
        "entra_role_spread": entra_role_spread_sorted,
        "graph_permission_spread": graph_perm_spread_sorted,
        "app_role_grant_spread": app_role_grant_spread,
        "management_group_reach": dict(sorted(_mg_reach.items(), key=lambda kv: -kv[1])[:30]),
        "management_group_reach_note": (
            "management_group_reach maps each management group to how many subscriptions "
            "sit beneath it (transitively). A role assignment at an MG scope applies to "
            "EVERY one of those subscriptions at once - cite this number when scoring the "
            "blast radius of an MG-scoped Owner / User Access Administrator."
        ),
        "note": (
            "These are raw breadth signals, NOT pre-filtered to known-bad patterns. "
            "Use them to detect non-standard posture: access granted too broadly, "
            "roles held by far too many principals, dynamic groups auto-granting "
            "access to all users, etc."
        ),
    }
    if len(large_priv_groups) > 40:
        fp.truncated["large_privileged_groups"] = len(large_priv_groups) - 40

    # ── Raw group list for Haiku - ALL groups with any privileged edges (no member-count floor) ──
    raw_groups: list[dict] = []
    for grp in g.nodes_of_kind(NodeKind.GROUP):
        priv_edges = [e for e in g.out_edges(grp.id) if e.type in _PRIV_EDGE_TYPES]
        if not priv_edges:
            continue
        members = [e.src for e in g.in_edges(grp.id, EdgeType.MEMBER_OF)]
        privs_compact = []
        for e in priv_edges[:5]:
            dst_n = g.node(e.dst)
            privs_compact.append({
                "primitive": e.type.value,
                "target_name": (dst_n.name if dst_n else e.dst) or e.dst,
                "target_id": e.dst,
                "role": (e.evidence or {}).get("role") or (e.evidence or {}).get("scope") or "",
            })
        fp.register(_ent(g, grp.id))
        raw_groups.append({
            "id": grp.id,
            "name": grp.name or grp.id,
            "member_count": len(members),
            "is_dynamic": bool((grp.props.get("membershipRule") or "").strip()) or "dynamic_membership" in grp.tags,
            "membership_rule": (grp.props.get("membershipRule") or "")[:200],
            "privileges": privs_compact,
            "is_tier0": "tier0" in grp.tags,
        })
    raw_groups.sort(key=lambda x: -x["member_count"])
    fp.raw_group_list = raw_groups

    # ── Raw app grant list for Haiku - ALL app role grants regardless of grantee count ──
    raw_app_grants: list[dict] = []
    _all_app_role_counts: dict[tuple, list] = {}
    for e in g.edges():
        if e.type != EdgeType.HAS_APP_ROLE:
            continue
        role_val = e.evidence.get("value") or e.evidence.get("roleId") or ""
        key = (e.dst, role_val)
        _all_app_role_counts.setdefault(key, []).append(e.src)
    for (sp_id, role_val), grantees in sorted(
        _all_app_role_counts.items(), key=lambda x: -len(x[1])
    )[:300]:
        sp_node = g.node(sp_id)
        if not sp_node:
            continue
        fp.register(_ent(g, sp_id))
        sample = []
        for gid in grantees[:5]:
            gn = g.node(gid)
            sample.append({"id": gid, "name": (gn.name if gn else gid) or gid})
        raw_app_grants.append({
            "sp_id":         sp_id,
            "sp_name":       sp_node.name or sp_id,
            "role_value":    role_val,
            "grantee_count": len(grantees),
            "sample_grantees": sample,
        })
    fp.raw_app_grant_list = raw_app_grants

    # ── Cross-subscription bridges - full-graph reach ───────────────────────
    # A principal is a bridge if it can reach two or more subscriptions, counting reach it
    # inherits through group membership, an owned service principal, PIM eligibility, or any
    # escalation chain - not only RBAC placed directly on it. Every privilege-reasoning
    # specialist sees this, so a finding on such a principal is scored with its true
    # cross-subscription blast radius instead of being read as a single-subscription issue.
    try:
        from .scoring import compute_subscription_reach, compute_cross_subscription
        _reach = compute_subscription_reach(g)
        _cs = compute_cross_subscription(g, {}, _reach)
        _rows: list[dict] = []
        for br in _cs.get("bridges", [])[:60]:
            fp.register(_ent(g, br["id"]))
            mech = []
            if br.get("member_count") is not None:
                inh = br.get("inherited_bridge_members") or 0
                mech.append(f"group confers reach to {br['member_count']} member(s)"
                            + (f" ({inh} bridge only via this group)" if inh else ""))
            if br.get("via_management_group"):
                mech.append("management-group role")
            if br.get("member_count") is None and br.get("indirect"):
                mech.append("combines grants (multiple groups / ownership)")
            if br.get("roles"):
                mech.append("direct RBAC")
            _rows.append({
                "id": br["id"], "name": br["name"], "kind": br["kind"],
                "subscription_count": br["subscription_count"],
                "subscriptions": br["subscriptions"][:8],
                "reaches_tier0": br["reaches_tier0"],
                "roles": br["roles"][:6],
                "member_count": br.get("member_count"),
                "mechanism": ", ".join(mech) or "direct RBAC",
            })
        fp.cross_subscription_bridges = _rows
        if _rows:
            fp.cross_subscription_bridges.insert(0, {
                "_note": (
                    "cross_subscription_bridges lists principals whose compromise spans two "
                    "or more subscriptions. subscription_count is the true blast radius over "
                    "the full escalation graph (mechanism says how the reach is gained: a "
                    "management-group role, direct RBAC, or reach INHERITED through a group, "
                    "an owned service principal, PIM eligibility, or an escalation chain). "
                    "Treat multi-subscription reach as a severity amplifier: a finding on one "
                    "of these principals is a cross-subscription attack, not a single-scope "
                    "issue - say which subscriptions fall together when it is compromised."
                )
            })
    except Exception:
        fp.cross_subscription_bridges = []

    # ── Multi-hop attack paths - graph traversal ────────────────────────────
    # Must run AFTER all other sections so entity_index is fully populated
    # for the grounding-registration calls inside _build_attack_paths.
    fp.raw_attack_paths = _build_attack_paths(g, fp)

    return fp


def audit_fact_pack(g: Graph, fp: "FactPack") -> dict:
    """Standing accuracy check: cross-validate a built fact pack against the graph it was
    derived from. An accurate pack returns all-empty violation lists (`ok=True`).

    Verifies the invariants that make the pack trustworthy as the AI's input:
      1. per-kind entity counts match the graph exactly,
      2. no fabricated entities - every id in an entity position is a real graph node
         (ARM scope paths, which legitimately appear in evidence, are allowed),
      3. every escalation edge in the pack corresponds to a REAL edge between real nodes
         (a phantom edge would let the AI narrate an attack that does not exist),
      4. the Tier-0 list is a subset of the graph's Tier-0 nodes,
      5. truncation is disclosed and internally well-formed.
    This is cheap enough to run on every scan and catches a derivation/reduction regression
    that would otherwise reach the model looking perfectly grounded."""
    from collections import Counter

    pack = fp.to_prompt_dict(None)
    known = fp.known_ids()
    report: dict = {
        "counts_mismatch": {}, "ungrounded_entities": [], "phantom_escalation_edges": [],
        "tier0_not_in_graph": [], "truncation_issues": [], "ok": True,
    }

    # (1) counts match the graph
    graph_counts = Counter(n.kind.value for n in g.nodes())
    for kind, c in (pack.get("counts") or {}).items():
        if c != graph_counts.get(kind, 0):
            report["counts_mismatch"][kind] = {"pack": c, "graph": graph_counts.get(kind, 0)}

    def _is_scope(s: str) -> bool:
        return isinstance(s, str) and s.startswith(("/subscriptions", "/SUBSCRIPTIONS",
                                                    "/providers", "/tenants"))

    def _entity_ids(obj) -> list:
        out: list = []
        if isinstance(obj, dict):
            if isinstance(obj.get("id"), str):
                out.append(obj["id"])
            for v in obj.values():
                out += _entity_ids(v)
        elif isinstance(obj, list):
            for x in obj:
                out += _entity_ids(x)
        return out

    # (2) grounding: no fabricated entity in any entity-bearing section
    for sec in ("tier0_principals", "over_permissive_apps", "credential_exposure",
                "guest_and_foreign", "service_principal_inventory", "keyvault_exposure",
                "storage_exposure", "compute_identity_exposure", "hygiene_issues",
                "container_exposure", "pim_eligible_shadow_admins"):
        for eid in _entity_ids(pack.get(sec) or []):
            if eid not in known and not _is_scope(eid):
                report["ungrounded_entities"].append({"section": sec, "id": eid})

    # (3) escalation-edge fidelity: each pack edge is a real graph edge between real nodes
    real_edges = {(e.src, e.dst, e.type.value) for e in g.edges()}
    for pe in (pack.get("escalation_edges") or []):
        s = (pe.get("src") or {}).get("id")
        d = (pe.get("dst") or {}).get("id")
        prim = pe.get("primitive")
        if s not in known or d not in known or (s, d, prim) not in real_edges:
            report["phantom_escalation_edges"].append({"src": s, "dst": d, "primitive": prim})

    # (4) Tier-0 subset
    graph_t0 = {n.id for n in g.nodes() if "tier0" in n.tags}
    for e in (pack.get("tier0_principals") or []):
        if e.get("id") not in graph_t0:
            report["tier0_not_in_graph"].append(e.get("id"))

    # (5) truncation disclosed and well-formed
    for k, v in (pack.get("truncated_buckets") or {}).items():
        if not isinstance(v, int) or v < 0:
            report["truncation_issues"].append({"bucket": k, "value": v})

    report["ok"] = not any(report[k] for k in (
        "counts_mismatch", "ungrounded_entities", "phantom_escalation_edges",
        "tier0_not_in_graph", "truncation_issues"))
    return report
