"""Edge-derivation engine - derives abusable attack-path edges.

AzureHound does not ship abusable edges; they are derived from raw role
assignments, app-role grants, ownerships, group membership and KV policies.
Mis-derivation here produces false attack paths, so every derived edge carries
its evidence and the named primitive, and the logic is conservative.
"""
from __future__ import annotations

from . import constants as C
from .model import Edge, EdgeType, Graph, NodeKind


def derive(g: Graph, extra_tier0: "set[str] | None" = None) -> None:
    _expand_effective_roles(g)
    _tag_tier0(g, extra_tier0)
    _derive_ownership_escalation(g)
    _derive_app_role_escalation(g)
    _derive_rbac_escalation(g)
    _derive_keyvault_reachability(g)
    _derive_app_admin_escalation(g)
    _derive_password_reset_escalation(g)
    _derive_compute_identity_theft(g)
    _derive_kv_management_escalation(g)
    _derive_storage_key_access(g)
    _derive_aks_cluster_access(g)
    _derive_storage_blob_access(g)
    _derive_container_push(g)


# --------------------------------------------------------------------------- #
def _principals(g: Graph):
    return g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)


def _is_tier0_role(role_node) -> bool:
    # AzureHound emits the role's template GUID as "templateId"; "roleTemplateId" is
    # never present, so reading only the latter left the GUID branch 100% dead and made
    # Tier-0 classification depend entirely on the display-name fallback. That silently
    # misses Microsoft's role renames (e.g. Cloud Device Administrator →
    # "Azure AD Joined Device Local Administrator"), which the GUID is immune to.
    props = role_node.props or {}
    tpl = str(props.get("templateId") or props.get("roleTemplateId") or "").lower()
    if tpl and tpl in C.TIER0_ENTRA_ROLE_TEMPLATES:
        return True
    return (role_node.name or "").lower() in C.TIER0_ENTRA_ROLE_NAMES


def _expand_effective_roles(g: Graph) -> None:
    """A principal holds a role directly or by (transitive) membership of a role
    assignable group that holds it. Emit EFFECTIVE_ROLE edges + tag holders."""
    # Map group -> set of role nodes it holds directly.
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_ENTRA_ROLE):
            _emit_effective_role(g, p.id, e.dst, ["direct assignment"])

    # Transitive membership: BFS up membership chains from each principal.
    members = g.nodes_of_kind(NodeKind.USER, NodeKind.SERVICE_PRINCIPAL, NodeKind.GROUP)
    for principal in members:
        for group_id, chain in _reachable_groups(g, principal.id):
            for e in g.out_edges(group_id, EdgeType.HAS_ENTRA_ROLE):
                _emit_effective_role(g, principal.id, e.dst,
                                     ["member of " + g.display(group_id)] + chain)


def _reachable_groups(g: Graph, start: str):
    """Yield (group_id, evidence_chain) for groups the principal is (transitively) in."""
    seen: set[str] = set()
    stack = [(start, [])]
    while stack:
        cur, chain = stack.pop()
        for e in g.out_edges(cur, EdgeType.MEMBER_OF):
            grp = e.dst
            if grp in seen:
                continue
            seen.add(grp)
            node = g.node(grp)
            if node and node.kind == NodeKind.GROUP:
                yield grp, chain
                stack.append((grp, chain + ["via " + g.display(grp)]))


def _emit_effective_role(g: Graph, principal_id: str, role_id: str, chain: list[str]) -> None:
    role = g.node(role_id)
    if not role:
        return
    g.add_edge(Edge(src=principal_id, dst=role_id, type=EdgeType.EFFECTIVE_ROLE,
                    derived=True, primitive="EffectiveRole",
                    evidence={"path": chain, "role": role.name}))


def _tag_tier0(g: Graph, extra_tier0: "set[str] | None" = None) -> None:
    # User-selected Tier-0 assets (chosen in the pre-assessment selection step) are treated
    # as Tier-0 crown jewels for THIS scan - tagged first so every downstream derivation,
    # rule, score and path sees them exactly like an auto-detected Tier-0 node.
    if extra_tier0:
        for nid in extra_tier0:
            n = g.node(nid)
            if n is not None:
                n.tags.add("tier0")
                n.tags.add("user_tier0")   # provenance: distinguishes a manual pick
    # Tag the Tier-0 ROLE nodes themselves, not just their holders. facts.py sorts
    # escalation_edges by whether the destination is tier0-tagged; because role nodes
    # were never tagged, every CanGrantRole edge ("this SP can assign itself Global
    # Administrator" - the most severe primitive in the graph) sorted last and was
    # evicted by the 5,000-edge cap before reaching the privilege-escalation specialist.
    for r in g.nodes_of_kind(NodeKind.ROLE):
        if _is_tier0_role(r):
            r.tags.add("tier0")
            if (r.name or "").lower() in C.CRITICAL_ENTRA_ROLE_NAMES:
                r.tags.add("tier0_critical")
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.EFFECTIVE_ROLE):
            role = g.node(e.dst)
            if role and _is_tier0_role(role):
                p.tags.add("tier0")
                p.tags.add("privileged")
                if role.name.lower() in C.CRITICAL_ENTRA_ROLE_NAMES:
                    p.tags.add("tier0_critical")
    # Subscription / MG Owner & UAA holders are also Tier-0 for the resource plane.
    # Use is_at_broad_scope so resource-level (VM, KV, RG) assignments do not
    # false-positive here - only exact subscription or MG scope is broad enough.
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role in C.RBAC_ESCALATION_ROLES and C.is_at_broad_scope(scope):
                p.tags.add("tier0")
                p.tags.add("privileged")
    # PIM-eligible (not currently active) Tier-0 roles: a "shadow admin" who can
    # self-activate without ever showing up as an active role holder above.
    for p in _principals(g):
        if "tier0" in p.tags:
            continue
        for e in g.out_edges(p.id, EdgeType.ELIGIBLE_FOR_ROLE):
            role = g.node(e.dst)
            if role and _is_tier0_role(role):
                p.tags.add("tier0_eligible")


def _derive_ownership_escalation(g: Graph) -> None:
    """Owner of an App/SP can add a credential and authenticate as that SP,
    inheriting its privilege (CanAddSecret). Owner of a group can add members
    (CanAddMember)."""
    # appId -> the SERVICE PRINCIPAL backing an app registration. Ownership records
    # (AZAppOwner) point at the APP node, but privilege (app-role grants, Tier-0 tags)
    # lives on the SP; without this bridge, owning the app registration of a Global-
    # Admin SP dead-ended at a node with no outgoing escalation.
    sp_by_appid = {}
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        aid = str((sp.props or {}).get("appId") or "").lower()
        if aid:
            sp_by_appid.setdefault(aid, sp)

    for e in list(g.edges()):
        if e.type != EdgeType.OWNS:
            continue
        target = g.node(e.dst)
        if not target:
            continue
        if target.kind in (NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
            # You cannot add usable credentials to a managed identity, nor
            # authenticate as a service principal whose app registration lives in
            # another tenant - skip these to avoid the classic false positive.
            if target.tags & {"managed_identity", "foreign_tenant"}:
                continue
            g.add_edge(Edge(src=e.src, dst=e.dst, type=EdgeType.CAN_ADD_SECRET,
                            derived=True, primitive="CanAddSecret",
                            evidence={"reason": "owner can add credential and sign in as the SP"}))
            # Bridge app-registration ownership to the backing service principal.
            if target.kind == NodeKind.APP:
                sp = sp_by_appid.get(str((target.props or {}).get("appId") or "").lower())
                if (sp is not None and sp.id != target.id
                        and not (sp.tags & {"managed_identity", "foreign_tenant"})):
                    g.add_edge(Edge(src=e.src, dst=sp.id, type=EdgeType.CAN_ADD_SECRET,
                                    derived=True, primitive="CanAddSecret",
                                    evidence={"reason": "owner of the app registration can add a "
                                              "credential and sign in as its service principal"}))
        elif target.kind == NodeKind.GROUP:
            g.add_edge(Edge(src=e.src, dst=e.dst, type=EdgeType.CAN_ADD_MEMBER,
                            derived=True, primitive="CanAddMember",
                            evidence={"reason": "owner can add themselves to the group"}))


def _derive_app_role_escalation(g: Graph) -> None:
    """A service principal holding a dangerous MS Graph app role can escalate.

    Creates real edges to Tier-0 targets so the AI fact pack sees actual paths,
    not opaque self-loops. Falls back to self-loops only when the tenant has no
    Tier-0 targets of the relevant type yet (very rare/empty tenants).
    """
    # _tag_tier0 has already run, so these sets are populated.
    tier0_roles = [n for n in g.nodes_of_kind(NodeKind.ROLE) if _is_tier0_role(n)]
    tier0_sps = [
        n for n in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
        if "tier0" in n.tags
        and "managed_identity" not in n.tags
        and "foreign_tenant" not in n.tags
    ]
    tier0_groups = [n for n in g.nodes_of_kind(NodeKind.GROUP) if "tier0" in n.tags]
    tier0_users = [n for n in g.nodes_of_kind(NodeKind.USER) if "tier0" in n.tags]

    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        # Read GRANTED roles only. Reading `appRoles` (what the app publishes) made every
        # Microsoft resource-server SP look omnipotent - Microsoft Graph alone generated
        # 138 fabricated escalation edges including "CanGrantRole → Global Administrator".
        for ar in sp.props.get("_granted_app_roles", []) or []:
            value = ar.get("value")
            meta = C.DANGEROUS_GRAPH_APP_ROLES.get(value)
            if not meta:
                continue

            sp.tags.add("dangerous_app_role")
            if meta["tier"] == "critical":
                sp.tags.add("can_reach_tier0")

            prim = meta["primitive"]
            if prim == "CanWeakenControls":
                sp.tags.add("can_weaken_controls")
                continue

            etype = {
                "CanGrantRole": EdgeType.CAN_GRANT_ROLE,
                "CanGrantAppRole": EdgeType.CAN_GRANT_APP_ROLE,
                "CanAddSecret": EdgeType.CAN_ADD_SECRET,
                "CanAddOwner": EdgeType.CAN_ADD_OWNER,
                "CanAddMember": EdgeType.CAN_ADD_MEMBER,
                "CanResetPassword": EdgeType.CAN_RESET_PASSWORD,
            }.get(prim, EdgeType.CAN_ADD_MEMBER)

            ev = {"appRole": value, "impact": meta["impact"]}

            if prim == "CanGrantRole":
                # Can assign any Entra role to itself or any principal.
                targets = tier0_roles
                for t in targets:
                    g.add_edge(Edge(src=sp.id, dst=t.id, type=etype, derived=True,
                                    primitive=prim,
                                    evidence={**ev, "target_role": t.name,
                                              "reason": "can assign this role to itself or any principal"}))
                    sp.tags.add("can_reach_tier0")
                if not targets:
                    g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                    primitive=prim, evidence=ev))

            elif prim == "CanGrantAppRole":
                # Can grant itself RoleManagement.ReadWrite.Directory → two-hop path to GA.
                # Self-loop is semantically correct here; tag the capability explicitly.
                g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                primitive=prim,
                                evidence={**ev, "reason": "can grant itself RoleManagement.ReadWrite.Directory, then assign Tier-0 roles"}))
                sp.tags.add("can_reach_tier0")

            elif prim == "CanAddSecret":
                # Can add credentials to any app/SP → authenticate as the most-privileged ones.
                targets = [t for t in tier0_sps if t.id != sp.id]
                for t in targets:
                    g.add_edge(Edge(src=sp.id, dst=t.id, type=etype, derived=True,
                                    primitive=prim,
                                    evidence={**ev, "target": t.name,
                                              "reason": "can add a credential and authenticate as this privileged SP"}))
                    sp.tags.add("can_reach_tier0")
                if not targets:
                    g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                    primitive=prim, evidence=ev))

            elif prim == "CanAddMember":
                # Can modify group membership → path through Tier-0 role-assignable groups.
                targets = tier0_groups
                for t in targets:
                    g.add_edge(Edge(src=sp.id, dst=t.id, type=etype, derived=True,
                                    primitive=prim,
                                    evidence={**ev, "target": t.name,
                                              "reason": "can add members to this privileged group"}))
                    sp.tags.add("can_reach_tier0")
                if not targets:
                    g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                    primitive=prim, evidence=ev))

            elif prim == "CanAddOwner":
                # Can add itself as owner of any SP → inherit all credential-add rights.
                targets = [t for t in tier0_sps if t.id != sp.id]
                for t in targets:
                    g.add_edge(Edge(src=sp.id, dst=t.id, type=etype, derived=True,
                                    primitive=prim,
                                    evidence={**ev, "target": t.name,
                                              "reason": "can add itself as owner, then add a credential"}))
                    sp.tags.add("can_reach_tier0")
                if not targets:
                    g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                    primitive=prim, evidence=ev))

            elif prim == "CanResetPassword":
                # Can reset passwords / replace MFA methods on Tier-0 user accounts.
                targets = tier0_users
                for t in targets:
                    g.add_edge(Edge(src=sp.id, dst=t.id, type=etype, derived=True,
                                    primitive=prim,
                                    evidence={**ev, "target": t.name,
                                              "reason": "can reset password or replace MFA for this Tier-0 user"}))
                    if t.tags & {"tier0"}:
                        sp.tags.add("can_reach_tier0")
                if not targets:
                    g.add_edge(Edge(src=sp.id, dst=sp.id, type=etype, derived=True,
                                    primitive=prim, evidence=ev))


def _derive_rbac_escalation(g: Graph) -> None:
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role in C.RBAC_ESCALATION_ROLES:
                # dst=scope is intentional: the scope string ("/subscriptions/<guid>")
                # IS the subscription node's id in production graphs. In test graphs built
                # without a real subscription node, this creates a bare networkx node -
                # Graph.nodes() silently skips those via the .get("node") guard.
                g.add_edge(Edge(src=p.id, dst=scope or e.dst, type=EdgeType.CAN_ESCALATE_RBAC,
                                derived=True, primitive="CanEscalateRBAC",
                                evidence={"role": role, "scope": scope,
                                          "reason": "can write role assignments within scope"}))


def _derive_keyvault_reachability(g: Graph) -> None:
    for e in list(g.edges()):
        if e.type != EdgeType.KV_ACCESS:
            continue
        perms = (e.evidence.get("permissions") or {})
        # An access policy granting get/list on secrets, KEYS, or CERTIFICATES all
        # expose vault material (AZGetSecrets / AZGetKeys / AZGetCertificates).
        # Reading only `secrets` dropped every key/cert data-plane exposure.
        exposed = {}
        for plane in ("secrets", "keys", "certificates"):
            pp = {str(x).lower() for x in (perms.get(plane) or [])}
            if pp & C.KV_SENSITIVE_SECRET_PERMS:
                exposed[plane] = sorted(pp & C.KV_SENSITIVE_SECRET_PERMS)
        if exposed:
            g.add_edge(Edge(src=e.src, dst=e.dst, type=EdgeType.CAN_REACH_KV_SECRET,
                            derived=True, primitive="CanReachKVSecret",
                            evidence={"planes": sorted(exposed), "permissions": exposed}))


def _effective_role_named(g: Graph, principal_id: str, names_lower: set[str]):
    for e in g.out_edges(principal_id, EdgeType.EFFECTIVE_ROLE):
        role = g.node(e.dst)
        if role and role.name.lower() in names_lower:
            return role
    return None


def _under(path: str, scope: str) -> bool:
    """True if `path` is `scope` or lives beneath it, matching on PATH SEGMENTS so a
    resource-group scope `.../rg1` never spuriously covers `.../rg10/...`."""
    return bool(path) and (path == scope or path.startswith(scope + "/"))


def _extract_sub(rid: str) -> str:
    """The `/subscriptions/<guid>` an ARM resource id lives in, or ''."""
    low = (rid or "").lower()
    i = low.find("/subscriptions/")
    if i < 0:
        return ""
    guid = low[i + len("/subscriptions/"):].split("/", 1)[0]
    return f"/subscriptions/{guid}" if guid else ""


def _mg_descendant_subs(g: Graph, mg_scope: str) -> set:
    """Subscriptions beneath a management group, via the CONTAINS hierarchy
    (MG -> nested MG -> subscription). Memoised on the graph - this is called once
    per (assignment, resource) pair across the resource-plane derivations."""
    from collections import deque
    key = mg_scope.lower()
    cache = getattr(g, "_mg_desc_cache", None)
    if cache is None:
        cache = {}
        try:
            g._mg_desc_cache = cache
        except Exception:
            pass
    if key in cache:
        return cache[key]
    start = next((n.id for n in g.nodes() if (n.id or "").lower() == key), None)
    subs: set = set()
    if start:
        seen = {start}
        q = deque([start])
        while q:
            cur = q.popleft()
            for e in g.out_edges(cur):
                if e.type != EdgeType.CONTAINS or e.dst in seen:
                    continue
                seen.add(e.dst)
                q.append(e.dst)
                dl = (e.dst or "").lower()
                if dl.startswith("/subscriptions/"):
                    subs.add(dl)
    cache[key] = subs
    return subs


def _scope_covers(scope: str, resource, g: "Graph | None" = None) -> bool:
    """Does an RBAC assignment at `scope` reach this resource?

    Handles the full ARM hierarchy: tenant root, management group (walking CONTAINS
    down to the resource's subscription - an MG Owner reaches every descendant
    subscription's resources), subscription, resource group, and the resource itself.
    Previously it only string-prefix-matched, so every management-group-scoped role
    covered ZERO resources - the single biggest missed-path class."""
    if not scope or not resource:
        return False
    scope = scope.lower()
    if scope == "/":                      # tenant root covers everything
        return True
    scope = scope.rstrip("/")
    rid = (resource.id or "").lower()
    rsub = (resource.props.get("subscriptionId") or "").lower()
    sub_path = _extract_sub(rid) or (f"/subscriptions/{rsub}" if rsub else "")
    # Assignment at the resource, its resource group, or its subscription (segment-aware).
    if _under(rid, scope) or (sub_path and _under(sub_path, scope)):
        return True
    # Management-group scope: covered iff the resource's subscription descends from it.
    if g is not None and "/managementgroups/" in scope:
        if sub_path and sub_path in _mg_descendant_subs(g, scope):
            return True
    return False


def _denied(g: Graph, principal_id: str, scope: str) -> bool:
    """Best-effort: a matching Azure deny assignment blocks the RBAC action."""
    for da in getattr(g, "deny_assignments", []):
        if da.get("scope") and (scope or "").lower().startswith(da["scope"].lower()):
            # Case-insensitive GUID match: AzureHound emits the same object id with varying
            # casing, so a case difference here silently ignored the deny and let the
            # escalation edge through anyway (the scope compare above already lowercases).
            principals = {str(p).lower() for p in (da.get("principals") or [])}
            _ALL_PRINCIPALS = "00000000-0000-0000-0000-000000000000"
            if (principal_id or "").lower() in principals or _ALL_PRINCIPALS in principals:
                return True
    return False


def _derive_app_admin_escalation(g: Graph) -> None:
    """Application / Cloud Application Administrator can add credentials to ANY
    application or service principal - escalating to the most-privileged SP.

    Excludes managed identities (you cannot manage their credentials) and
    foreign-tenant service principals (you cannot authenticate as an SP whose app
    registration lives in another tenant) - both are classic false positives.
    """
    priv_sps = [sp for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
                if (sp.tags & {"tier0", "privileged", "dangerous_app_role", "can_reach_tier0"})
                and "managed_identity" not in sp.tags
                and "foreign_tenant" not in sp.tags]
    if not priv_sps:
        return
    reaches_tier0 = any(sp.tags & {"tier0", "can_reach_tier0"} for sp in priv_sps)
    for p in _principals(g):
        role = _effective_role_named(g, p.id, C.APP_MANAGEMENT_ROLES)
        # NOTE: do NOT gate this on `"tier0" not in p.tags`. Both APP_MANAGEMENT_ROLES
        # are themselves Tier-0 templates, so _tag_tier0 has already tagged every holder
        # `tier0` by the time this runs - that guard was always false and this entire
        # primitive never fired. The escalation is real regardless of the holder's own
        # tier: what matters is that they can mint credentials on a privileged SP.
        if role:
            for sp in priv_sps:
                if sp.id == p.id:
                    continue  # no self-edges
                g.add_edge(Edge(src=p.id, dst=sp.id, type=EdgeType.CAN_ADD_SECRET, derived=True,
                                primitive="CanAddSecret",
                                evidence={"reason": f"{role.name} can add credentials to any app/SP",
                                          "target": sp.name}))
            if reaches_tier0:
                p.tags.add("can_reach_tier0")


def _derive_password_reset_escalation(g: Graph) -> None:
    """Password-reset-capable roles; Privileged Authentication Administrator can
    reset a Global Administrator's password - a direct Tier-0 takeover path."""
    tier0_users = [n for n in g.nodes() if "tier0" in n.tags and n.kind == NodeKind.USER]
    for p in _principals(g):
        emitted_reset: set[str] = set()  # dedup: one CAN_RESET_PASSWORD edge per (src, dst)
        for e in g.out_edges(p.id, EdgeType.EFFECTIVE_ROLE):
            role = g.node(e.dst)
            if not role:
                continue
            rn = role.name.lower()
            if rn not in C.RESET_PASSWORD_ROLES:
                continue
            p.tags.add("can_reset_passwords")
            # As with CanAddSecret above: RESET_PASSWORD_TIER0_ROLES is itself a Tier-0
            # template, so `"tier0" not in p.tags` was always false and this primitive
            # never fired. Privileged Authentication Administrator resetting a Global
            # Admin's password is a real takeover path whether or not the holder is
            # already Tier-0 - the edge is what makes the path visible.
            if rn in C.RESET_PASSWORD_TIER0_ROLES:
                p.tags.add("can_reach_tier0")
                for t in tier0_users:
                    if t.id in emitted_reset or t.id == p.id:
                        continue  # skip self - resetting your own password isn't escalation
                    emitted_reset.add(t.id)
                    g.add_edge(Edge(src=p.id, dst=t.id, type=EdgeType.CAN_RESET_PASSWORD,
                                    derived=True, primitive="CanResetPassword",
                                    evidence={"role": role.name,
                                              "reason": "can reset a Tier-0 account's password"}))


def _derive_compute_identity_theft(g: Graph) -> None:
    """A principal with a compute-management RBAC role over a resource can run
    code on it and steal its managed-identity token (IMDS), inheriting the MI's
    privilege."""
    res_mi: dict[str, list[str]] = {}
    for r in g.nodes():
        for e in g.out_edges(r.id, EdgeType.HAS_MANAGED_IDENTITY):
            res_mi.setdefault(r.id, []).append(e.dst)
    if not res_mi:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            how = C.COMPUTE_CONTRIBUTOR_ROLES.get(role)
            if not how:
                continue
            for rid, mis in res_mi.items():
                res = g.node(rid)
                if not _scope_covers(scope, res, g):
                    continue
                for mi in mis:
                    if mi == p.id:
                        continue
                    g.add_edge(Edge(src=p.id, dst=mi, type=EdgeType.CAN_STEAL_MANAGED_IDENTITY,
                                    derived=True, primitive="CanStealManagedIdentity",
                                    evidence={"via_resource": res.name, "via_resource_id": rid,
                                              "role": role, "how": how}))
                    mip = g.node(mi)
                    if mip and (mip.tags & {"tier0", "privileged"}) and "tier0" not in p.tags:
                        p.tags.add("can_reach_tier0")


def _derive_kv_management_escalation(g: Graph) -> None:
    """Management-plane control of a Key Vault (Key Vault Contributor / Owner) can
    grant the holder data-plane access; the Key Vault data-plane RBAC roles (Secrets
    User/Officer, Crypto User/Officer) grant it directly. Both reach the vault."""
    vaults = g.nodes_of_kind(NodeKind.KEY_VAULT)
    if not vaults:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            is_mgmt = role in C.KV_MANAGEMENT_ROLES
            is_data = role in C.KV_DATA_ROLES
            if not (is_mgmt or is_data):
                continue
            reason = ("data-plane RBAC role grants direct secret/key access" if is_data
                      else "management-plane access can grant data-plane secret access")
            for kv in vaults:
                if _scope_covers(scope, kv, g) and not _denied(g, p.id, scope):
                    g.add_edge(Edge(src=p.id, dst=kv.id, type=EdgeType.CAN_REACH_KV_SECRET,
                                    derived=True, primitive="CanReachKVSecret",
                                    evidence={"role": role, "reason": reason}))


def _derive_storage_key_access(g: Graph) -> None:
    """A principal able to list a storage account's keys (listKeys) gains full,
    audit-poor data-plane access to the account."""
    accounts = g.nodes_of_kind(NodeKind.STORAGE)
    if not accounts:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role not in C.STORAGE_KEY_ROLES:
                continue
            for acct in accounts:
                if _scope_covers(scope, acct, g) and not _denied(g, p.id, scope):
                    g.add_edge(Edge(src=p.id, dst=acct.id, type=EdgeType.CAN_GET_STORAGE_KEY,
                                    derived=True, primitive="CanGetStorageKey",
                                    evidence={"role": role, "reason": "can listKeys for the storage account"}))


def _derive_storage_blob_access(g: Graph) -> None:
    """Storage Blob Data Owner/Contributor/Reader grants direct data-plane access to blobs
    via Entra token authentication. Unlike listKeys (CAN_GET_STORAGE_KEY), no shared
    key rotation is needed - the holder reads data as a named identity."""
    accounts = g.nodes_of_kind(NodeKind.STORAGE)
    if not accounts:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role not in C.STORAGE_BLOB_DATA_ROLES:
                continue
            for acct in accounts:
                if _scope_covers(scope, acct, g) and not _denied(g, p.id, scope):
                    g.add_edge(Edge(src=p.id, dst=acct.id, type=EdgeType.CAN_READ_STORAGE_BLOB,
                                    derived=True, primitive="CanReadStorageBlob",
                                    evidence={"role": role,
                                              "reason": "direct blob data-plane access via Entra token"}))


def _derive_container_push(g: Graph) -> None:
    """AcrPush / Contributor / Owner on a container registry enables pushing images.
    A malicious image poisons any workload that subsequently pulls from the registry -
    a supply-chain primitive that persists after the attacker loses other access."""
    registries = g.nodes_of_kind(NodeKind.CONTAINER_REGISTRY)
    if not registries:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role not in C.CONTAINER_PUSH_ROLES:
                continue
            for reg in registries:
                if _scope_covers(scope, reg, g) and not _denied(g, p.id, scope):
                    g.add_edge(Edge(src=p.id, dst=reg.id, type=EdgeType.CAN_PUSH_CONTAINER,
                                    derived=True, primitive="CanPushContainer",
                                    evidence={"role": role,
                                              "reason": "can push container images to registry"}))


def _derive_aks_cluster_access(g: Graph) -> None:
    """A principal able to pull AKS cluster-admin credentials gets cluster-admin
    kubeconfig (and can exec into pods / steal the cluster's managed identity)."""
    clusters = g.nodes_of_kind(NodeKind.AKS)
    if not clusters:
        return
    for p in _principals(g):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = e.evidence.get("scope") or ""
            if role not in C.AKS_CLUSTER_ADMIN_ROLES:
                continue
            for cl in clusters:
                if _scope_covers(scope, cl, g) and not _denied(g, p.id, scope):
                    g.add_edge(Edge(src=p.id, dst=cl.id, type=EdgeType.CAN_EXEC_AKS,
                                    derived=True, primitive="CanExecAKS",
                                    evidence={"role": role, "reason": "can listClusterAdminCredential / exec"}))
