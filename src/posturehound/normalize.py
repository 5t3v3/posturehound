"""Normalize parsed records into the typed graph.

Loaders are intentionally defensive: missing optional fields never abort a build.
Relationship kinds are mapped to raw edges; the derivation layer adds abuse edges.
"""
from __future__ import annotations

import json
from typing import Any

from .ingest import IngestResult
from .model import Edge, EdgeType, Graph, Node, NodeKind
from . import constants as C

# Map node-bearing kinds to NodeKind.
_NODE_KINDS = {k.value: k for k in NodeKind}

# Per-resource Azure RBAC role-assignment kinds -> the field carrying the scope id.
_RBAC_ASSIGNMENT_KINDS = {
    "AZSubscriptionRoleAssignment": "subscriptionId",
    "AZResourceGroupRoleAssignment": "resourceGroupId",
    "AZManagementGroupRoleAssignment": "managementGroupId",
    "AZKeyVaultRoleAssignment": "keyVaultId",
    "AZVMRoleAssignment": "virtualMachineId",
    "AZStorageAccountRoleAssignment": "storageAccountId",
    "AZAutomationAccountRoleAssignment": "automationAccountId",
    "AZLogicAppRoleAssignment": "logicAppId",
    "AZFunctionAppRoleAssignment": "functionAppId",
    "AZContainerRegistryRoleAssignment": "containerRegistryId",
    "AZWebAppRoleAssignment": "webAppId",
    "AZManagedClusterRoleAssignment": "managedClusterId",
    "AZVMScaleSetRoleAssignment": "virtualMachineScaleSetId",
}

# Flat RBAC edge kinds: newer AzureHound native format where the
# kind encodes both the Azure resource type and the built-in role.  These are
# direct source→target edges; the role name is derived from the kind itself.
_FLAT_RBAC_KINDS: dict[str, str] = {
    "AZSubscriptionOwner":              "Owner",
    "AZSubscriptionContributor":        "Contributor",
    "AZSubscriptionUserAccessAdmin":    "User Access Administrator",
    "AZManagementGroupOwner":           "Owner",
    "AZManagementGroupContributor":     "Contributor",
    "AZManagementGroupUserAccessAdmin": "User Access Administrator",
    "AZKeyVaultOwner":                  "Owner",
    "AZKeyVaultContributor":            "Key Vault Contributor",
    "AZKeyVaultKVContributor":          "Key Vault Contributor",
    "AZKeyVaultUserAccessAdmin":        "User Access Administrator",
    "AZResourceGroupOwner":             "Owner",
    "AZResourceGroupContributor":       "Contributor",
    "AZResourceGroupUserAccessAdmin":   "User Access Administrator",
    "AZVMOwner":                        "Owner",
    "AZVMContributor":                  "Virtual Machine Contributor",
    "AZVMAdminLogin":                   "Virtual Machine Administrator Login",
    "AZVMAvereContributor":             "Avere Contributor",
    "AZVMUserAccessAdmin":              "User Access Administrator",
}

# Relationship/edge record kinds the normalizer understands (drives the coverage
# reconciliation, which flags record kinds we silently ignore). Matches the real
# AzureHound v2 output kinds (see enums/kind.go in the AzureHound source).
_RELATIONSHIP_KINDS = {
    "AZGroupMember", "AZGroupOwner", "AZAppOwner", "AZServicePrincipalOwner",
    "AZRoleAssignment", "AZAppRoleAssignment", "AZKeyVaultAccessPolicy",
    "AZContains", "AZManagementGroupDescendant", "AZDenyAssignment",
    "AZFederatedIdentityCredential", "AZRoleEligibilityScheduleInstance",
    "AZRoleManagementPolicy", "AZOAuth2GrantDelegated",
} | set(_RBAC_ASSIGNMENT_KINDS) | set(_FLAT_RBAC_KINDS)
CONSUMED_KINDS = set(_NODE_KINDS) | _RELATIONSHIP_KINDS

# Resource kinds that can carry a managed identity.
_IDENTITY_RESOURCE_KINDS = {
    NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION,
    NodeKind.FUNCTION_APP, NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.VMSS,
    NodeKind.CONTAINER_REGISTRY,
}


def _name(d: dict[str, Any]) -> str:
    return (d.get("displayName") or d.get("appDisplayName") or d.get("name")
            or d.get("userPrincipalName") or d.get("mail") or d.get("id")
            or d.get("appId") or "")


def build_graph(ing: IngestResult) -> Graph:
    g = Graph()
    g.meta = ing.meta
    g.ingest_summary = ing.summary
    g.deny_assignments = []

    # Process records in a DETERMINISTIC order, not the collection's array order. A live
    # AzureHound re-collection returns the tenant's objects in a different order every run,
    # and several build steps are first-write-wins: the case-insensitive id index keeps the
    # FIRST-seen casing of an ARM path as the node's canonical id, and node props merge in
    # processing order. Left in collection order, the same tenant produced graphs that were
    # equivalent but labelled with different casings, which rippled into the fact pack and
    # made the whole scan non-reproducible. Sorting the records by their canonical content
    # fixes the input to the build, so the same data always yields byte-identical results.
    records = sorted(ing.records, key=lambda r: json.dumps(r, sort_keys=True, default=str))

    # Pass 1: nodes
    for rec in records:
        kind = rec["kind"]
        d = rec["data"]
        if kind in _NODE_KINDS:
            nk = _NODE_KINDS[kind]
            if nk == NodeKind.SUBSCRIPTION:
                nid = d.get("id") or _sub_path(d.get("subscriptionId"))
            elif nk == NodeKind.TENANT:
                nid = d.get("id") or d.get("tenantId")
            else:
                nid = d.get("id") or d.get("appId") or d.get("objectId")
            if not nid:
                continue
            node = Node(id=nid, kind=nk, name=_name(d), props=dict(d))
            _tag_node(node, d)
            g.add_node(node)
            if nk == NodeKind.TENANT and g.tenant_id is None:
                g.tenant_id = nid

    # Pass 2: relationships (after nodes exist) - same deterministic order as pass 1.
    for rec in records:
        _load_relationship(g, rec["kind"], rec["data"])

    # Pass 3: tenant-relative tagging (tenant id is known after pass 1).
    # AzureHound stores the tenant node id as "/tenants/<guid>" (path format) but
    # appOwnerOrganizationId is the bare GUID - normalise both to lowercase GUID before comparing.
    def _bare_guid(s: str) -> str:
        return (s.split("/")[-1] if "/" in s else s).lower()

    tenant_guid = _bare_guid(str(g.tenant_id)) if g.tenant_id else None
    for n in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        owner_org = n.props.get("_owner_org")
        if owner_org and tenant_guid and _bare_guid(str(owner_org)) != tenant_guid:
            n.tags.add("foreign_tenant")

    return g


def _tag_node(node: Node, d: dict[str, Any]) -> None:
    if node.kind == NodeKind.USER:
        if str(d.get("userType", "")).lower() == "guest":
            node.tags.add("guest")
        if d.get("accountEnabled") is False:
            node.tags.add("disabled")
        if d.get("onPremisesSyncEnabled"):
            node.tags.add("synced")
    if node.kind == NodeKind.SERVICE_PRINCIPAL:
        node.tags.add("service_principal")
        if d.get("accountEnabled") is False:
            node.tags.add("disabled")
        sp_type = str(d.get("servicePrincipalType", "")).lower()
        if sp_type == "managedidentity" or "managed identity" in str(d.get("displayName", "")).lower():
            node.tags.add("managed_identity")
        # Foreign-tenant SP: app registration lives in another tenant - you cannot
        # add a credential and authenticate as it (avoids the classic false positive).
        owner_org = d.get("appOwnerOrganizationId")
        node.props["_owner_org"] = owner_org
    if node.kind in (NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        creds = (d.get("passwordCredentials") or []) + (d.get("keyCredentials") or [])
        if creds:
            node.tags.add("has_credentials")
        if d.get("federatedIdentityCredentials"):
            node.tags.add("has_federated_credential")
    if node.kind == NodeKind.GROUP:
        if d.get("isAssignableToRole"):
            node.tags.add("role_assignable")
        if d.get("membershipRule") or str(d.get("membershipType", "")).lower() == "dynamic":
            node.tags.add("dynamic_membership")


def _load_relationship(g: Graph, kind: str, d: dict[str, Any]) -> None:
    # ---- group / app / SP membership and ownership (plural nested lists) -----
    if kind == "AZGroupMember":
        gid = d.get("groupId")
        for m in d.get("members") or []:
            _edge(g, _obj_id(m.get("member")), gid, EdgeType.MEMBER_OF)
    elif kind == "AZGroupOwner":
        gid = d.get("groupId")
        for o in d.get("owners") or []:
            _edge(g, _obj_id(o.get("owner")), gid, EdgeType.OWNS, evidence={"object": "group"})
    elif kind == "AZAppOwner":
        aid = d.get("appId")
        for o in d.get("owners") or []:
            _edge(g, _obj_id(o.get("owner")), aid, EdgeType.OWNS, evidence={"object": "application"})
    elif kind == "AZServicePrincipalOwner":
        spid = d.get("servicePrincipalId")
        for o in d.get("owners") or []:
            _edge(g, _obj_id(o.get("owner")), spid, EdgeType.OWNS, evidence={"object": "servicePrincipal"})

    # ---- directory (Entra) role assignments ---------------------------------
    elif kind == "AZRoleAssignment":
        role_def = d.get("roleDefinitionId")
        for ra in d.get("roleAssignments") or []:
            rd = ra.get("roleDefinitionId") or role_def
            _edge(g, ra.get("principalId"), _role_node_for(g, rd), EdgeType.HAS_ENTRA_ROLE,
                  evidence={"roleTemplateId": rd})

    # ---- PIM-eligible (not active) directory role assignments ---------------
    # A principal here is NOT currently holding the role - it can self-activate
    # it via PIM. This is a real, commonly-missed escalation surface ("shadow
    # admin"): the active-only view above would show this principal as
    # unprivileged, while in fact it is one PIM activation away from Tier-0.
    elif kind == "AZRoleEligibilityScheduleInstance":
        _edge(g, d.get("principalId"), _role_node_for(g, d.get("roleDefinitionId")),
              EdgeType.ELIGIBLE_FOR_ROLE,
              evidence={"roleTemplateId": d.get("roleDefinitionId"),
                        "directoryScopeId": d.get("directoryScopeId")})

    # ---- PIM activation policy for a directory role -------------------------
    # How an eligible principal activates the role: MFA/approval requirements, the max
    # activation duration, and whether eligibility may be permanent. Attached to the role
    # node so a rule can flag a Tier-0 role with a weak policy. If the role currently has no
    # active holder it has no node yet; create one for a KNOWN Tier-0 role so its (often the
    # most important) policy is still assessable - a non-Tier-0 role with no node is skipped.
    elif kind == "AZRoleManagementPolicy":
        rid = d.get("roleDefinitionId")
        node = g.node(_role_node_for(g, rid) or "") if rid else None
        if node is None and rid:
            tpl = str(rid).lower()
            if tpl in C.PRIVILEGED_ENTRA_ROLE_TEMPLATES:
                g.add_node(Node(id=rid, kind=NodeKind.ROLE,
                                name=C.PRIVILEGED_ENTRA_ROLE_TEMPLATES[tpl],
                                props={"templateId": rid}))
                node = g.node(rid)
        if node is not None:
            node.props["pim_policy"] = {
                "activationRequiresMfa": d.get("activationRequiresMfa"),
                "activationRequiresApproval": d.get("activationRequiresApproval"),
                "activationMaxDuration": d.get("activationMaxDuration"),
                "permanentEligibilityAllowed": d.get("permanentEligibilityAllowed"),
            }

    # ---- MS Graph application-permission grants -----------------------------
    elif kind == "AZAppRoleAssignment":
        # GRANTED app roles go in `_granted_app_roles`, deliberately NOT in `appRoles`.
        # `appRoles` comes from the SP's own record and lists the permissions the app
        # PUBLISHES. Appending grants to the same list conflated the two, so every
        # consumer treated Microsoft Graph's 707 published permissions as permissions
        # Graph had been granted - fabricating 138 escalation edges, 13% of all attack
        # paths, and the nonsense finding "Microsoft Graph can grant Global Administrator".
        for ra in (d.get("appRoleAssignments") or [d]):
            spid = ra.get("principalId") or ra.get("servicePrincipalId") or d.get("appId")
            resource_id = ra.get("resourceId") or d.get("resourceId")
            role_id = str(ra.get("appRoleId") or "").lower()
            # Resolve the role's name: the caller's own value, then the static Graph map,
            # then the resource SP's published appRoles (exact and free), and finally the
            # raw GUID. Never drop the grant - the previous `and value` guard discarded
            # 576 of 710 grants, i.e. every non-Graph resource and every unmapped GUID.
            value = ra.get("appRoleValue") or C.GRAPH_APP_ROLE_IDS.get(role_id)
            if not value and resource_id:
                res_node = g.node(g.resolve_id(resource_id) or "")
                if res_node:
                    for pub in (res_node.props.get("appRoles") or []):
                        if str(pub.get("id") or "").lower() == role_id:
                            value = pub.get("value")
                            break
            if not value and role_id:
                value = f"appRoleId:{role_id}"
            node = g.node(g.resolve_id(spid) or "") if spid else None
            if node is not None and value:
                node.props.setdefault("_granted_app_roles", []).append({
                    "value": value, "resource_id": resource_id,
                })
                # Also emit the graph edge. EdgeType.HAS_APP_ROLE had three consumers in
                # facts.py and no producer anywhere, so app_role_grant_spread was always
                # [] and the "app" anomaly scanner emitted zero signals for ALL sixteen
                # specialists - three of which list "app" as a signal source.
                if resource_id:
                    _edge(g, node.id, resource_id, EdgeType.HAS_APP_ROLE,
                          evidence={"value": value})

    # ---- Azure RBAC assignments (per resource type, GUID role refs) ---------
    elif kind in _RBAC_ASSIGNMENT_KINDS:
        scope_key = _RBAC_ASSIGNMENT_KINDS[kind]
        # AzureHound nests these under "assignees" ([{"assignee": {"properties": {...}}}]),
        # NOT "roleAssignments". Reading only the latter matched 0 records against 19,275
        # real assignee entries, silently dropping every resource-scoped role assignment
        # (VMSS, ACR, AKS, Logic/Function/Web App, Automation Account). That is why the
        # whole graph carried only 6 distinct RBAC role names, and why purpose-granted
        # data-plane roles were invisible: AcrPush (219 principals), Storage Blob Data
        # Reader/Contributor, Key Vault Secrets Officer/User, AKS RBAC Cluster Admin
        # occurred ONLY in the dropped set.
        for ra in (d.get("assignees") or d.get("roleAssignments") or []):
            inner = ra.get("assignee") or ra.get("roleAssignment") or ra
            props = inner.get("properties") or inner
            principal = props.get("principalId")
            role_def_id = props.get("roleDefinitionId")
            scope = props.get("scope")
            # A "/" scope means the assignment is recorded against the parent resource.
            if not scope or scope == "/":
                scope = d.get(scope_key) or ra.get(scope_key) or d.get("objectId")
            # Custom roles are not in the built-in GUID map. Label them rather than
            # letting a full ARM path become the "role name" in reports and prompts.
            role_name = C.arm_role_name(role_def_id)
            if not role_name:
                _guid = str(role_def_id or "").rstrip("/").rsplit("/", 1)[-1]
                role_name = f"Custom role ({_guid})" if _guid else "Custom role"
            _edge(g, principal, scope, EdgeType.HAS_RBAC_ROLE,
                  evidence={"role": role_name, "roleDefinitionId": role_def_id,
                            "scope": scope, "is_custom_role": not C.arm_role_name(role_def_id)})

    # ---- Flat RBAC edge kinds (newer AzureHound / BH CE native format) ---------
    # Kind encodes resource type + role; data has source+target principal/resource IDs.
    elif kind in _FLAT_RBAC_KINDS:
        role = _FLAT_RBAC_KINDS[kind]
        is_sub = kind.startswith("AZSubscription")
        # Format A: simple flat record - SourceID/source/principalId → TargetID/target/resourceId.
        src = (d.get("SourceID") or d.get("source") or d.get("sourceId")
               or d.get("principalId") or d.get("objectId"))
        dst = (d.get("TargetID") or d.get("target") or d.get("targetId")
               or d.get("resourceId"))
        if isinstance(src, dict):
            src = _obj_id(src)
        if isinstance(dst, dict):
            dst = _obj_id(dst)
        if src and dst:
            src = str(src)
            dst = str(dst)
            if is_sub:
                dst = _sub_path(dst)
            _edge(g, src, dst, EdgeType.HAS_RBAC_ROLE, evidence={"role": role, "scope": dst})
        else:
            # Format B: AzureHound v2 nested format.
            # {"owners": [{"owner": {"properties": {"principalId": ..., "scope": ...}},
            #              "subscriptionId": ...}],
            #  "subscriptionId": ...}
            # The array key name is the pluralised role (owners/contributors/…).
            # Each item wraps one assignment object with a "properties" dict.
            top_scope = next((str(v) for v in d.values() if isinstance(v, str) and v), None)
            for arr in d.values():
                if not isinstance(arr, list):
                    continue
                for item in arr:
                    if not isinstance(item, dict):
                        continue
                    principal_id = None
                    scope = None
                    # Find the inner role-assignment object (has "properties" with principalId).
                    for item_val in item.values():
                        if isinstance(item_val, dict):
                            props = item_val.get("properties") or {}
                            pid = props.get("principalId")
                            if pid:
                                principal_id = str(pid)
                                # Only use properties.scope when it's a real resource path
                                # (not "/" which means tenant-root - fall through to item ID).
                                raw_scope = (props.get("scope") or "").strip("/")
                                if raw_scope:
                                    scope = props.get("scope")
                                break
                    # Prefer item-level resource ID (e.g. subscriptionId) over
                    # properties.scope = "/" (tenant-root assignments).
                    if not scope:
                        scope = next((str(v) for v in item.values()
                                      if isinstance(v, str) and v), top_scope)
                    if principal_id and scope:
                        if is_sub:
                            scope = _sub_path(scope)
                        _edge(g, principal_id, scope, EdgeType.HAS_RBAC_ROLE,
                              evidence={"role": role, "scope": scope})
                break  # only one array per record

    # ---- Key Vault access policies ------------------------------------------
    elif kind == "AZKeyVaultAccessPolicy":
        perms = d.get("permissions") or {}
        _edge(g, d.get("objectId") or d.get("principalId"), d.get("keyVaultId"),
              EdgeType.KV_ACCESS, evidence={"permissions": perms})

    # ---- containment ---------------------------------------------------------
    elif kind in ("AZContains", "AZManagementGroupDescendant"):
        _load_containment(g, kind, d)

    elif kind == "AZFederatedIdentityCredential":
        # Record federated credentials on the SP/app node so detection rules can check
        # them. Three separate faults previously dropped ALL of them:
        #   1. AzureHound nests the credential as {"fics": [{"fic": {...}, "appId": ...}]},
        #      so top-level d.get("issuer")/d.get("subject") were always None;
        #   2. the identifier is the appId (client ID), not the node's object GUID;
        #   3. the lookup was case-sensitive while the two casings differ.
        # Net effect on a real tenant: 107 records / 219 credentials → 0 recorded, which
        # also left AZ-APP-008 permanently dead and hid 65 GitHub Actions OIDC
        # federations plus 63 with an unsubstituted "{tenantId}" placeholder issuer.
        for entry in (d.get("fics") or [d]):
            fic = entry.get("fic") or entry
            target = (entry.get("servicePrincipalId") or entry.get("appId")
                      or d.get("servicePrincipalId") or d.get("appId"))
            n = g.node(g.resolve_id(target) or "") if target else None
            if n is None and target:
                n = g.node_by_app_id(str(target))
            if n is None:
                continue
            n.tags.add("has_federated_credential")
            n.props.setdefault("federatedIdentityCredentials", []).append({
                "issuer":    fic.get("issuer", ""),
                "subject":   fic.get("subject", ""),
                "audiences": fic.get("audiences") or [],
                "name":      fic.get("name", ""),
            })

    elif kind == "AZOAuth2GrantDelegated":
        # Delegated (on-behalf-of) MS Graph permission grant. Record the granted
        # scopes on the client service principal so a rule can flag dangerous
        # tenant-wide (admin-consented) delegated permissions - the illicit-consent
        # surface AzureHound's app-role-only view misses.
        client_id = d.get("clientId")
        n = g.node(g.resolve_id(client_id) or "") if client_id else None
        if n is None and client_id:
            n = g.node(client_id)
        if n is not None:
            n.props.setdefault("_delegated_grants", []).append({
                "scope": d.get("scope") or "",
                "consent_type": d.get("consentType"),
                "resource_id": d.get("resourceId"),
            })

    elif kind == "AZDenyAssignment":
        principals = d.get("principals") or d.get("principalIds") or []
        if isinstance(principals, str):
            principals = [principals]
        g.deny_assignments.append({
            "scope": d.get("scope"),
            "principals": [p.get("id") if isinstance(p, dict) else p for p in principals],
        })

    # ---- containment carried on the node records themselves ------------------
    if kind == "AZResourceGroup" and d.get("subscriptionId"):
        _edge(g, _sub_path(d.get("subscriptionId")), d.get("id"), EdgeType.CONTAINS)
    elif kind == "AZSubscription" and d.get("managementGroupId"):
        _edge(g, d.get("managementGroupId"), d.get("id") or _sub_path(d.get("subscriptionId")),
              EdgeType.CONTAINS)

    # ---- managed identity on a resource node --------------------------------
    nk = _NODE_KINDS.get(kind)
    if nk in _IDENTITY_RESOURCE_KINDS:
        ident = d.get("identity") or {}
        pid = ident.get("principalId")
        if pid:
            _edge(g, d.get("id"), pid, EdgeType.HAS_MANAGED_IDENTITY,
                  evidence={"identityType": ident.get("type")})
        for uami in (ident.get("userAssignedIdentities") or {}).values():
            if isinstance(uami, dict) and uami.get("principalId"):
                _edge(g, d.get("id"), uami["principalId"], EdgeType.HAS_MANAGED_IDENTITY,
                      evidence={"identityType": "UserAssigned"})


def _obj_id(raw: Any) -> str | None:
    """Pull the object id out of a raw embedded Graph/ARM object (or a bare id)."""
    if isinstance(raw, dict):
        return raw.get("id") or raw.get("objectId") or raw.get("appId")
    if isinstance(raw, str):
        return raw
    return None


def _sub_path(sub_id: str | None) -> str | None:
    if not sub_id:
        return None
    low = sub_id.lower()
    if low.startswith("/subscriptions/"):
        return low  # normalise to lowercase ARM path
    return f"/subscriptions/{sub_id.lower()}"


def _role_node_for(g: Graph, role_def_id: str | None) -> str | None:
    """Find the AZRole node matching a directory roleDefinitionId/templateId."""
    if not role_def_id:
        return None
    rid = str(role_def_id).lower()
    for r in g.nodes_of_kind(NodeKind.ROLE):
        if (r.id or "").lower() == rid or str((r.props or {}).get("templateId", "")).lower() == rid:
            return r.id
    return role_def_id  # fall back to a synthetic id so the edge still forms


def _load_containment(g: Graph, kind: str, d: dict[str, Any]) -> None:
    if kind == "AZManagementGroupDescendant":
        # AzureHound puts the parent management group at properties.parent.id and the
        # child (a subscription or a nested MG) at the top-level id. Reading
        # managementGroupId/parentId - neither of which the record contains - resolved
        # the parent to None, so _edge returned early and the ENTIRE management-group
        # tree was silently absent from the graph. That removed the blast radius of
        # every MG-scoped role: an MG Owner applies to all descendant subscriptions,
        # and without the hierarchy that reach cannot be computed.
        parent = (
            ((d.get("properties") or {}).get("parent") or {}).get("id")
            or d.get("managementGroupId")
            or d.get("parentId")
        )
        _edge(g, parent, d.get("id") or d.get("childId"), EdgeType.CONTAINS)
    elif kind == "AZContains":
        _edge(g, d.get("parentId"), d.get("childId"), EdgeType.CONTAINS)


def _edge(g: Graph, src: str | None, dst: str | None, etype: EdgeType, *,
          evidence: dict | None = None) -> None:
    if not src or not dst:
        return
    # Resolve each endpoint case-insensitively FIRST. AzureHound refers to the same
    # object with different casing across record types, so matching exactly created a
    # synthetic placeholder alongside the real node - e.g. all 1,243 subscription→
    # resource-group CONTAINS edges pointed at phantom /subscriptions/<guid> nodes
    # while the real subscription was /SUBSCRIPTIONS/<GUID>, breaking the hierarchy.
    src = g.resolve_id(src) or src
    dst = g.resolve_id(dst) or dst
    # Ensure endpoints exist (tolerate references to not-collected objects).
    if not g.node(src):
        g.add_node(Node(id=src, kind=NodeKind.UNKNOWN, name=src, props={"_synthetic": True}))
    if not g.node(dst):
        g.add_node(Node(id=dst, kind=NodeKind.UNKNOWN, name=dst, props={"_synthetic": True}))
    g.add_edge(Edge(src=src, dst=dst, type=etype, evidence=evidence or {}))
