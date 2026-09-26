"""Live Microsoft Graph directory collector - an AzureHound-equivalent (PostureHound v2, Track B).

AzureHound collects the Entra ID (Azure AD) directory graph and PostureHound ingests
its `.zip`/`.json`. This module collects that SAME graph LIVE from Microsoft Graph
using the read-only service principal, and emits records in AzureHound's exact
`{kind, data}` shape - so the existing ingest -> normalize -> derive -> rules pipeline
consumes it with zero changes. A tenant can then be assessed from one read-only SP,
with no separate AzureHound run.

Why the wrapping is thin: normalize.py reads the raw Microsoft Graph field names
(`displayName`, `userType`, `accountEnabled`, `servicePrincipalType`,
`appOwnerOrganizationId`, `keyCredentials`, `isAssignableToRole`, …) straight off each
record's `data`. So each collected Graph object becomes a record's `data` verbatim; only
the relationship records (members, owners, grants) are reshaped into AzureHound's nested
form. Field mappings are pinned to the kinds normalize.CONSUMED_KINDS understands.

Permission: this needs Microsoft Graph **Directory.Read.All** (application, admin-
consented) - the same read scope AzureHound uses - in addition to the Policy.Read.All
that azure_graph already uses. For full PIM coverage it also uses (each independently,
degrading gracefully with a 403 recorded in errors if absent):
**RoleManagement.Read.Directory** (role assignments/definitions),
**RoleEligibilitySchedule.Read.Directory** (PIM *eligible* assignments - shadow admins), and
**RoleManagementPolicy.Read.Directory** (PIM *activation* policies - MFA/approval/duration).
It never writes.

Same contract as the other collectors: injectable HTTP (tested with httpx.MockTransport),
graceful when unconfigured (returns None), never raises into a scan.
"""
from __future__ import annotations

import json
from urllib.parse import quote as _urlquote

from .azure_arg import (
    _ARM, _MAX_PAGES, ArgCredentials, _send_with_retry, credentials_from_settings,
)
from .azure_arg import _default_client as _arm_default_client
from .azure_arg import get_token as _arm_token
from .azure_graph import _GRAPH, _default_client, _get_all, get_token

# ARM REST for the Azure RBAC graph + management-group hierarchy (AzureHound's
# rm.json half). Reader on the root management group covers all of these reads.
_ARM_MG = f"{_ARM}/providers/Microsoft.Management/managementGroups"
_MG_API = "2020-05-01"
_ROLE_API = "2022-04-01"
_SUBS_API = "2020-01-01"

# $select projections - keep payloads small but carry every field normalize/derive read.
_SEL = {
    "users": "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
             "onPremisesSyncEnabled,jobTitle,createdDateTime",
    "groups": "id,displayName,mail,securityEnabled,isAssignableToRole,membershipRule,"
              "membershipType,onPremisesSyncEnabled,visibility",
    "servicePrincipals": "id,displayName,appId,servicePrincipalType,accountEnabled,"
                         "appOwnerOrganizationId,appRoles,keyCredentials,"
                         "passwordCredentials,tags,servicePrincipalNames",
    "applications": "id,displayName,appId,signInAudience,keyCredentials,passwordCredentials",
}


def _rec(kind: str, data: dict) -> dict:
    return {"kind": kind, "data": data}


_BATCH_MAX = 20   # Microsoft Graph caps a $batch at 20 sub-requests


def _batch_get(token: str, client, reqs, *, errors=None, what="") -> dict:
    """Run many GET requests via Microsoft Graph $batch (20 per call) instead of one
    round-trip each - the difference between a 45-minute and a few-minute collection on
    a large tenant.

    `reqs` is a list of (key, rel_url); rel_url is RELATIVE to the Graph version root,
    e.g. '/groups/<id>/members?$select=id&$top=999'. Returns {key: [value items]},
    following each sub-request's @odata.nextLink. Best-effort and never raises: a whole
    batch that fails, or a sub-request that errors, records an error and yields nothing
    for the affected keys; 429/5xx sub-requests are retried a few times."""
    out: dict = {}
    attempts: dict = {}
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    pending = list(reqs)
    while pending:
        chunk, pending = pending[:_BATCH_MAX], pending[_BATCH_MAX:]
        idmap = {str(i): (k, u) for i, (k, u) in enumerate(chunk)}
        body = {"requests": [{"id": i, "method": "GET", "url": u} for i, (k, u) in idmap.items()]}
        try:
            resp = _send_with_retry(lambda body=body: client.post(f"{_GRAPH}/$batch", json=body, headers=headers))
            payload = resp.json()
        except Exception as e:  # noqa: BLE001 - whole batch failed; record and continue
            if errors is not None:
                errors.append(f"{what} $batch: {e}")
            continue
        for r in (payload.get("responses") or []):
            key, url = idmap.get(str(r.get("id")), (None, None))
            if key is None:
                continue
            status = r.get("status")
            b = r.get("body") if isinstance(r.get("body"), dict) else {}
            if status == 200:
                out.setdefault(key, []).extend(b.get("value") or [])
                nl = b.get("@odata.nextLink")
                if nl:
                    out.setdefault(key, out.get(key, []))
                    pending.append((key, nl.split("/v1.0", 1)[-1] if "/v1.0" in nl else nl))
            elif status in (429, 503, 500) and attempts.get(key, 0) < 3:
                attempts[key] = attempts.get(key, 0) + 1
                pending.append((key, url))
            elif status not in (200, 404) and errors is not None:
                errors.append(f"{what} {key}: HTTP {status}")
    return out


def collect_directory(creds: "ArgCredentials | None" = None, *, client=None,
                      on_progress=None) -> "tuple[list[dict], list[str]] | None":
    """Collect the Entra directory graph live and return (records, errors).

    records are AzureHound `{kind, data}` dicts ready for ingest.parse_bytes via
    to_collection_bytes. Returns None when no SP is configured. Never raises: a
    per-collection failure (including a 403 from a missing Directory.Read.All) is
    recorded in `errors` and the rest of the collection continues."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return None

    def _log(m):
        if on_progress:
            on_progress(m)

    owns = client is None
    client = client or _default_client()
    records: list[dict] = []
    errors: list[str] = []

    def _all(url: str, what: str) -> list[dict]:
        try:
            return _get_all(token, url, client)
        except Exception as e:  # noqa: BLE001 - surface, never crash the scan
            errors.append(f"{what}: {e}")
            return []

    try:
        try:
            _log("[Dir] Authenticating for Microsoft Graph (directory)…")
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001
            return [], [f"authentication failed: {type(e).__name__}: {e}"]

        # ---- Tenant (AzureHound stores the id as /tenants/<guid>) --------------
        for org in _all(f"{_GRAPH}/organization", "organization"):
            tid = org.get("id") or creds.tenant_id
            records.append(_rec("AZTenant", {**org, "id": f"/tenants/{tid}", "tenantId": tid}))

        # ---- Users -------------------------------------------------------------
        users = _all(f"{_GRAPH}/users?$select={_SEL['users']}&$top=999", "users")
        records += [_rec("AZUser", u) for u in users if u.get("id")]
        _log(f"[Dir] {len(users)} user(s).")

        # ---- Groups + members + owners (batched) ------------------------------
        groups = _all(f"{_GRAPH}/groups?$select={_SEL['groups']}&$top=999", "groups")
        records += [_rec("AZGroup", g) for g in groups if g.get("id")]
        gids = [g["id"] for g in groups if g.get("id")]
        gm = _batch_get(token, client, [(gid, f"/groups/{gid}/members?$select=id&$top=999")
                                        for gid in gids], errors=errors, what="group members")
        go = _batch_get(token, client, [(gid, f"/groups/{gid}/owners?$select=id&$top=999")
                                        for gid in gids], errors=errors, what="group owners")
        for gid in gids:
            members = [m for m in (gm.get(gid) or []) if m.get("id")]
            if members:
                records.append(_rec("AZGroupMember", {
                    "groupId": gid, "members": [{"member": {"id": m["id"]}} for m in members]}))
            owners = [o for o in (go.get(gid) or []) if o.get("id")]
            if owners:
                records.append(_rec("AZGroupOwner", {
                    "groupId": gid, "owners": [{"owner": {"id": o["id"]}} for o in owners]}))
        _log(f"[Dir] {len(groups)} group(s) with membership + ownership.")

        # ---- Service principals + owners + app-role grants (batched) ----------
        sps = _all(f"{_GRAPH}/servicePrincipals?$select={_SEL['servicePrincipals']}&$top=999",
                   "servicePrincipals")
        records += [_rec("AZServicePrincipal", s) for s in sps if s.get("id")]
        spids = [s["id"] for s in sps if s.get("id")]
        so = _batch_get(token, client, [(spid, f"/servicePrincipals/{spid}/owners?$select=id&$top=999")
                                        for spid in spids], errors=errors, what="sp owners")
        sg = _batch_get(token, client, [
            (spid, f"/servicePrincipals/{spid}/appRoleAssignments"
                   f"?$select=principalId,resourceId,appRoleId&$top=999")
            for spid in spids], errors=errors, what="sp grants")
        for spid in spids:
            owners = [o for o in (so.get(spid) or []) if o.get("id")]
            if owners:
                records.append(_rec("AZServicePrincipalOwner", {
                    "servicePrincipalId": spid, "owners": [{"owner": {"id": o["id"]}} for o in owners]}))
            grants = sg.get(spid) or []
            if grants:
                records.append(_rec("AZAppRoleAssignment", {
                    "appId": spid,
                    "appRoleAssignments": [{
                        "principalId": gr.get("principalId") or spid,
                        "resourceId": gr.get("resourceId"),
                        "appRoleId": gr.get("appRoleId"),
                    } for gr in grants]}))
        _log(f"[Dir] {len(sps)} service principal(s) with grants.")

        # ---- Applications + owners + federated credentials (batched) ----------
        apps = _all(f"{_GRAPH}/applications?$select={_SEL['applications']}&$top=999",
                    "applications")
        records += [_rec("AZApp", a) for a in apps if a.get("id")]
        app_by_id = {a["id"]: a for a in apps if a.get("id")}
        aids = list(app_by_id)
        ao = _batch_get(token, client, [(aid, f"/applications/{aid}/owners?$select=id&$top=999")
                                        for aid in aids], errors=errors, what="app owners")
        af = _batch_get(token, client, [(aid, f"/applications/{aid}/federatedIdentityCredentials")
                                        for aid in aids], errors=errors, what="app fics")
        for aid in aids:
            owners = [o for o in (ao.get(aid) or []) if o.get("id")]
            if owners:
                records.append(_rec("AZAppOwner", {
                    "appId": aid, "owners": [{"owner": {"id": o["id"]}} for o in owners]}))
            fics = af.get(aid) or []
            if fics:
                records.append(_rec("AZFederatedIdentityCredential", {
                    "fics": [{"fic": {"issuer": f.get("issuer", ""), "subject": f.get("subject", ""),
                                      "audiences": f.get("audiences") or [], "name": f.get("name", "")},
                              "appId": app_by_id[aid].get("appId")} for f in fics]}))
        _log(f"[Dir] {len(apps)} application(s).")

        # ---- Directory roles (activated) + active members (batched) -----------
        roles = _all(f"{_GRAPH}/directoryRoles", "directoryRoles")
        # NB: the directoryRoles `members` navigation rejects $top/$select with HTTP 400
        # (unlike group/SP/app members which accept them), so request it bare. Roles
        # rarely have many members; _batch_get still follows any nextLink.
        rm = _batch_get(token, client, [(r["id"], f"/directoryRoles/{r['id']}/members")
                                        for r in roles if r.get("id")], errors=errors, what="role members")
        for r in roles:
            tmpl = r.get("roleTemplateId") or r.get("id")
            if not tmpl:
                continue
            records.append(_rec("AZRole", {**r, "id": tmpl, "templateId": tmpl}))
            members = [m for m in (rm.get(r.get("id")) or []) if m.get("id")]
            if members:
                records.append(_rec("AZRoleAssignment", {
                    "roleDefinitionId": tmpl,
                    # directoryScopeId is REQUIRED: the graph ingest splits this field, and an
                    # absent value crashes role-assignment parsing. Active directory
                    # role assignments are tenant-wide, so the scope is "/".
                    "roleAssignments": [{"principalId": m["id"], "roleDefinitionId": tmpl,
                                         "directoryScopeId": "/"}
                                        for m in members]}))
        _log(f"[Dir] {len(roles)} activated directory role(s).")

        # ---- PIM-eligible (not-yet-active) directory roles - shadow admins ----
        elig = _all(
            f"{_GRAPH}/roleManagement/directory/roleEligibilityScheduleInstances"
            f"?$select=principalId,roleDefinitionId,directoryScopeId&$top=999",
            "roleEligibilityScheduleInstances")
        for e in elig:
            if e.get("principalId") and e.get("roleDefinitionId"):
                records.append(_rec("AZRoleEligibilityScheduleInstance", {
                    "principalId": e.get("principalId"),
                    "roleDefinitionId": e.get("roleDefinitionId"),
                    "directoryScopeId": e.get("directoryScopeId")}))
        if elig:
            _log(f"[Dir] {len(elig)} PIM-eligible role assignment(s).")

        # ---- PIM activation policies (RoleManagementPolicy.Read.Directory) -----
        # The rules governing how an eligible principal ACTIVATES a directory role: whether
        # MFA and approval are required, the maximum activation duration, and whether an
        # eligible assignment is allowed to be permanent. A Tier-0 role that activates with no
        # MFA, or whose eligibility never expires, is a weak-PIM misconfiguration that the
        # eligibility data alone cannot reveal. One policy is assigned per role at "/" scope;
        # $expand pulls the rule set inline so no per-policy follow-up call is needed.
        _pfilter = _urlquote("scopeId eq '/' and scopeType eq 'DirectoryRole'")
        pols = _all(
            f"{_GRAPH}/policies/roleManagementPolicyAssignments"
            f"?$filter={_pfilter}&$expand=policy($expand=rules)",
            "roleManagementPolicyAssignments")
        for pa in pols:
            rdid = pa.get("roleDefinitionId")
            if not rdid:
                continue
            rules = ((pa.get("policy") or {}).get("rules")) or []
            mfa = approval = False
            max_dur = None
            permanent_eligibility = None
            for r in rules:
                rid = r.get("id")
                if rid == "Enablement_EndUser_Assignment":
                    mfa = "MultiFactorAuthentication" in (r.get("enabledRules") or [])
                elif rid == "Approval_EndUser_Assignment":
                    approval = bool((r.get("setting") or {}).get("isApprovalRequired"))
                elif rid == "Expiration_EndUser_Assignment":
                    max_dur = r.get("maximumDuration")
                elif rid == "Expiration_Admin_Eligibility":
                    # isExpirationRequired == False means an eligible assignment may be permanent.
                    ie = r.get("isExpirationRequired")
                    permanent_eligibility = (ie is False)
            records.append(_rec("AZRoleManagementPolicy", {
                "roleDefinitionId": rdid,
                "activationRequiresMfa": mfa,
                "activationRequiresApproval": approval,
                "activationMaxDuration": max_dur,
                "permanentEligibilityAllowed": permanent_eligibility}))
        if pols:
            _log(f"[Dir] {len(pols)} PIM role activation policy assignment(s).")

        # ---- Delegated OAuth2 permission grants (illicit-consent surface) ------
        grants = _all(f"{_GRAPH}/oauth2PermissionGrants?$top=999", "oauth2PermissionGrants")
        for gr in grants:
            if gr.get("clientId") and gr.get("scope"):
                records.append(_rec("AZOAuth2GrantDelegated", {
                    "clientId": gr.get("clientId"),          # the client SERVICE PRINCIPAL object id
                    "consentType": gr.get("consentType"),    # AllPrincipals (tenant-wide) or Principal
                    "principalId": gr.get("principalId"),
                    "resourceId": gr.get("resourceId"),
                    "scope": gr.get("scope")}))              # space-delimited delegated scopes
        if grants:
            _log(f"[Dir] {len(grants)} delegated OAuth2 grant(s).")

        return records, errors
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass


def _arm_get_all(token: str, url: str, client) -> list[dict]:
    """GET an ARM collection following `nextLink`, honouring 429/Retry-After."""
    out: list[dict] = []
    headers = {"Authorization": f"Bearer {token}"}
    for _ in range(_MAX_PAGES):
        resp = _send_with_retry(lambda url=url: client.get(url, headers=headers))
        payload = resp.json()
        out.extend(payload.get("value") or [])
        url = payload.get("nextLink")
        if not url:
            break
    return out


def _arm_get_one(token: str, url: str, client) -> dict:
    """GET a single ARM object (throttling-aware). {} on any error - never raises."""
    try:
        resp = _send_with_retry(lambda: client.get(
            url, headers={"Authorization": f"Bearer {token}"}))
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _rbac_kind_for(scope: str) -> str:
    s = (scope or "").lower()
    if "/managementgroups/" in s:
        return "AZManagementGroupRoleAssignment"
    if "/resourcegroups/" in s:
        return "AZResourceGroupRoleAssignment"
    return "AZSubscriptionRoleAssignment"


def collect_arm(creds: "ArgCredentials | None" = None, *, client=None,
                on_progress=None) -> "tuple[list[dict], list[str]] | None":
    """Collect the Azure RBAC graph + management-group hierarchy live via ARM REST
    and return (records, errors) in AzureHound's {kind, data} shape.

    This is the rm.json half AzureHound produces: subscriptions, management groups
    and their hierarchy, and every Azure RBAC role assignment across management-group,
    subscription, resource-group and resource scope - the Owner/Contributor/User
    Access Administrator reach that drives cross-subscription blast radius.

    Role assignments are read per subscription (the whole subtree, including
    inherited) AND per management group at-scope, then de-duplicated by assignment
    id, so nothing at any scope is missed or double-counted. Never raises; each
    per-scope failure is recorded and the rest continues."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return None

    def _log(m):
        if on_progress:
            on_progress(m)

    owns = client is None
    client = client or _arm_default_client()
    records: list[dict] = []
    errors: list[str] = []

    def _all(url: str, what: str) -> list[dict]:
        try:
            return _arm_get_all(token, url, client)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{what}: {e}")
            return []

    try:
        try:
            _log("[ARM] Authenticating for Azure Resource Manager…")
            token = _arm_token(creds, client)
        except Exception as e:  # noqa: BLE001
            return [], [f"ARM authentication failed: {type(e).__name__}: {e}"]

        # ---- Subscriptions (with display names) --------------------------------
        sub_ids: list[str] = []
        for s in _all(f"{_ARM}/subscriptions?api-version={_SUBS_API}", "subscriptions"):
            sid = s.get("subscriptionId")
            state = (s.get("state") or "").lower()
            if not sid or state not in ("", "enabled"):
                continue
            sub_ids.append(sid)
            records.append(_rec("AZSubscription", {
                "id": f"/subscriptions/{sid}", "subscriptionId": sid,
                "displayName": s.get("displayName")}))
        _log(f"[ARM] {len(sub_ids)} subscription(s).")

        # ---- Management groups + hierarchy ------------------------------------
        mgs = _all(f"{_ARM_MG}?api-version={_MG_API}", "managementGroups")
        for mg in mgs:
            props = mg.get("properties") or {}
            records.append(_rec("AZManagementGroup", {
                "id": mg.get("id"), "name": mg.get("name"),
                "displayName": props.get("displayName")}))
        for mg in mgs:
            detail = _arm_get_one(
                token, f"{_ARM_MG}/{mg.get('name')}?api-version={_MG_API}&$expand=children", client)
            for child in ((detail.get("properties") or {}).get("children") or []):
                if child.get("id"):
                    records.append(_rec("AZManagementGroupDescendant", {
                        "id": child["id"], "properties": {"parent": {"id": mg.get("id")}}}))
        _log(f"[ARM] {len(mgs)} management group(s) with hierarchy.")

        # ---- RBAC role assignments (per-sub subtree + per-MG at-scope) --------
        seen: set[str] = set()

        def _emit(ra: dict) -> None:
            rid = ra.get("id")
            if rid and rid in seen:
                return
            if rid:
                seen.add(rid)
            p = ra.get("properties") or {}
            scope = p.get("scope") or ""
            records.append(_rec(_rbac_kind_for(scope), {"assignees": [{"assignee": {"properties": {
                "principalId": p.get("principalId"),
                "roleDefinitionId": p.get("roleDefinitionId"),
                "scope": scope}}}]}))

        for sid in sub_ids:
            for ra in _all(
                f"{_ARM}/subscriptions/{sid}/providers/Microsoft.Authorization/"
                f"roleAssignments?api-version={_ROLE_API}", f"sub {sid} roleAssignments"):
                _emit(ra)
        for mg in mgs:
            for ra in _all(
                f"{_ARM_MG}/{mg.get('name')}/providers/Microsoft.Authorization/"
                f"roleAssignments?api-version={_ROLE_API}&$filter=atScope()",
                f"mg {mg.get('name')} roleAssignments"):
                _emit(ra)
        _log(f"[ARM] {len(seen)} distinct RBAC role assignment(s).")

        # ---- Deny assignments (so paths Azure actually BLOCKS aren't reported) -
        deny = 0
        for sid in sub_ids:
            for da in _all(
                f"{_ARM}/subscriptions/{sid}/providers/Microsoft.Authorization/"
                f"denyAssignments?api-version={_ROLE_API}", f"sub {sid} denyAssignments"):
                p = da.get("properties") or {}
                principals = [{"id": (pr.get("objectId") or pr.get("id"))}
                              for pr in (p.get("principals") or []) if isinstance(pr, dict)]
                records.append(_rec("AZDenyAssignment", {
                    "scope": p.get("scope"), "principals": principals}))
                deny += 1
        if deny:
            _log(f"[ARM] {deny} deny assignment(s).")

        return records, errors
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass


def collect_live(creds: "ArgCredentials | None" = None, *, client=None,
                 on_progress=None) -> "tuple[list[dict], list[str]] | None":
    """The full live collection: the Entra directory graph (Microsoft Graph) PLUS the
    Azure RBAC graph, management-group hierarchy, and deny assignments (ARM). This
    covers the identity + access-control plane end to end from one read-only SP.

    It also collects the individual RESOURCE objects (VMs, Key Vaults, storage accounts,
    AKS, ACR, automation/function/logic/web apps, VMSS) with their managed identities, Key
    Vault access policies and security config, via Azure Resource Graph - so resource-scoped
    RBAC resolves to real resource nodes and the resource-plane abuse edges (managed-identity
    theft, Key Vault data-plane reach, storage-key / blob / ACR-push / AKS-exec) are derived
    the same as from an AzureHound rm.json. A live SP collection is therefore full-coverage
    on its own. Returns (records, errors), or None when no SP is configured."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return None
    records: list[dict] = []
    errors: list[str] = []
    directory = collect_directory(creds, client=client, on_progress=on_progress)
    if directory:
        records += directory[0]
        errors += directory[1]
    arm = collect_arm(creds, client=client, on_progress=on_progress)
    if arm:
        records += arm[0]
        errors += arm[1]
    # Individual resource objects (Resource Graph) - the managed identities, Key Vault
    # access policies and config that power the resource-plane abuse edges.
    from . import azure_arg
    try:
        records += azure_arg.collect_resource_objects(creds, client=client, on_progress=on_progress)
    except Exception as e:  # noqa: BLE001 - best-effort; never fail the whole collection
        errors.append(f"resource-object collection failed: {e}")
    return records, errors


def to_collection_bytes(records: list[dict], *, meta: dict | None = None) -> bytes:
    """Wrap collected records in AzureHound's {meta, data} envelope so
    ingest.parse_bytes consumes them exactly like an uploaded collection.

    `meta.type` MUST be "azure": the collection parser validates the meta tag and
    rejects the whole upload ("no valid meta tag found" / "All files failed to ingest as
    JSON Content") without it. "azure" is AzureHound's own meta type;
    only "azure" is accepted ("azurehound"/"AzureHound" are rejected)."""
    envelope = {"meta": {"type": "azure", "version": 5, "count": len(records),
                         "source": "posturehound-live", **(meta or {})},
                "data": records}
    return json.dumps(envelope).encode()


def probe(creds: "ArgCredentials | None" = None, *, client=None) -> dict:
    """Validate the SP's Directory.Read.All: authenticate and read one user page.
    Returns {ok, message} - never raises. Directory.Read.All is a DIFFERENT grant
    from Policy.Read.All, so it is checked separately."""
    creds = creds or credentials_from_settings()
    if creds is None:
        return {"ok": False, "message": "No service principal configured."}
    owns = client is None
    client = client or _default_client()
    try:
        try:
            token = get_token(creds, client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": f"Graph authentication failed: {type(e).__name__}: {e}"}
        try:
            users = _get_all(token, f"{_GRAPH}/users?$select=id&$top=1", client)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "message": "Authenticated, but reading the directory failed - "
                    f"grant the SP Directory.Read.All and admin-consent it ({e})"}
        return {"ok": True, "message": f"Directory readable - {len(users)} user(s) on the first page."}
    finally:
        if owns:
            try:
                client.close()
            except Exception:
                pass
