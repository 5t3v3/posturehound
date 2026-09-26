"""PostureHound detection rule library.

Severity rubric:
  Critical = direct/derivable tenant or subscription takeover
  High     = significant privilege or credential exposure
  Medium   = meaningful over-permission / hygiene weakness
  Low      = best-practice deviation / defense-in-depth (see best_practice=True)
  Info     = observational

Best-practice rules are tagged best_practice=True and kept at Low/Info severity:
they are not active vulnerabilities but configurations that *should* be followed.
"""
from __future__ import annotations

from .. import constants as C
from ..model import Category, EdgeType, Graph, NodeKind, Severity
from .base import REGISTRY, Entity, rule

MS = "https://learn.microsoft.com/azure/active-directory/roles/security-planning"
SPEC = "https://microsoft.github.io/Azure-Threat-Research-Matrix/"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _ent(g: Graph, node_id: str, **evidence) -> Entity:
    n = g.node(node_id)
    return Entity(id=node_id, name=n.name if n else node_id,
                  kind=n.kind.value if n else "?", evidence=evidence)


def _ents_by_principal(g: Graph, rows, *, list_key: str = "roles",
                       **shared_evidence) -> list[Entity]:
    """Collapse (principal, value) rows into ONE entity per principal.

    Rules that appended an entity per (principal, role) or per (principal, scope)
    listed the same person many times inside a single finding: a user holding 10 Tier-0
    roles appeared 10 times, and AZ-RBAC-002 emitted 35,796 entities for 46 principals
    (~7 MB of report payload). That inflated the user-facing affected-count and the
    score's entity factor while conveying no extra information - the *set* of roles is
    the fact, so aggregate it into evidence instead of repeating the principal.

    Rows are `(principal_id, value)` or `(principal_id, value, scope)`. When a scope is
    supplied its subscription is resolved to a NAME and accumulated into
    `evidence["subscriptions"]` - the key the report's "Affected subscriptions" section
    reads. Aggregating without it silently removed that mandatory section from every
    RBAC and Key Vault finding, because the per-assignment entities it used to come from
    no longer existed.
    """
    # Dedupe case-insensitively, keeping the first-seen spelling. AzureHound emits the
    # same ARM scope with inconsistent casing, so a raw set counted one assignment twice
    # ("UAA @ /SUBSCRIPTIONS/115E…" and "UAA @ /subscriptions/115e…" → count 2 for a
    # single grant), re-introducing the very inflation this helper exists to remove.
    grouped: dict[str, dict[str, str]] = {}
    subs: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for row in rows:
        pid, value = row[0], row[1]
        scope = row[2] if len(row) > 2 else None
        if pid not in grouped:
            grouped[pid] = {}
            subs[pid] = {}
            order.append(pid)
        if value:
            grouped[pid].setdefault(str(value).lower(), str(value))
        if scope:
            name = _subscription_for(g, scope)
            if name and name != "unknown":
                subs[pid].setdefault(str(name).lower(), str(name))
    out: list[Entity] = []
    for pid in order:
        values = sorted(grouped[pid].values())
        ev = dict(shared_evidence)
        ev[list_key] = values[:10]
        ev[f"{list_key.rstrip('s')}_count"] = len(values)
        if len(values) > 10:
            ev[f"{list_key}_withheld"] = len(values) - 10
        sub_names = sorted(subs[pid].values())
        if sub_names:
            ev["subscriptions"] = sub_names[:15]
            ev["subscription_count"] = len(sub_names)
        out.append(_ent(g, pid, **ev))
    return out


def _subscription_for(g: Graph, node_id: str) -> str:
    """Return the display name (or path) of the subscription containing a resource.

    Parses the subscription GUID from the ARM resource ID
    (/subscriptions/{guid}/...) and looks up the subscription node's name.
    Falls back to the path string when no matching node is found.
    """
    parts = node_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("subscriptions")
        sub_guid = parts[idx + 1]
    except (ValueError, IndexError):
        return "unknown"
    sub_path = f"/subscriptions/{sub_guid}"
    sub = g.node(sub_path) or g.node(sub_path.lower())
    if sub:
        return sub.name or sub_path
    for n in g.nodes_of_kind(NodeKind.SUBSCRIPTION):
        if n.id.lower() == sub_path.lower():
            return n.name or n.id
    return sub_path


def _effective_role_holders(g: Graph, predicate):
    """Yield (principal_node, role_node, evidence) for effective roles matching predicate."""
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL):
        for e in g.out_edges(p.id, EdgeType.EFFECTIVE_ROLE):
            role = g.node(e.dst)
            if role and predicate(role):
                yield p, role, e.evidence


def _rbac(g: Graph):
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            yield p, (e.evidence.get("role") or ""), (e.evidence.get("scope") or "")


def _is_tier0_role(role) -> bool:
    # AzureHound emits "templateId", not "roleTemplateId" - see derive._is_tier0_role.
    props = role.props or {}
    tpl = str(props.get("templateId") or props.get("roleTemplateId") or "").lower()
    return (tpl in C.TIER0_ENTRA_ROLE_TEMPLATES) or (role.name or "").lower() in C.TIER0_ENTRA_ROLE_NAMES


# =========================================================================== #
# Domain A - Privileged identity
# =========================================================================== #
@rule(id="AZ-IDENT-001", title="Excessive Global Administrators",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="More than the recommended number of accounts hold the Global Administrator role. Each GA is a full-tenant compromise target.",
      remediation="Reduce standing Global Admins to the minimum (Microsoft recommends no more than 5). Use PIM for just-in-time elevation and dedicated cloud-only admin accounts.",
      data_source=[NodeKind.ROLE], references=[MS],
      frameworks={"CIS Azure": "1.1", "MITRE ATT&CK": "T1098"})
def excessive_global_admins(g: Graph):
    holders = {p.id: p for p, r, _ in _effective_role_holders(
        g, lambda r: r.name.lower() == "global administrator")}
    # Threshold and prose must agree. The code fires above 5 (i.e. at 6+); the
    # remediation text and knowledge base now say "no more than 5" to match, rather
    # than "fewer than 5", which implied 5 itself was already a violation.
    if len(holders) > 5:
        return [_ent(g, pid, note="holds Global Administrator",
                     total_global_admins=len(holders)) for pid in holders]
    return []


@rule(id="AZ-IDENT-002", title="Insufficient Global Administrators (break-glass)",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="Fewer than two Global Administrators were observed. A single GA risks tenant lockout if that account is lost.",
      remediation="Maintain at least two emergency-access (break-glass) Global Admin accounts, cloud-only, excluded from CA, with stored credentials and monitoring.",
      data_source=[NodeKind.ROLE],
      references=["https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access"],
      frameworks={"CIS Azure": "1.3"})
def insufficient_global_admins(g: Graph):
    holders = {p.id for p, r, _ in _effective_role_holders(
        g, lambda r: r.name.lower() == "global administrator")}
    if 0 < len(holders) < 2:
        return [Entity(id="tenant", name=g.tenant_id or "tenant", kind="AZTenant",
                       evidence={"global_admin_count": len(holders)})]
    return []


@rule(id="AZ-IDENT-019", title="Recently-created account holds a Tier-0 role (possible backdoor admin)",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A user account created within the last 30 days already holds a Tier-0 directory "
                  "role. A brand-new account with tenant-level privilege is a classic persistence "
                  "move: an attacker who reaches an admin often provisions a fresh admin account to "
                  "retain access after the original foothold is remediated. Legitimate new admins do "
                  "exist, so this is an alert to corroborate against change tickets, not proof of "
                  "compromise.",
      remediation="Verify the account and its role assignment against an approved change/joiner "
                  "request. If unrecognised, disable it, revoke the role, and review recent "
                  "directory-role and account-creation audit logs for related activity.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1136.003"})
def recent_tier0_account(g: Graph):
    from datetime import datetime, timezone, timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    def _created(n):
        v = n.props.get("createdDateTime")
        if not isinstance(v, str):
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None

    out, seen = [], set()
    for p, role, _ in _effective_role_holders(g, _is_tier0_role):
        if p.id in seen or p.kind != NodeKind.USER:
            continue
        created = _created(p)
        if created and created >= cutoff:
            seen.add(p.id)
            out.append(_ent(g, p.id, created=p.props.get("createdDateTime"),
                            role=role.name,
                            note="Tier-0 account created within the last 30 days"))
    return out


@rule(id="AZ-IDENT-020", title="No cloud-only break-glass Global Administrator (all GAs are hybrid-synced)",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="Every human Global Administrator is a directory-synced (hybrid) account mastered in "
                  "on-premises Active Directory. There is no cloud-only Global Admin, so a compromise "
                  "of on-prem AD - or the AD Connect sync account - yields tenant-wide control with no "
                  "independent, cloud-only account to detect, contain or recover from it. Microsoft's "
                  "emergency-access guidance requires cloud-only break-glass GAs precisely so the "
                  "cloud does not inherit on-prem blast radius.",
      remediation="Create at least two cloud-only, non-synced emergency-access Global Admin accounts, "
                  "excluded from Conditional Access, with stored credentials and monitored sign-ins. "
                  "Keep on-prem-synced accounts out of the Global Administrator role.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      references=["https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access"],
      frameworks={"MITRE ATT&CK": "T1556.007"})
def no_cloud_only_global_admin(g: Graph):
    ga_users = {p.id: p for p, r, _ in _effective_role_holders(
        g, lambda r: (r.name or "").lower() == "global administrator")
        if p.kind == NodeKind.USER}
    if not ga_users:
        return []
    cloud_only = [p for p in ga_users.values() if "synced" not in p.tags]
    if cloud_only:
        return []                                   # at least one cloud-only GA exists - good
    return [Entity(id="tenant", name=g.tenant_id or "tenant", kind="AZTenant",
                   evidence={"global_admin_count": len(ga_users),
                             "all_hybrid_synced": True,
                             "cloud_only_global_admins": 0,
                             "note": "every Global Administrator is on-prem-synced - no cloud-only break-glass"})]


@rule(id="AZ-IDENT-003", title="Service principal holds a privileged Entra role",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A service principal (non-human identity) holds a Tier-0 directory role. SPs often carry static credentials and are weakly monitored.",
      remediation="Remove the directory role or scope it down. If automation truly needs directory privilege, isolate it, rotate credentials, and monitor sign-ins.",
      data_source=[NodeKind.SERVICE_PRINCIPAL, NodeKind.ROLE], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1098.003"})
def sp_with_privileged_role(g: Graph):
    return _ents_by_principal(g, [
        (p.id, role.name) for p, role, ev in _effective_role_holders(g, _is_tier0_role)
        if p.kind == NodeKind.SERVICE_PRINCIPAL
    ])


@rule(id="AZ-IDENT-004", title="Guest user holds a privileged Entra role",
      severity=Severity.CRITICAL, category=Category.GUEST,
      description="An external/guest identity holds a Tier-0 directory role, exposing tenant administration to an account governed by another organisation.",
      remediation="Remove the privileged role from the guest immediately. Convert to a managed internal account if the access is legitimate, and review guest invitation controls.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"CIS Azure": "1.4", "MITRE ATT&CK": "T1078.004"})
def guest_with_privileged_role(g: Graph):
    return _ents_by_principal(g, [
        (p.id, role.name) for p, role, ev in _effective_role_holders(g, _is_tier0_role)
        if "guest" in p.tags
    ])


@rule(id="AZ-IDENT-005", title="Privileged role held via group membership",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A principal holds a Tier-0 role transitively through (possibly nested) group membership. Such privilege is easily overlooked in manual review.",
      remediation="Audit role-assignable group membership. Prefer direct, PIM-managed assignments over group-conferred standing privilege.",
      data_source=[NodeKind.GROUP, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1098"})
def privilege_via_group(g: Graph):
    out = []
    for p, role, ev in _effective_role_holders(g, _is_tier0_role):
        path = ev.get("path") or []
        if any("member of" in s or "via" in s for s in path):
            out.append(_ent(g, p.id, role=role.name, path=path))
    return out


@rule(id="AZ-IDENT-006", title="Disabled user retains a privileged role",
      severity=Severity.MEDIUM, category=Category.HYGIENE,
      description="A disabled USER account still holds Tier-0 privilege - a directory role OR broad-scope Azure RBAC (Owner / User Access Administrator). Re-enablement (e.g. via account takeover) would restore full privilege. The disabled-service-principal equivalent is AZ-HYG-007.",
      remediation="Remove privileged roles/assignments from disabled accounts; complete the deprovisioning/offboarding process.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1098"})
def disabled_with_privilege(g: Graph):
    # Two planes: a disabled USER holding a Tier-0 DIRECTORY role, PLUS a disabled user that is
    # Tier-0 via broad-scope Azure RBAC (Owner / UAA). Scoping to directory roles alone missed
    # disabled subscription Owners entirely. Service principals are intentionally excluded here -
    # a disabled privileged SP is AZ-HYG-007's job, so the two rules don't double-report one SP.
    out, seen = [], set()
    for p, role, ev in _effective_role_holders(g, _is_tier0_role):
        if p.kind == NodeKind.USER and "disabled" in p.tags and p.id not in seen:
            seen.add(p.id)
            out.append(_ent(g, p.id, role=role.name))
    for n in g.nodes_of_kind(NodeKind.USER):
        if "disabled" in n.tags and "tier0" in n.tags and n.id not in seen:
            seen.add(n.id)
            out.append(_ent(g, n.id, via="broad-scope Azure RBAC (Owner / User Access Administrator)"))
    return out


@rule(id="AZ-IDENT-011", title="Enabled privileged account has never signed in",
      severity=Severity.MEDIUM, category=Category.HYGIENE,
      description="An ENABLED account holds a Tier-0 directory role but has no recorded sign-in activity. A dormant-but-enabled privileged account is a prime, low-visibility takeover target and is often a forgotten or backdoor admin - the disabled case is covered elsewhere; this is the more dangerous enabled one.",
      remediation="Remove the privileged role or disable the account. If it is an intentional break-glass account, exclude it by design and monitor it explicitly; if it is an automation identity, use a least-privilege service principal instead.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1078"},
      requires_props=['signInActivity'],
      )
def stale_enabled_privileged(g: Graph):
    out, seen = [], set()
    for p, role, ev in _effective_role_holders(g, _is_tier0_role):
        if p.id in seen or "disabled" in p.tags:
            continue
        sia = p.props.get("signInActivity")
        # Only fire when sign-in activity WAS collected (a dict) but shows no sign-in;
        # absent activity means "not collected", not "never signed in".
        if isinstance(sia, dict) and not (sia.get("lastSignInDateTime")
                                          or sia.get("lastNonInteractiveSignInDateTime")):
            seen.add(p.id)
            out.append(_ent(g, p.id, role=role.name,
                            note="enabled Tier-0 account with no recorded sign-in"))
    return out


@rule(id="AZ-IDENT-007", title="On-prem synced account holds a privileged role",
      severity=Severity.MEDIUM, category=Category.IDENTITY,
      description="A directory-synced (hybrid) account holds a Tier-0 role, extending on-prem compromise directly into cloud tenant administration.",
      remediation="Use cloud-only accounts for privileged Entra roles; do not assign Tier-0 roles to synchronised identities.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1078"})
def synced_with_privilege(g: Graph):
    return _ents_by_principal(g, [
        (p.id, role.name) for p, role, ev in _effective_role_holders(g, _is_tier0_role)
        if "synced" in p.tags
    ])


@rule(id="AZ-IDENT-016", title="Guest user holds an administrative Entra role (non-Tier-0)",
      severity=Severity.HIGH, category=Category.GUEST,
      description="An external (guest/B2B) user holds an Entra directory role that is administrative but below Tier-0 - e.g. Billing Administrator, User Administrator, Helpdesk Administrator. Every Entra directory role grants standing management capability, and an account whose credentials are governed by another organisation should not hold one. AZ-IDENT-004 covers the Tier-0 case; this covers the equally-real non-Tier-0 admin roles it does not.",
      remediation="Remove directory role assignments from guest accounts. If an external collaborator genuinely needs an administrative role, provision a cloud-only member account governed by this tenant instead, and prefer PIM just-in-time activation.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1078.004", "Best Practice": "External identity governance"})
def guest_with_nontier0_role(g: Graph):
    # Guests holding a Tier-0 role are AZ-IDENT-004 (Critical); this rule takes the
    # remainder - any other directory role a guest effectively holds.
    return _ents_by_principal(g, [
        (p.id, role.name)
        for p in g.nodes_of_kind(NodeKind.USER) if "guest" in p.tags
        for e in g.out_edges(p.id, EdgeType.EFFECTIVE_ROLE)
        for role in [g.node(e.dst)]
        if role and not _is_tier0_role(role)
    ])


@rule(id="AZ-IDENT-017", title="Excessive standing Tier-0 principals (Tier-0 sprawl)",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="An unusually large number of principals (users, groups and service principals) hold standing Tier-0 privilege. Each is a full-tenant compromise target, and a large standing Tier-0 population is unmanageable to review, widens the blast radius, and defeats least-privilege. Microsoft guidance is to keep standing privileged access to the minimum and use PIM for just-in-time elevation.",
      remediation="Inventory every Tier-0 principal and remove standing assignments that are not strictly required. Convert the rest to PIM-eligible (just-in-time) rather than permanent, and consolidate role-assignable groups.",
      data_source=[NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1098", "Best Practice": "Minimize standing privilege"})
def tier0_sprawl(g: Graph):
    _THRESHOLD = 25
    t0 = [n for n in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL)
          if "tier0" in n.tags]
    if len(t0) > _THRESHOLD:
        return [Entity(id="tenant", name=g.tenant_id or "tenant", kind="AZTenant",
                       evidence={"tier0_principal_count": len(t0),
                                 "recommended_ceiling": _THRESHOLD,
                                 "note": f"{len(t0)} standing Tier-0 principals - well above the "
                                         f"{_THRESHOLD} recommended for a reviewable, least-privilege estate"})]
    return []


# =========================================================================== #
# Domain B - Applications & service principals (crown jewels)
# =========================================================================== #
@rule(id="AZ-APP-001", title="Service principal can grant itself any Entra role",
      severity=Severity.CRITICAL, category=Category.APPLICATION,
      description="A service principal holds RoleManagement.ReadWrite.Directory (or equivalent) on Microsoft Graph, allowing it to assign itself Global Administrator - a direct tenant takeover primitive.",
      remediation="Remove the RoleManagement.ReadWrite.Directory app role. Replace with least-privilege scoped permissions and rotate the SP credentials.",
      data_source=[NodeKind.SERVICE_PRINCIPAL], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1098.003", "MS Threat Matrix": "Privilege Escalation"})
def sp_role_management_write(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in sp.tags:
            continue
        for ar in sp.props.get("_granted_app_roles", []) or []:
            if ar.get("value") in ("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All"):
                out.append(_ent(g, sp.id, appRole=ar.get("value"),
                                impact=C.DANGEROUS_GRAPH_APP_ROLES[ar["value"]]["impact"]))
    return out


# Dangerous Graph permissions that have their OWN dedicated rule: AZ-APP-002 is the catch-all
# for high-impact Graph permissions, so it must not also report the ones a more specific rule
# already covers, or the same SP surfaces twice. Every permission here reads the same
# `_granted_app_roles` data (directly, or via the can_weaken_controls tag) that AZ-APP-002 does,
# so excluding it never opens a coverage gap - whenever AZ-APP-002 would have caught it, the
# dedicated rule does. UserAuthenticationMethod.ReadWrite.All is deliberately NOT here: it is
# CanResetPassword (no can_weaken_controls tag) with no dedicated rule, so it stays with -002.
_APP002_COVERED_ELSEWHERE = frozenset({
    "RoleManagement.ReadWrite.Directory",           # AZ-APP-001 (CanGrantRole)
    "AppRoleAssignment.ReadWrite.All",              # AZ-APP-001 (CanGrantAppRole)
    "PrivilegedAccess.ReadWrite.AzureADGroup",      # AZ-APP-010
    "EntitlementManagement.ReadWrite.All",          # AZ-APP-011
    "Domain.ReadWrite.All",                         # AZ-APP-015
    # AZ-APP-014 (data-exfiltration Graph permissions)
    "Mail.ReadWrite.All", "Mail.Read.All", "Mail.Send",
    "Files.ReadWrite.All", "Sites.ReadWrite.All",
    "Chat.ReadWrite.All", "ChannelMessage.Read.All",
    # AZ-APP-009 (can-weaken-controls): every CanWeakenControls permission sets that tag
    "Policy.ReadWrite.ConditionalAccess", "Policy.ReadWrite.AuthenticationMethod",
    "RoleManagementPolicy.ReadWrite.Directory", "SecurityConfiguration.ReadWrite.All",
    "Policy.ReadWrite.PermissionGrant",
})


@rule(id="AZ-APP-002", title="Service principal holds dangerous Graph write permission",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal holds a high-impact Microsoft Graph application permission (e.g. Application.ReadWrite.All, Directory.ReadWrite.All) usable for privilege escalation or persistence. Permissions with a dedicated rule (PIM/entitlement group writes, data-exfiltration scopes, federation, security-control weakening) are reported there instead, not here.",
      remediation="Review and remove unneeded Graph application permissions; apply least privilege and require admin-consent governance for high-impact scopes.",
      data_source=[NodeKind.SERVICE_PRINCIPAL], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1098.003"})
def sp_dangerous_graph(g: Graph):
    seen: set[str] = set()
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in sp.tags or sp.id in seen:
            continue
        for ar in sp.props.get("_granted_app_roles", []) or []:
            v = ar.get("value")
            meta = C.DANGEROUS_GRAPH_APP_ROLES.get(v)
            if meta and meta["tier"] in ("high", "medium") and v not in _APP002_COVERED_ELSEWHERE:
                out.append(_ent(g, sp.id, appRole=v, impact=meta["impact"]))
                seen.add(sp.id)
                break  # one entity per SP; worst/first role is enough
    return out


@rule(id="AZ-APP-031", title="Application authenticates with a client secret instead of a certificate",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="An application/service principal has a password credential (client secret) and no "
                  "certificate credential. Microsoft and CIS recommend certificate-based credentials "
                  "for app authentication: client secrets are long, high-entropy bearer strings that "
                  "are easily copied into code, CI variables or config and leaked, with no proof of "
                  "possession. Certificates are harder to exfiltrate and support cleaner rotation.",
      remediation="Replace client secrets with certificate credentials (or a federated/workload "
                  "identity where possible). Register a certificate on the app, switch the client to "
                  "certificate auth, then remove the secret.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1552.001", "Best Practice": "Certificate over secret"})
def app_secret_not_certificate(g: Graph):
    out, seen = [], set()
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if n.id in seen or n.props.get("servicePrincipalType") == "ManagedIdentity":
            continue
        secrets = n.props.get("passwordCredentials") or []
        certs = n.props.get("keyCredentials") or []
        if secrets and not certs:
            seen.add(n.id)
            out.append(_ent(g, n.id, secret_count=len(secrets),
                            note="uses a client secret with no certificate credential"))
    return out


@rule(id="AZ-APP-003", title="Application owned by a non-privileged user (AddSecret escalation)",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A privileged application/service principal is owned by a non-Tier-0 principal. An owner can add credentials and authenticate as the SP, inheriting its privilege.",
      remediation="Restrict app/SP ownership to Tier-0 administrators. Remove unnecessary owners and review credential-add audit logs.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1098.001"})
def app_owned_by_nonpriv(g: Graph):
    # One entity per owning principal, aggregating the privileged SPs it can take over.
    rows: list[tuple[str, str]] = []
    for e in g.edges():
        if e.type != EdgeType.CAN_ADD_SECRET:
            continue
        owner = g.node(e.src)
        target = g.node(e.dst)
        if owner and target and "tier0" not in owner.tags:
            if ("dangerous_app_role" in target.tags or "tier0" in target.tags
                    or "privileged" in target.tags):
                rows.append((owner.id, target.name or target.id))
    return _ents_by_principal(
        g, rows, list_key="owns",
        reason="owner can add a credential and sign in as the service principal")


@rule(id="AZ-APP-004", title="Service principal credential is long-lived or non-expiring",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal/application has a password or certificate credential with no expiry or a very long lifetime. Stolen long-lived secrets enable durable, unauthenticated persistence.",
      remediation="Set short credential lifetimes, rotate regularly, prefer certificate or workload-identity federation over client secrets, and remove unused credentials.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"CIS Azure": "1.x", "MITRE ATT&CK": "T1078.004"})
def long_lived_credentials(g: Graph):
    # Azure's portal caps a client secret at 24 months, so any credential whose
    # validity window exceeds ~2 years was deliberately extended via API/script
    # and represents standing credential risk. Flag non-expiring, far-future
    # (>=2099), AND long-lived (>730-day) windows - the last class (e.g. a
    # 60-year secret with end-year <2099) previously slipped through silently.
    from datetime import datetime

    def _parse(v):
        if not isinstance(v, str):
            return None
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None

    out = []
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        creds = (n.props.get("passwordCredentials") or []) + (n.props.get("keyCredentials") or [])
        for cred in creds:
            end = cred.get("endDateTime") or cred.get("endDate")
            start = cred.get("startDateTime") or cred.get("startDate")
            note = None
            if end is None or (isinstance(end, str) and end[:4].isdigit() and int(end[:4]) >= 2099):
                note = "non-expiring or far-future credential"
            else:
                s, e = _parse(start), _parse(end)
                if s and e and (e - s).days > 730:
                    note = f"long-lived credential ({(e - s).days // 365}-year validity window)"
            if note:
                out.append(_ent(g, n.id, credentialKeyId=cred.get("keyId"),
                                endDateTime=end, startDateTime=start, note=note))
                break
    return out


@rule(id="AZ-APP-005", title="Privileged service principal with standing credentials",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal that is privileged (Tier-0 role or dangerous Graph permission) also has stored client credentials, creating a high-value, always-usable token source.",
      remediation="Replace static secrets with workload-identity federation/managed identity, minimise the SP's privilege, and monitor its sign-ins closely.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1078.004"})
def privileged_sp_with_creds(g: Graph):
    return [_ent(g, sp.id, note="privileged SP with stored credentials")
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if "has_credentials" in sp.tags and (sp.tags & {"tier0", "privileged", "dangerous_app_role"})]


@rule(id="AZ-APP-006", title="Multi-tenant application registration",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="An application is configured with a multi-tenant sign-in audience. This is sometimes required, but broadens the trust boundary and should be deliberate.",
      remediation="Confirm multi-tenant is required. If single-tenant suffices, set signInAudience to AzureADMyOrg. Restrict who can consent.",
      data_source=[NodeKind.APP],
      frameworks={"Best Practice": "App audience minimisation"})
def multi_tenant_app(g: Graph):
    out = []
    for app in g.nodes_of_kind(NodeKind.APP):
        aud = str(app.props.get("signInAudience", "")).lower()
        # Pure organisational multi-tenant only. Audiences that also admit personal
        # (consumer) Microsoft accounts are the stronger AZ-APP-030 case and are reported
        # there instead, so a single app is not flagged twice.
        if aud == "azureadmultipleorgs":
            out.append(_ent(g, app.id, signInAudience=app.props.get("signInAudience")))
    return out


@rule(id="AZ-APP-030", title="Application admits personal Microsoft (consumer) accounts",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="An application's sign-in audience includes personal Microsoft accounts "
                  "(signInAudience = AzureADandPersonalMicrosoftAccount or PersonalMicrosoftAccount). "
                  "Any consumer Microsoft account - Outlook.com, Hotmail, Xbox, Skype - can authenticate "
                  "to the app, not just the organisation's work/school identities. This trust boundary is "
                  "far wider than intended for most enterprise apps and is a common oversight.",
      remediation="Unless the app genuinely serves consumers, set signInAudience to AzureADMyOrg "
                  "(single tenant) or AzureADMultipleOrgs (organisational accounts only). Never use a "
                  "personal-account audience for an internal or privileged application.",
      data_source=[NodeKind.APP],
      frameworks={"MITRE ATT&CK": "T1199"})
def personal_msa_app(g: Graph):
    out = []
    for app in g.nodes_of_kind(NodeKind.APP):
        aud = str(app.props.get("signInAudience", "")).lower()
        if "personalmicrosoftaccount" in aud:            # matches the two consumer audiences
            out.append(_ent(g, app.id, signInAudience=app.props.get("signInAudience")))
    return out


# =========================================================================== #
# Domain C - Azure RBAC
# =========================================================================== #
@rule(id="AZ-RBAC-001", title="Owner role assigned at management-group scope",
      severity=Severity.CRITICAL, category=Category.RBAC,
      description="A principal holds the Owner role at management-group scope, granting full control (including role assignment) over all child subscriptions and resources.",
      remediation="Remove Owner at MG scope. Assign least-privilege roles at the narrowest scope and use PIM for any elevated access.",
      data_source=[NodeKind.MANAGEMENT_GROUP],
      frameworks={"CIS Azure": "1.23", "MITRE ATT&CK": "T1098"})
def owner_at_mg(g: Graph):
    # One entity per principal, aggregating the management groups they own.
    return _ents_by_principal(g, [
        (p.id, scope, scope) for p, role, scope in _rbac(g)
        if role.lower() == "owner"
        and scope.lower().startswith("/providers/microsoft.management/managementgroups")
    ], list_key="management_groups", role="Owner")


@rule(id="AZ-RBAC-002", title="User Access Administrator at broad scope (self-escalation)",
      severity=Severity.CRITICAL, category=Category.RBAC,
      description="A principal can write role assignments (User Access Administrator / RBAC Administrator / Owner) at subscription or management-group scope, allowing it to grant itself any role.",
      remediation="Remove the role-assignment-write capability at broad scope. Restrict to break-glass use under PIM with approval and alerting.",
      data_source=[NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Privilege Escalation"})
def uaa_broad_scope(g: Graph):
    # One entity per principal with its scope set aggregated. Per-assignment entities
    # produced 35,796 rows for 46 principals (~7 MB of report JSON).
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {scope}", scope) for p, role, scope in _rbac(g)
        if role.lower() in C.RBAC_ESCALATION_ROLES and C.is_at_broad_scope(scope)
    ], list_key="assignments")


@rule(id="AZ-RBAC-011", title="Custom RBAC role at broad scope (privilege not analysed)",
      severity=Severity.MEDIUM, category=Category.RBAC,
      description="A principal holds a CUSTOM Azure RBAC role at subscription or management-group scope. Custom roles are not in the built-in catalogue, so their actions - which may include Microsoft.Authorization/roleAssignments/write, a wildcard */action, or listKeys (full self-escalation) - are not analysed here. The role definition must be reviewed; the model reasons over built-in role names, not custom-role actions.",
      remediation="Review the custom role's Actions/DataActions. If it grants role-assignment write, wildcard actions, or key/secret access at broad scope, treat it as a privileged role, restrict its scope, and prefer a least-privilege built-in role.",
      data_source=[NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1098"})
def custom_role_broad_scope(g: Graph):
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {scope}", scope) for p, role, scope in _rbac(g)
        if role.lower().startswith("custom role") and C.is_at_broad_scope(scope)
    ], list_key="assignments")


@rule(id="AZ-RBAC-003", title="Owner/Contributor sprawl at subscription scope",
      severity=Severity.HIGH, category=Category.RBAC,
      description="Multiple principals hold Owner or Contributor at subscription scope. Broad standing control increases blast radius and the chance of compromise.",
      remediation="Reduce subscription-level Owner/Contributor assignments; delegate at resource-group scope and adopt PIM.",
      data_source=[NodeKind.SUBSCRIPTION],
      frameworks={"CIS Azure": "1.23"})
def rbac_sprawl(g: Graph):
    _ROLE_RANK = {"owner": 0, "contributor": 1}
    holders: dict[str, tuple[str, str]] = {}
    for p, role, scope in _rbac(g):
        if role.lower() in _ROLE_RANK and C.is_at_broad_scope(scope):
            existing = holders.get(p.id)
            if existing is None or _ROLE_RANK[role.lower()] < _ROLE_RANK[existing[0].lower()]:
                holders[p.id] = (role, scope)
    if len(holders) > 5:
        return [_ent(g, pid, role=holders[pid][0], scope=holders[pid][1]) for pid in holders]
    return []


@rule(id="AZ-RBAC-004", title="Guest principal holds an Azure RBAC role",
      severity=Severity.HIGH, category=Category.GUEST,
      description="An external/guest identity holds an Azure RBAC role, granting resource-plane access to an externally governed account.",
      remediation="Remove RBAC from guests unless contractually required; prefer internal managed identities and review guest access governance.",
      data_source=[NodeKind.USER, NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1078.004"})
def guest_rbac(g: Graph):
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {scope}", scope) for p, role, scope in _rbac(g) if "guest" in p.tags
    ], list_key="assignments")


@rule(id="AZ-RBAC-005", title="Service principal with Owner/Contributor at broad scope",
      severity=Severity.HIGH, category=Category.RBAC,
      description="A service principal holds Owner or Contributor at subscription/management-group scope. Combined with stored credentials this is a powerful, durable foothold.",
      remediation="Scope SP RBAC to the specific resources it manages; avoid subscription-wide Owner/Contributor for automation identities.",
      data_source=[NodeKind.SERVICE_PRINCIPAL, NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1098.003"})
def sp_broad_rbac(g: Graph):
    # See uaa_broad_scope: this emitted 22,180 entities for 47 service principals.
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {scope}", scope) for p, role, scope in _rbac(g)
        if p.kind == NodeKind.SERVICE_PRINCIPAL
        and role.lower() in C.RBAC_PRIVILEGED_ROLES and C.is_at_broad_scope(scope)
    ], list_key="assignments")


# =========================================================================== #
# Domain D - Groups & membership
# =========================================================================== #
@rule(id="AZ-GRP-001", title="Role-assignable group with dynamic membership",
      severity=Severity.HIGH, category=Category.GROUP,
      description="A group that can hold directory roles uses dynamic (rule-based) membership. Attribute manipulation could add an attacker to a privileged group automatically.",
      remediation="Do not combine dynamic membership with role-assignable groups. Use assigned membership for any group that confers privilege.",
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098"})
def role_group_dynamic(g: Graph):
    return [_ent(g, grp.id, note="role-assignable + dynamic membership")
            for grp in g.nodes_of_kind(NodeKind.GROUP)
            if {"role_assignable", "dynamic_membership"} <= grp.tags]


# AZ-GRP-002 (non-privileged owner of a privileged group) was removed in the V2 dedup: it fired
# on the exact same relation as AZ-GRP-003 (a non-Tier-0 principal with CAN_ADD_MEMBER into a
# privileged/Tier-0 group - the two rules computed an identical privileged-group set) and drove
# the same remediation, differing only in which endpoint it reported. AZ-GRP-003 is the survivor:
# it is correctly CRITICAL (a Tier-0-group escalation) and already records the adding principal in
# its evidence (joinable_by / adder_id), so no signal is lost.


# =========================================================================== #
# Domain E - Key Vault
# =========================================================================== #
@rule(id="AZ-KV-001", title="Principal can read secrets from multiple Key Vaults",
      severity=Severity.HIGH, category=Category.KEYVAULT,
      description="A single principal has secret get/list access across several Key Vaults, concentrating credential-theft impact if that principal is compromised.",
      remediation="Apply least-privilege Key Vault access per workload; prefer RBAC data-plane roles scoped to specific vaults and use separate identities.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001"})
def kv_broad_reader(g: Graph):
    reach = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_REACH_KV_SECRET:
            reach.setdefault(e.src, set()).add(e.dst)
    out = []
    for pid, vault_ids in reach.items():
        if len(vault_ids) < 2:
            continue
        subs: set[str] = set()
        vaults = []
        for vid in vault_ids:
            sub = _subscription_for(g, vid)
            subs.add(sub)
            vaults.append({"vault": g.display(vid), "subscription": sub})
        out.append(_ent(g, pid, vault_count=len(vault_ids), vaults=vaults,
                        subscriptions=sorted(subs)))
    return out


@rule(id="AZ-KV-002", title="Key Vault uses legacy access policies instead of RBAC",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="A Key Vault relies on the legacy access-policy model rather than Azure RBAC. RBAC offers finer granularity, central management and PIM integration.",
      remediation="Migrate the vault to the Azure RBAC permission model (enableRbacAuthorization=true) and remove legacy access policies.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"Best Practice": "Key Vault RBAC", "CIS Azure": "8.x"},
      requires_props=['enableRbacAuthorization'])
def kv_legacy_access_policy(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        props = kv.props.get("properties") or kv.props
        # Azure omits these flags when false rather than sending false, so `is False`
        # never matched and this rule could not fire at all. Measured on a real tenant:
        # enableRbacAuthorization was True on 497 vaults, ABSENT on 18, and False on 0 -
        # so the 18 vaults genuinely on the legacy access-policy model went unreported.
        rbac_auth = props.get("enableRbacAuthorization")
        if rbac_auth is not True:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            enableRbacAuthorization=rbac_auth if rbac_auth is not None else "not set",
                            confirmed=rbac_auth is False,
                            note="legacy access-policy model in use"
                                 if rbac_auth is False else
                                 "RBAC authorization not enabled (flag absent - Azure omits "
                                 "it when off, so the legacy access-policy model applies)"))
    return out


# =========================================================================== #
# Domain F - Managed identities & resources
# =========================================================================== #
@rule(id="AZ-MI-001", title="Resource managed identity has broad privilege (IMDS pivot)",
      severity=Severity.HIGH, category=Category.MANAGED_IDENTITY,
      description="A compute resource (VM, AKS, Automation, Function/Logic/Web App) has a managed identity holding Owner/Contributor at broad scope. Code execution on the resource yields that privilege via IMDS.",
      remediation="Scope managed-identity RBAC to the minimum required resources; never grant subscription-wide Owner/Contributor to a workload identity.",
      data_source=[NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION, NodeKind.FUNCTION_APP,
                   NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.VMSS],
      frameworks={"MITRE ATT&CK": "T1078.004", "MS Threat Matrix": "Credential Access"})
def mi_broad_privilege(g: Graph):
    # principalId -> resource(s)
    res_by_identity = {}
    for r in g.nodes_of_kind(NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION,
                             NodeKind.FUNCTION_APP, NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.VMSS):
        for e in g.out_edges(r.id, EdgeType.HAS_MANAGED_IDENTITY):
            res_by_identity.setdefault(e.dst, []).append(r)
    # One entity per affected RESOURCE, aggregating the identity's assignments.
    # Per-(assignment × resource) rows produced 1,973 entities for 7 resources.
    rows: list[tuple] = []
    identity_of: dict[str, str] = {}
    for p, role, scope in _rbac(g):
        # Use is_at_broad_scope, not a bare prefix test: every resource-group and
        # resource scope also starts with "/subscriptions", so the prefix check fired
        # on narrowly-scoped assignments and contradicted this rule's own title.
        if p.id in res_by_identity and role.lower() in C.RBAC_PRIVILEGED_ROLES \
                and C.is_at_broad_scope(scope):
            for res in res_by_identity[p.id]:
                # Resolve from the RESOURCE id, not the assignment scope: the affected
                # subscription is the one hosting the VM/Function/etc.
                rows.append((res.id, f"{role} @ {scope}", res.id))
                identity_of.setdefault(res.id, p.id)
    ents = _ents_by_principal(g, rows, list_key="assignments")
    for e in ents:
        e.evidence["identity"] = identity_of.get(e.id)
    return ents


# =========================================================================== #
# Domain G - Hygiene & best practices
# =========================================================================== #
@rule(id="AZ-HYG-001", title="High proportion of guest users",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="Guests make up a large share of the directory. Unmanaged external accounts expand the identity attack surface and should be governed.",
      remediation="Enable access reviews for guests, restrict guest invitation and external collaboration settings, and remove stale guest accounts.",
      data_source=[NodeKind.USER],
      frameworks={"Best Practice": "External collaboration governance"})
def high_guest_ratio(g: Graph):
    users = g.nodes_of_kind(NodeKind.USER)
    guests = [u for u in users if "guest" in u.tags]
    if users and len(guests) / len(users) > 0.25:
        return [Entity(id="tenant", name=g.tenant_id or "tenant", kind="AZTenant",
                       evidence={"guest_ratio": round(len(guests) / len(users), 2),
                                 "guests": len(guests), "users": len(users)})]
    return []


# A disabled SP carrying any of these tags is the privileged case owned by AZ-HYG-007 (and, for
# the Tier-0 subset, AZ-IDENT-006's user-only scope no longer overlaps). AZ-HYG-002 reports only
# the remaining lifecycle-hygiene case (a disabled SP with NO standing privilege), so the two do
# not both fire on the same principal.
_DISABLED_SP_PRIV_TAGS = frozenset({
    "tier0", "privileged", "dangerous_app_role", "can_escalate", "can_weaken_controls"})


@rule(id="AZ-HYG-002", title="Orphaned/disabled service principal",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="A disabled service principal with no standing privilege still exists in the tenant. Stale SPs add attack surface and review burden and should be cleaned up. A disabled SP that DOES retain privilege is the more serious AZ-HYG-007 instead.",
      remediation="Remove disabled or unused service principals after confirming they are no longer required.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"Best Practice": "Identity lifecycle"})
def stale_sp(g: Graph):
    # Skip the privileged disabled SPs - AZ-HYG-007 reports those, so -002 isn't a duplicate row.
    return [_ent(g, sp.id, note="disabled service principal present")
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if "disabled" in sp.tags and not (sp.tags & _DISABLED_SP_PRIV_TAGS)]


@rule(id="AZ-HYG-007", title="Disabled service principal still holds privileged authorization",
      severity=Severity.MEDIUM, category=Category.HYGIENE,
      description="A disabled service principal still carries privileged authorization - a Tier-0 "
                  "directory role, a dangerous Microsoft Graph app permission, or the ability to "
                  "self-escalate. Being disabled it cannot authenticate today, but the standing "
                  "grant remains: an owner (or an attacker who can re-enable it) flips accountEnabled "
                  "back on and instantly regains the privilege, with none of the review a fresh grant "
                  "would attract. Disabled principals are also routinely skipped in access reviews.",
      remediation="Remove the privileged role / Graph permissions from the service principal before "
                  "leaving it disabled, or delete the SP outright if it is no longer required. Do not "
                  "let a dormant principal retain standing tenant privilege.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.003"})
def disabled_privileged_sp(g: Graph):
    return [_ent(g, sp.id, note="disabled SP retains privileged authorization",
                 privilege=sorted(sp.tags & _DISABLED_SP_PRIV_TAGS))
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if "disabled" in sp.tags and (sp.tags & _DISABLED_SP_PRIV_TAGS)]


@rule(id="AZ-HYG-003", title="Privileged role assigned directly rather than via PIM",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="Tier-0 roles are held as permanent direct assignments. Standing privilege is a larger target than just-in-time elevation.",
      remediation="Adopt Privileged Identity Management (PIM) for eligible, time-bound, approval-gated Tier-0 access instead of permanent assignment.",
      data_source=[NodeKind.ROLE],
      frameworks={"Best Practice": "Just-in-time access", "CIS Azure": "1.x"})
def direct_privileged_assignment(g: Graph):
    return _ents_by_principal(g, [
        (p.id, role.name) for p, role, ev in _effective_role_holders(g, _is_tier0_role)
        if "direct assignment" in (ev.get("path") or []) and p.kind == NodeKind.USER
    ], note="permanent direct assignment")


# =========================================================================== #
# Domain H - Attack-path derived
# =========================================================================== #
@rule(id="AZ-PATH-001", title="Non-privileged principal can escalate to a Tier-0 role",
      severity=Severity.CRITICAL, category=Category.ATTACK_PATH,
      description="A principal that does not directly hold a Tier-0 role can reach one through a derived abuse primitive (group ownership, app ownership/AddSecret, or dangerous Graph permission).",
      remediation="Break the escalation: remove the ownership/permission enabling it. See the choke-point analysis for the highest-impact single fixes.",
      data_source=[NodeKind.SERVICE_PRINCIPAL, NodeKind.ROLE], references=[SPEC],
      frameworks={"MS Threat Matrix": "Privilege Escalation", "MITRE ATT&CK": "T1098"})
def path_to_tier0(g: Graph):
    seen: set[str] = set()
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "can_reach_tier0" in sp.tags and "tier0" not in sp.tags and sp.id not in seen:
            out.append(_ent(g, sp.id, via="dangerous Graph app role"))
            seen.add(sp.id)
    # principals who can add a secret to a Tier-0 SP
    for e in g.edges():
        if e.type == EdgeType.CAN_ADD_SECRET:
            tgt = g.node(e.dst)
            src = g.node(e.src)
            if tgt and src and ("tier0" in tgt.tags or "can_reach_tier0" in tgt.tags) \
                    and "tier0" not in src.tags and src.id not in seen:
                out.append(_ent(g, src.id, via=f"AddSecret on {tgt.name}", target_id=e.dst))
                seen.add(src.id)
    return out


# =========================================================================== #
# Domain I - Compute & resource-plane abuse
# =========================================================================== #
@rule(id="AZ-RBAC-006", title="Compute role enables managed-identity theft (run-command → IMDS)",
      severity=Severity.HIGH, category=Category.COMPUTE,
      description="A principal holds a compute-management RBAC role (VM/AKS/Automation/Web/Logic App Contributor, or broad Contributor/Owner) over a resource that has a managed identity. It can run code on the resource and steal the identity's token via IMDS, inheriting its privilege.",
      remediation="Scope compute-management roles to the minimum, separate workload identities from privileged ones, and restrict IMDS access inside workloads.",
      data_source=[NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION, NodeKind.FUNCTION_APP,
                   NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.VMSS], references=[SPEC],
      frameworks={"MS Threat Matrix": "Credential Access", "MITRE ATT&CK": "T1552.005"})
def compute_mi_theft(g: Graph):
    seen = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_STEAL_MANAGED_IDENTITY:
            mi = g.node(e.dst)
            if mi and e.src not in seen:
                seen[e.src] = _ent(g, e.src, steals_identity=mi.name,
                                   via_resource=e.evidence.get("via_resource"), role=e.evidence.get("role"))
    return list(seen.values())


@rule(id="AZ-PATH-002", title="Compute foothold escalates to Tier-0 via managed identity",
      severity=Severity.CRITICAL, category=Category.ATTACK_PATH,
      description="A non-privileged principal can run code on a resource whose managed identity is Tier-0, producing a full escalation from compute access to tenant/subscription control.",
      remediation="Remove the broad managed-identity privilege or the compute role enabling code execution; see the choke-point analysis.",
      data_source=[NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION], references=[SPEC],
      frameworks={"MS Threat Matrix": "Privilege Escalation", "MITRE ATT&CK": "T1078.004"})
def path_compute_tier0(g: Graph):
    out = []
    for e in g.edges():
        if e.type == EdgeType.CAN_STEAL_MANAGED_IDENTITY:
            mi = g.node(e.dst)
            src = g.node(e.src)
            if mi and src and "tier0" in mi.tags and "tier0" not in src.tags:
                out.append(_ent(g, e.src, via=f"managed identity {mi.name} on {e.evidence.get('via_resource')}"))
    return out


# Derived abuse edges that constitute a one-hop PRIVILEGE-escalation primitive (as opposed to
# data-plane reach). If a DISABLED principal holds one of these into a Tier-0 target, re-enabling
# the account is one Graph/ARM call away from Tier-0.
_ESCALATION_PRIMITIVES = {
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_OWNER, EdgeType.CAN_ADD_MEMBER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
    EdgeType.CAN_RESET_PASSWORD,
}


@rule(id="AZ-PATH-003", title="Disabled account retains a one-hop escalation primitive to Tier-0",
      severity=Severity.CRITICAL, category=Category.ATTACK_PATH,
      description="A DISABLED principal still holds a derived escalation primitive - add a credential "
                  "to a Tier-0 service principal (CanAddSecret), add itself to a Tier-0 group "
                  "(CanAddMember), take ownership (CanAddOwner), grant a role (CanGrantRole / "
                  "CanGrantAppRole), self-escalate RBAC (CanEscalateRBAC), or reset a Tier-0 "
                  "principal's password (CanResetPassword) - whose target is Tier-0. Being disabled it "
                  "cannot sign in today, but Azure/Entra does not strip these rights on disable: a "
                  "help-desk mistake, a stale on-prem sync that re-activates the account, or an insider "
                  "re-enabling it restores a single-hop path to Tier-0. Disabled identities are also "
                  "routinely skipped in access reviews, so this dormant path lingers unseen. Distinct "
                  "from AZ-HYG-005/006 (disabled account holds an RBAC role / owns an app) and "
                  "AZ-IDENT-006 (disabled holds a Tier-0 role directly): this is a disabled account "
                  "one abuse edge away from Tier-0.",
      remediation="Revoke the escalation primitive (remove the group-membership-management right, app "
                  "ownership, role-grant permission, or reset capability) before leaving the account "
                  "disabled - or delete the account. Do not rely on the disabled flag as a control.",
      data_source=[NodeKind.USER, NodeKind.SERVICE_PRINCIPAL, NodeKind.ROLE], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1078.004", "MS Threat Matrix": "Privilege Escalation"})
def disabled_one_hop_to_tier0(g: Graph):
    seen: dict[str, Entity] = {}
    for e in g.edges():
        if e.type not in _ESCALATION_PRIMITIVES:
            continue
        src = g.node(e.src)
        tgt = g.node(e.dst)
        if not src or not tgt or "disabled" not in src.tags:
            continue
        if not ("tier0" in tgt.tags or "can_reach_tier0" in tgt.tags):
            continue
        prim = e.type.value if hasattr(e.type, "value") else str(e.type)
        if e.src not in seen:
            seen[e.src] = _ent(g, e.src, via=prim, target=tgt.name, target_id=e.dst,
                               note="disabled account is one hop from Tier-0")
    return list(seen.values())


# =========================================================================== #
# Domain J - Authentication-admin & password reset
# =========================================================================== #
@rule(id="AZ-IDENT-008", title="Privileged Authentication Administrator can reset any password",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A principal holds Privileged Authentication Administrator, which can reset credentials and manage authentication methods for ANY account, including Global Administrators - a direct Tier-0 takeover path.",
      remediation="Remove the role or restrict it to PIM-eligible, approval-gated, audited use. Treat it as Tier-0.",
      data_source=[NodeKind.ROLE], references=[MS],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Persistence"})
def priv_auth_admin(g: Graph):
    seen = {}
    for p, role, _ in _effective_role_holders(g, lambda r: r.name.lower() == "privileged authentication administrator"):
        seen[p.id] = _ent(g, p.id, role=role.name)
    return list(seen.values())


@rule(id="AZ-IDENT-009", title="Password-reset-capable admin role assigned",
      severity=Severity.MEDIUM, category=Category.IDENTITY,
      description="A principal holds a role able to reset other users' passwords (Authentication / Helpdesk / Password / User Administrator). Depending on target tier, this enables account takeover and lateral movement.",
      remediation="Limit these roles, scope them with administrative units where possible, and use PIM.",
      data_source=[NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1098"})
def reset_capable_admins(g: Graph):
    names = {"authentication administrator", "helpdesk administrator",
             "password administrator", "user administrator"}
    seen = {}
    for p, role, _ in _effective_role_holders(g, lambda r: r.name.lower() in names):
        seen[p.id] = _ent(g, p.id, role=role.name)
    return list(seen.values())


@rule(id="AZ-IDENT-010", title="Principal is PIM-eligible for a Tier-0 role without holding it actively",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A principal is eligible to self-activate a Tier-0 directory role (e.g. Global Administrator) via Privilege Identity Management, but does not currently hold it as an active assignment. This is a 'shadow admin' path: the principal is invisible in an active-roles-only review, yet is one PIM activation away from Tier-0. AzureHound's active-role-assignment data alone would miss this entirely.",
      remediation="Review whether this eligibility is required. If it is, confirm the PIM activation policy enforces MFA and (ideally) approval, and that activations are alerted on. Remove eligibility that isn't operationally necessary.",
      data_source=[NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1078.004"})
def pim_eligible_shadow_admins(g: Graph):
    return [_ent(g, n.id) for n in g.nodes() if "tier0_eligible" in n.tags]


@rule(id="AZ-APP-007", title="Application / Cloud Application Administrator can add credentials to any app",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A principal holds Application or Cloud Application Administrator, which can add credentials to ANY application or service principal (not only owned ones), allowing authentication as the most-privileged SP in the tenant.",
      remediation="Remove the role or restrict via PIM. Monitor credential additions across all applications.",
      data_source=[NodeKind.ROLE, NodeKind.SERVICE_PRINCIPAL], references=[SPEC],
      frameworks={"MITRE ATT&CK": "T1098.001", "MS Threat Matrix": "Privilege Escalation"})
def app_admin_any_app(g: Graph):
    names = {"application administrator", "cloud application administrator"}
    seen = {}
    for p, role, _ in _effective_role_holders(g, lambda r: r.name.lower() in names):
        seen[p.id] = _ent(g, p.id, role=role.name)
    return list(seen.values())


# =========================================================================== #
# Domain K - Key Vault management-plane & storage
# =========================================================================== #
@rule(id="AZ-KV-003", title="Key Vault management-plane access can expose secrets",
      severity=Severity.HIGH, category=Category.KEYVAULT,
      description="A principal holds Key Vault Contributor / Administrator over a vault. Management-plane control lets the holder change access policies or RBAC to grant itself data-plane access and read the secrets.",
      remediation="Separate management-plane and data-plane roles; avoid Key Vault Contributor for principals that should not read secrets, and enable purge protection + RBAC.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001"})
def kv_management_access(g: Graph):
    # One entity per principal. Per-assignment rows produced 8,414 entities for 116
    # principals (72x) and never told the reader how many vaults were involved.
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {_subscription_for(g, scope) if scope else 'unknown'}", scope)
        for p, role, scope in _rbac(g)
        if role.lower() in ("key vault contributor", "key vault administrator")
    ], list_key="assignments")


@rule(id="AZ-KV-012", title="Key Vault is readable by an unusually large number of principals",
      severity=Severity.MEDIUM, category=Category.KEYVAULT,
      description="A single Key Vault grants data-plane access (secrets/keys/certificates) directly to "
                  "a large number of distinct principals via access policies. A broad accessor list - "
                  "common under the legacy access-policy model, where grants are coarse (get/list/all) "
                  "and vault-wide rather than per-secret - means every one of those identities can read "
                  "every secret in the vault. The vault becomes a high-value, low-effort target: "
                  "compromising ANY one of the accessors yields the whole secret inventory, and the "
                  "large surface makes least-privilege review impractical.",
      remediation="Reduce the accessor list to the minimum. Migrate the vault to the Azure RBAC "
                  "authorization model and grant scoped data-plane roles (Key Vault Secrets User on "
                  "specific secrets) instead of vault-wide access policies; split high-fan-out secrets "
                  "into separate vaults per workload.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001"})
def kv_broad_accessors(g: Graph):
    THRESHOLD = 20                                   # distinct principals with a direct access policy
    accessors: dict[str, set[str]] = {}
    for e in g.edges():
        if e.type == EdgeType.KV_ACCESS:
            accessors.setdefault(e.dst, set()).add(e.src)
    out = []
    for vault_id, principals in accessors.items():
        if len(principals) >= THRESHOLD:
            out.append(_ent(g, vault_id, subscription=_subscription_for(g, vault_id),
                            accessor_count=len(principals),
                            note=f"{len(principals)} principals hold a direct Key Vault access policy"))
    return out


@rule(id="AZ-STOR-001", title="Storage account allows anonymous public blob access",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="A storage account permits anonymous (unauthenticated) public access to blob data. Misconfigured containers then expose data directly to the internet.",
      remediation="Set allowBlobPublicAccess=false at the account, audit container public-access levels, and prefer SAS / RBAC data-plane access.",
      data_source=[NodeKind.STORAGE],
      frameworks={"CIS Azure": "3.x", "MITRE ATT&CK": "T1530"},
      requires_props=['allowBlobPublicAccess'])
def storage_public_access(g: Graph):
    return [_ent(g, s.id, subscription=_subscription_for(g, s.id),
                 note="anonymous blob access enabled")
            for s in g.nodes_of_kind(NodeKind.STORAGE)
            if ((s.props.get("properties") or s.props).get("allowBlobPublicAccess") is True
                or s.props.get("allowBlobPublicAccess") is True)]


@rule(id="AZ-HYG-004", title="Application without an assigned owner",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="An application registration has no owner. Orphaned apps lack accountability for their credentials and permissions and are easily forgotten during reviews.",
      remediation="Assign at least one accountable owner to every application, or remove the app if unused.",
      data_source=[NodeKind.APP],
      frameworks={"Best Practice": "Application ownership"})
def orphaned_app(g: Graph):
    return [_ent(g, app.id, note="no owner assigned")
            for app in g.nodes_of_kind(NodeKind.APP) if not g.in_edges(app.id, EdgeType.OWNS)]


# =========================================================================== #
# Domain L - Application credential & control-plane surface
# =========================================================================== #
@rule(id="AZ-APP-008", title="Privileged application/SP has a federated identity credential",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A privileged application or service principal is configured with a federated identity credential (workload identity federation). Anyone controlling the trusted external issuer/subject can obtain tokens as this identity with no stored secret to rotate or detect.",
      remediation="Review every federated credential's issuer and subject. Remove unexpected federations and constrain the subject/audience tightly.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.001"})
def federated_credential(g: Graph):
    _CI = ("githubusercontent", "token.actions.github", "gitlab", "bitbucket", "terraform")
    out = []
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if "has_federated_credential" in n.tags and (n.tags & {"tier0", "privileged", "can_reach_tier0", "dangerous_app_role"}):
            issuers = sorted({str(f.get("issuer") or "") for f in
                              (n.props.get("federatedIdentityCredentials") or []) if f.get("issuer")})
            ci = [i for i in issuers if any(k in i.lower() for k in _CI)]
            note = "federated identity credential on a privileged identity"
            if ci:
                note += (" - trusts an external CI/OIDC issuer, so anyone who can push to (or open a "
                         "PR against) the trusted repo/pipeline can mint a token as this privileged identity")
            out.append(_ent(g, n.id, issuers=issuers[:5], trusts_ci=bool(ci), note=note))
    return out


@rule(id="AZ-APP-009", title="Service principal can weaken tenant security controls",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal holds a Microsoft Graph permission able to modify Conditional Access or authentication-method policy (e.g. Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.AuthenticationMethod, UserAuthenticationMethod.ReadWrite.All). It can disable MFA or access controls tenant-wide, enabling or masking other attacks.",
      remediation="Remove the permission unless essential; if required, isolate it on a tightly-governed SP and alert on CA/auth-method policy changes.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1556", "MS Threat Matrix": "Defense Evasion"})
def control_weakening_sp(g: Graph):
    return [_ent(g, sp.id, note="can modify Conditional Access / authentication-method policy")
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL) if "can_weaken_controls" in sp.tags]


# =========================================================================== #
# Domain M - Storage & Key Vault data-plane
# =========================================================================== #
@rule(id="AZ-STOR-002", title="Storage account keys retrievable via RBAC (listKeys)",
      severity=Severity.HIGH, category=Category.STORAGE,
      description="A principal can list a storage account's access keys (Storage Account Contributor / Key Operator / Contributor / Owner). Account keys grant full, shared, audit-poor access to all data in the account and bypass per-identity RBAC.",
      remediation="Disable shared-key access where possible, prefer Entra (RBAC) data-plane roles, and restrict who holds listKeys-capable roles.",
      data_source=[NodeKind.STORAGE],
      frameworks={"MITRE ATT&CK": "T1552.001", "CIS Azure": "3.x"})
def storage_key_access(g: Graph):
    seen = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_GET_STORAGE_KEY and e.src not in seen:
            acct = g.node(e.dst)
            seen[e.src] = _ent(g, e.src, account=acct.name if acct else e.dst,
                                subscription=_subscription_for(g, e.dst),
                                role=e.evidence.get("role"))
    return list(seen.values())


@rule(id="AZ-KV-004", title="Key Vault grants cryptographic key operations (sign/decrypt)",
      severity=Severity.MEDIUM, category=Category.KEYVAULT,
      description="A principal holds Key Vault key permissions enabling cryptographic operations (sign, decrypt, unwrapKey, wrapKey). Even without exporting the key, the holder can use it - forging signatures or decrypting protected data.",
      remediation="Restrict key operation permissions to the specific services that need them; separate sign/decrypt from management permissions.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001"})
def kv_crypto_ops(g: Graph):
    out, sensitive = [], {"sign", "decrypt", "unwrapkey", "wrapkey", "all"}
    for e in g.edges():
        if e.type == EdgeType.KV_ACCESS:
            keys = {str(x).lower() for x in ((e.evidence.get("permissions") or {}).get("keys") or [])}
            if keys & sensitive:
                out.append(_ent(g, e.src, vault=g.display(e.dst),
                                subscription=_subscription_for(g, e.dst),
                                key_permissions=sorted(keys)))
    return out


@rule(id="AZ-KV-005", title="Key Vault has purge protection or soft-delete disabled",
      severity=Severity.LOW, category=Category.BEST_PRACTICE, best_practice=True,
      description="A Key Vault does not have purge protection (and/or soft delete) enabled, so an attacker or mistake can permanently destroy secrets, keys and certificates, causing irrecoverable loss.",
      remediation="Enable soft delete and purge protection on all key vaults.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"CIS Azure": "8.x", "Best Practice": "Key Vault recoverability"},
      requires_props=['enablePurgeProtection', 'enableSoftDelete'])
def kv_purge_protection(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        props = kv.props or {}
        p = props.get("properties") or props
        # enablePurgeProtection is omitted when off (measured: 371 True, 144 ABSENT,
        # 0 False), so `is False` never fired and 144 vaults with no purge protection
        # were silently passed. enableSoftDelete IS always present, so it stays strict.
        purge = p.get("enablePurgeProtection")
        soft = p.get("enableSoftDelete")
        if purge is not True or soft is False:
            reasons = []
            if soft is False:
                reasons.append("soft delete disabled")
            if purge is False:
                reasons.append("purge protection disabled")
            elif purge is None:
                reasons.append("purge protection not enabled (flag absent - Azure omits it when off)")
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            enablePurgeProtection=purge if purge is not None else "not set",
                            enableSoftDelete=soft,
                            confirmed=(soft is False or purge is False),
                            note="; ".join(reasons)))
    return out


# =========================================================================== #
# Domain N - Resource-plane credential access
# =========================================================================== #
@rule(id="AZ-RBAC-007", title="AKS cluster-admin credentials retrievable via RBAC",
      severity=Severity.HIGH, category=Category.COMPUTE,
      description="A principal can pull cluster-admin credentials for an AKS cluster (listClusterAdminCredential) or holds a cluster-admin role, granting full Kubernetes control - workload tampering, secret theft, and managed-identity abuse on the nodes.",
      remediation="Disable local accounts on AKS and use Entra/Kubernetes RBAC, restrict the listClusterAdminCredential-capable roles, and scope assignments tightly.",
      data_source=[NodeKind.AKS],
      frameworks={"MS Threat Matrix": "Lateral Movement", "MITRE ATT&CK": "T1552.005"})
def aks_cluster_cred(g: Graph):
    seen = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_EXEC_AKS and e.src not in seen:
            cl = g.node(e.dst)
            seen[e.src] = _ent(g, e.src, cluster=cl.name if cl else e.dst, role=e.evidence.get("role"))
    return list(seen.values())


@rule(id="AZ-STOR-003", title="Principal has direct Storage Blob Data access (Entra data-plane role)",
      severity=Severity.HIGH, category=Category.STORAGE,
      description="A principal holds Storage Blob Data Owner, Contributor, or Reader on a storage account. Unlike the listKeys path, this grants named-identity Entra token access to all blob data - a quieter exfiltration path that bypasses shared-key monitoring and requires no key rotation to exploit.",
      remediation="Review whether this level of blob access is required. Prefer tightly scoped container-level RBAC over account-level data roles. Enable storage diagnostic logs for blob operations.",
      data_source=[NodeKind.STORAGE],
      frameworks={"MITRE ATT&CK": "T1530", "CIS Azure": "3.x"})
def storage_blob_direct_access(g: Graph):
    seen = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_READ_STORAGE_BLOB and e.src not in seen:
            acct = g.node(e.dst)
            seen[e.src] = _ent(g, e.src, account=acct.name if acct else e.dst,
                                subscription=_subscription_for(g, e.dst),
                                role=e.evidence.get("role"))
    return list(seen.values())


@rule(id="AZ-RBAC-009", title="Principal can push images to an Azure Container Registry (supply-chain risk)",
      severity=Severity.HIGH, category=Category.RBAC,
      description="A principal holds AcrPush, Contributor, or Owner on a container registry. An attacker can push a malicious container image that is subsequently pulled by production workloads, achieving persistent code execution across any consumer of the registry.",
      remediation="Restrict push access to trusted CI/CD service principals only. Enable Azure Defender for Container Registries, require image signing (Notary), and limit production workloads to pull-only access.",
      data_source=[NodeKind.CONTAINER_REGISTRY],
      frameworks={"MITRE ATT&CK": "T1525", "MS Threat Matrix": "Initial Access"})
def container_push_access(g: Graph):
    seen = {}
    for e in g.edges():
        if e.type == EdgeType.CAN_PUSH_CONTAINER and e.src not in seen:
            reg = g.node(e.dst)
            seen[e.src] = _ent(g, e.src, registry=reg.name if reg else e.dst,
                                role=e.evidence.get("role"))
    return list(seen.values())


@rule(id="AZ-RBAC-015",
      title="Container registry is pushable by many principals (broad supply-chain surface)",
      severity=Severity.MEDIUM, category=Category.COMPUTE,
      description=(
          "A single Azure Container Registry can have images pushed to it by a large number of "
          "distinct principals. Any one of them can poison an image that downstream workloads "
          "(AKS clusters, App Services, functions) pull and execute - so the registry is a shared "
          "supply-chain chokepoint whose effective trust boundary is the UNION of everyone who can "
          "push. AZ-RBAC-009 flags each pusher individually; this names the registry itself as the "
          "concentrated risk and quantifies how many principals must be trusted, which is the "
          "actionable supply-chain view (lock down the registry, not chase 200 principals)."
      ),
      remediation=(
          "Restrict AcrPush / Contributor on the registry to a minimal set of CI/CD identities. Use "
          "per-pipeline tokens or dedicated push identities, enable content trust / image signing, "
          "and separate build registries from the registries production pulls from."
      ),
      data_source=[NodeKind.CONTAINER_REGISTRY],
      frameworks={"MITRE ATT&CK": "T1610", "Best Practice": "Supply-chain integrity"})
def registry_broad_push(g: Graph):
    from collections import defaultdict
    _THRESHOLD = 10
    pushers: dict[str, set] = defaultdict(set)
    for e in g.edges():
        if e.type == EdgeType.CAN_PUSH_CONTAINER:
            pushers[e.dst].add(e.src)
    out = []
    for rid, srcs in pushers.items():
        if len(srcs) >= _THRESHOLD:
            out.append(_ent(g, rid, subscription=_subscription_for(g, rid),
                            distinct_pushers=len(srcs),
                            note=(f"{len(srcs)} distinct principals can push images to this "
                                  f"registry - any one can poison what downstream workloads pull")))
    out.sort(key=lambda e: -(e.evidence.get("distinct_pushers") or 0))
    return out


@rule(id="AZ-APP-010", title="Service principal can activate Tier-0 group memberships via PIM",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal holds PrivilegedAccess.ReadWrite.AzureADGroup, which enables managing PIM eligible and active assignments for Entra groups. It can activate a group membership for any principal into a group that holds a Tier-0 role - achieving full privilege escalation without directly touching directory role assignments.",
      remediation="Remove this permission unless the SP is a dedicated PIM governance tool. If required, scope it tightly and alert on all group PIM activation events generated by this SP.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Privilege Escalation"})
def sp_pim_group_write(g: Graph):
    perm = "PrivilegedAccess.ReadWrite.AzureADGroup"
    return [_ent(g, sp.id, permission=perm)
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if any(r.get("value") == perm for r in (sp.props.get("_granted_app_roles") or []))]


@rule(id="AZ-APP-011", title="Service principal can add users to any group via Entitlement Management",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal holds EntitlementManagement.ReadWrite.All, which enables managing access packages and directly adding any user to any group - including Tier-0 role-assignable groups. This is a shadow path to Tier-0 that bypasses direct role assignment auditing.",
      remediation="Remove this permission unless it belongs to a dedicated identity governance SP. Monitor all access package assignments and group additions made by this SP via the Entra audit log.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Privilege Escalation"})
def sp_entitlement_management(g: Graph):
    perm = "EntitlementManagement.ReadWrite.All"
    return [_ent(g, sp.id, permission=perm)
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if any(r.get("value") == perm for r in (sp.props.get("_granted_app_roles") or []))]


@rule(id="AZ-RBAC-010", title="Principal can execute code directly on a VM",
      severity=Severity.HIGH, category=Category.COMPUTE,
      description="A principal holds Owner, VM Contributor, or Virtual Machine Administrator Login directly on a virtual machine, enabling run-command, password reset, and credential theft. Even VMs without a managed identity are a lateral-movement foothold.",
      remediation="Scope compute-management roles to the minimum. Prefer break-glass assignments under PIM; remove standing VM Owner/Contributor from non-automation principals.",
      data_source=[NodeKind.VM],
      frameworks={"MITRE ATT&CK": "T1021.006", "MS Threat Matrix": "Lateral Movement"})
def vm_direct_execution(g: Graph):
    vm_exec_roles = {
        "owner", "contributor", "virtual machine contributor",
        "virtual machine administrator login", "virtual machine user login",
    }
    # One entity per principal, aggregating the VMs it can execute on. Keying on
    # (principal, scope) still produced one row per VM for the same person.
    return _ents_by_principal(g, [
        (p.id, f"{role} @ {scope}", scope) for p, role, scope in _rbac(g)
        if role.lower() in vm_exec_roles
        and scope and "microsoft.compute/virtualmachines" in scope.lower()
    ], list_key="vm_assignments")


@rule(id="AZ-GRP-003", title="Tier-0 group can have members added by non-privileged principals",
      severity=Severity.CRITICAL, category=Category.GROUP,
      description="A group that holds a Tier-0 Entra role or is tagged Tier-0 can have members added by principals that are not themselves Tier-0 (via group ownership, Group.ReadWrite.All, Directory.ReadWrite.All, etc.). Any of those principals can add themselves or a puppet account to the group and inherit Tier-0 privilege.",
      remediation="Restrict all CAN_ADD_MEMBER paths to Tier-0 groups to Tier-0 administrators only. Remove broad Group.ReadWrite.All / Directory.ReadWrite.All grants from non-Tier-0 SPs.",
      data_source=[NodeKind.GROUP, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Privilege Escalation"})
def priv_group_joinable(g: Graph):
    tier0_groups: set[str] = set()
    for grp in g.nodes_of_kind(NodeKind.GROUP):
        if "tier0" in grp.tags:
            tier0_groups.add(grp.id)
        for e in g.out_edges(grp.id, EdgeType.HAS_ENTRA_ROLE):
            role = g.node(e.dst)
            if role and _is_tier0_role(role):
                tier0_groups.add(grp.id)
    out = []
    seen: set[str] = set()
    for e in g.edges():
        if e.type == EdgeType.CAN_ADD_MEMBER and e.dst in tier0_groups and e.dst not in seen:
            adder = g.node(e.src)
            if adder and "tier0" not in adder.tags:
                out.append(_ent(g, e.dst, joinable_by=adder.name, adder_id=e.src,
                                note="non-privileged principal can add members to this Tier-0 group"))
                seen.add(e.dst)
    return out


@rule(id="AZ-HYG-005", title="Disabled user still holds Azure RBAC role assignments",
      severity=Severity.MEDIUM, category=Category.HYGIENE,
      description="A disabled user account retains Azure RBAC role assignments. If re-enabled (account takeover or admin error) the user immediately regains resource-plane access.",
      remediation="Remove all RBAC assignments from disabled accounts as part of the offboarding process.",
      data_source=[NodeKind.USER, NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1098", "CIS Azure": "1.x"})
def disabled_user_rbac(g: Graph):
    out = []
    for p, role, scope in _rbac(g):
        if p.kind == NodeKind.USER and "disabled" in p.tags:
            out.append(_ent(g, p.id, role=role, scope=scope))
    return out


@rule(id="AZ-STOR-004", title="Storage account has shared-key access enabled",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="The storage account allows authentication with the account-level shared key (allowSharedKeyAccess is not disabled). Shared keys bypass Entra identity and RBAC controls, grant full data-plane access, cannot be revoked per-user, and are often hardcoded in application config - a single key leak exposes all storage data.",
      remediation="Set allowSharedKeyAccess=false on all storage accounts and migrate applications to use Entra-based authentication (managed identity or service principal RBAC).",
      data_source=[NodeKind.STORAGE],
      requires_props=['allowSharedKeyAccess'],
      frameworks={"CIS Azure": "3.x", "MITRE ATT&CK": "T1552.001"})
def storage_shared_key_access(g: Graph):
    # Only a COLLECTED allowSharedKeyAccess=true is a finding. When the property was not
    # collected the rule is reported not-assessed (requires_props gate), never as a per-
    # account UNCONFIRMED finding - otherwise an AzureHound-only scan emitted one row per
    # storage account (309 here) for a control it never actually saw.
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        if (s.props.get("properties") or s.props).get("allowSharedKeyAccess") is True:
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            allowSharedKeyAccess=True, confirmed=True,
                            note="shared-key access explicitly enabled"))
    return out


@rule(id="AZ-KV-006", title="Key Vault network access not restricted",
      severity=Severity.MEDIUM, category=Category.KEYVAULT,
      description="A Key Vault has its network ACL default action set to Allow (or no firewall configured). Any host on the internet can reach the management and data-plane endpoints - while auth is still required, it removes network-layer defence-in-depth and enables unauthenticated enumeration attacks.",
      remediation="Set the Key Vault firewall defaultAction to Deny, restrict to specific VNets/IP ranges, and enable Private Endpoints for sensitive workloads.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"CIS Azure": "8.x", "Best Practice": "Network restriction"})
def kv_network_open(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        props = kv.props.get("properties") or kv.props
        # Distinguish "networkAcls key absent from the collection" from "key present but
        # empty". `props.get("networkAcls") or {}` collapsed both into one branch, which
        # made an EMPTY-but-present ACL - meaning no firewall rules exist, i.e. the vault
        # genuinely accepts all networks - get labelled UNCONFIRMED. On a real tenant that
        # was 320 of 515 vaults told "verify first" when the collection already proved
        # them open. Only a missing key is actually unconfirmed.
        has_acls_key = "networkAcls" in props
        acls = props.get("networkAcls") or {}
        raw_action = acls.get("defaultAction")
        if raw_action is not None and str(raw_action).lower() == "allow":
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            networkAcls_defaultAction=raw_action, confirmed=True,
                            note="defaultAction=Allow - vault reachable from any network"))
        elif has_acls_key and not acls:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            networkAcls_defaultAction="none configured", confirmed=True,
                            note="no firewall rules configured on the vault - open to all networks"))
        elif not has_acls_key:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            networkAcls_defaultAction="not collected", confirmed=False,
                            note="networkAcls absent from the collection; an unconfigured "
                                 "firewall defaults to Allow, so the vault is likely "
                                 "internet-reachable but this is UNCONFIRMED - verify first"))
    return out


@rule(id="AZ-APP-013", title="Application or service principal has excessive stored credentials",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="An application/service principal has three or four active password or certificate credentials. Multiple credentials on the same identity indicate credential sprawl, increase the chance that a forgotten/leaked secret exists, and create noise during incident response. AZ-APP-024 flags the more severe case of five or more.",
      remediation="Remove all credentials not actively in use. Prefer one active credential per SP, rotate on a schedule, and consider workload-identity federation to eliminate stored secrets entirely.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"Best Practice": "Credential minimisation"})
def excessive_sp_credentials(g: Graph):
    out = []
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in n.tags:
            continue  # you do not manage an external app's credentials
        creds = (n.props.get("passwordCredentials") or []) + (n.props.get("keyCredentials") or [])
        # 5+ is the more severe AZ-APP-024; keep 013 to the 3–4 band so they don't double-report.
        if 3 <= len(creds) < 5:
            out.append(_ent(g, n.id, credential_count=len(creds),
                            note=f"{len(creds)} active credentials on one identity"))
    return out


@rule(id="AZ-APP-014", title="Service principal holds data-exfiltration Graph permissions (Mail/Files/Sites/Teams)",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal holds Microsoft Graph application permissions that enable mass data exfiltration: Mail.ReadWrite.All / Mail.Read.All / Mail.Send / Files.ReadWrite.All / Sites.ReadWrite.All / Chat.ReadWrite.All / ChannelMessage.Read.All. A compromised SP with any of these can silently copy, delete or forge communications and files across the entire organisation without user interaction.",
      remediation="Remove any data-access permission not demonstrably required by the application. Prefer delegated (user-consented) permissions over application permissions and scope to individual mailboxes where possible.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1114.002", "MS Threat Matrix": "Collection"})
def sp_data_exfiltration_perms(g: Graph):
    _EXFIL = {
        "Mail.ReadWrite.All", "Mail.Read.All", "Mail.Send",
        "Files.ReadWrite.All", "Sites.ReadWrite.All",
        "Chat.ReadWrite.All", "ChannelMessage.Read.All",
    }
    seen: set[str] = set()
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if sp.id in seen:
            continue
        for ar in sp.props.get("_granted_app_roles", []) or []:
            v = ar.get("value")
            if v in _EXFIL:
                out.append(_ent(g, sp.id, permission=v))
                seen.add(sp.id)
                break
    return out


@rule(id="AZ-APP-015", title="Service principal holds Domain.ReadWrite.All (tenant federation takeover)",
      severity=Severity.CRITICAL, category=Category.APPLICATION,
      description="A service principal holds Domain.ReadWrite.All on Microsoft Graph. This permission allows registering a new federated domain and configuring an attacker-controlled external identity provider as a SAML/OIDC issuer, after which the external IdP can issue valid tokens for any user in the tenant - a full tenant takeover without touching user credentials.",
      remediation="Remove Domain.ReadWrite.All unless this SP is a dedicated domain/federation management tool. Monitor domain configuration changes via the Entra audit log.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1484.002", "MS Threat Matrix": "Persistence"})
def sp_domain_write(g: Graph):
    perm = "Domain.ReadWrite.All"
    return [_ent(g, sp.id, permission=perm)
            for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)
            if any(r.get("value") == perm for r in (sp.props.get("_granted_app_roles") or []))]


@rule(id="AZ-APP-017",
      title="Service principal holds a dangerous delegated Graph permission (tenant-wide)",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description=(
          "A service principal has a high-impact DELEGATED Microsoft Graph permission "
          "(e.g. Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory) that was "
          "admin-consented for ALL users (consentType AllPrincipals). This is the "
          "illicit-consent-grant surface: when any admin uses the app, it can write to the "
          "directory or manage roles on their behalf - a persistence and escalation path "
          "that an application-permission-only view (AzureHound) does not see."
      ),
      remediation=(
          "Review the tenant-wide (admin) consent for this app. Revoke the delegated grant "
          "if unnecessary, scope consent to specific users/groups, and require admin review "
          "for high-impact delegated scopes. Audit oauth2PermissionGrants regularly."
      ),
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      requires_records=["AZOAuth2GrantDelegated"],
      frameworks={"MITRE ATT&CK": "T1528", "Best Practice": "Consent governance"})
def dangerous_delegated_grant(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in sp.tags:
            continue
        for gr in (sp.props.get("_delegated_grants") or []):
            scopes = {s.strip().lower() for s in (gr.get("scope") or "").split()}
            dangerous = scopes & C.DANGEROUS_DELEGATED_SCOPES
            tenant_wide = str(gr.get("consent_type") or "").lower() == "allprincipals"
            if dangerous and tenant_wide:
                out.append(_ent(g, sp.id, delegated_scopes=sorted(dangerous),
                                consent="tenant-wide (AllPrincipals)",
                                note="admin-consented dangerous delegated permission"))
                break
    return out


@rule(id="AZ-APP-023",
      title="Multi-tenant (external) app holds a tenant-wide dangerous delegated Graph permission",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="An application whose registration lives in ANOTHER tenant (a third-party SaaS or Microsoft-published multi-tenant app) has been admin-consented, for ALL users, to a high-impact delegated Microsoft Graph scope (e.g. Directory.ReadWrite.All, User.ReadWrite.All). Delegated tenant-wide consent lets the external app act with the signed-in user's directory privileges - so when a privileged user signs in, the external service can write to the directory on their behalf. AZ-APP-017 deliberately skips external apps (you cannot add a credential to one); this surfaces the consent-governance risk that skip leaves uncovered. Review each: a genuine third-party SaaS with Directory.ReadWrite.All is the illicit-consent-grant surface; a Microsoft first-party tool may be acceptable but should still be an explicit decision.",
      remediation="Review the tenant-wide admin consent for each external app. Revoke consent that is not required, scope it to specific users/groups instead of AllPrincipals, and establish an admin-consent review workflow so future high-impact delegated grants are governed.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1528", "Best Practice": "Consent governance"})
def foreign_dangerous_delegated_grant(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" not in sp.tags:
            continue  # tenant-owned apps are AZ-APP-017's job
        for gr in (sp.props.get("_delegated_grants") or []):
            scopes = {s.strip().lower() for s in (gr.get("scope") or "").split()}
            dangerous = scopes & C.DANGEROUS_DELEGATED_SCOPES
            tenant_wide = str(gr.get("consent_type") or "").lower() == "allprincipals"
            if dangerous and tenant_wide:
                out.append(_ent(g, sp.id, delegated_scopes=sorted(dangerous),
                                consent="tenant-wide (AllPrincipals)",
                                app_owner_tenant=sp.props.get("_owner_org"),
                                note="external/multi-tenant app with admin-consented dangerous delegated permission"))
                break
    return out


def _foreign_tenant_wide_data_scopes(sp) -> set[str]:
    """All lowercased Graph DATA scopes an external app holds tenant-wide, from BOTH
    consent mechanisms: delegated grants consented for AllPrincipals, AND application
    (app-only) permissions - which need no signed-in user and are therefore at least as
    powerful. e.g. app-only Mail.Read reads every mailbox with the app's own credential."""
    scopes: set[str] = set()
    for gr in (sp.props.get("_delegated_grants") or []):
        if str(gr.get("consent_type") or "").lower() == "allprincipals":
            scopes |= {s.strip().lower() for s in (gr.get("scope") or "").split()}
    scopes |= {str(r.get("value") or "").lower() for r in (sp.props.get("_granted_app_roles") or [])}
    return scopes


@rule(id="AZ-APP-025",
      title="External app has tenant-wide consent to bulk mailbox / file / site / chat data",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="An application registered in another tenant (third-party SaaS or a Microsoft multi-tenant app) has been admin-consented, for ALL users, to a high-impact Microsoft Graph DATA scope - reading or writing every user's mailbox (Mail.Read/ReadWrite), files (Files.*.All), SharePoint sites (Sites.*.All) or Teams chat (Chat.*) - via delegated AllPrincipals consent and/or an application (app-only) permission. This is the mass-data-exposure/exfiltration surface, distinct from directory escalation (AZ-APP-023): the external service can read or exfiltrate that content across the whole organisation, and an app-only permission needs no signed-in user at all. Low-risk ubiquitous integrations (calendar sync, contacts, mail-send) are deliberately excluded to keep this precise.",
      remediation="Review each external app's tenant-wide consent to bulk-data scopes (both delegated AllPrincipals grants and application permissions). Revoke what is not required, scope delegated consent to specific users/groups instead of AllPrincipals, and require admin-consent review for data-plane Graph scopes. Prioritise apps that can read all mail, files or chat.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1114", "Best Practice": "Consent governance"})
def foreign_bulk_data_delegated_grant(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" not in sp.tags:
            continue
        data = _foreign_tenant_wide_data_scopes(sp) & C.BULK_DATA_DELEGATED_SCOPES
        if data:
            out.append(_ent(g, sp.id, scopes=sorted(data),
                            consent="tenant-wide (delegated AllPrincipals and/or application permission)",
                            app_owner_tenant=sp.props.get("_owner_org"),
                            note="external app can read/write bulk user data (mail/files/sites/chat) tenant-wide"))
    return out


@rule(id="AZ-APP-026",
      title="External app has tenant-wide consent to calendar / contacts / send-as",
      severity=Severity.LOW, category=Category.APPLICATION, best_practice=True,
      description="An external multi-tenant app has been admin-consented, for ALL users, to a lower-impact but still tenant-wide delegated scope: reading or writing every user's calendar or contacts, sending mail as any user, or reading org meetings/presence. These are the ubiquitous productivity integrations (calendar sync, scheduling, mailers), so the risk is lower than bulk mailbox/file access (AZ-APP-025) - but tenant-wide consent still means the vendor can, e.g., inject meeting invites into every calendar or send mail as staff. This is a consent-governance hygiene item: confirm each integration is sanctioned. Apps that also hold a higher-impact scope are reported under AZ-APP-023/025 instead, not here.",
      remediation="Maintain an allow-list of sanctioned productivity integrations. Prefer per-user consent for calendar/contacts add-ins rather than tenant-wide AllPrincipals consent, and periodically review the list of externally-consented apps.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1114", "Best Practice": "Consent governance"})
def foreign_lower_data_delegated_grant(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" not in sp.tags:
            continue
        scopes = _foreign_tenant_wide_data_scopes(sp)
        # Higher tiers own the app: don't double-report it at Low.
        if scopes & (C.DANGEROUS_DELEGATED_SCOPES | C.BULK_DATA_DELEGATED_SCOPES):
            continue
        lower = scopes & C.LOWER_DATA_DELEGATED_SCOPES
        if lower:
            out.append(_ent(g, sp.id, scopes=sorted(lower),
                            consent="tenant-wide (delegated AllPrincipals and/or application permission)",
                            app_owner_tenant=sp.props.get("_owner_org"),
                            note="external app with tenant-wide calendar/contacts/send-as consent"))
    return out


@rule(id="AZ-APP-024",
      title="Service principal accumulates many credentials (credential sprawl)",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="A single application/service principal carries an unusually large number of client secrets and/or certificates. Each credential is an independent way to authenticate as the identity, so a large set widens the theft surface, signals poor rotation hygiene (old secrets left in place when new ones are added), and makes it hard to revoke a leaked one with confidence. AZ-APP-004 flags a credential's lifetime; this flags their count.",
      remediation="Consolidate to a single active credential per workload, remove superseded secrets/certificates, and prefer federated identity credentials (workload identity federation) or managed identities over long-lived secrets.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1552", "Best Practice": "Credential lifecycle"})
def credential_sprawl(g: Graph):
    _THRESHOLD = 5
    out = []
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" in n.tags:
            continue  # you do not manage an external app's credentials
        count = (len(n.props.get("passwordCredentials") or [])
                 + len(n.props.get("keyCredentials") or []))
        if count >= _THRESHOLD:
            out.append(_ent(g, n.id, credential_count=count,
                            note=f"{count} credentials on one identity - consolidate and rotate"))
    return out


@rule(id="AZ-APP-016",
      title="High-privilege application accessible by all users (no assignment restriction)",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description=(
          "The application's service principal has appRoleAssignmentRequired = false (the default), "
          "meaning any user in the tenant can sign in to it and use its delegated permissions. "
          "This includes ex-employees whose accounts have not been disabled - they retain access "
          "to the app and anything it can reach on their behalf. For apps with powerful delegated "
          "Graph permissions (Mail, Files, Directory) this is an exfiltration and persistence risk."
      ),
      remediation=(
          "Set appRoleAssignmentRequired = true on each affected service principal (Enterprise Apps → "
          "Properties → 'Assignment required'). Then explicitly grant access only to the users/groups "
          "who need it. Pair this with a periodic access review and a leaver process that disables "
          "Entra accounts on the day of departure."
      ),
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1078.004", "CIS Azure": "1.x", "Best Practice": "App access restriction"})
def sp_no_assignment_required(g: Graph):
    """Flag Application-type SPs where any user can sign in (appRoleAssignmentRequired != true)
    AND the SP has meaningful permissions or credentials that make unrestricted access risky."""
    # Dangerous Graph delegated/application scope keywords - a subset that matters for this rule.
    _SENSITIVE_SCOPES = {
        "mail.read", "mail.readwrite", "mail.send",
        "files.read", "files.readwrite", "files.readwrite.all",
        "directory.read.all", "directory.readwrite.all",
        "user.read.all", "user.readwrite.all",
        "group.read.all", "group.readwrite.all",
        "calendars.readwrite", "contacts.readwrite",
        "sites.read.all", "sites.readwrite.all",
        "application.readwrite.all", "rolemanagement.readwrite.directory",
    }
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        # Only custom/enterprise apps - skip managed identities and foreign-tenant SPs
        if sp.props.get("servicePrincipalType") == "ManagedIdentity":
            continue
        if "foreign_tenant" in sp.tags:
            continue
        # Skip if assignment is already required
        if sp.props.get("appRoleAssignmentRequired") is True:
            continue
        # Skip if no live credentials AND no dangerous permissions - low risk
        cred_count = (len(sp.props.get("passwordCredentials") or []) +
                      len(sp.props.get("keyCredentials") or []))
        has_creds = cred_count > 0
        # appRoles here are permissions GRANTED TO the SP via AZAppRoleAssignment records
        # (not the roles it exposes - those live on the resource SP, not the principal SP)
        app_roles = {
            (r.get("value") or "").lower()
            for r in (sp.props.get("_granted_app_roles") or [])
        }
        has_sensitive = bool(
            app_roles & _SENSITIVE_SCOPES
            or "dangerous_app_role" in sp.tags
            or "tier0" in sp.tags
            or "privileged" in sp.tags
        )
        if not (has_creds or has_sensitive):
            continue
        dangerous_scopes = sorted(app_roles & _SENSITIVE_SCOPES)
        out.append(_ent(g, sp.id,
                        assignment_required=False,
                        credential_count=cred_count,
                        sensitive_scopes=dangerous_scopes[:5] or None))
    # Cap at 30 to avoid an unactionable bulk list - most-dangerous first (privileged/tier0 first)
    out.sort(key=lambda e: (
        0 if g.node(e.id) and ("tier0" in (g.node(e.id).tags or set()) or "privileged" in (g.node(e.id).tags or set())) else 1,
        0 if g.node(e.id) and "dangerous_app_role" in (g.node(e.id).tags or set()) else 1,
    ))
    return out[:30]


@rule(id="AZ-APP-018",
      title="Duplicate application registrations share a display name (shadow / unreviewed apps)",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description=(
          "Two or more DISTINCT applications (different appIds) share the same display name. "
          "Duplicate registrations are almost always unintended - a re-created or copy-pasted app - "
          "and each carries its own credentials and consented permissions. They evade review (an admin "
          "auditing 'Synology Active Backup for M365' sees one entry, not four), and any single duplicate "
          "can hold a dangerous Graph permission or a live secret the others lack, giving an attacker a "
          "low-visibility credential and persistence surface that hides behind a familiar name."
      ),
      remediation=(
          "Consolidate to one registration per application. After confirming which one is live, delete the "
          "unused duplicates and rotate the survivor's credentials. Enforce a naming standard and review "
          "newly created app registrations so duplicates are caught at creation."
      ),
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      requires_records=["AZApp", "AZServicePrincipal"],
      frameworks={"MITRE ATT&CK": "T1098.001", "MS Threat Matrix": "Persistence",
                  "Best Practice": "Application inventory hygiene"})
def duplicate_app_registrations(g: Graph):
    """Flag a display name shared by two or more DISTINCT applications where the duplicate set
    carries real risk - at least one duplicate holds a live credential or a dangerous Graph
    permission. The risk filter is what makes this signal, not noise: without it, benign
    auto-provisioned first-party apps (Microsoft Copilot Studio / Dynamics 365 agents, which
    legitimately register many same-named instances) dominate the result.

    An application is identified by appId (client id), so its app registration and its own
    service principal - sharing one appId - aggregate to ONE logical app, never a false
    duplicate. Managed identities and foreign-tenant SPs are excluded: they share names across
    tenants by design. Credentials and dangerous-permission tags are read across BOTH the app
    and its SP, since a granted Graph app role is tagged on the SP while secrets may sit on
    either."""
    from collections import defaultdict

    def _appkey(n):
        return ((n.props.get("appId") or "").lower()) or n.id.lower()

    # Aggregate every APP / SP node into its logical application (keyed by appId).
    logical: "dict[str, dict]" = {}
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if n.props.get("servicePrincipalType") == "ManagedIdentity" or "foreign_tenant" in n.tags:
            continue
        name = (n.name or "").strip()
        if len(name) < 3:
            continue
        app = logical.setdefault(_appkey(n),
                                 {"name": name, "rep": n.id, "creds": False, "dangerous": False})
        if n.props.get("passwordCredentials") or n.props.get("keyCredentials"):
            app["creds"] = True
        if "dangerous_app_role" in n.tags or (n.tags & {"tier0", "privileged"}):
            app["dangerous"] = True

    by_name: "dict[str, list]" = defaultdict(list)
    for app in logical.values():
        by_name[app["name"].lower()].append(app)

    out = []
    for apps in by_name.values():
        if len(apps) < 2:                       # one logical app is not a duplicate
            continue
        if not any(a["creds"] or a["dangerous"] for a in apps):   # risk filter
            continue
        for a in apps:
            out.append(_ent(g, a["rep"], shared_name=a["name"], duplicate_count=len(apps),
                            holds_credentials=a["creds"], dangerous_permission=a["dangerous"]))
    # Most dangerous first: duplicates holding a dangerous permission or a live secret lead.
    out.sort(key=lambda e: (
        0 if e.evidence.get("dangerous_permission") else 1,
        0 if e.evidence.get("holds_credentials") else 1,
        -(e.evidence.get("duplicate_count") or 0),
    ))
    return out


@rule(id="AZ-APP-019",
      title="Federated identity credential has an overly broad or cross-tenant trust",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description=(
          "A workload-identity federation (federated identity credential) on an application trusts "
          "tokens far more broadly than a single, pinned external workload should. Two shapes are "
          "flagged: a WILDCARD subject (a '*' in the subject, e.g. 'repo:org/*:ref:refs/heads/main', "
          "which trusts every repository in a GitHub org rather than one repo), and a CROSS-TENANT "
          "Entra issuer (the credential trusts an Entra tenant that is not this one, so an identity in "
          "a foreign directory can mint tokens for this application). Either lets a party the tenant "
          "does not control obtain tokens as this identity - with no stored secret to rotate or detect. "
          "Distinct from AZ-APP-008, which flags any federation on an already-privileged identity; this "
          "flags the over-broad TRUST itself, on any identity, because a broad trust is a foothold "
          "regardless of the identity's current privilege."
      ),
      remediation=(
          "Pin every federated credential to the exact external workload: for GitHub Actions use a "
          "specific 'repo:owner/name:ref:refs/heads/<branch>' or ':environment:<env>' subject, never a "
          "'*'. Remove any federation whose issuer is a foreign Entra tenant unless a cross-tenant trust "
          "is explicitly intended and documented. Constrain audiences to 'api://AzureADTokenExchange'."
      ),
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      requires_records=["AZFederatedIdentityCredential"],
      frameworks={"MITRE ATT&CK": "T1098.001", "MS Threat Matrix": "Persistence"})
def broad_federated_trust(g: Graph):
    import re
    home = (str(g.tenant_id or "").split("/")[-1]).lower()

    def _issuer_tenant(iss):
        m = re.search(r"(?:login\.microsoftonline\.com|sts\.windows\.net)/([0-9a-f]{8}-[0-9a-f-]{27})",
                      iss or "", re.I)
        return m.group(1).lower() if m else None

    out = []
    for n in g.nodes_of_kind(NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
        if n.props.get("servicePrincipalType") == "ManagedIdentity":
            continue
        for fc in (n.props.get("federatedIdentityCredentials") or []):
            subject = fc.get("subject") or ""
            issuer = fc.get("issuer") or ""
            reasons = []
            if not subject.strip():
                reasons.append("null/empty subject (trusts ANY subject from the issuer)")
            elif "*" in subject:
                reasons.append("wildcard subject")
            it = _issuer_tenant(issuer)
            if it and home and it != home:
                reasons.append("cross-tenant Entra issuer")
            if reasons:
                out.append(_ent(g, n.id, trust_issue=", ".join(reasons),
                                subject=subject or None, issuer=issuer or None))
                break   # one finding per identity is enough
    return out


@rule(id="AZ-APP-020",
      title="External (multi-tenant) third-party app holds high-impact Graph permissions",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description=(
          "A service principal that belongs to a FOREIGN Entra tenant - a third-party SaaS vendor's "
          "multi-tenant application consented into this tenant - holds a high-impact Microsoft Graph "
          "APPLICATION permission such as Directory.ReadWrite.All, Mail.ReadWrite.All, Files.ReadWrite.All "
          "or Sites.ReadWrite.All. Application permissions apply tenant-wide and need no user present, so "
          "the vendor (or anyone who compromises the vendor) can read or write the corresponding data "
          "across the whole organisation. This is the classic illicit-consent / supply-chain exposure: the "
          "risk is not an internal escalation but standing external access that outlives any one employee "
          "and is rarely re-reviewed after the initial consent."
      ),
      remediation=(
          "Re-review the consent for every external application under Enterprise applications → Permissions. "
          "Revoke application permissions the vendor does not demonstrably require, prefer delegated "
          "(user-scoped) permissions, and scope data access (e.g. application access policies for Mail) to "
          "the minimum. Track third-party apps with directory/data write access on a recurring access review."
      ),
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1550.001", "MS Threat Matrix": "Persistence"})
def external_app_high_impact_perms(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" not in sp.tags:
            continue
        granted = {(r.get("value") or "") for r in (sp.props.get("_granted_app_roles") or [])}
        dangerous = sorted(granted & set(C.DANGEROUS_GRAPH_APP_ROLES))
        if dangerous:
            out.append(_ent(g, sp.id, external_vendor=True, permissions=dangerous[:5],
                            permission_count=len(dangerous)))
    out.sort(key=lambda e: -(e.evidence.get("permission_count") or 0))
    return out


@rule(id="AZ-IDENT-012",
      title="Principal accumulates an excessive number of Entra directory roles",
      severity=Severity.MEDIUM, category=Category.IDENTITY,
      description=(
          "A single principal actively holds six or more distinct Entra directory roles. Broad role "
          "accumulation violates least privilege: the union of many roles' permissions is far larger than "
          "any one job needs, the account becomes a high-value single point of compromise, and standing "
          "assignments (rather than just-in-time PIM activation) mean every one of those privileges is "
          "always live. Role sprawl also defeats review - nobody can reason about what a 13-role account "
          "can actually do."
      ),
      remediation=(
          "Reduce each principal to the minimum roles its function requires. Move elevated roles to PIM "
          "eligible (just-in-time) assignment rather than standing active, and run an access review over "
          "every account holding many roles. Split broad break-glass duties across separate, monitored "
          "accounts."
      ),
      data_source=[NodeKind.USER, NodeKind.SERVICE_PRINCIPAL, NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098", "Best Practice": "Least privilege"})
def excessive_directory_roles(g: Graph):
    out = []
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.SERVICE_PRINCIPAL, NodeKind.GROUP):
        roles = {(e.evidence.get("role") or e.dst) for e in g.out_edges(p.id, EdgeType.HAS_ENTRA_ROLE)}
        roles = {r for r in roles if r}
        if len(roles) >= 6:
            out.append(_ent(g, p.id, directory_role_count=len(roles), roles=sorted(roles)[:8]))
    out.sort(key=lambda e: -(e.evidence.get("directory_role_count") or 0))
    return out


@rule(id="AZ-RBAC-013",
      title="Principal holds Owner / User Access Administrator across multiple subscriptions",
      severity=Severity.HIGH, category=Category.RBAC,
      description=(
          "A single principal holds Owner or User Access Administrator on three or more distinct "
          "subscriptions. Both roles can grant any RBAC role (including to themselves), so this is standing "
          "self-escalating control over a wide blast radius: one compromised credential re-grants full "
          "access across every one of those subscriptions. Cross-subscription concentration like this is "
          "exactly the pivot that turns a single-workload compromise into estate-wide impact."
      ),
      remediation=(
          "Remove Owner / User Access Administrator wherever it is not essential, and scope any remaining "
          "grant to the narrowest resource group. Use PIM eligible assignment for cross-subscription admin "
          "duties, and prefer per-subscription least-privilege roles over one principal spanning many."
      ),
      data_source=[NodeKind.SUBSCRIPTION],
      frameworks={"MITRE ATT&CK": "T1098", "CIS Azure": "1.x"})
def cross_subscription_high_privilege(g: Graph):
    _BIG = {"owner", "user access administrator"}
    out = []
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.SERVICE_PRINCIPAL, NodeKind.GROUP):
        subs: set[str] = set()
        role_hit = ""
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = (e.evidence.get("scope") or "")
            if role in _BIG and "/subscriptions/" in scope.lower():
                subs.add(scope.lower().split("/resourcegroups/")[0])
                role_hit = role
        if len(subs) >= 3:
            out.append(_ent(g, p.id, subscription_count=len(subs), role=role_hit))
    out.sort(key=lambda e: -(e.evidence.get("subscription_count") or 0))
    return out


@rule(id="AZ-MI-002",
      title="Privileged user-assigned managed identity is shared across many resources",
      severity=Severity.HIGH, category=Category.MANAGED_IDENTITY,
      description=(
          "One user-assigned managed identity is attached to three or more resources AND holds a "
          "privileged Azure RBAC role (Owner, Contributor or User Access Administrator). Because the same "
          "identity is shared, code execution on ANY one of those resources - a single vulnerable VM, "
          "function, or AKS workload - yields that privileged role via IMDS, and therefore access to "
          "everything the identity can reach. Sharing collapses the blast radius of every host onto one "
          "identity: the weakest resource in the set defines the security of all of them."
      ),
      remediation=(
          "Give each workload its own least-privilege managed identity instead of sharing one. Scope the "
          "identity's RBAC to the specific resources it must touch, never subscription-wide Owner/"
          "Contributor. Where a shared identity is unavoidable, harden every resource it is attached to as "
          "if it were the most sensitive one."
      ),
      data_source=[NodeKind.VM, NodeKind.AKS, NodeKind.AUTOMATION, NodeKind.FUNCTION_APP,
                   NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.VMSS],
      frameworks={"MITRE ATT&CK": "T1078.004", "MS Threat Matrix": "Lateral Movement"})
def shared_privileged_managed_identity(g: Graph):
    from collections import defaultdict
    _PRIV = {"owner", "contributor", "user access administrator"}
    resources: "dict[str, set]" = defaultdict(set)
    for e in g.edges():
        if e.type != EdgeType.HAS_MANAGED_IDENTITY:
            continue
        dst = g.node(e.dst)
        mi = e.dst if (dst and dst.props.get("servicePrincipalType") == "ManagedIdentity") else e.src
        res = e.src if mi == e.dst else e.dst
        resources[mi].add(res)
    out = []
    for mi, res in resources.items():
        if len(res) < 3:
            continue
        roles = {(e.evidence.get("role") or "").lower() for e in g.out_edges(mi, EdgeType.HAS_RBAC_ROLE)}
        priv = sorted(roles & _PRIV)
        if priv:
            out.append(_ent(g, mi, resource_count=len(res), privileged_roles=priv))
    out.sort(key=lambda e: -(e.evidence.get("resource_count") or 0))
    return out


@rule(id="AZ-IDENT-013",
      title="Disabled account retains PIM eligibility for a Tier-0 role",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description=(
          "A DISABLED account is still eligible to self-activate a Tier-0 directory role (e.g. Global "
          "Administrator) through Privileged Identity Management. Disabling the account was meant to remove "
          "its access, but the standing PIM eligibility survives: if the account is ever re-enabled - an "
          "offboarding reversal, a helpdesk mistake, or an attacker who takes over the identity - it is one "
          "PIM activation away from Tier-0. It is invisible to an active-roles-only review AND to a "
          "'disabled accounts have no access' assumption, making it a silent persistence path."
      ),
      remediation=(
          "Remove all PIM eligibility from disabled accounts as part of offboarding - disabling is not "
          "enough. Delete the account once retention requirements allow, and audit PIM eligible assignments "
          "against account state so a disabled principal can never retain a Tier-0 activation path."
      ),
      data_source=[NodeKind.USER, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1078.004", "MS Threat Matrix": "Persistence"})
def disabled_retains_pim_eligibility(g: Graph):
    return [_ent(g, n.id, note="disabled account eligible to activate a Tier-0 role")
            for n in g.nodes()
            if "disabled" in n.tags and "tier0_eligible" in n.tags]


@rule(id="AZ-IDENT-015",
      title="Tier-0 role has a weak PIM activation policy",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description=(
          "A Tier-0 directory role's Privileged Identity Management activation policy is weak: an eligible "
          "principal can activate the role WITHOUT multi-factor authentication, and/or an eligible "
          "assignment is allowed to be PERMANENT (never expires). PIM's protection is only as strong as its "
          "activation rules - if activating Global Administrator needs no MFA, a single stolen password "
          "yields Tier-0 on demand, and permanent eligibility means the shadow-admin path never lapses. "
          "These gaps are invisible to assignment data alone; they live in the role-management policy."
      ),
      remediation=(
          "For every Tier-0 role's PIM policy: require MFA on activation, require approval for the most "
          "sensitive roles (Global Administrator, Privileged Role Administrator), require justification, cap "
          "the activation duration, and require eligible assignments to expire (no permanent eligibility). "
          "Alert on activations."
      ),
      data_source=[NodeKind.ROLE],
      requires_records=["AZRoleManagementPolicy"],
      frameworks={"MITRE ATT&CK": "T1078.004", "MS Threat Matrix": "Persistence"})
def weak_pim_activation_policy(g: Graph):
    def _is_tier0(r):
        tpl = str((r.props or {}).get("templateId") or (r.props or {}).get("roleTemplateId") or "").lower()
        return tpl in C.TIER0_ENTRA_ROLE_TEMPLATES or (r.name or "").lower() in C.TIER0_ENTRA_ROLE_NAMES

    out = []
    for r in g.nodes_of_kind(NodeKind.ROLE):
        pol = (r.props or {}).get("pim_policy")
        if not pol or not _is_tier0(r):
            continue
        gaps = []
        if pol.get("activationRequiresMfa") is False:
            gaps.append("no MFA on activation")
        if pol.get("permanentEligibilityAllowed") is True:
            gaps.append("permanent eligibility allowed")
        if pol.get("activationRequiresApproval") is False:
            gaps.append("no approval required")
        # Fire only on the material weaknesses (MFA / permanent eligibility); approval-not-
        # required is recorded as context but is not, on its own, a finding.
        if any(g_ in ("no MFA on activation", "permanent eligibility allowed") for g_ in gaps):
            out.append(_ent(g, r.id, weaknesses=gaps,
                            activation_max_duration=pol.get("activationMaxDuration")))
    return out


@rule(id="AZ-RBAC-014",
      title="Data-plane RBAC role granted at subscription / management-group scope",
      severity=Severity.HIGH, category=Category.RBAC,
      description=(
          "A principal holds an Azure DATA-plane role - such as Storage Blob Data Contributor/Owner/"
          "Reader, Storage Account Key Operator, or Key Vault Administrator / Secrets Officer / Secrets "
          "User - at subscription or management-group scope. Data-plane roles grant direct access to the "
          "DATA inside resources (blobs, queues, Key Vault secrets/keys), bypassing the control-plane "
          "checks that Owner/Contributor findings focus on. Granted at subscription or MG scope, one "
          "assignment reaches the data in EVERY storage account or vault beneath it - e.g. Key Vault "
          "Secrets User at subscription scope reads every secret in every vault in the subscription. This "
          "is exactly the reach that turns a single compromised principal into mass data exfiltration."
      ),
      remediation=(
          "Scope data-plane roles to the specific storage account or Key Vault that needs them, never to a "
          "subscription or management group. Prefer per-resource assignments, and review any principal "
          "holding a data role above resource-group scope."
      ),
      data_source=[NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1530", "MS Threat Matrix": "Collection"})
def data_plane_role_broad_scope(g: Graph):
    _DATA_ROLES = {
        "storage blob data contributor", "storage blob data owner", "storage blob data reader",
        "storage queue data contributor", "storage account key operator service role",
        "key vault administrator", "key vault secrets officer", "key vault secrets user",
        "key vault crypto officer",
    }
    out = []
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            role = (e.evidence.get("role") or "").lower()
            scope = (e.evidence.get("scope") or "")
            sl = scope.lower()
            broad_sub = "/subscriptions/" in sl and "/resourcegroups/" not in sl and "/providers/" not in sl
            mg = "/managementgroups/" in sl
            if role in _DATA_ROLES and (broad_sub or mg):
                out.append(_ent(g, p.id, data_role=e.evidence.get("role"),
                                scope_kind="management group" if mg else "subscription"))
                break
    return out


@rule(id="AZ-GRP-005",
      title="Group confers a self-escalating Azure role to all its members",
      severity=Severity.HIGH, category=Category.GROUP,
      description=(
          "A group holds Owner or User Access Administrator on a subscription or management group, so "
          "EVERY member of the group inherits a self-escalating role - each can assign themselves any RBAC "
          "role across that scope. The risk scales with membership: a large group turns a self-escalation "
          "primitive into a wide, hard-to-review attack surface, and adding a member (often a lighter-"
          "touch action than a direct role assignment) silently grants full control. Distinct from the "
          "per-assignment broad-scope findings: this quantifies how many principals inherit the escalation "
          "through membership."
      ),
      remediation=(
          "Do not grant Owner / User Access Administrator to broad membership groups. Restrict these roles "
          "to a small, named, PIM-governed set of principals, tighten group membership, and enable access "
          "reviews on any group that confers a self-escalating role."
      ),
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098", "MS Threat Matrix": "Privilege Escalation"})
def group_confers_self_escalation(g: Graph):
    _SE = {"owner", "user access administrator"}
    out = []
    for grp in g.nodes_of_kind(NodeKind.GROUP):
        roles = {(e.evidence.get("role") or "").lower() for e in g.out_edges(grp.id, EdgeType.HAS_RBAC_ROLE)}
        hit = sorted(roles & _SE)
        if hit:
            members = sum(1 for _ in g.in_edges(grp.id, EdgeType.MEMBER_OF))
            out.append(_ent(g, grp.id, member_count=members, self_escalating_roles=hit))
    out.sort(key=lambda e: -(e.evidence.get("member_count") or 0))
    return out


@rule(id="AZ-GRP-006",
      title="Group confers Key Vault secret access to a large membership",
      severity=Severity.MEDIUM, category=Category.GROUP,
      description=(
          "A group grants Key Vault data-plane access (secret/key/certificate read, via an access "
          "policy or a data-plane RBAC role) and has a large membership, so every member inherits the "
          "ability to read those vaults' secrets. The blast radius is the membership count: a "
          "175-member group with vault access means 175 principals can read the credentials it "
          "reaches, and the group name may not reflect that (e.g. a 'Read Only' or 'Support' group "
          "that in fact holds Key Vault access). Adding a member silently grants secret access, and "
          "the wide, hard-to-review membership is exactly where over-provisioned data access hides. "
          "The remediation target is the GROUP, not each member."
      ),
      remediation=(
          "Scope Key Vault access to per-workload identities, not broad membership groups. Remove the "
          "group's vault access or split it into a small, named, reviewed group; enable access reviews "
          "on any group that reaches Key Vault secrets."
      ),
      data_source=[NodeKind.GROUP, NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001", "Best Practice": "Least-privilege data access"})
def group_confers_kv_access(g: Graph):
    _THRESHOLD = 10
    out = []
    for grp in g.nodes_of_kind(NodeKind.GROUP):
        vaults = {e.dst for e in g.out_edges(grp.id, EdgeType.KV_ACCESS)} | \
                 {e.dst for e in g.out_edges(grp.id, EdgeType.CAN_REACH_KV_SECRET)}
        if not vaults:
            continue
        members = sum(1 for _ in g.in_edges(grp.id, EdgeType.MEMBER_OF))
        if members >= _THRESHOLD:
            out.append(_ent(g, grp.id, member_count=members,
                            key_vaults_reachable=len(vaults),
                            note=(f"{members} members inherit read access to {len(vaults)} "
                                  f"Key Vault(s) through this group")))
    out.sort(key=lambda e: -(e.evidence.get("member_count") or 0))
    return out


@rule(id="AZ-APP-022",
      title="Ownerless privileged service principal (dangerous Graph permission or Tier-0)",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description=(
          "A service principal with NO assigned owner is privileged - either it holds a high-impact "
          "Microsoft Graph application permission (e.g. Directory.ReadWrite.All, "
          "RoleManagement.ReadWrite.Directory, Group.ReadWrite.All, Mail.ReadWrite.All), OR it is "
          "Tier-0 by another mechanism (commonly User Access Administrator / Owner at subscription "
          "scope via Azure RBAC). Ownerless means no one is accountable for the "
          "identity: its credentials go un-rotated, its permissions un-reviewed, and its compromise "
          "un-noticed - yet it wields a permission that can escalate privilege or exfiltrate data "
          "tenant-wide. Combining no accountability with high privilege is precisely the forgotten, "
          "over-powered identity attackers look for. Distinct from AZ-APP-002 (any SP with the permission) "
          "and AZ-HYG-004 (any ownerless app): this is the dangerous intersection of the two."
      ),
      remediation=(
          "Assign an accountable owner to every service principal, or decommission it. For the ones that "
          "remain, remove Graph permissions they do not need, rotate credentials, and place them under a "
          "recurring access review."
      ),
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.003", "MS Threat Matrix": "Persistence"})
def ownerless_dangerous_sp(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if sp.props.get("servicePrincipalType") == "ManagedIdentity":
            continue
        if g.in_edges(sp.id, EdgeType.OWNS):
            continue
        granted = {(r.get("value") or "") for r in (sp.props.get("_granted_app_roles") or [])}
        dangerous = sorted(granted & set(C.DANGEROUS_GRAPH_APP_ROLES))
        # An ownerless SP is a finding either because it holds a dangerous Graph
        # permission OR because it is Tier-0 by any other mechanism (e.g. an ownerless
        # SP holding User Access Administrator at subscription scope via Azure RBAC -
        # like AKS-Spoke here). The Graph-permission-only test missed the RBAC-Tier-0
        # case even though it is the same "forgotten, over-powered identity" risk.
        is_tier0 = "tier0" in sp.tags
        if dangerous or is_tier0:
            out.append(_ent(g, sp.id, ownerless=True, permissions=dangerous[:5],
                            permission_count=len(dangerous),
                            tier0=is_tier0,
                            reason=("dangerous Graph permission" if dangerous else "")
                                   + (" + " if dangerous and is_tier0 else "")
                                   + ("Tier-0 via Azure RBAC / role" if is_tier0 else "")))
    out.sort(key=lambda e: (not e.evidence.get("tier0"),
                            -(e.evidence.get("permission_count") or 0)))
    return out


@rule(id="AZ-GRP-004", title="Role-assignable group has no owner (orphaned privileged group)",
      severity=Severity.MEDIUM, category=Category.GROUP,
      description="A role-assignable group (which can hold Entra directory roles and must be tightly governed) has no assigned owner. Without an accountable owner, membership changes are unreviewed and the group becomes an unmonitored escalation surface.",
      remediation="Assign at least two accountable Tier-0 owners to every role-assignable group. Enable access reviews for all privileged groups.",
      data_source=[NodeKind.GROUP],
      frameworks={"Best Practice": "Privileged group governance"})
def orphaned_privileged_group(g: Graph):
    return [_ent(g, grp.id, note="role-assignable group with no owner")
            for grp in g.nodes_of_kind(NodeKind.GROUP)
            if "role_assignable" in grp.tags and not g.in_edges(grp.id, EdgeType.OWNS)]


@rule(id="AZ-RBAC-008", title="Classic (co-)administrator assigned on a subscription",
      severity=Severity.MEDIUM, category=Category.RBAC,
      description="A subscription has a classic Service Administrator / Co-Administrator. Classic administrators have full control equivalent to Owner, predate Azure RBAC, are poorly audited, and are frequently forgotten.",
      remediation="Remove classic administrators and migrate to Azure RBAC role assignments with least privilege.",
      data_source=[NodeKind.SUBSCRIPTION],
      frameworks={"CIS Azure": "1.x"},
      requires_props=['classicAdministrators', 'classic_administrators'],
      )
def classic_admins(g: Graph):
    out = []
    for sub in g.nodes_of_kind(NodeKind.SUBSCRIPTION):
        for adm in (sub.props.get("classicAdministrators") or sub.props.get("classic_administrators") or []):
            name = adm.get("emailAddress") if isinstance(adm, dict) else str(adm)
            out.append(_ent(g, sub.id, classic_admin=name,
                            role=(adm.get("role") if isinstance(adm, dict) else None)))
    return out


# --------------------------------------------------------------------------- #
# v2 Phase 1 - resource-configuration depth (grounded in AzureHound-collected
# resource properties). Storage accounts carry the richest config, so the first
# batch deepens Storage beyond the existing anonymous-blob / shared-key / key-
# retrieval rules. Every rule distinguishes a confirmed misconfiguration from a
# property AzureHound never collected - claiming a finding from absent data is
# exactly what the quality guardrails forbid.
# --------------------------------------------------------------------------- #
def _stor_props(s):
    return s.props.get("properties") or s.props


@rule(id="AZ-STOR-005", title="Storage account accepts a weak TLS version",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="The storage account's minimumTlsVersion permits TLS 1.0 or 1.1. Both are deprecated and carry known cryptographic weaknesses (BEAST, POODLE-style downgrade), so data in transit to the account can be intercepted or downgraded by a network attacker.",
      remediation="Set minimumTlsVersion=TLS1_2 on every storage account. Confirm clients support TLS 1.2 before enforcing.",
      data_source=[NodeKind.STORAGE],
      requires_props=['minimumTlsVersion'],
      frameworks={"CIS Azure": "3.15", "MITRE ATT&CK": "T1040"})
def storage_weak_tls(g: Graph):
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        val = _stor_props(s).get("minimumTlsVersion")
        if isinstance(val, str) and val.upper() in ("TLS1_0", "TLS1_1"):
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            minimumTlsVersion=val, confirmed=True,
                            note=f"accepts {val.replace('_', ' ')} - below TLS 1.2"))
    return out


@rule(id="AZ-STOR-006", title="Storage account does not enforce HTTPS-only traffic",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="supportsHttpsTrafficOnly is disabled, so the account's data-plane endpoints answer plaintext HTTP. Credentials (SAS tokens, shared keys) and data traverse the network unencrypted and can be captured or replayed.",
      remediation="Set supportsHttpsTrafficOnly=true (Secure transfer required) on every storage account.",
      data_source=[NodeKind.STORAGE],
      requires_props=['supportsHttpsTrafficOnly'],
      frameworks={"CIS Azure": "3.1", "MITRE ATT&CK": "T1040"})
def storage_no_https_only(g: Graph):
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        val = _stor_props(s).get("supportsHttpsTrafficOnly")
        if val is False:
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            supportsHttpsTrafficOnly=val, confirmed=True,
                            note="secure transfer not required - plaintext HTTP accepted"))
    return out


@rule(id="AZ-STOR-007", title="Storage account network access is not restricted",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="The storage account firewall defaultAction is Allow (or no firewall is configured), so the blob/file/queue/table endpoints are reachable from any network. Authentication is still required, but this removes network-layer defence-in-depth and exposes the account to credential-replay and data-plane enumeration from the internet.",
      remediation="Set the storage firewall defaultAction=Deny, allow only required VNets/IP ranges, and prefer Private Endpoints for sensitive data.",
      data_source=[NodeKind.STORAGE],
      requires_props=['networkAcls'],
      frameworks={"CIS Azure": "3.8", "Best Practice": "Network restriction"})
def storage_network_open(g: Graph):
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        acls = _stor_props(s).get("networkAcls") or {}
        action = acls.get("defaultAction")
        if action is not None and str(action).lower() == "allow":
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            networkAcls_defaultAction=action, confirmed=True,
                            note="defaultAction=Allow - reachable from any network"))
    return out


@rule(id="AZ-STOR-008", title="Storage account has no Private Endpoint and is publicly reachable",
      severity=Severity.LOW, category=Category.STORAGE, best_practice=True,
      description="The account has no Private Endpoint connection and its firewall is not set to Deny, so all access traverses the public endpoint. A Private Endpoint keeps traffic on the Azure backbone and removes the account from the public DNS/attack surface entirely.",
      remediation="Add a Private Endpoint for the account's blob/file services and set the public firewall defaultAction=Deny once clients use the private path.",
      data_source=[NodeKind.STORAGE],
      frameworks={"Best Practice": "Private connectivity"},
      requires_props=['privateEndpointConnections'],
      )
def storage_no_private_endpoint(g: Graph):
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        props = _stor_props(s)
        if "privateEndpointConnections" not in props:
            continue  # not collected - say nothing rather than guess
        pe = props.get("privateEndpointConnections") or []
        acls = props.get("networkAcls") or {}
        denied = str(acls.get("defaultAction") or "").lower() == "deny"
        if not pe and not denied:
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            private_endpoints=0, confirmed=True,
                            note="no Private Endpoint and public access not denied"))
    return out


# --------------------------------------------------------------------------- #
# v2 Phase 1 batch 2 - Key Vault configuration depth (515 vaults collected with
# rich config). Complements the existing KV-001..006 (data-plane breadth, legacy
# access policies, crypto ops, purge protection, network).
# --------------------------------------------------------------------------- #
def _kv_props(kv):
    return kv.props.get("properties") or kv.props


@rule(id="AZ-KV-007", title="Key Vault is enabled for VM deployment (secrets reachable from compute)",
      severity=Severity.MEDIUM, category=Category.KEYVAULT,
      description="enabledForDeployment is true, so Azure VMs in the subscription can retrieve the vault's certificates and secrets as part of deployment - without an explicit Key Vault RBAC or access-policy grant. Any principal that can create or control a VM in the subscription can therefore reach the vault's material.",
      remediation="Set enabledForDeployment=false unless a specific VM deployment genuinely needs it, and grant per-workload access through RBAC/access policies instead.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"CIS Azure": "8.x", "MITRE ATT&CK": "T1552.001"},
      requires_props=['enabledForDeployment'],
      )
def kv_enabled_for_deployment(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        if _kv_props(kv).get("enabledForDeployment") is True:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            enabledForDeployment=True, confirmed=True,
                            note="VMs in the subscription can retrieve this vault's secrets/certs"))
    return out


@rule(id="AZ-KV-008", title="Key Vault soft-delete retention is short",
      severity=Severity.LOW, category=Category.KEYVAULT, best_practice=True,
      description="softDeleteRetentionInDays is below 90. A short retention window shrinks the time available to recover secrets, keys and certificates that are deleted maliciously or accidentally - reducing resilience against a destructive attacker or a mistaken purge.",
      remediation="Set softDeleteRetentionInDays to 90 and enable purge protection so deletions cannot be fast-tracked.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"CIS Azure": "8.x", "Best Practice": "Recoverability"},
      requires_props=['softDeleteRetentionInDays'],
      )
def kv_short_soft_delete(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        days = _kv_props(kv).get("softDeleteRetentionInDays")
        if isinstance(days, int) and days < 90:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            softDeleteRetentionInDays=days, confirmed=True,
                            note=f"retention {days} days - below the 90-day maximum"))
    return out


@rule(id="AZ-KV-009", title="Key Vault has no Private Endpoint and is publicly reachable",
      severity=Severity.LOW, category=Category.KEYVAULT, best_practice=True,
      description="The vault has no Private Endpoint connection and its firewall is not set to Deny, so its management and data-plane endpoints stay on the public attack surface. A Private Endpoint keeps traffic on the Azure backbone and removes the vault from public reachability.",
      remediation="Add a Private Endpoint for the vault and set the firewall defaultAction=Deny once clients use the private path.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"Best Practice": "Private connectivity"},
      requires_props=['privateEndpointConnections'],
      )
def kv_no_private_endpoint(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        props = _kv_props(kv)
        if "privateEndpointConnections" not in props:
            continue
        pe = props.get("privateEndpointConnections") or []
        acls = props.get("networkAcls") or {}
        denied = str(acls.get("defaultAction") or "").lower() == "deny"
        if not pe and not denied:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            private_endpoints=0, confirmed=True,
                            note="no Private Endpoint and public access not denied"))
    return out


# --------------------------------------------------------------------------- #
# v2 Phase 1 batch 3 - VM security posture (securityProfile is collected).
# --------------------------------------------------------------------------- #
@rule(id="AZ-VM-001", title="Virtual machine does not use Trusted Launch",
      severity=Severity.LOW, category=Category.COMPUTE, best_practice=True,
      description="The VM's securityType is not TrustedLaunch, so it lacks Secure Boot and vTPM. Trusted Launch defends against boot-kits, rootkits and kernel-level tampering, and is a prerequisite for VM guest attestation; a Standard VM has none of these protections.",
      remediation="Recreate or upgrade the VM as a Trusted Launch (Gen2) VM with Secure Boot and vTPM enabled.",
      data_source=[NodeKind.VM],
      frameworks={"CIS Azure": "7.x", "Best Practice": "Boot integrity"},
      requires_props=['securityProfile'],
      )
def vm_no_trusted_launch(g: Graph):
    out = []
    for vm in g.nodes_of_kind(NodeKind.VM):
        props = vm.props.get("properties") or vm.props
        sp = props.get("securityProfile")
        if not isinstance(sp, dict):
            continue  # securityProfile not collected - no claim
        stype = sp.get("securityType")
        if str(stype or "").lower() != "trustedlaunch":
            out.append(_ent(g, vm.id, subscription=_subscription_for(g, vm.id),
                            securityType=(stype or "Standard"), confirmed=True,
                            note="not a Trusted Launch VM - no Secure Boot / vTPM"))
    return out


# --------------------------------------------------------------------------- #
# v2 Phase 1 batch 4 - data-exfil / deployment-secret exposure and app entry
# points (all grounded in collected properties).
# --------------------------------------------------------------------------- #
@rule(id="AZ-STOR-009", title="Storage account allows cross-tenant object replication",
      severity=Severity.MEDIUM, category=Category.STORAGE,
      description="allowCrossTenantReplication is true, so object-replication rules can copy this account's blobs to a storage account in a DIFFERENT Entra tenant. An attacker with write access to replication policy - or an insider - can use it as a sanctioned data-exfiltration channel that leaves the tenant boundary.",
      remediation="Set allowCrossTenantReplication=false unless a cross-tenant replication scenario is explicitly required and reviewed.",
      data_source=[NodeKind.STORAGE],
      frameworks={"CIS Azure": "3.x", "MITRE ATT&CK": "T1537"},
      requires_props=['allowCrossTenantReplication'],
      )
def storage_cross_tenant_replication(g: Graph):
    out = []
    for s in g.nodes_of_kind(NodeKind.STORAGE):
        if _stor_props(s).get("allowCrossTenantReplication") is True:
            out.append(_ent(g, s.id, subscription=_subscription_for(g, s.id),
                            allowCrossTenantReplication=True, confirmed=True,
                            note="cross-tenant object replication permitted - data can leave the tenant"))
    return out


@rule(id="AZ-KV-010", title="Key Vault is enabled for ARM template deployment (secrets reachable from templates)",
      severity=Severity.MEDIUM, category=Category.KEYVAULT,
      description="enabledForTemplateDeployment is true, so Azure Resource Manager can read the vault's secrets during a template deployment - without an explicit Key Vault RBAC or access-policy grant. Any principal that can deploy an ARM/Bicep template referencing the vault can extract its secrets.",
      remediation="Set enabledForTemplateDeployment=false unless a specific deployment requires it, and pass secrets to deployments through a scoped, audited mechanism instead.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"CIS Azure": "8.x", "MITRE ATT&CK": "T1552.001"},
      requires_props=['enabledForTemplateDeployment'],
      )
def kv_enabled_for_template(g: Graph):
    out = []
    for kv in g.nodes_of_kind(NodeKind.KEY_VAULT):
        if _kv_props(kv).get("enabledForTemplateDeployment") is True:
            out.append(_ent(g, kv.id, subscription=_subscription_for(g, kv.id),
                            enabledForTemplateDeployment=True, confirmed=True,
                            note="ARM template deployments can read this vault's secrets"))
    return out


@rule(id="AZ-KV-011", title="Key Vault access granted to a guest / external principal",
      severity=Severity.HIGH, category=Category.KEYVAULT,
      description="A Key Vault using the access-policy model grants data-plane permissions "
                  "(secrets, keys or certificates) to a guest (external / B2B) identity. Vault "
                  "contents are exposed to an account governed by another organisation - outside "
                  "this tenant's lifecycle, credential and conditional-access controls. If that "
                  "external identity or its home tenant is compromised, so are the vault's secrets. "
                  "Access-policy grants are invisible to the Azure RBAC guest-role check, so this "
                  "exposure is otherwise unreported.",
      remediation="Remove the guest's access policy. Grant Key Vault data access only to internal "
                  "identities, preferably via scoped Azure RBAC data-plane roles rather than the "
                  "legacy access-policy model.",
      data_source=[NodeKind.KEY_VAULT],
      frameworks={"MITRE ATT&CK": "T1552.001"})
def kv_guest_access(g: Graph):
    out, seen = [], set()
    for e in g.edges():
        if e.type != EdgeType.KV_ACCESS:
            continue
        src = g.node(e.src)
        if not src or "guest" not in src.tags:
            continue
        key = (e.src, e.dst)
        if key in seen:
            continue
        seen.add(key)
        perms = e.evidence.get("permissions") or {}
        out.append(_ent(g, e.src, vault=g.display(e.dst),
                        subscription=_subscription_for(g, e.dst),
                        permissions=perms,
                        note="guest / external principal holds a Key Vault access policy"))
    return out


@rule(id="AZ-LOGIC-001", title="Internet-triggered Logic App carries a managed identity",
      severity=Severity.MEDIUM, category=Category.COMPUTE,
      description="The workflow has a Request (manual/HTTP) trigger, so it exposes an externally reachable HTTPS callback endpoint, AND it carries a managed identity. A caller who obtains the callback URL (or exploits weak SAS/authorization on it) can drive the workflow's actions - and its managed identity's Azure permissions - from outside the tenant. An HTTP-triggered workflow with no identity is a far lower concern and is not flagged.",
      remediation="Restrict the trigger with IP ranges and strong SAS/authorization, front it with API Management or a gateway, and ensure the managed identity the workflow uses is least-privilege.",
      data_source=[NodeKind.LOGIC_APP],
      frameworks={"MITRE ATT&CK": "T1190", "Best Practice": "External entry point"},
      requires_props=['definition'],
      )
def logicapp_http_trigger(g: Graph):
    out = []
    for la in g.nodes_of_kind(NodeKind.LOGIC_APP):
        definition = (la.props.get("properties") or la.props).get("definition")
        triggers = definition.get("triggers") if isinstance(definition, dict) else None
        if not isinstance(triggers, dict):
            continue
        http = [name for name, t in triggers.items()
                if isinstance(t, dict) and str(t.get("type", "")).lower() == "request"]
        if not http:
            continue
        # The exposure only matters when the trigger can drive privileged Azure actions: gate on
        # the workflow carrying a managed identity (the condition the description states).
        if not list(g.out_edges(la.id, EdgeType.HAS_MANAGED_IDENTITY)):
            continue
        out.append(_ent(g, la.id, subscription=_subscription_for(g, la.id),
                        http_triggers=", ".join(http), confirmed=True,
                        note="internet-facing HTTP trigger on a workflow with a managed identity"))
    return out


# --------------------------------------------------------------------------- #
# v2 Phase 1 batch 5 - apex-scope, nested-privilege, external/stale ownership,
# and self-join misconfigurations (all grounded in collected graph structure).
# --------------------------------------------------------------------------- #
@rule(id="AZ-RBAC-016", title="Privileged role assigned at the tenant-root management group",
      severity=Severity.CRITICAL, category=Category.RBAC,
      description="A principal holds a write-capable role (Owner, Contributor, User Access "
                  "Administrator, RBAC Administrator, or a custom role) at the TENANT-ROOT management "
                  "group - the apex Azure scope. A role here is inherited by every management group, "
                  "subscription, resource group and resource in the tenant, so it is effectively "
                  "whole-tenant control. This is the single broadest blast radius in Azure RBAC and "
                  "should be held by no standing principal.",
      remediation="Remove standing role assignments at the root management group. If a role is "
                  "genuinely needed tenant-wide, scope it to a specific management group or "
                  "subscription, and grant it just-in-time via PIM to a minimal, named set.",
      data_source=[NodeKind.MANAGEMENT_GROUP],
      frameworks={"MITRE ATT&CK": "T1098", "CIS Azure": "1.23", "Azure Threat Matrix": "AZT402"})
def role_at_root_mg(g: Graph):
    troot = (str(g.tenant_id or "").split("/")[-1]).lower()
    if not troot:
        return []
    _WRITE = C.RBAC_ESCALATION_ROLES | {"contributor"}
    rows = []
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            scope = (e.evidence.get("scope") or "")
            role = (e.evidence.get("role") or "")
            rl = role.lower()
            if ("managementgroups/" + troot) in scope.lower() and (
                    rl in _WRITE or rl.startswith("custom role")):
                rows.append((p.id, role))
    return _ents_by_principal(g, rows)


@rule(id="AZ-GRP-007", title="Group is nested inside a Tier-0 group",
      severity=Severity.HIGH, category=Category.GROUP,
      description="A group is a MEMBER of a Tier-0 group, so every member of the child group "
                  "transitively inherits the parent's Tier-0 privilege. Nested membership hides "
                  "privilege one level down, where a review of the Tier-0 group's DIRECT members "
                  "misses it, and expanding the child group silently expands Tier-0.",
      remediation="Remove the nesting, or govern the child group as Tier-0 too (tight membership, "
                  "accountable owners, access reviews). Prefer direct, reviewed membership of "
                  "privileged groups over nesting.",
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098", "Azure Threat Matrix": "AZT501.1"})
def group_nested_in_tier0(g: Graph):
    out = []
    for e in g.edges():
        if e.type != EdgeType.MEMBER_OF:
            continue
        child = g.node(e.src)
        parent = g.node(e.dst)
        if child and child.kind == NodeKind.GROUP and parent and "tier0" in parent.tags:
            members = sum(1 for _ in g.in_edges(child.id, EdgeType.MEMBER_OF))
            out.append(_ent(g, child.id, nested_in=parent.name, nested_in_id=parent.id,
                            member_count=members,
                            note=(f"nested inside Tier-0 group '{parent.name}' - its {members} "
                                  f"member(s) inherit Tier-0")))
    return out


@rule(id="AZ-GRP-008", title="Privileged dynamic group keyed on a user-settable attribute (self-join)",
      severity=Severity.HIGH, category=Category.GROUP,
      description="A privileged group (Tier-0, role-assignable, or holding a role) uses DYNAMIC "
                  "membership whose rule keys on a user-settable attribute - display name, mail, "
                  "other-mails, job title, department, city, country, and similar. A user who can "
                  "edit that attribute on their own profile can make themselves match the rule and "
                  "self-join the group, inheriting its privilege with no admin action.",
      remediation="Do not drive privileged group membership from user-editable attributes. Use "
                  "assigned membership for role-assignable / Tier-0 groups, or restrict dynamic "
                  "rules to admin-controlled attributes only.",
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098", "Azure Threat Matrix": "AZT501.1"})
def dynamic_group_self_join(g: Graph):
    _USER_CTRL = ("displayname", "mail", "othermails", "othermail", "jobtitle", "department",
                  "city", "country", "companyname", "givenname", "surname")
    out = []
    for n in g.nodes_of_kind(NodeKind.GROUP):
        rule = (n.props.get("membershipRule") or "").lower()
        if not rule:
            continue
        privileged = bool(n.tags & {"tier0", "role_assignable"}) \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_ENTRA_ROLE)) \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_RBAC_ROLE))
        if not privileged:
            continue
        matched = sorted({a for a in _USER_CTRL if ("user." + a) in rule})
        if matched:
            out.append(_ent(g, n.id, membership_attributes=matched,
                            note="privileged dynamic group keyed on user-settable attribute(s) - self-join risk"))
    return out


@rule(id="AZ-GRP-009", title="On-premises-synced group confers a privileged (Tier-0) role",
      severity=Severity.HIGH, category=Category.GROUP,
      description="A group synchronised from on-premises Active Directory (onPremisesSyncEnabled) is "
                  "role-assignable and/or already confers a Tier-0 directory or Azure role. Its "
                  "membership is mastered in on-prem AD, not Entra - so anyone who can edit that AD "
                  "group, or who compromises on-prem AD / AD Connect, silently gains the cloud "
                  "privilege. This bridges an on-premises compromise straight into Entra Tier-0, "
                  "outside cloud PIM, MFA and conditional-access controls.",
      remediation="Never confer Tier-0 / privileged roles through on-prem-synced groups. Grant "
                  "privilege via a cloud-only, role-assignable group with tightly governed, assigned "
                  "membership under PIM; if the group must stay synced, stop using it for privileged "
                  "role assignment.",
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1078.004"})
def synced_privileged_group(g: Graph):
    out = []
    for n in g.nodes_of_kind(NodeKind.GROUP):
        if not n.props.get("onPremisesSyncEnabled"):
            continue
        confers = bool(n.tags & {"tier0", "role_assignable"}) \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_ENTRA_ROLE)) \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_RBAC_ROLE))
        if not confers:
            continue
        out.append(_ent(g, n.id, synced_from_on_prem=True,
                        role_assignable=("role_assignable" in n.tags),
                        confers_tier0=("tier0" in n.tags),
                        note="on-prem-synced group holds/eligible for a privileged role - hybrid bridge"))
    return out


@rule(id="AZ-GRP-010", title="Publicly-joinable group confers a privileged role (self-join escalation)",
      severity=Severity.HIGH, category=Category.GROUP,
      description="A Microsoft 365 group with Public visibility confers a Tier-0 or Azure/directory "
                  "role. Any member of the organisation can join a Public group themselves, without "
                  "owner approval - so anyone can self-join and inherit whatever privilege the group "
                  "carries. Privilege must never sit behind a self-service, publicly-joinable group.",
      remediation="Set the group's visibility to Private (owner-approved membership) or, better, do "
                  "not confer privilege through a Microsoft 365 group at all - use a security / "
                  "role-assignable group with assigned membership under PIM.",
      data_source=[NodeKind.GROUP],
      frameworks={"MITRE ATT&CK": "T1098"})
def public_privileged_group(g: Graph):
    out = []
    for n in g.nodes_of_kind(NodeKind.GROUP):
        if str(n.props.get("visibility", "")).lower() != "public":
            continue
        confers = "tier0" in n.tags \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_ENTRA_ROLE)) \
            or any(True for _ in g.out_edges(n.id, EdgeType.HAS_RBAC_ROLE))
        if confers:
            out.append(_ent(g, n.id, visibility="Public",
                            confers_tier0=("tier0" in n.tags),
                            note="public (self-joinable) Microsoft 365 group confers a privileged role"))
    return out


@rule(id="AZ-APP-027", title="Guest / external user owns an application or service principal",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A guest (external / B2B) user is an owner of an application registration or "
                  "service principal. An owner can add a credential (client secret or certificate) "
                  "to the app and then authenticate AS it - so an external identity governed by "
                  "another organisation can take over the app and everything it can reach. This "
                  "crosses the external-to-internal trust boundary through app ownership.",
      remediation="Remove guest owners from all application registrations and service principals. "
                  "Restrict app ownership to cloud-only accounts governed by this tenant.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.001", "Azure Threat Matrix": "AZT405.3"})
def guest_owns_app(g: Graph):
    seen: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type != EdgeType.OWNS:
            continue
        owner = g.node(e.src)
        target = g.node(e.dst)
        if owner and "guest" in owner.tags and target and target.kind in (NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
            seen.setdefault(target.id, [])
            if owner.name not in seen[target.id]:
                seen[target.id].append(owner.name)
    return [_ent(g, tid, guest_owners=owners,
                 note=(f"external/guest owner(s) {', '.join(owners)} can add a credential and "
                       f"authenticate as this identity"))
            for tid, owners in seen.items()]


@rule(id="AZ-HYG-006", title="Disabled account owns an application or service principal",
      severity=Severity.MEDIUM, category=Category.HYGIENE,
      description="A disabled user account is an owner of an application or service principal. The "
                  "app has no active accountable owner, and if the account is re-enabled (or "
                  "compromised through a residual path) it immediately regains the ability to add a "
                  "credential and authenticate as the app - a stale-governance and latent-takeover "
                  "risk.",
      remediation="Reassign ownership to an active, accountable cloud-only owner, or decommission "
                  "the app. Remove disabled accounts from all application/service-principal ownership.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.001"})
def disabled_owns_app(g: Graph):
    seen: dict[str, list[str]] = {}
    for e in g.edges():
        if e.type != EdgeType.OWNS:
            continue
        owner = g.node(e.src)
        target = g.node(e.dst)
        if owner and "disabled" in owner.tags and target and target.kind in (NodeKind.APP, NodeKind.SERVICE_PRINCIPAL):
            seen.setdefault(target.id, [])
            if owner.name not in seen[target.id]:
                seen[target.id].append(owner.name)
    return [_ent(g, tid, disabled_owners=owners,
                 note=f"disabled owner(s) {', '.join(owners)} - no active accountable owner")
            for tid, owners in seen.items()]


# --------------------------------------------------------------------------- #
# v2 Phase 1 batch 6 - IMPACT tactic (destruction / ransomware / resource
# hijacking / account access removal) and Discovery (estate-wide recon). These
# are capabilities distinct from privilege ESCALATION: a Contributor cannot grant
# itself a role, but it CAN wipe or ransom the subscription - a different, equally
# severe outcome the escalation rules do not surface.
# --------------------------------------------------------------------------- #
# NOTE: a former AZ-RBAC-018 ("broad-scope Contributor → destruction") was removed as a
# duplicate of AZ-RBAC-003 (Owner/Contributor sprawl), which already lists the same
# broad-scope Contributor principals. The data-destruction / ransomware IMPACT lens it
# added is preserved by mapping AZ-RBAC-003 to T1485 + the Impact tactic (see the
# framework-enrichment table and AZ-RBAC-003's knowledge entry).
@rule(id="AZ-RBAC-017", title="Reader at management-group scope - full-estate reconnaissance surface",
      severity=Severity.LOW, category=Category.RBAC, best_practice=True,
      description="A principal holds Reader at management-group scope, so it can enumerate every "
                  "subscription, resource, configuration and role assignment beneath that management "
                  "group. Reader cannot change anything, but compromise of such a principal hands an "
                  "attacker a complete, authenticated map of the estate - network layout, resource "
                  "inventory, identities, and where the crown jewels are - which is the reconnaissance "
                  "that precedes every targeted attack. Broad read is routinely over-granted to "
                  "monitoring and automation and rarely reviewed.",
      remediation="Scope read access to the specific management groups or subscriptions each workload "
                  "needs. Prefer purpose-built roles (e.g. Security Reader, Monitoring Reader) over "
                  "blanket Reader at a high management-group scope, and review broad-read grants.",
      data_source=[NodeKind.MANAGEMENT_GROUP],
      frameworks={"MITRE ATT&CK": "T1580", "MS Threat Matrix": "Reconnaissance"})
def reader_at_mg(g: Graph):
    rows = []
    for p in g.nodes_of_kind(NodeKind.USER, NodeKind.GROUP, NodeKind.SERVICE_PRINCIPAL):
        for e in g.out_edges(p.id, EdgeType.HAS_RBAC_ROLE):
            scope = (e.evidence.get("scope") or "")
            if (e.evidence.get("role") or "").lower() == "reader" and "managementgroups/" in scope.lower():
                rows.append((p.id, e.evidence.get("role"), scope))
    return _ents_by_principal(g, rows)


@rule(id="AZ-IDENT-018", title="Principal can reset or disable accounts tenant-wide (mass lockout / takeover)",
      severity=Severity.HIGH, category=Category.IDENTITY,
      description="A principal effectively holds a role that can reset passwords / replace MFA methods "
                  "and disable accounts across the tenant - User Administrator, Global Administrator, or "
                  "Privileged Authentication Administrator. Beyond the escalation angle (resetting one "
                  "admin), this is a mass-IMPACT capability: the holder can disable or reset EVERY user, "
                  "denying the whole organisation access (an availability / extortion event) or taking "
                  "over accounts at scale.",
      remediation="Minimise standing holders of tenant-wide user-management roles; use PIM just-in-time "
                  "activation with approval, and alert on bulk password-reset / account-disable actions.",
      data_source=[NodeKind.USER, NodeKind.ROLE],
      frameworks={"MITRE ATT&CK": "T1531", "MS Threat Matrix": "Impact"})
def mass_account_lockout(g: Graph):
    _LOCKOUT_ROLES = {"user administrator", "global administrator",
                      "privileged authentication administrator"}
    return _ents_by_principal(g, [
        (p.id, role.name)
        for p, role, ev in _effective_role_holders(g, lambda r: (r.name or "").lower() in _LOCKOUT_ROLES)
    ])


@rule(id="AZ-APP-028", title="External app holds a dangerous APPLICATION (app-only) Graph permission",
      severity=Severity.HIGH, category=Category.APPLICATION,
      description="A service principal whose app registration lives in ANOTHER tenant holds a "
                  "high-impact Microsoft Graph APPLICATION (app-only) permission in this tenant - "
                  "e.g. Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory, Mail.ReadWrite.All, "
                  "Files/Sites.ReadWrite.All. Application permissions need NO signed-in user: the "
                  "external app authenticates with its own credential (held in its home tenant) and "
                  "acts app-only against your directory or data, tenant-wide, with no user interaction. "
                  "So a third-party SaaS - or a compromise of it - can write to your directory or "
                  "read/modify all mail and files, and you hold no credential to revoke, only the "
                  "grant. Distinct from the delegated-consent findings (AZ-APP-023/025), which need a "
                  "user to sign in.",
      remediation="Review every application-permission grant to a foreign / multi-tenant service "
                  "principal. Revoke what is not required, prefer delegated + least-privilege, and "
                  "require admin review for any app-only directory- or data-write grant to an external app.",
      data_source=[NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1098.001", "Azure Threat Matrix": "AZT405.1"})
def foreign_app_only_dangerous(g: Graph):
    out = []
    for sp in g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL):
        if "foreign_tenant" not in sp.tags:
            continue
        roles = {(r.get("value") or "") for r in (sp.props.get("_granted_app_roles") or [])}
        dang = sorted(roles & set(C.DANGEROUS_GRAPH_APP_ROLES))
        if dang:
            crit = any((C.DANGEROUS_GRAPH_APP_ROLES.get(d) or {}).get("tier") == "critical" for d in dang)
            out.append(_ent(g, sp.id, permissions=dang[:6],
                            app_owner_tenant=sp.props.get("_owner_org"),
                            note=("external app holds app-only " + ", ".join(dang[:3]) +
                                  " - acts on your tenant with no signed-in user"
                                  + (" (critical directory/role write)" if crit else ""))))
    return out


@rule(id="AZ-APP-029", title="Credential (certificate/key) reused across multiple applications",
      severity=Severity.MEDIUM, category=Category.APPLICATION,
      description="The same certificate/key credential (identified by thumbprint / "
                  "customKeyIdentifier) is registered on two or more distinct applications or service "
                  "principals. A single stolen private key then authenticates as ALL of them, so the "
                  "blast radius of one credential compromise is every identity that shares it - and "
                  "rotating safely means coordinating the change across all of them at once.",
      remediation="Issue a unique credential per application / service principal. Never share a "
                  "certificate or key across identities; rotate any shared credential and re-issue "
                  "distinct ones.",
      data_source=[NodeKind.APP, NodeKind.SERVICE_PRINCIPAL],
      frameworks={"MITRE ATT&CK": "T1552", "Best Practice": "Credential isolation"})
def shared_credential(g: Graph):
    from collections import defaultdict
    idmap: dict[str, list[str]] = defaultdict(list)
    node: dict[str, object] = {}
    for n in list(g.nodes_of_kind(NodeKind.APP)) + list(g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL)):
        node[n.id] = n
        for c in (n.props.get("keyCredentials") or []):
            tid = c.get("customKeyIdentifier") or c.get("thumbprint")
            if tid and n.id not in idmap[str(tid)]:
                idmap[str(tid)].append(n.id)
    out, seen = [], set()
    for nids in idmap.values():
        if len(nids) < 2:
            continue
        for nid in nids:
            if nid in seen:
                continue
            seen.add(nid)
            others = [node[x].name for x in nids if x != nid]
            out.append(_ent(g, nid, shared_with=others[:5],
                            note=f"shares a certificate/key credential with {len(nids) - 1} other identity(ies)"))
    return out


# ── Record dependencies (audit F-03) ──────────────────────────────────────────
# A rule that reads relationship records must be reported NOT ASSESSED - never a
# silent clean pass - when those records were not collected. Node presence alone
# cannot distinguish "no dangerous grants exist" from "grant records were never
# ingested". Annotated post-registration to keep each rule's decorator readable.
_GRANT_RECORDS = ["AZAppRoleAssignment"]            # MS Graph app-permission grants
_ROLE_RECORDS = ["AZRoleAssignment"]                # active directory-role assignments
_ELIGIBLE_RECORDS = ["AZRoleEligibilityScheduleInstance"]   # PIM-eligible roles
_DELEGATED_RECORDS = ["AZOAuth2GrantDelegated"]     # OAuth2 delegated permission grants
# Azure (ARM) RBAC assignment records - both the per-resource assignment kinds and the
# newer flat edge kinds. A rule that reads HAS_RBAC_ROLE (or an edge derived from it)
# finds nothing when these were never collected; without this gate that read as a clean
# pass on the entire resource-plane RBAC domain. Sourced from normalize so the two stay
# in sync as AzureHound's kinds evolve.
from ..normalize import _FLAT_RBAC_KINDS, _RBAC_ASSIGNMENT_KINDS  # noqa: E402
_RBAC_RECORDS = sorted(set(_RBAC_ASSIGNMENT_KINDS) | set(_FLAT_RBAC_KINDS))

_RECORD_REQUIREMENTS: dict[str, list[str]] = {
    # App-permission rules read _granted_app_roles, built only from AZAppRoleAssignment.
    "AZ-APP-001": _GRANT_RECORDS, "AZ-APP-002": _GRANT_RECORDS,
    "AZ-APP-009": _GRANT_RECORDS, "AZ-APP-010": _GRANT_RECORDS,
    "AZ-APP-011": _GRANT_RECORDS, "AZ-APP-014": _GRANT_RECORDS,
    "AZ-APP-015": _GRANT_RECORDS, "AZ-APP-016": _GRANT_RECORDS,
    # Directory-role rules read active role assignments (AZRoleAssignment).
    "AZ-IDENT-001": _ROLE_RECORDS, "AZ-IDENT-003": _ROLE_RECORDS,
    "AZ-IDENT-004": _ROLE_RECORDS, "AZ-IDENT-005": _ROLE_RECORDS,
    "AZ-IDENT-006": _ROLE_RECORDS, "AZ-IDENT-007": _ROLE_RECORDS,
    "AZ-IDENT-008": _ROLE_RECORDS, "AZ-IDENT-009": _ROLE_RECORDS,
    "AZ-IDENT-016": _ROLE_RECORDS, "AZ-APP-007": _ROLE_RECORDS,
    # The PIM shadow-admin rule reads eligibility records specifically.
    "AZ-IDENT-010": _ELIGIBLE_RECORDS,
    # Delegated-consent rules read OAuth2 grant records.
    "AZ-APP-017": _DELEGATED_RECORDS, "AZ-APP-023": _DELEGATED_RECORDS,
    # The bulk/lower-data rules read delegated grants AND app-only app-role grants,
    # so either record kind makes them assessable.
    "AZ-APP-025": _DELEGATED_RECORDS + _GRANT_RECORDS,
    "AZ-APP-026": _DELEGATED_RECORDS + _GRANT_RECORDS,
    # Azure RBAC rules read HAS_RBAC_ROLE (or an edge derived purely from it): scope-sprawl,
    # managed-identity privilege, compute→MI theft, disabled-but-RBAC accounts, storage-key
    # access. These have NO non-RBAC data source, so missing RBAC records must read as
    # not-assessed, never a clean pass. (The Key Vault reachability rules are deliberately
    # NOT here: they also derive from AZKeyVaultAccessPolicy, so RBAC absence alone does not
    # blind them.)
    "AZ-RBAC-001": _RBAC_RECORDS, "AZ-RBAC-002": _RBAC_RECORDS,
    "AZ-RBAC-003": _RBAC_RECORDS, "AZ-RBAC-004": _RBAC_RECORDS,
    "AZ-RBAC-005": _RBAC_RECORDS, "AZ-RBAC-006": _RBAC_RECORDS,
    "AZ-RBAC-010": _RBAC_RECORDS, "AZ-RBAC-011": _RBAC_RECORDS,
    "AZ-MI-001": _RBAC_RECORDS, "AZ-PATH-002": _RBAC_RECORDS,
    "AZ-HYG-005": _RBAC_RECORDS, "AZ-STOR-002": _RBAC_RECORDS,
    # Registry-push concentration derives purely from Azure RBAC (AcrPush/Contributor).
    "AZ-RBAC-015": _RBAC_RECORDS,
    # Root-MG role assignment reads HAS_RBAC_ROLE only.
    "AZ-RBAC-016": _RBAC_RECORDS,
    "AZ-RBAC-017": _RBAC_RECORDS,
    "AZ-IDENT-018": _ROLE_RECORDS,
    # Foreign app-only dangerous perm reads _granted_app_roles (AZAppRoleAssignment).
    "AZ-APP-028": _GRANT_RECORDS,
}
for _rule in REGISTRY:
    if _rule.id in _RECORD_REQUIREMENTS:
        _rule.requires_records = _RECORD_REQUIREMENTS[_rule.id]


# ── Framework mapping enrichment ───────────────────────────────────────────────
# A coverage audit against the current MITRE ATT&CK cloud matrix, the Microsoft Azure
# Threat Research Matrix (ATRM, https://microsoft.github.io/Azure-Threat-Research-Matrix)
# and CIS Azure Foundations showed our DETECTION was complete for AzureHound-derivable
# techniques, but the MAPPING was thin: 18 rules carried no ATT&CK technique (so they were
# invisible in the threat-coverage view) and we tagged only ATRM TACTIC NAMES, never the
# granular AZT### technique ids. This table, applied post-registration, fills the missing
# ATT&CK ids and adds the specific ATRM technique id for every rule that maps to one, so a
# reviewer can trace each finding to both frameworks. Merge semantics: keys here are added
# to (and win over) the decorator's frameworks, so a rule keeps its CIS / Best-Practice
# tags and gains the technique ids. `_ATRM` = the "Azure Threat Matrix" key.
_ATRM = "Azure Threat Matrix"
_FRAMEWORK_ENRICH: dict[str, dict] = {
    # ---- Applications & service principals ----
    "AZ-APP-001": {_ATRM: "AZT405.1"}, "AZ-APP-002": {_ATRM: "AZT405.1"},
    "AZ-APP-003": {_ATRM: "AZT405.3"}, "AZ-APP-004": {_ATRM: "AZT501.2"},
    "AZ-APP-005": {_ATRM: "AZT201.2"}, "AZ-APP-007": {_ATRM: "AZT405.1"},
    "AZ-APP-008": {_ATRM: "AZT501.2"}, "AZ-APP-009": {_ATRM: "AZT508"},
    "AZ-APP-010": {_ATRM: "AZT401"},   "AZ-APP-011": {_ATRM: "AZT501.1"},
    "AZ-APP-014": {_ATRM: "AZT604"},   "AZ-APP-015": {_ATRM: "AZT507.4"},
    "AZ-APP-016": {_ATRM: "AZT203"},   "AZ-APP-017": {_ATRM: "AZT203"},
    "AZ-APP-018": {_ATRM: "AZT501.2"}, "AZ-APP-019": {_ATRM: "AZT501.2"},
    "AZ-APP-020": {_ATRM: "AZT203"},   "AZ-APP-022": {_ATRM: "AZT405.3"},
    "AZ-APP-023": {_ATRM: "AZT203"},   "AZ-APP-024": {_ATRM: "AZT501.2"},
    "AZ-APP-025": {_ATRM: "AZT203"},   "AZ-APP-026": {_ATRM: "AZT203"},
    # MITRE fills for previously-unmapped app rules.
    "AZ-APP-006": {"MITRE ATT&CK": "T1199", _ATRM: "AZT203"},
    "AZ-APP-013": {"MITRE ATT&CK": "T1098.001", _ATRM: "AZT501.2"},
    "AZ-APP-030": {_ATRM: "AZT203"},
    # ---- Identity / directory roles / PIM ----
    "AZ-IDENT-001": {_ATRM: "AZT106.1"}, "AZ-IDENT-003": {_ATRM: "AZT201.2"},
    "AZ-IDENT-004": {_ATRM: "AZT502.3"}, "AZ-IDENT-005": {_ATRM: "AZT501.1"},
    "AZ-IDENT-006": {_ATRM: "AZT501.1"}, "AZ-IDENT-008": {_ATRM: "AZT501.1"},
    "AZ-IDENT-009": {_ATRM: "AZT501.1"}, "AZ-IDENT-010": {"MITRE ATT&CK": "T1548.005", _ATRM: "AZT401"},
    "AZ-IDENT-013": {"MITRE ATT&CK": "T1548.005", _ATRM: "AZT401"},
    "AZ-IDENT-015": {"MITRE ATT&CK": "T1548.005", _ATRM: "AZT401"},
    "AZ-IDENT-016": {_ATRM: "AZT502.3"}, "AZ-IDENT-017": {_ATRM: "AZT106.1"},
    "AZ-IDENT-007": {"MITRE ATT&CK": "T1556.007"},
    "AZ-IDENT-011": {_ATRM: "AZT106.1"}, "AZ-IDENT-012": {_ATRM: "AZT106.1"},
    # AZ-IDENT-002 (break-glass sufficiency) is an availability/resilience control, not an
    # attack technique - it keeps its CIS tag and intentionally has no ATT&CK/ATRM id.
    # ---- Groups ----
    "AZ-GRP-001": {_ATRM: "AZT501.1"},
    "AZ-GRP-003": {_ATRM: "AZT501.1"}, "AZ-GRP-004": {"MITRE ATT&CK": "T1098", _ATRM: "AZT405.3"},
    "AZ-GRP-005": {_ATRM: "AZT501.1"}, "AZ-GRP-006": {_ATRM: "AZT604.1"},
    "AZ-GRP-009": {_ATRM: "AZT501.1"}, "AZ-GRP-010": {_ATRM: "AZT501.1"},
    # ---- Azure RBAC ----
    "AZ-RBAC-001": {_ATRM: "AZT402"}, "AZ-RBAC-002": {_ATRM: "AZT402"},
    # AZ-RBAC-003 also carries the destruction/ransomware IMPACT lens absorbed from the
    # removed AZ-RBAC-018 (a broad Owner/Contributor can wipe or ransom the subscription).
    "AZ-RBAC-003": {"MITRE ATT&CK": "T1485", "MS Threat Matrix": "Impact", _ATRM: "AZT106.3"},
    "AZ-RBAC-004": {_ATRM: "AZT106.3"}, "AZ-RBAC-005": {_ATRM: "AZT402"},
    "AZ-RBAC-006": {_ATRM: "AZT601.1"}, "AZ-RBAC-007": {_ATRM: "AZT301.5"},
    "AZ-RBAC-008": {"MITRE ATT&CK": "T1078.004", _ATRM: "AZT106.3"},
    "AZ-RBAC-009": {_ATRM: "AZT301.4"}, "AZ-RBAC-010": {_ATRM: "AZT301.1"},
    "AZ-RBAC-011": {_ATRM: "AZT106.3"}, "AZ-RBAC-013": {_ATRM: "AZT402"},
    "AZ-RBAC-014": {_ATRM: "AZT605.1"}, "AZ-RBAC-015": {_ATRM: "AZT301.4"},
    "AZ-RBAC-016": {_ATRM: "AZT402"}, "AZ-RBAC-017": {_ATRM: "AZT106.3"},
    "AZ-IDENT-018": {_ATRM: "AZT501.1"},
    "AZ-IDENT-019": {_ATRM: "AZT501.1"},
    # AZ-IDENT-020 (no cloud-only break-glass GA) is a hybrid-resilience posture condition; it
    # keeps its MITRE T1556.007 mapping and intentionally carries no ATRM technique id.
    # ---- Managed identity / attack paths ----
    "AZ-MI-001": {_ATRM: "AZT601.1"}, "AZ-MI-002": {_ATRM: "AZT601.1"},
    "AZ-PATH-002": {_ATRM: "AZT601.1"}, "AZ-PATH-003": {_ATRM: "AZT501.1"},
    # ---- Key Vault ----
    "AZ-KV-001": {_ATRM: "AZT604.1"}, "AZ-KV-003": {_ATRM: "AZT604.1"},
    "AZ-KV-004": {_ATRM: "AZT604.3"}, "AZ-KV-007": {_ATRM: "AZT604.1"},
    "AZ-KV-010": {_ATRM: "AZT604.1"}, "AZ-KV-011": {_ATRM: "AZT604.1"},
    "AZ-KV-012": {_ATRM: "AZT604.1"},
    "AZ-KV-002": {"MITRE ATT&CK": "T1555.006"},
    "AZ-KV-005": {"MITRE ATT&CK": "T1485", _ATRM: "AZT704.1", "CIS Azure": "8.5"},
    "AZ-KV-006": {"MITRE ATT&CK": "T1552.001"},
    "AZ-KV-008": {"MITRE ATT&CK": "T1485", _ATRM: "AZT704.1", "CIS Azure": "8.5"},
    "AZ-KV-009": {"MITRE ATT&CK": "T1552.001"},
    # ---- Storage ----
    "AZ-STOR-001": {_ATRM: "AZT701.1", "CIS Azure": "3.7"}, "AZ-STOR-002": {_ATRM: "AZT605.1"},
    "AZ-STOR-003": {_ATRM: "AZT701.1"}, "AZ-STOR-004": {_ATRM: "AZT605.1", "CIS Azure": "3.8"},
    "AZ-STOR-009": {_ATRM: "AZT703", "CIS Azure": "3.15"},
    "AZ-APP-031":  {_ATRM: "AZT501.2"},       # client secret over certificate (new best-practice rule)
    "AZ-STOR-007": {"MITRE ATT&CK": "T1530"}, "AZ-STOR-008": {"MITRE ATT&CK": "T1530"},
    # ---- Compute ----
    "AZ-VM-001": {"MITRE ATT&CK": "T1542"},
    "AZ-LOGIC-001": {_ATRM: "AZT503.1"},
    # ---- Hygiene fills ----
    "AZ-HYG-001": {"MITRE ATT&CK": "T1199"}, "AZ-HYG-002": {"MITRE ATT&CK": "T1078.004"},
    "AZ-HYG-003": {"MITRE ATT&CK": "T1098"},  "AZ-HYG-004": {"MITRE ATT&CK": "T1098.001"},
    "AZ-HYG-007": {_ATRM: "AZT501.2"},
}
for _rule in REGISTRY:
    _enrich = _FRAMEWORK_ENRICH.get(_rule.id)
    if _enrich:
        _rule.frameworks = {**_rule.frameworks, **_enrich}
