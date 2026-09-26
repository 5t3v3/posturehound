"""Collection-completeness reconciliation.

The most dangerous failure mode is a *silent* one: a rule returns zero findings
not because the tenant is clean but because the relevant data was never collected
(low-privilege AzureHound run, default $select dropping a field, or a record kind
this tool doesn't yet parse). This module turns those silences into explicit
warnings so a clean-looking report is never mistaken for a clean tenant.
"""
from __future__ import annotations

from .model import EdgeType, Graph, NodeKind
from .normalize import CONSUMED_KINDS


def assess_collection(g: Graph) -> dict:
    by_kind = (g.ingest_summary or {}).get("by_kind", {})
    warnings: list[dict] = []

    def warn(level: str, code: str, msg: str) -> None:
        warnings.append({"level": level, "code": code, "message": msg})

    # 1. Record kinds present in the data that we do not consume → blind spots.
    unconsumed = sorted(k for k in by_kind if k not in CONSUMED_KINDS)
    if unconsumed:
        warn("info", "UNCONSUMED_KINDS",
             "Collection contains record kinds PostureHound does not yet evaluate: "
             + ", ".join(unconsumed) + ". Findings for these objects are not produced.")

    # 2. Whole-domain absence that usually means under-collection, not a clean tenant.
    n_app = len(g.nodes_of_kind(NodeKind.APP))
    n_sp = len(g.nodes_of_kind(NodeKind.SERVICE_PRINCIPAL))
    n_sub = len(g.nodes_of_kind(NodeKind.SUBSCRIPTION))
    n_kv = len(g.nodes_of_kind(NodeKind.KEY_VAULT))
    n_users = len(g.nodes_of_kind(NodeKind.USER))

    has_rbac = any(e.type == EdgeType.HAS_RBAC_ROLE for e in g.edges())
    has_entra_role = any(e.type == EdgeType.HAS_ENTRA_ROLE or e.type == EdgeType.EFFECTIVE_ROLE
                         for e in g.edges())
    has_kv_policy = any(
        e.type in (EdgeType.KV_ACCESS, EdgeType.CAN_REACH_KV_SECRET)
        for e in g.edges()
    )

    if g.tenant_id is None:
        warn("warning", "NO_TENANT", "No tenant object was collected; tenant-level context is missing.")
    if n_app == 0 and n_sp == 0:
        warn("warning", "NO_APPS",
             "No applications or service principals were collected - the Entra application plane "
             "appears un-enumerated. Application/SP escalation rules cannot fire.")
    if n_users > 0 and not has_entra_role:
        warn("warning", "NO_ENTRA_ROLES",
             "Users were collected but no directory-role assignments were - privileged-role rules "
             "cannot fire. Re-run collection with directory role data.")
    if n_sub > 0 and not has_rbac:
        warn("warning", "NO_RBAC",
             "Subscriptions were collected but no Azure RBAC role assignments were - the resource "
             "plane is blind. The collecting principal may lack read access to IAM.")
    if n_kv > 0 and not has_kv_policy:
        warn("info", "NO_KV_POLICY",
             "Key Vaults were collected but no access policies or RBAC secret-access edges were found - "
             "Key Vault data-plane exposure cannot be assessed. The vault may use RBAC-only authorization, "
             "or policies were not collected.")

    # 3. Field-level under-collection: AzureHound's default $select omits some
    #    properties, which silently blanks the rules that depend on them.
    users = g.nodes_of_kind(NodeKind.USER)
    if users and not any("onPremisesSyncEnabled" in (u.props or {}) for u in users):
        warn("warning", "NO_SYNC_FIELD",
             "No user has the onPremisesSyncEnabled property - AzureHound's default collection omits "
             "it, so the on-prem synced-admin check (AZ-IDENT-007) is blind. Collect with the field "
             "selected.")
    # accountEnabled coverage is a ratio, not all-or-nothing: warning only when the
    # field is absent everywhere hid the common case of partial collection, where the
    # users missing the field are silently treated as enabled.
    if users:
        with_enabled = sum(1 for u in users if "accountEnabled" in (u.props or {}))
        if with_enabled == 0:
            warn("info", "NO_ACCOUNT_ENABLED",
                 "No user has the accountEnabled property collected - disabled-account "
                 "checks (AZ-IDENT-006, AZ-HYG-005) cannot fire.")
        elif with_enabled < len(users) * 0.9:
            warn("warning", "PARTIAL_ACCOUNT_ENABLED",
                 f"Only {with_enabled} of {len(users)} users have accountEnabled collected - "
                 f"the remaining {len(users) - with_enabled} are assumed enabled, so "
                 f"disabled-but-privileged accounts among them cannot be detected.")

    # PIM role-eligibility. Without this, AZ-IDENT-010 returns zero and the pim_risk
    # specialist sees an empty section - both of which render as a clean pass. This is
    # the single most dangerous silence in the tool: "no shadow admins found" when the
    # truth is "shadow admins were never looked for".
    n_roles = len(g.nodes_of_kind(NodeKind.ROLE))
    has_pim_eligibility = any(e.type == EdgeType.ELIGIBLE_FOR_ROLE for e in g.edges())
    if n_roles > 0 and not has_pim_eligibility:
        warn("warning", "NO_PIM_ELIGIBILITY",
             "No PIM role-eligibility records were collected (AzureHound "
             "az-role-eligibility-schedule-instances), so PIM-eligible 'shadow admin' "
             "detection (AZ-IDENT-010) and the PIM-risk analysis are blind. This is NOT "
             "evidence that no standing-privilege-free eligibility exists.")

    # On-prem identity linkage. Every onPremises* field is omitted by AzureHound's
    # default $select, and the fact pack previously rendered that absence as
    # synced_from_onprem=false - asserting every Tier-0 principal is cloud-only.
    if users and not any(
        any(k.startswith("onPremises") for k in (u.props or {}))
        for u in users
    ):
        warn("warning", "NO_ONPREM_FIELDS",
             "No user carries any onPremises* property (SyncEnabled, ImmutableId, "
             "SamAccountName), so hybrid-identity analysis cannot determine whether any "
             "Tier-0 principal is synced from on-premises Active Directory. Treat "
             "hybrid findings as UNASSESSED rather than clean.")

    return {
        "warnings": warnings,
        "unconsumed_kinds": unconsumed,
        # Domains that are unassessable *for this collection*, derived from the warnings
        # above rather than hardcoded, so the report can name them precisely.
        "blind_domains": sorted({
            w["code"] for w in warnings if w["level"] == "warning"
        }),
        "signals": {
            "tenant": g.tenant_id is not None,
            "applications": n_app, "service_principals": n_sp,
            "subscriptions": n_sub, "key_vaults": n_kv, "users": n_users,
            "rbac_assignments_present": has_rbac,
            "entra_roles_present": has_entra_role,
            "kv_policies_present": has_kv_policy,
            "pim_eligibility_present": has_pim_eligibility,
            "onprem_fields_present": bool(users) and any(
                any(k.startswith("onPremises") for k in (u.props or {})) for u in users),
        },
        "complete": not any(w["level"] == "warning" for w in warnings),
    }
