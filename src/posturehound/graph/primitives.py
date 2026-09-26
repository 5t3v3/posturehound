"""Attack-primitive knowledge: how hard each escalation edge is, and why it exists.

One entry per escalation primitive (the `primitive` / EdgeType value that derive.py stamps on
an edge). It supplies:
  - weight:     traversal difficulty (lower = easier / more likely). Used for the cost-aware
                "easiest path" - a 1-hop path over a hard edge can be less likely than a 2-hop
                path over trivial ones.
  - why:        a plain explanation of the abuse, shown in the edge provenance panel.
  - conditions: extra pre-requisites an attacker needs (e.g. a compute foothold, a PIM activation).
  - technique:  a short category label.

Kept in one place (mirrors rules/knowledge.py for findings) so weights and explanations stay
consistent across the graph, the report, and any future scoring.
"""
from __future__ import annotations

# Default difficulty for a derived edge with no explicit entry.
DEFAULT_WEIGHT = 1.5

# primitive -> knowledge. weight: 0.5 trivial .. 3 hard.
PRIMITIVES: dict[str, dict] = {
    "EffectiveRole": {
        "title": "Holds directory role",
        "why": "Already holds this directory role, directly or through group membership - no action needed to use it.",
        "weight": 0.5, "conditions": [], "technique": "Valid privilege",
    },
    "CanAddMember": {
        "title": "Add group member",
        "why": "Can add a member to this group and inherit everything the group grants.",
        "weight": 1.0, "conditions": [], "technique": "Group manipulation",
    },
    "CanAddSecret": {
        "title": "Add credential to principal",
        "why": "Can add a client secret or certificate to this service principal / app, then authenticate as it.",
        "weight": 1.0, "conditions": [], "technique": "Credential injection",
    },
    "CanResetPassword": {
        "title": "Reset password",
        "why": "Can reset this account's password or authentication methods and take it over.",
        "weight": 1.0, "conditions": [], "technique": "Account takeover",
    },
    "CanAddOwner": {
        "title": "Take ownership",
        "why": "Can add itself as an owner of the target, gaining full control over it.",
        "weight": 1.5, "conditions": [], "technique": "Ownership abuse",
    },
    "CanGrantRole": {
        "title": "Grant directory role",
        "why": "Can assign a privileged Entra directory role (or grant itself a role-management permission and then assign one).",
        "weight": 2.0, "conditions": [], "technique": "Role assignment",
    },
    "CanGrantAppRole": {
        "title": "Grant app role / API permission",
        "why": "Can grant an application role or API permission (e.g. a dangerous Microsoft Graph permission) that leads to escalation.",
        "weight": 2.0, "conditions": [], "technique": "Consent / app role abuse",
    },
    "CanEscalateRBAC": {
        "title": "Escalate via Azure RBAC",
        "why": "Holds an Azure RBAC role that can write role assignments at this scope (e.g. Owner / User Access Administrator), so it can grant itself anything.",
        "weight": 2.0, "conditions": [], "technique": "RBAC escalation",
    },
    "CanReachKVSecret": {
        "title": "Read Key Vault secrets",
        "why": "Has data-plane access to read secrets, keys or certificates from this Key Vault.",
        "weight": 2.0, "conditions": [], "technique": "Secret access",
    },
    "CanStealManagedIdentity": {
        "title": "Abuse managed identity",
        "why": "Can execute on a resource that carries a managed identity and mint tokens as that identity.",
        "weight": 2.0, "conditions": ["requires_compute_foothold"], "technique": "Managed-identity abuse",
    },
    "CanGetStorageKey": {
        "title": "Retrieve storage keys",
        "why": "Can list this storage account's access keys and read or tamper with its data.",
        "weight": 2.0, "conditions": [], "technique": "Storage key theft",
    },
    "CanReadStorageBlob": {
        "title": "Read storage blobs",
        "why": "Has data-plane read access to this storage account's blob data.",
        "weight": 1.5, "conditions": [], "technique": "Data access",
    },
    "CanExecAKS": {
        "title": "Exec on AKS",
        "why": "Can exec into workloads on this Kubernetes cluster and abuse the identities available there.",
        "weight": 2.5, "conditions": ["requires_cluster_access"], "technique": "Container escape",
    },
    "CanPushContainer": {
        "title": "Push container image",
        "why": "Can push images to this container registry, poisoning workloads that pull from it.",
        "weight": 2.5, "conditions": [], "technique": "Supply-chain",
    },
    "EligibleForRole": {
        "title": "PIM-eligible for role",
        "why": "Is eligible (via PIM) for this role and can self-activate it - a standing shadow-admin path.",
        "weight": 2.0, "conditions": ["requires_pim_activation"], "technique": "PIM abuse",
    },
}

# Light labels for the raw (structural) relationships, for the provenance panel on expand.
RAW_RELATIONSHIPS: dict[str, str] = {
    "MemberOf": "Is a member of this group.",
    "Owns": "Owns this object.",
    "HasEntraRole": "Holds this Entra directory role.",
    "HasRBACRole": "Holds this Azure RBAC role assignment.",
    "Contains": "Contains this child resource (management hierarchy).",
    "KVAccess": "Has a Key Vault access-policy entry.",
    "HasManagedIdentity": "Has this managed identity assigned.",
    "HasAppRole": "Has this application role granted.",
}


# Why each Tier-0 Entra role earns the label - shown as the justification in node details.
TIER0_ROLE_INFO: dict[str, str] = {
    "global administrator": "Unrestricted control of the entire Entra tenant and Microsoft 365 - the top of the tenant.",
    "privileged role administrator": "Can assign any directory role to anyone (including Global Administrator) - a direct path to full control.",
    "privileged authentication administrator": "Can reset authentication methods / MFA for any user, including admins - account takeover of admins.",
    "authentication administrator": "Can reset authentication methods / MFA for non-admin users - account takeover.",
    "application administrator": "Can add credentials to any application or service principal and then authenticate as it, inheriting its access.",
    "cloud application administrator": "Can add credentials to applications/service principals and act as them (no on-prem proxy).",
    "user administrator": "Can create/manage users and reset passwords for many accounts, including some admins.",
    "password administrator": "Can reset passwords for non-administrator accounts - account takeover.",
    "security administrator": "Can read and manage tenant security settings and policies across the estate.",
    "conditional access administrator": "Can change Conditional Access policies - e.g. disable MFA or location controls - weakening tenant-wide auth.",
    "exchange administrator": "Full control of Exchange Online - mailboxes, transport rules, delegation.",
    "sharepoint administrator": "Full control of SharePoint/OneDrive content across the tenant.",
    "intune administrator": "Can push scripts and configuration to managed devices - code execution on endpoints.",
    "hybrid identity administrator": "Controls directory synchronization / on-prem federation - can forge or sync cloud identities.",
    "directory synchronization accounts": "The Entra Connect sync identity - effectively writes to the directory; abused for privilege escalation.",
    "domain name administrator": "Can manage custom domains and federation settings - enables federation-trust takeover.",
    "cloud device administrator": "Can manage devices, disable them, and read BitLocker recovery keys.",
    "partner tier2 support": "Legacy partner role with broad administrative privileges over the tenant.",
    "partner tier1 support": "Legacy partner role that can reset passwords / invalidate tokens for non-admins.",
}

RBAC_BROAD_TIER0_DESC = ("Owner / User Access Administrator at subscription or management-group scope can "
                         "grant itself any role over every resource in that scope - full control of the resource plane.")
CUSTOM_TIER0_DESC = "Added to the Tier-0 set by an analyst."


def tier0_role_info(role_name: str | None) -> str | None:
    return TIER0_ROLE_INFO.get((role_name or "").strip().lower())


def knowledge_for(primitive: str | None, edge_type: str | None = None) -> dict:
    """Return {title, why, weight, conditions, technique} for an edge, raw or derived."""
    e = PRIMITIVES.get(primitive or "") or PRIMITIVES.get(edge_type or "")
    if e:
        return {"title": e["title"], "why": e["why"], "weight": float(e["weight"]),
                "conditions": list(e["conditions"]), "technique": e["technique"]}
    raw = RAW_RELATIONSHIPS.get(edge_type or "") or RAW_RELATIONSHIPS.get(primitive or "")
    return {"title": (edge_type or primitive or "relationship"),
            "why": raw or "", "weight": DEFAULT_WEIGHT, "conditions": [], "technique": ""}
