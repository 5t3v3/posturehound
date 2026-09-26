"""Pre-assessment asset inventory + recommended Tier-0.

Between the collect phase and the assessment phase the user may pick extra Tier-0
assets. This builds, from the collected blobs, a browsable inventory (assets grouped
by category, each with a display name + a short detail) and a recommended Tier-0 list
(the assets the deterministic engine would auto-detect as Tier-0, each with a reason).

It runs only the cheap front of the pipeline - parse → build graph → expand effective
roles → tag Tier-0 - never the full escalation derivation, so it stays fast.
"""
from __future__ import annotations

from typing import Any

from . import constants as C
from . import ingest
from .normalize import build_graph
from .model import Graph, NodeKind, EdgeType
from .derive import _expand_effective_roles, _tag_tier0, _is_tier0_role

# Category display order + labels - principals first (the usual Tier-0 crown jewels),
# then resources. Only categories with at least one asset are surfaced.
_CATEGORY_ORDER: list[tuple[str, str]] = [
    (NodeKind.USER.value, "Users"),
    (NodeKind.GROUP.value, "Groups"),
    (NodeKind.SERVICE_PRINCIPAL.value, "Service Principals"),
    (NodeKind.APP.value, "App Registrations"),
    (NodeKind.ROLE.value, "Directory Roles"),
    (NodeKind.MANAGEMENT_GROUP.value, "Management Groups"),
    (NodeKind.SUBSCRIPTION.value, "Subscriptions"),
    (NodeKind.KEY_VAULT.value, "Key Vaults"),
    (NodeKind.STORAGE.value, "Storage Accounts"),
    (NodeKind.AKS.value, "AKS Clusters"),
    (NodeKind.CONTAINER_REGISTRY.value, "Container Registries"),
    (NodeKind.AUTOMATION.value, "Automation Accounts"),
    (NodeKind.VM.value, "Virtual Machines"),
    (NodeKind.VMSS.value, "VM Scale Sets"),
    (NodeKind.FUNCTION_APP.value, "Function Apps"),
    (NodeKind.WEB_APP.value, "Web Apps"),
    (NodeKind.LOGIC_APP.value, "Logic Apps"),
    (NodeKind.RESOURCE_GROUP.value, "Resource Groups"),
    (NodeKind.DEVICE.value, "Devices"),
]
_LABELS = dict(_CATEGORY_ORDER)


def _detail(n) -> str:
    """A short, human line for the asset row (kept generic across kinds)."""
    p = n.props or {}
    k = n.kind
    if k == NodeKind.USER:
        upn = p.get("userPrincipalName") or p.get("mail") or ""
        bits = []
        if str(p.get("userType", "")).lower() == "guest":
            bits.append("Guest")
        if p.get("accountEnabled") is False:
            bits.append("disabled")
        return " · ".join([b for b in [upn] if b] + bits) or upn
    if k == NodeKind.GROUP:
        bits = []
        if p.get("isAssignableToRole"):
            bits.append("role-assignable")
        if p.get("securityEnabled"):
            bits.append("security")
        return " · ".join(bits)
    if k == NodeKind.SERVICE_PRINCIPAL:
        bits = []
        t = p.get("servicePrincipalType")
        if t:
            bits.append(str(t))
        if p.get("accountEnabled") is False:
            bits.append("disabled")
        return " · ".join(bits)
    if k == NodeKind.APP:
        return str(p.get("appId") or "")
    if k in (NodeKind.SUBSCRIPTION, NodeKind.MANAGEMENT_GROUP, NodeKind.RESOURCE_GROUP):
        return str(p.get("subscriptionId") or p.get("id") or "")
    return ""


def _recommend_reason(n, g: "Graph") -> str | None:
    """Why the engine considers this node Tier-0 (None if it is not)."""
    if n.kind == NodeKind.ROLE:
        return "Privileged directory role" if _is_tier0_role(n) else None
    if "tier0" not in n.tags:
        return None
    # A holder of a Tier-0 directory role (active).
    for e in g.out_edges(n.id, EdgeType.EFFECTIVE_ROLE):
        role = g.node(e.dst)
        if role and _is_tier0_role(role):
            return f"Holds {role.name}"
    # Owner / User Access Administrator at subscription or management-group scope.
    for e in g.out_edges(n.id, EdgeType.HAS_RBAC_ROLE):
        role = (e.evidence.get("role") or "").lower()
        scope = e.evidence.get("scope") or ""
        if role in C.RBAC_ESCALATION_ROLES and C.is_at_broad_scope(scope):
            return f"{(e.evidence.get('role') or 'Owner')} at subscription/MG scope"
    if n.kind == NodeKind.GROUP and (n.props or {}).get("isAssignableToRole"):
        return "Role-assignable group"
    return "Meets Tier-0 criteria"


def build_inventory(blobs: list[tuple[bytes, str]]) -> dict[str, Any]:
    """Return {categories, assets, recommended} for the Tier-0 selection UI.

    `assets` maps kind -> full sorted list; the API paginates/searches over it in memory
    so no re-parse happens per page. `recommended` is the auto-detected Tier-0 set.
    """
    ing = ingest.parse_many(blobs)
    g = build_graph(ing)
    # Cheap front of the pipeline only - enough to know what is Tier-0.
    _expand_effective_roles(g)
    _tag_tier0(g)

    assets: dict[str, list[dict]] = {}
    for n in g.nodes():
        kind = n.kind.value if hasattr(n.kind, "value") else str(n.kind)
        assets.setdefault(kind, []).append({
            "id": n.id,
            "name": n.name or n.id,
            "kind": kind,
            "detail": _detail(n),
            "tier0": "tier0" in n.tags,
        })
    for kind in assets:
        assets[kind].sort(key=lambda a: (a["name"] or a["id"]).lower())

    categories = [
        {"kind": kind, "label": _LABELS.get(kind, kind.replace("AZ", "")),
         "count": len(assets.get(kind, []))}
        for kind, _label in _CATEGORY_ORDER if assets.get(kind)
    ]
    # Any kinds not in the ordered list (future-proof) appended alphabetically.
    for kind in sorted(assets):
        if kind not in _LABELS and assets[kind]:
            categories.append({"kind": kind, "label": kind.replace("AZ", ""),
                               "count": len(assets[kind])})

    recommended: list[dict] = []
    for n in g.nodes():
        reason = _recommend_reason(n, g)
        if reason:
            recommended.append({
                "id": n.id, "name": n.name or n.id,
                "kind": n.kind.value if hasattr(n.kind, "value") else str(n.kind),
                "reason": reason,
            })
    recommended.sort(key=lambda a: (a["name"] or a["id"]).lower())

    return {"categories": categories, "assets": assets, "recommended": recommended,
            "total_assets": sum(len(v) for v in assets.values())}


def paginate(inventory: dict, category: str, q: str = "", page: int = 1,
             per_page: int = 20) -> dict[str, Any]:
    """Search + paginate one category's assets from a prebuilt inventory."""
    items = list((inventory.get("assets") or {}).get(category, []))
    q = (q or "").strip().lower()
    if q:
        items = [a for a in items
                 if q in (a["name"] or "").lower() or q in (a["id"] or "").lower()
                 or q in (a.get("detail") or "").lower()]
    total = len(items)
    per_page = max(1, min(int(per_page or 20), 100))
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(int(page or 1), pages))
    start = (page - 1) * per_page
    return {"items": items[start:start + per_page], "total": total,
            "page": page, "pages": pages, "per_page": per_page}
