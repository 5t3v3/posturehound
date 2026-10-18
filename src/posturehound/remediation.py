"""Proactive, review-first remediation points for every finding's How-to-fix.

Two things a good fix should always say, but a per-rule `steps` list often omits:

  1. VALIDATE before you change. The access may be legitimately required, so confirm no live
     workload depends on it (owners, recent sign-ins, pipelines) and make the change under change
     control with a rollback, before removing anything.
  2. SCOPE instead of revoke where the workload genuinely needs the access. Narrow it to the
     specific mailbox / site / container / secret / scope rather than leaving it tenant-wide.

Computed deterministically from the finding, so it applies uniformly across every rule with no
per-rule editing, and at read time so existing scans get it too.
"""
from __future__ import annotations

_REVIEW = (
    "Validate before you change anything: this access may be required by a live workload, so "
    "first confirm nothing depends on it, check the application/role owners, recent sign-in and "
    "usage, and any pipelines that use the identity. Make the change under change control, out of "
    "hours, with a rollback plan, so a genuinely-needed grant is not removed blind."
)

_MAIL = (
    "Scope instead of revoke if mail access is genuinely needed: apply an Exchange Online "
    "Application Access Policy to limit the app to specific mailboxes or a mail-enabled group, or "
    "move to RBAC for Applications, and choose the narrowest scope (for example Mail.ReadBasic "
    "rather than Mail.ReadWrite.All)."
)
_SITES = (
    "Scope SharePoint/OneDrive access with Sites.Selected and per-site grants instead of a "
    "tenant-wide Sites/Files permission."
)
_STORAGE = (
    "Scope storage data access to the specific container or queue with an Azure RBAC data role at "
    "that scope, not the whole account; disable shared-key access and require Entra authentication."
)
_KV = (
    "Scope Key Vault access to only the secrets or keys the workload needs (an RBAC role at the "
    "individual secret scope, or a tightly-scoped access policy), not the whole vault; enable RBAC "
    "authorization."
)
_ARM = (
    "Replace user-delegated management access with a least-privilege Azure RBAC role on the "
    "specific subscription or resource scope, rather than impersonation across the whole tenant."
)
_RBAC = (
    "Re-assign at the narrowest scope that works (a resource or resource group, not the "
    "subscription or the root management group), and use PIM for just-in-time elevation instead of "
    "standing access."
)
_GRAPH = (
    "If some access is genuinely required, grant the narrowest permission that covers the use "
    "case: prefer a read-only or scoped variant, or a delegated permission with a signed-in user, "
    "over a broad .ReadWrite.All application role."
)

# Ordered most-specific first; the first match wins, so a storage/KV/RBAC finding is not captured
# by the broad Graph rule below it.
_SCOPE_RULES: list[tuple[tuple[str, ...], str]] = [
    (("mail.", "mailboxsettings", "full_access_as_app", "exchange online"), _MAIL),
    (("sites.", "files.", "sharepoint"), _SITES),
    (("az-stor", "storage blob", "storageaccount", "allowblobpublicaccess", "shared key"), _STORAGE),
    (("az-kv", "key vault", "keyvault", "accesspolic"), _KV),
    (("user_impersonation", "service management"), _ARM),
    (("az-rbac", "user access administrator", "privileged role"), _RBAC),
    (("readwrite.all", "read.all", ".readwrite", "rolemanagement", "directory.read",
      "application.read", "graph permission"), _GRAPH),
]


def _finding_text(finding: dict) -> str:
    """The lowercased permission/role surface of a finding: its id, title and every entity's
    evidence, plus any grouped members, so the scoping class can be detected from real data."""
    parts = [str(finding.get("rule_id") or ""), str(finding.get("title") or "")]
    for e in (finding.get("entities") or []):
        if isinstance(e, dict):
            ev = e.get("evidence")
            if isinstance(ev, dict):
                for k in ("appRole", "permission", "value", "role", "roles", "note", "impact",
                          "notable_permissions", "permissions", "apis"):
                    v = ev.get(k)
                    if isinstance(v, (list, tuple)):
                        parts.append(" ".join(str(x) for x in v))
                    elif v is not None:
                        parts.append(str(v))
    for m in (finding.get("_grouped") or []):
        parts.append(f"{m.get('rule_id', '')} {m.get('title', '')} {m.get('evidence', '')}")
    return " ".join(parts).lower()


def scoping_hint(finding: dict) -> "str | None":
    text = _finding_text(finding)
    for keywords, hint in _SCOPE_RULES:
        if any(k in text for k in keywords):
            return hint
    return None


def points(finding: dict) -> list[str]:
    """The augmented How-to-fix for a finding: a validate-first step, the rule's own steps, and a
    scope-it-down step when the finding touches a scopable permission class."""
    base = [s for s in ((finding.get("detail") or {}).get("steps") or []) if str(s).strip()]
    if not base:
        rem = str(finding.get("remediation") or "").strip()
        base = [rem] if rem else []
    out = [_REVIEW] + base
    hint = scoping_hint(finding)
    if hint and hint not in out:
        out.append(hint)
    return out
