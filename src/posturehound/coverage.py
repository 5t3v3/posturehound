"""Framework coverage: MITRE ATT&CK + Azure Threat Research Matrix (ATRM) tagging.

Every finding - deterministic rule or AI-generated - is stamped with both a MITRE ATT&CK
technique and the Microsoft Azure Threat Research Matrix (ATRM) technique it maps to, so the
report shows both and the tenant's coverage can be rendered as a matrix rather than asserted.

ATRM (https://microsoft.github.io/Azure-Threat-Research-Matrix/) is Microsoft's Azure-specific
ATT&CK-style matrix; its AZT IDs are the precise Azure attack techniques, where generic ATT&CK
techniques (e.g. T1098 Account Manipulation) are broad. We therefore key the ATRM mapping on
ATT&CK technique with per-rule overrides where the Azure technique is more specific than the
ATT&CK id alone conveys.
"""
from __future__ import annotations

import re

# The AI sometimes emits a technique as "T1098.001 (Additional Cloud Credentials)" or
# "T1098.003 Additional Cloud Roles" instead of the bare id. Extract the canonical id so
# coverage counts don't fragment and the ATRM lookup resolves.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _normalize_technique(s: str) -> str:
    m = _TECHNIQUE_RE.search(s or "")
    return m.group(0) if m else ""

# MITRE ATT&CK technique id -> display name, for the techniques PostureHound emits.
ATTACK_NAME: dict[str, str] = {
    "T1078": "Valid Accounts", "T1078.001": "Valid Accounts: Default Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation", "T1098.001": "Additional Cloud Credentials",
    "T1098.003": "Additional Cloud Roles",
    "T1110.003": "Brute Force: Password Spraying",
    "T1114.002": "Email Collection: Remote Email Collection",
    "T1190": "Exploit Public-Facing Application",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1210": "Exploitation of Remote Services",
    "T1213": "Data from Information Repositories",
    "T1484.002": "Domain Policy Modification: Trust Modification",
    "T1525": "Implant Internal Image",
    "T1528": "Steal Application Access Token",
    "T1530": "Data from Cloud Storage",
    "T1537": "Transfer Data to Cloud Account",
    "T1040": "Network Sniffing",
    "T1552.001": "Unsecured Credentials: Credentials in Files",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1556": "Modify Authentication Process",
    "T1562.008": "Impair Defenses: Disable Cloud Logs",
}

# ATT&CK technique -> (ATRM tactic, ATRM technique id, ATRM technique name). Best-fit mapping
# of the generic ATT&CK technique to Microsoft's Azure-specific ATRM technique. Per-rule
# overrides below take precedence where a rule's Azure technique is more specific.
ATTACK_TO_ATRM: dict[str, tuple[str, str, str]] = {
    "T1078":     ("Initial Access", "AZT201",   "Valid Credentials"),
    "T1078.001": ("Initial Access", "AZT201.1", "Valid Credentials: User Account"),
    "T1078.004": ("Initial Access", "AZT201.2", "Valid Credentials: Service Principal"),
    "T1110.003": ("Initial Access", "AZT202",   "Password Spraying"),
    "T1098":     ("Persistence",    "AZT501",   "Account Manipulation"),
    "T1098.001": ("Persistence",    "AZT501.2", "Service Principal Manipulation"),
    "T1098.003": ("Privilege Escalation", "AZT405.2", "Azure AD Application: Application Role"),
    "T1528":     ("Initial Access", "AZT203",   "Malicious Application Consent"),
    "T1484.002": ("Persistence",    "AZT507.4", "External Entity Access: Domain Trust Modification"),
    "T1556":     ("Persistence",    "AZT508",   "Azure Policy"),
    "T1552.001": ("Credential Access", "AZT604", "Azure KeyVault Dumping"),
    "T1552.005": ("Credential Access", "AZT601.1", "Steal Managed Identity JWT: VM IMDS Request"),
    "T1530":     ("Credential Access", "AZT605.1", "Resource Secret Reveal: Storage Account Access Key"),
    "T1537":     ("Impact",         "AZT703",   "Replication"),
    "T1525":     ("Execution",      "AZT301.4", "VM Scripting: Compute Gallery Application"),
    "T1021.006": ("Execution",      "AZT301.1", "VM Scripting: RunCommand"),
    "T1210":     ("Execution",      "AZT301",   "Virtual Machine Scripting"),
    "T1213":     ("Credential Access", "AZT605.3", "Resource Secret Reveal: RG Deployment History"),
    "T1190":     ("Reconnaissance", "AZT103",   "Public Accessible Resource"),
    "T1562.008": ("Persistence",    "AZT508",   "Azure Policy"),
    # ATT&CK-only (no clean ATRM analogue - M365 mail / transport-layer posture).
    "T1114.002": ("", "", ""),
    "T1040":     ("", "", ""),
}

# Deterministic rules missing a MITRE ATT&CK tag on their decorator get one here, so every
# finding is framework-tagged. (Governance/hygiene rules that model no adversary technique map
# to the closest enabling technique.)
RULE_ATTACK_FILL: dict[str, str] = {
    "AZ-APP-006": "T1199",       # Multi-tenant app -> Trusted Relationship
    "AZ-APP-013": "T1098.001",   # excessive stored SP credentials
    "AZ-GRP-004": "T1098",       # orphaned role-assignable group
    "AZ-HYG-001": "T1078.004",   # guest sprawl
    "AZ-HYG-002": "T1098.001",   # orphaned/disabled SP (credential persistence surface)
    "AZ-HYG-003": "T1098",       # direct (non-PIM) privileged assignment
    "AZ-HYG-004": "T1098.001",   # app without owner
    "AZ-IDENT-002": "T1078",     # insufficient break-glass GAs (availability of valid admin)
    "AZ-KV-002": "T1552.001",    # KV legacy access policies
    "AZ-KV-005": "T1490",        # purge/soft-delete disabled -> Inhibit System Recovery
    "AZ-KV-006": "T1552.001",    # KV network not restricted
    "AZ-KV-008": "T1490",        # short soft-delete retention
    "AZ-KV-009": "T1552.001",    # KV publicly reachable
    "AZ-RBAC-003": "T1098",      # Owner/Contributor sprawl
    "AZ-RBAC-008": "T1078.001",  # classic co-administrator
    "AZ-STOR-007": "T1530",      # storage network not restricted
    "AZ-STOR-008": "T1530",      # storage publicly reachable
    "AZ-VM-001": "T1078.004",    # no Trusted Launch (weakens VM identity assurance)
}
ATTACK_NAME.update({
    "T1199": "Trusted Relationship",
    "T1490": "Inhibit System Recovery",
    # Techniques the AI specialists legitimately emit that were missing display names,
    # so they rendered blank in the coverage matrix.
    "T1114":     "Email Collection",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1548":     "Abuse Elevation Control Mechanism",
    "T1550.001": "Use Alternate Authentication Material: Application Access Token",
    "T1087.004": "Account Discovery: Cloud Account",
    "T1485":     "Data Destruction",
})
ATTACK_TO_ATRM.update({
    "T1199": ("Persistence", "AZT507.2", "External Entity Access: Microsoft Partners"),
    "T1490": ("Impact",      "AZT704",   "Soft-Delete Recovery"),
    # ATRM analogues where Azure has a clean one; the rest stay ATT&CK-only (blank id).
    "T1548":     ("Privilege Escalation", "AZT402", "Elevated Access Toggle"),
    "T1195.002": ("Execution", "AZT301.4", "VM Scripting: Compute Gallery Application"),
    "T1550.001": ("", "", ""),   # app access-token reuse - no clean ATRM analogue
    "T1087.004": ("", "", ""),   # cloud account discovery - Discovery, ATT&CK-only
    "T1114":     ("", "", ""),
    "T1485":     ("Impact", "AZT703", "Replication"),
})

# Per-rule ATRM override where the Azure technique is more precise than the ATT&CK mapping.
RULE_ATRM_OVERRIDE: dict[str, tuple[str, str, str]] = {
    "AZ-APP-001": ("Privilege Escalation", "AZT405.1", "Azure AD Application: Application API Permissions"),
    "AZ-APP-002": ("Privilege Escalation", "AZT405.1", "Azure AD Application: Application API Permissions"),
    "AZ-APP-003": ("Privilege Escalation", "AZT405.3", "Azure AD Application: Application Registration Owner"),
    "AZ-APP-007": ("Persistence", "AZT501.2", "Account Manipulation: Service Principal"),
    "AZ-APP-008": ("Persistence", "AZT501.2", "Account Manipulation: Service Principal"),
    "AZ-APP-010": ("Privilege Escalation", "AZT401", "Privileged Identity Management Role"),
    "AZ-APP-015": ("Persistence", "AZT507.4", "External Entity Access: Domain Trust Modification"),
    "AZ-APP-016": ("Initial Access", "AZT203", "Malicious Application Consent"),
    "AZ-APP-017": ("Initial Access", "AZT203", "Malicious Application Consent"),
    "AZ-IDENT-001": ("Privilege Escalation", "AZT402", "Elevated Access Toggle"),
    "AZ-IDENT-004": ("Persistence", "AZT502.3", "Account Creation: Guest Account"),
    "AZ-IDENT-010": ("Privilege Escalation", "AZT401", "Privileged Identity Management Role"),
    "AZ-KV-001": ("Credential Access", "AZT604.1", "Azure KeyVault Secret Dump"),
    "AZ-KV-003": ("Credential Access", "AZT604.1", "Azure KeyVault Secret Dump"),
    "AZ-KV-004": ("Credential Access", "AZT604.3", "Azure KeyVault Key Dump"),
    "AZ-KV-007": ("Credential Access", "AZT604.1", "Azure KeyVault Secret Dump"),
    "AZ-KV-010": ("Credential Access", "AZT604.1", "Azure KeyVault Secret Dump"),
    "AZ-MI-001": ("Credential Access", "AZT601.1", "Steal Managed Identity JWT: VM IMDS Request"),
    "AZ-RBAC-006": ("Credential Access", "AZT601.1", "Steal Managed Identity JWT: VM IMDS Request"),
    "AZ-RBAC-007": ("Credential Access", "AZT601.2", "Steal Managed Identity JWT: AKS IMDS Request"),
    "AZ-RBAC-009": ("Execution", "AZT301.4", "VM Scripting: Compute Gallery Application"),
    "AZ-RBAC-010": ("Execution", "AZT301.1", "VM Scripting: RunCommand"),
    "AZ-STOR-002": ("Credential Access", "AZT605.1", "Resource Secret Reveal: Storage Account Access Key"),
    "AZ-STOR-004": ("Credential Access", "AZT605.1", "Resource Secret Reveal: Storage Account Access Key"),
    "AZ-STOR-009": ("Impact", "AZT703", "Replication"),
    "AZ-LOGIC-001": ("Persistence", "AZT503.1", "HTTP Trigger: Logic Application"),
    "AZ-KV-005": ("Impact", "AZT704.1", "Soft-Delete Recovery: Key Vault"),
    "AZ-KV-008": ("Impact", "AZT704.1", "Soft-Delete Recovery: Key Vault"),
}


# Keyword -> ATT&CK technique fallback for AI findings that arrive with NO technique and no
# attack_primitive. Ordered: first keyword found in the finding's category/title wins. Ensures
# every finding is framework-tagged instead of dropping out of the coverage matrix.
_CATEGORY_ATTACK_FALLBACK: list[tuple[tuple[str, ...], str]] = [
    (("managed identity", "imds", "workload identity"), "T1552.005"),
    (("key vault", "secret", "certificate"),            "T1552.001"),
    (("storage", "blob", "data exfil"),                 "T1530"),
    (("delegated", "consent", "oauth", "graph permission", "api permission"), "T1528"),
    (("credential", "add secret", "password", "key credential"), "T1098.001"),
    (("rbac", "owner", "contributor", "user access administrator", "role", "escalat", "privileged"), "T1098.003"),
    (("orphan", "ownerless", "hygiene", "disabled", "stale", "guest"), "T1078.004"),
    (("group", "member"),                               "T1098.003"),
]


def _category_attack_fallback(finding: dict) -> str:
    hay = f"{finding.get('category', '')} {finding.get('title', '')}".lower()
    for keys, tech in _CATEGORY_ATTACK_FALLBACK:
        if any(k in hay for k in keys):
            return tech
    return "T1078.004"   # broadest cloud-identity technique - never leave a finding untagged


def attack_for(rule_id: str | None, existing_attack: str = "",
               ai_mitre: str = "") -> str:
    """Resolve the MITRE ATT&CK technique for a finding: the rule's own tag, then a fill for
    rules missing one, then the AI-provided technique. Every source is normalised to the bare
    canonical id (the AI often appends the technique name, which broke lookups and split counts)."""
    if existing_attack:
        return _normalize_technique(existing_attack) or existing_attack.strip()
    if rule_id and rule_id in RULE_ATTACK_FILL:
        return RULE_ATTACK_FILL[rule_id]
    return _normalize_technique(ai_mitre)


def atrm_for(rule_id: str | None, attack: str) -> tuple[str, str, str] | None:
    """Resolve the ATRM (tactic, id, name) for a finding - per-rule override first, then the
    ATT&CK-to-ATRM map. Returns None when there is no meaningful Azure technique."""
    if rule_id and rule_id in RULE_ATRM_OVERRIDE:
        return RULE_ATRM_OVERRIDE[rule_id]
    hit = ATTACK_TO_ATRM.get(attack)
    if hit and hit[1]:
        return hit
    return None


def enrich_frameworks(finding: dict) -> dict:
    """Stamp a finding's `frameworks` with MITRE ATT&CK and Azure Threat Matrix (ATRM) tags.

    Works for both deterministic findings (which carry a rule_id and often an existing
    frameworks['MITRE ATT&CK']) and AI findings (which carry `mitre_technique`). Idempotent and
    non-destructive: existing framework entries are preserved, missing ones are filled. Returns
    the finding for chaining."""
    fw = dict(finding.get("frameworks") or {})
    rule_id = finding.get("rule_id")
    attack = attack_for(rule_id, fw.get("MITRE ATT&CK", ""),
                        finding.get("mitre_technique", ""))
    # An AI finding may arrive with no technique and no attack_primitive; derive one from its
    # category/title so it is never dropped from the MITRE coverage matrix.
    if not attack and not rule_id:
        attack = _category_attack_fallback(finding)
        finding["mitre_technique"] = attack        # overwrite the empty value, not setdefault
    if attack:
        label = ATTACK_NAME.get(attack)
        fw["MITRE ATT&CK"] = f"{attack} {label}" if (label and label not in attack) else attack
        # Store the CANONICAL id (not the AI's "T#### (name)" form) so coverage rollups group
        # correctly - overwrite, since a malformed value is worse than useful here.
        finding["mitre_technique"] = attack
    atrm = atrm_for(rule_id, attack)
    if atrm:
        tactic, aid, aname = atrm
        if "Azure Threat Matrix" not in fw:
            fw["Azure Threat Matrix"] = f"{aid} {aname}"
        # Machine-readable tactic for the report's tactic-coverage rollup.
        finding.setdefault("atrm_tactic", tactic)
    if fw:
        finding["frameworks"] = fw
    return finding
