"""CIS Microsoft Azure Foundations Benchmark coverage matrix.

PostureHound is more than an escalation-path engine: this module maps its deterministic rules
onto the CIS Azure Foundations Benchmark so the posture of the tenant can be read AS posture -
which controls are covered by a rule, which are not yet covered, and (per scan) which pass, fail,
or could not be assessed.

This is an *alignment* catalog keyed by the benchmark's section/control numbers (facts) with
short original descriptions of each control's intent, not a reproduction of the licensed CIS
document. `covered_by` lists the PostureHound rule id(s) that assess each control; an empty list
is a known coverage gap. Keep it the single source of truth for the matrix.
"""
from __future__ import annotations

CIS_VERSION = "CIS Microsoft Azure Foundations Benchmark v3.0.0"

SECTIONS = {
    # v3.0.0 drops the old section 1; Key Vault moved under 3 (Security), VMs are 8.
    "2": "Identity",
    "3": "Security (Microsoft Defender for Cloud and Key Vault)",
    "4": "Storage Accounts",
    "5": "Database Services",
    "6": "Logging and Monitoring",
    "7": "Networking",
    "8": "Virtual Machines",
    "9": "App Service",
    "10": "Miscellaneous",
}

# (id, title, [covered_by rule ids]). Section is derived from the id's leading number.
# Titles are short original paraphrases of each control's intent, not the licensed CIS text.
# v3.0.0 numbering: sections 2-10 (there is NO section 1); Key Vault lives at 3.3.x and Virtual
# Machines at 8.x. `covered_by` names the PostureHound rule(s) that assess the control; an empty
# list is a coverage gap explained in _GAP_REQUIRES.
_CONTROLS: list[tuple[str, str, list[str]]] = [
    # ── 2 Identity ────────────────────────────────────────────────────────────
    ("2.1.1", "Security Defaults enabled on Microsoft Entra ID", ["IDG-004"]),
    ("2.1.2", "Multi-factor authentication enabled for all privileged users", ["IDG-001"]),
    ("2.1.3", "Multi-factor authentication enabled for all non-privileged users", ["IDG-001"]),
    ("2.1.4", "\"Remember MFA on trusted devices\" is disabled", []),
    ("2.2.1", "Trusted named locations defined for Conditional Access", []),
    ("2.2.2", "An exclusionary country / geographic access policy is considered", ["IDG-013"]),
    ("2.2.3", "Device-code authentication flow blocked by policy", ["IDG-014"]),
    ("2.2.4", "A Conditional Access MFA policy exists for administrative groups", ["IDG-010", "IDG-003"]),
    ("2.2.5", "A Conditional Access MFA policy exists for all users", ["IDG-001", "IDG-003"]),
    ("2.2.6", "MFA required for risky sign-ins", ["IDG-012"]),
    ("2.2.7", "MFA required for the Azure (Windows) Service Management API", ["IDG-015"]),
    ("2.2.8", "MFA required to reach the Microsoft admin portals", ["IDG-016"]),
    ("2.3",   "Non-admin users restricted from creating new tenants", ["IDG-009"]),
    ("2.4",   "Guest users reviewed on a regular basis", []),
    ("2.5",   "Self-service password reset requires two methods", []),
    ("2.6",   "Account lockout threshold is 10 or fewer", []),
    ("2.7",   "Account lockout duration is at least 60 seconds", []),
    ("2.8",   "A custom banned-password list is enforced", []),
    ("2.9",   "Re-confirm authentication-info interval is not set to 0 days", []),
    ("2.10",  "Users are notified on their own password resets", []),
    ("2.11",  "All admins are notified when another admin resets a password", []),
    ("2.12",  "User consent to applications is disabled", ["IDG-005"]),
    ("2.13",  "User app consent limited to verified publishers", ["IDG-005"]),
    ("2.14",  "Users cannot register applications", ["IDG-006"]),
    ("2.15",  "Guest access restricted to their own directory objects",
     ["IDG-008", "AZ-IDENT-004", "AZ-IDENT-016"]),
    ("2.16",  "Guest invitations limited to specific admin roles", ["IDG-007"]),
    ("2.17",  "Access to the Entra admin center is restricted", []),
    ("2.18",  "Users restricted from the Groups features in the access pane", []),
    ("2.19",  "Users cannot create security groups", []),
    ("2.20",  "Group owners cannot manage membership requests in My Groups", []),
    ("2.21",  "Users cannot create Microsoft 365 groups", []),
    ("2.22",  "MFA required to register or join devices with Entra", ["IDG-017"]),
    ("2.23",  "No custom subscription Administrator (Owner-equivalent) roles exist", ["AZ-RBAC-011"]),
    ("2.24",  "A custom least-privilege role administers resource locks", []),
    ("2.25",  "Subscription transfer in / out of the tenant set to \"permit no one\"", []),
    ("2.26",  "Fewer than 5 Global Administrators", ["AZ-IDENT-001"]),
    # ── 3 Security (Microsoft Defender for Cloud + Key Vault) ──────────────────
    ("3.1.1.1", "Auto-provisioning of the Log Analytics agent is On", ["ARG-DEFENDER-002"]),
    ("3.1.1.2", "Defender for Cloud Apps integration is selected", []),
    ("3.1.3.1", "Microsoft Defender for Servers is On", ["ARG-DEFENDER-001"]),
    ("3.1.3.2", "Defender \"vulnerability assessment for machines\" component is On", []),
    ("3.1.3.3", "Defender \"endpoint protection\" component is On", ["ARG-DEFENDER-004"]),
    ("3.1.3.4", "Defender \"agentless scanning for machines\" component is On", ["ARG-DEFENDER-005"]),
    ("3.1.3.5", "Defender \"file integrity monitoring\" component is On", ["ARG-DEFENDER-006"]),
    ("3.1.4.1", "Microsoft Defender for Containers is On", ["ARG-DEFENDER-001"]),
    ("3.1.4.2", "Defender \"agentless discovery for Kubernetes\" component is On", ["ARG-DEFENDER-007"]),
    ("3.1.4.3", "Defender \"agentless container vulnerability assessment\" is On", ["ARG-DEFENDER-008"]),
    ("3.1.5.1", "Microsoft Defender for Storage is On", ["ARG-DEFENDER-001"]),
    ("3.1.6.1", "Microsoft Defender for App Service is On", ["ARG-DEFENDER-001"]),
    ("3.1.7.1", "Microsoft Defender for Azure Cosmos DB is On", ["ARG-DEFENDER-001"]),
    ("3.1.7.2", "Microsoft Defender for open-source relational databases is On", ["ARG-DEFENDER-001"]),
    ("3.1.7.3", "Microsoft Defender for Azure SQL (managed instance) is On", ["ARG-DEFENDER-001"]),
    ("3.1.7.4", "Microsoft Defender for SQL servers on machines is On", ["ARG-DEFENDER-001"]),
    ("3.1.8.1", "Microsoft Defender for Key Vault is On", ["ARG-DEFENDER-001"]),
    ("3.1.9.1", "Microsoft Defender for Resource Manager is On", ["ARG-DEFENDER-001"]),
    ("3.1.10",  "Defender \"apply system updates\" recommendation is completed", []),
    ("3.1.11",  "Microsoft Cloud Security Benchmark policies are not disabled", []),
    ("3.1.12",  "Security-contact \"all users with role\" set to Owner", []),
    ("3.1.13",  "A security contact email is configured", ["ARG-DEFENDER-003"]),
    ("3.1.14",  "Alert-notification severity is set to High", ["ARG-DEFENDER-003"]),
    ("3.1.15",  "Defender External Attack Surface Monitoring (EASM) is enabled", []),
    ("3.1.16",  "[legacy] Microsoft Defender for DNS is On", []),
    ("3.2.1",   "Microsoft Defender for IoT Hub is On", []),
    ("3.3.1",   "Expiry set on keys in RBAC key vaults", []),
    ("3.3.2",   "Expiry set on keys in non-RBAC key vaults", []),
    ("3.3.3",   "Expiry set on secrets in RBAC key vaults", []),
    ("3.3.4",   "Expiry set on secrets in non-RBAC key vaults", []),
    ("3.3.5",   "Key Vault is recoverable (soft-delete and purge protection)", ["AZ-KV-005", "AZ-KV-008"]),
    ("3.3.6",   "Key Vault uses RBAC authorization (not access policies)", ["AZ-KV-002"]),
    ("3.3.7",   "Private endpoints are used for Key Vault", ["AZ-KV-009", "AZ-KV-006"]),
    ("3.3.8",   "Automatic key rotation is enabled", []),
    # ── 4 Storage Accounts ────────────────────────────────────────────────────
    ("4.1",  "Secure transfer (HTTPS-only) required", ["AZ-STOR-006"]),
    ("4.2",  "Infrastructure (double) encryption enabled", ["ARG-STOR-002"]),
    ("4.3",  "Key-rotation reminders enabled", ["ARG-STOR-003"]),
    ("4.4",  "Account access keys periodically regenerated", []),
    ("4.5",  "SAS tokens expire within an hour", ["ARG-STOR-004"]),
    ("4.6",  "Public network access disabled", ["AZ-STOR-011", "AZ-STOR-007", "AZ-STOR-008"]),
    ("4.7",  "Default network access rule set to Deny", ["AZ-STOR-007"]),
    ("4.8",  "\"Allow trusted Azure services\" network exception enabled", []),
    ("4.9",  "Private endpoints used to access storage", ["AZ-STOR-008"]),
    ("4.10", "Soft delete enabled for blobs and containers", ["ARG-STOR-005"]),
    ("4.11", "Critical data encrypted with customer-managed keys", ["ARG-STOR-001"]),
    ("4.12", "Queue-service logging enabled for read / write / delete", ["ARG-LOG-002"]),
    ("4.13", "Blob-service logging enabled for read / write / delete", ["ARG-LOG-002"]),
    ("4.14", "Table-service logging enabled for read / write / delete", ["ARG-LOG-002"]),
    ("4.15", "Minimum TLS version is 1.2", ["AZ-STOR-005"]),
    ("4.16", "Cross-tenant replication not enabled", ["AZ-STOR-009"]),
    ("4.17", "Blob anonymous access disabled", ["AZ-STOR-001"]),
    # ── 5 Database Services ───────────────────────────────────────────────────
    ("5.1.1", "SQL server auditing is On", ["ARG-SQL-004"]),
    ("5.1.2", "No SQL database allows ingress from 0.0.0.0/0", ["ARG-SQL-003"]),
    ("5.1.3", "SQL TDE protector uses a customer-managed key", ["ARG-SQL-006"]),
    ("5.1.4", "Entra authentication configured for SQL servers", ["ARG-SQL-007"]),
    ("5.1.5", "SQL database data encryption (TDE) is On", ["ARG-SQL-005"]),
    ("5.1.6", "SQL audit log retention is greater than 90 days", ["ARG-SQL-008"]),
    ("5.1.7", "SQL public network access disabled", ["ARG-SQL-001"]),
    ("5.2.1", "PostgreSQL flexible server requires secure transport", ["ARG-PG-002"]),
    ("5.2.2", "PostgreSQL flexible server logs checkpoints", ["ARG-PG-003"]),
    ("5.2.3", "PostgreSQL flexible server connection throttling on", ["ARG-PG-004"]),
    ("5.2.4", "PostgreSQL flexible server log retention greater than 3 days", ["ARG-PG-005"]),
    ("5.2.5", "PostgreSQL flexible server public Azure-service access disabled", ["ARG-PG-001"]),
    ("5.2.6", "[legacy] PostgreSQL single server logs connections", []),
    ("5.2.7", "[legacy] PostgreSQL single server logs disconnections", []),
    ("5.2.8", "[legacy] PostgreSQL single server infrastructure double encryption", []),
    ("5.3.1", "MySQL flexible server requires secure transport", ["ARG-MYSQL-002"]),
    ("5.3.2", "MySQL flexible server minimum TLS 1.2", ["ARG-MYSQL-003"]),
    ("5.3.3", "MySQL flexible server audit log enabled", ["ARG-MYSQL-004"]),
    ("5.3.4", "MySQL flexible server audit log captures CONNECTION events", ["ARG-MYSQL-005"]),
    ("5.4.1", "Cosmos DB firewall limited to selected networks", ["ARG-COSMOS-001"]),
    ("5.4.2", "Cosmos DB private endpoints used where possible", ["ARG-COSMOS-003"]),
    ("5.4.3", "Cosmos DB uses Entra authentication and RBAC", ["ARG-COSMOS-002"]),
    # ── 6 Logging and Monitoring ──────────────────────────────────────────────
    ("6.1.1", "A diagnostic setting exists for subscription activity logs", ["ARG-LOG-003"]),
    ("6.1.2", "Diagnostic setting captures the appropriate log categories", ["ARG-LOG-003"]),
    ("6.1.3", "Activity-log storage account encrypted with a customer-managed key", []),
    ("6.1.4", "Logging for Azure Key Vault is enabled", ["ARG-LOG-001"]),
    ("6.1.5", "NSG flow logs captured and sent to Log Analytics", ["ARG-LOG-004"]),
    ("6.1.6", "App Service HTTP logs enabled", ["ARG-APP-008"]),
    ("6.2.1", "Activity-log alert for create policy assignment", ["ARG-MON-001"]),
    ("6.2.2", "Activity-log alert for delete policy assignment", ["ARG-MON-002"]),
    ("6.2.3", "Activity-log alert for create / update NSG", ["ARG-MON-003"]),
    ("6.2.4", "Activity-log alert for delete NSG", ["ARG-MON-004"]),
    ("6.2.5", "Activity-log alert for create / update security solution", ["ARG-MON-005"]),
    ("6.2.6", "Activity-log alert for delete security solution", ["ARG-MON-006"]),
    ("6.2.7", "Activity-log alert for create / update SQL firewall rule", ["ARG-MON-007"]),
    ("6.2.8", "Activity-log alert for delete SQL firewall rule", ["ARG-MON-008"]),
    ("6.2.9", "Activity-log alert for create / update public IP", ["ARG-MON-009"]),
    ("6.2.10","Activity-log alert for delete public IP", ["ARG-MON-010"]),
    ("6.3.1", "Application Insights configured", []),
    ("6.4",   "Azure Monitor resource logging enabled for all supporting services", []),
    ("6.5",   "Non-Basic SKU used for artifacts that must be monitored", []),
    # ── 7 Networking ──────────────────────────────────────────────────────────
    ("7.1", "RDP access from the internet restricted", ["ARG-NET-001"]),
    ("7.2", "SSH access from the internet restricted", ["ARG-NET-001"]),
    ("7.3", "UDP access from the internet restricted", ["ARG-NET-001"]),
    ("7.4", "HTTP(S) access from the internet restricted", ["ARG-NET-001"]),
    ("7.5", "NSG flow-log retention greater than 90 days", ["ARG-LOG-005"]),
    ("7.6", "Network Watcher enabled in regions in use", ["ARG-NET-004"]),
    ("7.7", "Public IP addresses reviewed on a periodic basis", ["ARG-NET-002"]),
    # ── 8 Virtual Machines ────────────────────────────────────────────────────
    ("8.1",  "An Azure Bastion host exists", ["ARG-NET-003"]),
    ("8.2",  "Virtual machines use managed disks", ["ARG-DISK-004"]),
    ("8.3",  "OS and data disks encrypted with customer-managed keys", ["ARG-DISK-003"]),
    ("8.4",  "Unattached disks encrypted with customer-managed keys", ["ARG-DISK-003"]),
    ("8.5",  "Disk network access not open to all networks", ["ARG-DISK-001", "ARG-DISK-002"]),
    ("8.6",  "Disk data-access authentication mode enabled", ["ARG-DISK-005"]),
    ("8.7",  "Only approved VM extensions installed", []),
    ("8.8",  "Endpoint protection installed on all VMs", []),
    ("8.9",  "[legacy] VHDs encrypted", []),
    ("8.10", "Only MFA-enabled identities can access privileged VMs", []),
    ("8.11", "Trusted Launch enabled on virtual machines", ["AZ-VM-001"]),
    # ── 9 App Service ─────────────────────────────────────────────────────────
    ("9.1",  "HTTPS only is On", ["ARG-APP-001"]),
    ("9.2",  "App Service authentication is configured", ["ARG-APP-009"]),
    ("9.3",  "FTP state set to FTPS-only or disabled", ["ARG-APP-003"]),
    ("9.4",  "Latest TLS version enforced", ["ARG-APP-002"]),
    ("9.5",  "Register with Entra ID (managed identity) enabled", ["ARG-APP-006"]),
    ("9.6",  "Basic authentication disabled", ["ARG-APP-010"]),
    ("9.7",  "Supported PHP version in use", []),
    ("9.8",  "Supported Python version in use", []),
    ("9.9",  "Supported Java version in use", []),
    ("9.10", "HTTP/2 enabled", ["ARG-APP-007"]),
    ("9.11", "Key Vault used to store application secrets", []),
    ("9.12", "Remote debugging is Off", ["ARG-APP-004"]),
    # ── 10 Miscellaneous ──────────────────────────────────────────────────────
    ("10.1", "Resource locks set for mission-critical resources", []),
]


# Why each currently-uncovered control has no rule: the data it needs is not in the collection
# PostureHound gathers today (AzureHound identity/RBAC + the Graph identity-config + the ARG
# resource queries). Labelling the gap with its data requirement keeps the matrix HONEST, an
# uncovered control is a known collection limit, not a silent "nothing to see here". Every gap
# has an entry below; a control with no entry would count as a buildable gap (a rule writable
# against data already collected). Reason templates are shared across the many like-for-like gaps.
_R_CA = "Conditional Access / sign-in policy detail (named locations, device-code, risk, device state), not collected"
_R_PWD = "Entra password-protection and self-service-password-reset policy, not collected"
_R_DIR = "Entra ID directory / authorization policy setting, not collected"
_R_MANUAL = "Manual-review control; no collectable configuration signal"
_R_DEF = "Per-plan Defender component / extension / recommendation status, not individually collected"
_R_KVDP = "Key Vault data-plane object attributes (expiry, rotation), needs Key Vault data-plane access"
_R_STORENC = "Storage encryption / customer-managed-key / infrastructure-encryption property, not collected"
_R_STORNET = "Storage network-rule bypass (trusted Azure services) flag, not collected"
_R_DBP = "Database server parameter configuration, not collected"
_R_APP = "App Service configuration (auth, runtime version, HTTP/2, Key Vault refs, HTTP logs), not collected"
_R_APPINS = "Application Insights configuration, not collected"
_R_DIAG = "Per-resource diagnostic-setting detail across all services, not collected"
_R_DISK = "VM disk encryption-at-rest / data-access authentication mode, not collected"
_R_VM = "VM inventory detail (Bastion, managed-disk use, extensions, endpoint protection), not collected"
_R_LOCKS = "Resource-lock inventory, not collected"

_GAP_REQUIRES: dict[str, str] = {
    **{c: _R_CA for c in ("2.1.4", "2.2.1", "8.10")},
    **{c: _R_PWD for c in ("2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11")},
    **{c: _R_DIR for c in ("2.17", "2.18", "2.19", "2.20", "2.21", "2.25")},
    **{c: _R_MANUAL for c in ("2.4", "2.24", "4.4", "6.5")},
    # Defender sub-components: 3.1.3.3/3.1.3.4/3.1.3.5/3.1.4.2/3.1.4.3 now have component rules;
    # the rest still need per-plan extension / recommendation / policy data not collected.
    **{c: _R_DEF for c in ("3.1.1.2", "3.1.3.2", "3.1.10", "3.1.11", "3.1.12", "3.1.15",
                           "3.1.16", "3.2.1")},
    **{c: _R_KVDP for c in ("3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.8")},
    # 6.1.3 is the activity-log storage account's CMK specifically (needs log->account correlation);
    # the generic storage-CMK posture is ARG-STOR-001 (4.11).
    "6.1.3": _R_STORENC,
    "4.8": _R_STORNET,
    # 5.2.6-5.2.8 are the retired PostgreSQL SINGLE-server parameters ([LEGACY] in CIS); the
    # flexible-server equivalents are covered by ARG-PG-*/ARG-MYSQL-* rules.
    **{c: _R_DBP for c in ("5.2.6", "5.2.7", "5.2.8")},
    "6.3.1": _R_APPINS,
    "6.4": _R_DIAG,
        **{c: _R_VM for c in ("8.7", "8.8")},
    "8.9": _R_DISK,
    **{c: _R_APP for c in ("9.7", "9.8", "9.9", "9.11")},
    "10.1": _R_LOCKS,
}


def controls(include_unassessed: bool = False) -> list[dict]:
    """The CIS v3.0.0 controls PostureHound assesses (those with a covering rule).

    The complete v3.0.0 catalog, including controls that a read-only control-plane scan cannot
    assess (data-plane attributes, Entra policy endpoints not collected, manual-review items), is
    kept in `_CONTROLS` as the maintainer reference. By product decision the application surfaces
    ONLY assessed controls: a control PostureHound cannot check is not shown as a gap. Pass
    `include_unassessed=True` to get the complete catalog (used by tooling, not the UI)."""
    out = []
    for cid, title, covered_by in _CONTROLS:
        if not covered_by and not include_unassessed:
            continue
        sec = cid.split(".")[0]
        out.append({
            "id": cid, "section": sec, "section_name": SECTIONS.get(sec, sec),
            "title": title, "covered_by": list(covered_by), "covered": bool(covered_by),
            "requires": "" if covered_by else _GAP_REQUIRES.get(cid, ""),
        })
    return out


def summary() -> dict:
    """How many CIS v3.0.0 controls PostureHound assesses, by section."""
    ctrls = controls()
    by_section: dict[str, dict] = {}
    for c in ctrls:
        s = by_section.setdefault(c["section"], {"name": c["section_name"], "assessed": 0})
        s["assessed"] += 1
    return {
        "version": CIS_VERSION,
        "controls_assessed": len(ctrls),
        "by_section": by_section,
    }


def _entity_brief(e: dict) -> dict:
    """A compact, display-ready view of one affected entity: its name, kind, and the most
    specific evidence available (a concrete role, else the first few evidence key/values)."""
    ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else {}
    role = (e.get("role_in_finding") or "").strip()
    if role and not role.lower().startswith("affected"):
        detail = role
    else:
        detail = " · ".join(f"{k}: {v}" for k, v in list(ev.items())[:4])
    return {"name": e.get("name") or e.get("id") or "", "kind": (e.get("kind") or "").replace("AZ", ""),
            "detail": detail}


def _rule_evidence(cov: list, fired_ids: set, na_ids: set,
                   findings_by_rule: dict, na_by_rule: dict, rule_meta: dict) -> list:
    """Per covering-rule evidence for ONE control: why it is pass / fail / not-assessed.
    A FAIL carries the violating entities and their concrete evidence (the audit trail that
    backs the verdict); a PASS confirms the rule ran clean; a not-assessed carries the reason."""
    out = []
    for rid in cov:
        meta = rule_meta.get(rid, {})
        title = meta.get("title") or rid
        if rid in fired_ids:
            f = findings_by_rule.get(rid) or {}
            ents = f.get("entities") or []
            out.append({
                "rule_id": rid, "status": "fail", "title": f.get("title") or title,
                "severity": f.get("severity") or meta.get("severity"),
                "affected": f.get("affected_count") or len(ents),
                "entities": [_entity_brief(e) for e in ents[:10] if isinstance(e, dict)],
                "remediation": f.get("remediation") or meta.get("remediation") or "",
            })
        elif rid in na_ids:
            out.append({"rule_id": rid, "status": "not_assessed", "title": title,
                        "reason": na_by_rule.get(rid) or "required data was not collected"})
        else:
            out.append({"rule_id": rid, "status": "pass", "title": title,
                        "detail": "Assessed against the collected data; no violation found."})
    return out


def coverage_for_scan(fired: dict, not_assessed: list, *,
                      findings_by_rule: "dict | None" = None,
                      na_by_rule: "dict | None" = None,
                      rule_meta: "dict | None" = None) -> dict:
    """Per-scan control status given a scan's rule outcomes, over the assessed controls.

    `fired`: {rule_id: count} rules that produced a finding. `not_assessed`: [rule_id] rules
    whose required data was not collected. A control:
      * fail        , a covering rule fired,
      * not_assessed, every covering rule could not be assessed (required data absent),
      * pass        , assessed, nothing fired.

    When the optional detail maps are supplied, each row also carries a `rules` list explaining
    WHY it has that status (the firing findings' entities/evidence, or the not-assessed reason),
    so the control can be audited like a finding.
    """
    fired_ids = set(fired or {})
    na_ids = set(not_assessed or [])
    findings_by_rule = findings_by_rule or {}
    na_by_rule = na_by_rule or {}
    rule_meta = rule_meta or {}
    want_detail = bool(findings_by_rule or na_by_rule or rule_meta)
    rows = []
    counts = {"pass": 0, "fail": 0, "not_assessed": 0}
    for c in controls():
        cov = c["covered_by"]
        if any(r in fired_ids for r in cov):
            status = "fail"
        elif cov and all(r in na_ids for r in cov):
            status = "not_assessed"
        else:
            status = "pass"
        counts[status] += 1
        row = {**c, "status": status, "fired": [r for r in cov if r in fired_ids]}
        if want_detail and cov:
            row["rules"] = _rule_evidence(cov, fired_ids, na_ids,
                                          findings_by_rule, na_by_rule, rule_meta)
        rows.append(row)
    assessed = counts["pass"] + counts["fail"]
    return {
        "version": CIS_VERSION,
        "controls": rows,
        "counts": counts,
        # Posture score over ASSESSED, covered controls (pass / (pass+fail)).
        "score_pct": round(100 * counts["pass"] / assessed) if assessed else None,
    }
