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
    "1": "Identity and Access Management",
    "2": "Microsoft Defender for Cloud",
    "3": "Storage Accounts",
    "4": "Database Services",
    "5": "Logging and Monitoring",
    "6": "Networking",
    "7": "Virtual Machines",
    "8": "Key Vault",
    "9": "App Service",
}

# (id, title, [covered_by rule ids]). Section is derived from the id's leading number.
_CONTROLS: list[tuple[str, str, list[str]]] = [
    # ── 1 Identity and Access Management ──────────────────────────────────────
    ("1.1",  "Multi-factor authentication enforced for all users", ["IDG-001", "IDG-004"]),
    ("1.2",  "Legacy (basic) authentication blocked", ["IDG-002"]),
    ("1.3",  "Conditional Access policies exist and are enforced (not report-only)", ["IDG-003"]),
    ("1.4",  "Applications restricted to assigned users (no tenant-wide access)", ["AZ-APP-016"]),
    ("1.5",  "Guest / external account access and privilege restricted",
     ["AZ-IDENT-004", "AZ-IDENT-016", "AZ-GRP-007", "AZ-APP-020"]),
    ("1.6",  "Number of Global Administrators kept within a safe band", ["AZ-IDENT-001"]),
    ("1.7",  "Break-glass emergency-access accounts maintained", ["AZ-IDENT-002"]),
    ("1.8",  "Privileged roles not assigned at broad (subscription / MG root) scope",
     ["AZ-RBAC-001", "AZ-RBAC-003", "AZ-RBAC-016", "AZ-RBAC-008", "AZ-RBAC-013"]),
    ("1.9",  "Application credentials hygienic (certificate over secret, not expired)",
     ["AZ-APP-004", "AZ-APP-031"]),
    ("1.10", "Stale / disabled accounts deprovisioned of privilege",
     ["AZ-HYG-003", "AZ-HYG-005", "AZ-IDENT-006", "AZ-HYG-007"]),
    ("1.11", "User consent to applications restricted", ["IDG-005"]),
    ("1.12", "Security Defaults or an equivalent CA baseline enabled", ["IDG-004"]),
    # ── 2 Microsoft Defender for Cloud ────────────────────────────────────────
    ("2.1",  "Microsoft Defender for Cloud enabled (not Free tier)", ["ARG-DEFENDER-001"]),
    ("2.2",  "All relevant Defender plans enabled (Servers/Storage/SQL/Containers/KeyVault)", ["ARG-DEFENDER-001"]),
    ("2.3",  "Agent / monitoring auto-provisioning enabled", ["ARG-DEFENDER-002"]),
    ("2.4",  "Security contact email and alert notifications configured", ["ARG-DEFENDER-003"]),
    # ── 3 Storage Accounts ────────────────────────────────────────────────────
    ("3.1",  "Secure transfer (HTTPS-only) required", ["AZ-STOR-006"]),
    ("3.2",  "Infrastructure (double) encryption enabled", []),            # GAP
    ("3.5",  "Storage logging / diagnostic settings enabled", []),         # GAP
    ("3.7",  "Anonymous public blob access disabled", ["AZ-STOR-001"]),
    ("3.8",  "Default network access denied; shared-key access restricted",
     ["AZ-STOR-004", "AZ-STOR-007", "AZ-STOR-002"]),
    ("3.9",  "Private endpoints used; public network access disabled",
     ["AZ-STOR-008"]),
    ("3.12", "Customer-managed keys (CMK) for encryption at rest", []),    # GAP
    ("3.15", "Minimum TLS 1.2; cross-tenant replication disabled",
     ["AZ-STOR-005", "AZ-STOR-009", "AZ-STOR-003"]),
    # ── 4 Database Services ───────────────────────────────────────────────────
    ("4.1.1", "SQL auditing enabled", ["ARG-SQL-004"]),
    ("4.1.2", "SQL transparent data encryption / TLS enforced", ["ARG-SQL-002", "ARG-SQL-003"]),
    ("4.1.3", "SQL public network access disabled", ["ARG-SQL-001"]),
    ("4.3",   "PostgreSQL / MySQL hardened (SSL, public access)", ["ARG-PG-001", "ARG-MYSQL-001"]),
    ("4.5",   "Cosmos DB network / local-auth restricted", ["ARG-COSMOS-001", "ARG-COSMOS-002"]),
    ("4.x",   "Database auditing / log retention configured", []),         # GAP
    # ── 5 Logging and Monitoring ──────────────────────────────────────────────
    ("5.1",  "A diagnostic/log profile captures activity-log categories", []),   # GAP (whole section)
    ("5.2",  "Activity-log alerts for critical operations (NSG/policy/SQL/KeyVault changes)", []),
    ("5.3",  "Diagnostic settings enabled on key resources (KV, NSG, storage)", []),
    ("5.4",  "Log Analytics / storage retention >= 90 days", []),
    ("5.5",  "Activity log retained and protected", []),
    # ── 6 Networking ──────────────────────────────────────────────────────────
    ("6.1",  "Management ports (RDP/SSH) not open to the internet", ["ARG-NET-001"]),
    ("6.2",  "No NSG rule allows any-source inbound to sensitive ports", ["ARG-NET-001"]),
    ("6.5",  "NSG flow logs enabled", []),                                 # GAP
    ("6.6",  "Network Watcher enabled", []),                               # GAP
    # ── 7 Virtual Machines ────────────────────────────────────────────────────
    ("7.1",  "OS and data disks encrypted", []),                          # GAP (encryption-at-rest not collected)
    ("7.2",  "Managed disks restricted from public network export", ["ARG-DISK-002", "ARG-DISK-001"]),
    ("7.3",  "Trusted Launch (Secure Boot + vTPM) enabled", ["AZ-VM-001"]),
    ("7.4",  "Disk encryption with customer-managed keys", ["ARG-DISK-003"]),
    # ── 8 Key Vault ───────────────────────────────────────────────────────────
    ("8.1",  "Key Vault uses RBAC authorization (not access policies)", ["AZ-KV-002"]),
    ("8.4",  "Key Vault network access restricted / public access disabled",
     ["AZ-KV-006", "AZ-KV-007", "AZ-KV-010"]),
    ("8.5",  "Key Vault soft-delete and purge protection enabled", ["AZ-KV-005", "AZ-KV-008"]),
    ("8.6",  "Key / secret / certificate expiry set", []),                 # GAP
    # ── 9 App Service ─────────────────────────────────────────────────────────
    ("9.1",  "App Service authentication enabled", []),                    # GAP (EasyAuth config not collected)
    ("9.2",  "App Service requires HTTPS and TLS 1.2", ["ARG-APP-001", "ARG-APP-002"]),
    ("9.3",  "App Service uses a managed identity (no stored secrets)", ["ARG-APP-006"]),
    ("9.4",  "App Service not publicly exposed where avoidable", ["ARG-APP-005"]),
    ("9.5",  "App Service FTP state hardened (no plaintext FTP)", ["ARG-APP-003"]),
]


# Why each currently-uncovered control has no rule: the data it needs is simply not in the
# collection PostureHound gathers today (AzureHound identity/RBAC plus the ARG resource queries).
# Labelling the gap with its data requirement keeps the matrix HONEST, an uncovered control is a
# known collection limit, not a silent "nothing to see here". Every current gap is here; a control
# with no entry is a buildable gap (a rule could be written against data already collected).
_GAP_REQUIRES: dict[str, str] = {
    "3.2":  "Storage infrastructure-encryption property, not collected",
    "3.5":  "Resource diagnostic-settings, not collected",
    "3.12": "Storage customer-managed-key (CMK) config, not collected",
    "4.x":  "Database audit / log-retention config, not collected",
    "5.1":  "Activity-log / diagnostic profile config, not collected",
    "5.2":  "Activity-log alert rules, not collected",
    "5.3":  "Resource diagnostic-settings, not collected",
    "5.4":  "Log Analytics / storage retention config, not collected",
    "5.5":  "Activity-log retention config, not collected",
    "6.5":  "NSG flow-log config, not collected",
    "6.6":  "Network Watcher config, not collected",
    "7.1":  "Disk encryption-at-rest status not collected (disks are platform-encrypted by default; ADE/CMK state not gathered)",
    "9.1":  "App Service authentication (EasyAuth) config, not collected",
    "8.6":  "Key Vault object expiry attributes, needs Key Vault data-plane access",
}


def controls() -> list[dict]:
    """The full catalog as dicts, with section name attached."""
    out = []
    for cid, title, covered_by in _CONTROLS:
        sec = cid.split(".")[0]
        covered = bool(covered_by)
        out.append({
            "id": cid, "section": sec, "section_name": SECTIONS.get(sec, sec),
            "title": title, "covered_by": list(covered_by), "covered": covered,
            # For an uncovered control, WHY there is no rule (what data it would need). Empty
            # string for a covered control, or for a gap that could be built from current data.
            "requires": "" if covered else _GAP_REQUIRES.get(cid, ""),
        })
    return out


def summary() -> dict:
    """Static coverage: how many CIS controls PostureHound has a rule for, and, for the rest -
    how many are blocked on data the current collection does not gather versus buildable gaps."""
    ctrls = controls()
    covered = sum(1 for c in ctrls if c["covered"])
    needs_collection = sum(1 for c in ctrls if not c["covered"] and c["requires"])
    total = len(ctrls)
    buildable_gap = total - covered - needs_collection
    by_section: dict[str, dict] = {}
    for c in ctrls:
        s = by_section.setdefault(c["section"], {"name": c["section_name"], "covered": 0,
                                                 "needs_collection": 0, "total": 0})
        s["total"] += 1
        if c["covered"]:
            s["covered"] += 1
        elif c["requires"]:
            s["needs_collection"] += 1
    return {
        "version": CIS_VERSION,
        "controls_total": total,
        "controls_covered": covered,
        # Uncovered controls blocked on resource/config data PostureHound does not collect today.
        "controls_needs_collection": needs_collection,
        # Uncovered controls that COULD be built from data already collected (0 = none outstanding).
        "controls_buildable_gap": buildable_gap,
        "coverage_pct": round(100 * covered / total) if total else 0,
        # Share of controls that are either covered or honestly accounted for as a collection limit.
        "accounted_pct": round(100 * (covered + needs_collection) / total) if total else 0,
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
    """Per-scan control status given a scan's rule outcomes.

    `fired`: {rule_id: count} rules that produced a finding. `not_assessed`: [rule_id] rules
    whose required data was not collected. A control:
      * fail        , a covering rule fired,
      * not_assessed, no covering rule fired but one could not be assessed,
      * pass        , covered, assessed, nothing fired,
      * no_coverage , no rule maps to it (a catalog gap).

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
    counts = {"pass": 0, "fail": 0, "not_assessed": 0, "no_coverage": 0}
    for c in controls():
        cov = c["covered_by"]
        if not cov:
            status = "no_coverage"
        elif any(r in fired_ids for r in cov):
            status = "fail"
        elif all(r in na_ids for r in cov):
            status = "not_assessed"
        elif any(r in na_ids for r in cov) and not any(r not in na_ids for r in cov):
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
