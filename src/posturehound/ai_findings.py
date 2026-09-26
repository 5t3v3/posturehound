"""AI-generated findings via a multi-specialist parallel pipeline with tool-use output.

Stage 1  – Sonnet specialist analysts (17) run in parallel (ThreadPoolExecutor), each
            focused on a distinct attack domain:
              priv_esc, lateral_movement, entry_points, data_plane, hygiene,
              rbac_governance, app_lifecycle, pim_risk, tenant_defaults, devops_surface,
              hybrid_identity, supply_chain_container,
              cross_subscription, security_misconfig, entitlement_delegation,
              access_breadth, resource_exposure.
            Tool-use output → no JSON-parse or truncation risk.

Stage 2  – Soft dedup (same entity set + same category → keep highest-confidence;
            also title-similarity dedup to collapse near-duplicate findings).

Stage 3  – Opus cross-domain compound synthesizer ADDS findings that span two or more
            domains, and may re-rate an existing specialist finding's severity via an
            upgrade_finding call (it never rewrites their content; dedup stays mechanical).

Stage 4  – Opus correlation agent takes the confirmed findings + the real escalation
            edges and builds explicit multi-step attack chains (entry-point → lateral-
            move → priv-esc) at elevated severity. A chain that individually was 2× High
            becomes Critical here. Each chain hop is edge-grounded against the graph.

Stage 5  – Haiku skeptic pass on all Critical/High findings (including chains). Each
            finding is adversarially evaluated; confirmed-bad findings are downgraded or
            dropped before the final list is returned.

Grounding: entity IDs validated against the fact pack after every AI stage; chain hops
            are additionally validated against real graph edges (Stage 4).
"""
from __future__ import annotations

import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .facts import FactPack

DEFAULT_SONNET_MODEL = "claude-sonnet-5"
# Narration/summarisation stages (cartographer path-naming, executive summary) don't reason
# over the fact pack - they restate an already-computed result - so they run on Haiku 4.5, not
# Sonnet. Quality-neutral for these tasks; ~3× cheaper. The reasoning stages (specialists,
# skeptic, coherence gate) stay on Sonnet, and the cross-domain reasoners stay on Opus.
DEFAULT_NARRATION_MODEL = "claude-haiku-4-5-20251001"
# The flagship reasoning stages - cross-domain compound synthesizer, multi-step attack-chain
# correlator, and attack-map cartographer - run on the opus slot. Opus 5 is the most capable
# model available and these are the highest-value, lowest-volume calls in the pipeline, so the
# quality gain is worth the per-token cost. Specialists stay on Sonnet 5, the skeptic on Haiku.
DEFAULT_OPUS_MODEL   = "claude-opus-5"
DEFAULT_HAIKU_MODEL  = "claude-haiku-4-5-20251001"

# How many specialists run at once. The 17 are independent, so this only trades speed against
# rate-limit pressure - a smaller number is gentler on 429/overload (fewer dropped domains),
# a larger one is faster. 6 keeps a scan quick while rarely tripping throttling.
_SPECIALIST_MAX_CONCURRENCY = 6


# ── Shared prompt fragments ─────────────────────────────────────────────────

_CONFIDENCE_GUIDANCE = """
CONFIDENCE CALIBRATION (honest, not optimistic):
- 90-100: fact pack directly and completely confirms every step - no assumptions.
- 70-89: core issue confirmed, but one supporting detail is inferred.
- 40-69: plausible and worth flagging, but a meaningful piece of the chain is inferred -
  say exactly what in the reasoning field.
- Below 40: speculative - include only for severe potential impact, and say so explicitly.
Never report 100 out of habit; if you assumed anything the confidence must reflect it."""

_GROUNDING_RULES = """
STRICT GROUNDING:
1. Every entity id MUST be the exact "id" string from the fact pack. Never invent one.
2. Do not state anything as fact unless directly supported by the fact pack.
   Inferences must be clearly labelled as such in the reasoning field.
3. Call record_finding once per distinct confirmed finding.
   If you find no issues in your domain, do not call record_finding at all.
4. TITLE QUALITY: Each finding title MUST name the specific principal(s), permission, or
   group involved - never use generic titles like "Service principal holds X" or
   "Non-privileged owner of a privileged group". Bad: "Privileged role held via group
   membership". Good: "Jordan Lee and 7 Others Reach Tier-0 via 'Platform Engineers' Group".
   Generic titles without named entities will be treated as low-quality and deprioritised.
5. CONFIDENCE REQUIRED: Always provide an integer confidence (0-100). Never leave it null.
   If you are unsure how confident to be, use 50.
6. ALL TEXT FIELDS MUST BE NON-EMPTY: Never provide empty strings ("") for summary,
   reasoning, what, why_it_matters, attack_scenario, remediation, or detection.
   - summary: Write 2-3 plain-language sentences for a non-technical audience describing
     the risk in business terms. This MUST have real content, never empty.
   - reasoning: Write ≥4 sentences citing specific fact-pack values (IDs, counts, names).
     This MUST have real content, never empty.
   - evidence: Provide ≥2 specific string facts from the fact pack (entity IDs, counts,
     permission names, subscription paths). This MUST have at least 2 items, never empty.
   - attack_scenario: Numbered steps. At least 3 steps. Never empty.
   An empty field will be treated as a quality failure and the finding deprioritised.
7. ENTITY RELATION (load-bearing for the attack path): for EACH entity set "relation" to
   "subject" or "context". A SUBJECT is a principal the finding is ABOUT - it holds the
   risky access, or is the actor whose capability you describe. CONTEXT is a party named
   only to explain the finding and is NOT part of its own attack - e.g. an admin who could
   reset the subject's password, a bystander, a comparison account. The maximum-impact
   attack path is anchored on the SUBJECT and NEVER on a context entity, so if you list a
   helper (say, "PAA that can reset the disabled account's password"), mark it "context" or
   the path will wrongly start from that helper. When unsure, use "subject"."""


# Domain-agnostic severity anchors. Appended to every specialist so severity is assigned the
# SAME way each run and across agents, instead of each agent (and each run) guessing - a major
# source of both inconsistency and mis-ranked reports.
_SEVERITY_RUBRIC = """

SEVERITY - anchor it to these, do not guess (the same finding must get the same severity every run):
• Critical - a principal reaches Tier-0 in ONE or TWO hops; a standing Tier-0 / Global-Admin-
  equivalent assignment; mass data access at subscription or management-group scope (every
  secret, key, or blob under it); OR any of the above held by a DISABLED, ORPHANED, GUEST, or
  FOREIGN-tenant identity.
• High - a THREE-plus-hop path to Tier-0; a broad-scope privileged role (Owner / User Access
  Administrator / Contributor at subscription or management-group scope); a dangerous Microsoft
  Graph APPLICATION permission (Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory,
  Mail.ReadWrite.All, …); cross-subscription blast radius. Exploitable, but needs a step.
• Medium - risk that needs a precondition: a specific pre-existing access, or a second
  misconfiguration to combine; or a hygiene gap that enables FUTURE escalation.
• Low - a best-practice deviation or cleanup item with no direct escalation path.
Elevate ONE level when the subject is disabled / orphaned / guest / foreign, or when a
data-plane reach (read secrets/blobs) is combined with an escalation primitive.

PRECISION - cite EXACT entity names and EXACT counts from the fact pack. Never write "several",
"many", "multiple", or "some" without the number, and every number you state must come from a
fact-pack field, not an estimate."""


# Per-DOMAIN reading guide - tells each agent exactly which fact-pack sections hold its evidence
# and what PAIRING constitutes a finding, so the weaker agents ground as tightly as the strong
# ones and read the same sections the same way every run. Keyed by _SPECIALIST_DOMAIN value.
_DOMAIN_READING_GUIDE = {
    "attack_paths": (
        "\n\nREAD: escalation_edges (each abuse primitive as src → dst, with dst_is_tier0), "
        "tier0_principals (who already holds the keys), pim_eligible_shadow_admins "
        "(self-activation to Tier-0), entra_role_all, cross_subscription_bridges (multi-sub reach). "
        "A finding = a SOURCE principal + the chain of escalation_edges it can walk to a Tier-0 "
        "destination - name every hop and its primitive."),
    "applications": (
        "\n\nREAD: over_permissive_apps (apps/SPs with dangerous Graph permissions + owners), "
        "credential_exposure (each SP's password/cert/federated credentials, incl. FIC "
        "issuer+subject), service_principal_inventory (privilege rank, foreign/orphan flags), "
        "compute_identity_exposure. A finding pairs a dangerous permission / over-broad federated "
        "trust / missing owner WITH the privilege that identity carries."),
    "resources": (
        "\n\nREAD: keyvault_exposure (access model, purge/soft-delete, who can read secrets), "
        "storage_exposure (public blob, shared-key), compute_identity_exposure (managed-identity "
        "theft reach), container_exposure (ACR push/admin), subscription_rbac_all (data-plane / "
        "control roles at scope). A finding pairs an exposed resource WITH the principal set that "
        "can reach it."),
    "identity": (
        "\n\nREAD: hygiene_issues (disabled-but-privileged, classic admins, credential sprawl), "
        "tier0_principals, entra_role_all, pim_eligible_shadow_admins, guest_and_foreign, "
        "escalation_edges. A subject that is PIM-eligible OR disabled/hygiene-flagged AND ALSO "
        "holds a direct escalation primitive is the higher-severity finding - check for that pairing."),
    "tenant_config": (
        "\n\nREAD: external_exposure (live IDG-/ARG- rows for Conditional Access, security "
        "defaults, legacy auth - cite the exact row) plus the identity core. Flag ONLY "
        "positively-confirmed control gaps; never infer a gap from data that was not collected."),
    "devops": (
        "\n\nREAD: credential_exposure (FIC issuer+subject - inspect for over-broad trust: "
        "repo:org/*, environment:*, wildcard ref), service_principal_inventory + "
        "over_permissive_apps (the SP's Graph/RBAC privilege), compute_identity_exposure "
        "(MIs on automation compute), subscription_rbac_all. A finding pairs a broad federated "
        "trust or Run-As identity WITH the privilege it carries."),
    "rbac": (
        "\n\nREAD: subscription_rbac_all (every Owner/Contributor/UAA assignment with role + "
        "scope), broad_access_signals (large privileged groups), entra_role_all, tier0_principals, "
        "cross_subscription_bridges. A finding names the principal, the EXACT role, the EXACT "
        "scope, and the blast radius (subscriptions/MGs reached)."),
    "breadth": (
        "\n\nREAD: broad_access_signals + large_privileged_groups_detail (group size + what it "
        "confers), subscription_rbac_all, entra_role_all. A finding pairs a large / undifferentiated "
        "membership WITH the privilege every member inherits."),
    "external": (
        "\n\nREAD: external_exposure (internet-facing resources, live ARG/Graph rows), "
        "tier0_principals, subscription_rbac_all, broad_access_signals. A finding pairs an "
        "internet-exposed resource WITH who can reach it and what that unlocks."),
}


# Appended to EVERY specialist's system prompt. Turns each agent's free-form "look for" list
# into a disciplined checklist so two runs over the same tenant surface the same set of
# findings - the single biggest lever against run-to-run drift on the AI side.
_CHECKLIST_DISCIPLINE = """

CHECKLIST DISCIPLINE - analyse the SAME way every run; this is what makes the result repeatable:
• The itemised focus list above is your CHECKLIST. Work through it top to bottom on EVERY scan and
  evaluate each item against this tenant's fact pack + anomaly_signals. Do not skip items, and do
  not let what looks interesting this run change which items you assess.
• Report EVERY instance that matches a checklist item - never sample, never collapse a group into
  "one example", never stop early because you have enough. Two runs over identical data MUST
  produce the same findings. Decide "one finding naming N entities" vs "N findings" by the item,
  the same way each time.
• Stay INSIDE your checklist. Do NOT record a finding that matches none of your items - another
  specialist owns that ground, and an off-checklist finding is drift, not insight.
• Title deterministically: build each title from its SUBJECT entity plus the checklist condition it
  matches (e.g. "<name> holds User Access Administrator across N subscriptions"). The same issue
  must read the same on every scan - do not re-phrase a recurring finding for variety.
• A checklist item that does not apply: move on silently. Never emit an "all clear" / "no issues"
  finding."""


# Domains that AzureHound does not collect - AI findings that are purely about these
# domains cannot be confirmed from the fact pack and are suppressed as noise.
_NON_ASSESSABLE_DOMAINS = {
    "conditional access", "mfa", "multi-factor authentication",
    "sign-in log", "sign in log", "audit log",
    "network security group", "nsg", "network exposure",
    "encryption at rest", "encryption-at-rest", "data-plane encryption",
    "diagnostic log", "diagnostic setting",
}

# Phrases that mark an "absence of data" finding rather than a confirmed risk.
_ABSENCE_PHRASES = (
    "no data available", "cannot be confirmed", "not assessable",
    "data not collected", "unable to confirm", "unable to assess",
    "not collected", "no conditional access", "no ca policy",
    "no mfa policy", "no mfa data", "no sign-in",
)


# Domains the live Reader SP (Track B) DOES collect - Conditional Access / security
# defaults (Policy.Read.All) and network exposure (Resource Graph). When Track B ran,
# a finding about these is confirmable from external_exposure and must NOT be suppressed
# as "non-assessable"; only the genuinely-uncollected domains (MFA methods, sign-in /
# audit logs, encryption-at-rest, diagnostics) stay suppressed.
_TRACK_B_ASSESSABLE = {
    "conditional access", "no conditional access", "no ca policy",
    "network security group", "nsg", "network exposure",
}


def _is_non_assessable_finding(f: dict, track_b: bool = False) -> bool:
    """Return True if a finding is solely about a non-assessable domain with no confirmable data.

    When `track_b` is set (a live Reader service principal ran), Conditional Access and
    network exposure ARE collected, so findings about them are dropped from the suppression
    set - otherwise a legitimate, live-confirmed "no Conditional Access baseline" finding
    would be silently discarded by the same phrase-match that suppresses uncollected-domain noise."""
    domains = _NON_ASSESSABLE_DOMAINS - _TRACK_B_ASSESSABLE if track_b else _NON_ASSESSABLE_DOMAINS
    absences = tuple(p for p in _ABSENCE_PHRASES if p not in _TRACK_B_ASSESSABLE) if track_b else _ABSENCE_PHRASES
    text = " ".join(filter(None, [
        f.get("title", ""), f.get("summary", ""),
        f.get("what", ""), f.get("reasoning", ""),
    ])).lower()
    domain_hit = any(kw in text for kw in domains)
    absence_hit = any(ph in text for ph in absences)
    return domain_hit and absence_hit


# ── Tool schemas ────────────────────────────────────────────────────────────

_ENTITIES_PROP = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "id":              {"type": "string", "description": "Exact entity id from the fact pack"},
            "role_in_finding": {"type": "string", "description": "How this entity participates"},
            "relation":        {"type": "string", "enum": ["subject", "context"],
                                "description":
                                    "Whether this entity is what the finding is ABOUT. 'subject' = a principal that "
                                    "holds the risky access or is the actor whose capability this finding describes "
                                    "(e.g. the disabled account that still retains Owner). 'context' = a related party "
                                    "named only to EXPLAIN the finding, not part of its own attack (e.g. an admin who "
                                    "could reset the subject's password, a bystander, a comparison account). The "
                                    "attack path is anchored on the SUBJECT and NEVER on a context entity, so any "
                                    "helper or bystander MUST be 'context'. Omit or use 'subject' when in doubt."},
        },
        "required": ["id", "role_in_finding"],
    },
}

_CHAIN_PROP = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "from_id":   {"type": "string"},
            "to_id":     {"type": "string"},
            "technique": {"type": "string"},
        },
        "required": ["from_id", "to_id", "technique"],
    },
}

# The closed set of first-move attack primitives a finding can declare. Each maps (in
# scoring._PRIMITIVE_ATTACK_EDGES) to the escalation edge(s) that anchor the finding's
# attack path, so the path matches the description. Shared by the
# specialist finding schema and the coherence-check tool.
ATTACK_PRIMITIVES = [
    "azure_rbac_escalation", "key_vault_secret_read", "storage_key_theft",
    "storage_blob_read", "managed_identity_theft", "aks_exec", "container_push",
    "entra_role_grant", "app_credential_add", "group_member_add",
    "password_reset", "pim_activation", "none",
]

_FINDING_BASE = {
    "title":            {"type": "string", "minLength": 5},
    "severity":         {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
    "confidence":       {"type": "integer", "minimum": 0, "maximum": 100},
    "category":         {"type": "string", "minLength": 1},
    "entities":         _ENTITIES_PROP,
    "summary":          {"type": "string", "minLength": 20,
                         "description": "2-3 plain-language sentences for a non-technical executive audience - no jargon, just impact. MUST be non-empty."},
    "what":             {"type": "string", "minLength": 10},
    "reasoning":        {"type": "string", "minLength": 30,
                         "description": "Full technical narrative ≥4 sentences - exact fact-pack references, how facts connect. MUST be non-empty."},
    "why_it_matters":   {"type": "string", "minLength": 10},
    "attack_scenario":  {"type": "string", "minLength": 20,
                         "description": "Step-by-step how an attacker exploits this - numbered steps, cite entity IDs. MUST be non-empty."},
    "escalation_chain": _CHAIN_PROP,
    "evidence":         {"type": "array", "items": {"type": "string", "minLength": 5},
                         "minItems": 2,
                         "description": "≥2 specific facts from the fact pack proving this finding (entity IDs, counts, permission names). MUST have at least 2 items."},
    "remediation":      {"type": "string", "minLength": 10},
    "detection":        {"type": "string", "minLength": 10,
                         "description": "Specific log events, Sentinel/Defender alerts, or KQL query hints to detect this in flight"},
    "mitre_technique":  {"type": "string", "minLength": 5,
                         "description": "REQUIRED. The single best-fit MITRE ATT&CK technique ID for this "
                         "finding, e.g. T1098.001 (Additional Cloud Credentials), T1552.005 (Cloud Instance "
                         "Metadata API), T1078.004 (Valid Accounts: Cloud), T1528 (Steal Application Access "
                         "Token). Pick the closest technique even when the mapping is approximate - every "
                         "finding maps to at least one adversary technique."},
    "attack_primitive": {"type": "string", "enum": ATTACK_PRIMITIVES,
                         "description": "REQUIRED. The SINGLE concrete first escalation move in your attack "
                         "scenario - it anchors the attack-path diagram to YOUR scenario, "
                         "so they must match. Pick the one your scenario's first step performs: "
                         "azure_rbac_escalation (assign yourself a higher AZURE role - UAA/Owner self-escalation, "
                         "Microsoft.Authorization/roleAssignments/write), entra_role_grant (grant an ENTRA "
                         "directory role or app role), password_reset (reset another account's password), "
                         "app_credential_add (add a secret/cert to an app or SP to impersonate it), "
                         "group_member_add (add a member to a privileged group), pim_activation (activate an "
                         "eligible PIM role), key_vault_secret_read, storage_key_theft, storage_blob_read, "
                         "managed_identity_theft (run code on a VM/app to steal its MI via IMDS), aks_exec, "
                         "container_push. CRITICAL: an Azure RBAC self-escalation (User Access Administrator, "
                         "Owner, Contributor → grant yourself Owner) is 'azure_rbac_escalation', NEVER "
                         "'entra_role_grant' - those are different planes. Use 'none' only for a pure "
                         "exposure/hygiene finding with no single escalation move."},
    "exploitability":   {"type": "string", "enum": ["immediate", "hours", "days", "complex"],
                         "description": "Realistic exploitation complexity: immediate=single API call, hours=script+creds, days=custom tooling, complex=physical/insider"},
}

_REQUIRED_FINDING = [
    "title", "severity", "confidence", "category", "entities",
    "summary", "what", "reasoning", "why_it_matters", "attack_scenario",
    "evidence", "remediation", "detection", "mitre_technique", "attack_primitive",
]

_FINDING_TOOL = {
    "name": "record_finding",
    "description": "Record one confirmed security finding. Call once per distinct finding.",
    "input_schema": {
        "type": "object",
        "properties": _FINDING_BASE,
        "required": _REQUIRED_FINDING,
    },
}

_CHAIN_TOOL = {
    "name": "record_attack_chain",
    "description": (
        "Record a multi-step attack chain formed by combining two or more confirmed findings. "
        "Use this when a sequence of findings creates a path from external access (or low-privilege) "
        "all the way to high-impact compromise - the combined chain is more severe than any single finding alone."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "Short descriptive title, e.g. 'External app credential → managed identity → Tier-0'",
            },
            "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
            "combined_finding_titles": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Exact titles of the confirmed findings this chain connects, in chain order",
            },
            "entry_entity_id": {
                "type": "string",
                "description": "Entity id of the attacker's starting point (must be in fact pack)",
            },
            "terminal_impact": {
                "type": "string",
                "description": "What the attacker achieves at the end - e.g. 'Full tenant compromise via Global Admin'",
            },
            "step_by_step_narrative": {
                "type": "string",
                "description": "Full attack walkthrough, numbered steps, citing specific entity ids and techniques at each hop",
            },
            "why_more_severe_combined": {
                "type": "string",
                "description": "Why this combination is more dangerous than each finding in isolation",
            },
            "entities": _ENTITIES_PROP,
            "escalation_chain": _CHAIN_PROP,
            "remediation_priority": {
                "type": "string",
                "description": "Which single finding to remediate first to break this chain, and why that breaks the whole path",
            },
            "detection": {
                "type": "string",
                "description": "Key log events / Sentinel signals that would reveal this multi-step path in progress",
            },
        },
        "required": [
            "title", "severity", "confidence", "combined_finding_titles",
            "entry_entity_id", "terminal_impact", "step_by_step_narrative",
            "why_more_severe_combined", "entities", "escalation_chain",
            "remediation_priority", "detection",
        ],
    },
}

# ── Deterministic anomaly signal computation ────────────────────────────────
# Replaces AI-based scanning with pure Python - zero cost, zero hallucination, 100% coverage.

_SP_READ_TOKENS = frozenset({
    "monitor", "monitoring", "read", "reader", "report", "reporting",
    "log", "logging", "audit", "view", "viewer", "observer", "metric",
    "analytics", "insights", "readonly", "read-only",
})
_SP_WRITE_TOKENS = frozenset({
    "write", "readwrite", "manage", "admin", "delete", "create",
    "update", "import", "reset", "grant", "assign", "invite",
})
_CRITICAL_GRAPH_PERMS = frozenset({
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
})
_DANGEROUS_GRAPH_PERMS = frozenset({
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Mail.ReadWrite.All",
    "User.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Group.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "EntitlementManagement.ReadWrite.All",
    "Exchange.ManageAsApp",
    "Sites.FullControl.All",
    "full_access_as_app",
})


def _sig(scanner: str, eid: str, ename: str, atype: str,
         detail: str, severity: str, **extra) -> dict:
    d = {"entity_id": eid, "entity_name": ename, "anomaly_type": atype,
         "detail": detail, "severity_hint": severity, "_scanner": scanner}
    d.update(extra)
    return d


_SUB_GUID_RE = re.compile(r"/subscriptions/([0-9a-fA-F-]{36})", re.IGNORECASE)


def _subscription_of(scope: str | None) -> "str | None":
    """Extract the subscription GUID from an ARM scope, or None (e.g. MG scope).

    Case-insensitive: AzureHound emits ARM paths upper-cased.
    """
    m = _SUB_GUID_RE.search(scope or "")
    return m.group(1).lower() if m else None


def _compute_anomaly_signals(fact_pack: "FactPack") -> "dict[str, list[dict]]":
    """Deterministic anomaly signals from complete uncapped inventories.

    Produces the same compact signal dict that Sonnet specialists and the
    synthesizer consume. Every single inventory item is checked - no sampling,
    no chunking, no AI calls.
    """
    out: "dict[str, list[dict]]" = {
        "sp": [], "rbac": [], "entra": [], "group": [], "app": [], "paths": [],
    }

    # ── SP ────────────────────────────────────────────────────────────────────
    orphan_rows: list[tuple[str, str, int, int]] = []
    for sp in fact_pack.raw_sp_list:
        eid, ename = sp["id"], sp["name"]
        perms       = sp.get("permissions") or []
        perm_count  = sp.get("permission_count", 0)
        cred_count  = sp.get("credential_count", 0)
        owner_count = sp.get("owner_count", 0)
        nl          = (ename or "").lower().replace("-", " ").replace("_", " ")

        if perm_count >= 5:
            sev = "Critical" if perm_count >= 10 else "High"
            out["sp"].append(_sig("sp", eid, ename, "excessive_permissions",
                f"{perm_count} Graph permissions: {', '.join(perms[:10])}", sev))

        bad = [p for p in perms if p in _DANGEROUS_GRAPH_PERMS]
        if bad:
            crit = any(p in _CRITICAL_GRAPH_PERMS for p in bad)
            out["sp"].append(_sig("sp", eid, ename, "sensitive_permission_broad",
                f"Holds {'critical' if crit else 'high-risk'} Graph permission(s): {', '.join(bad)}",
                "Critical" if crit else "High",
                _permissions=bad))

        if perm_count < 5 and not bad:
            is_readonly = any(tok in nl for tok in _SP_READ_TOKENS)
            write_p = [p for p in perms if any(w in p.lower() for w in _SP_WRITE_TOKENS)]
            if is_readonly and write_p:
                out["sp"].append(_sig("sp", eid, ename, "name_permission_mismatch",
                    f"Name implies read-only but holds write permissions: {', '.join(write_p[:5])}",
                    "High"))

        if cred_count >= 3:
            out["sp"].append(_sig("sp", eid, ename, "many_credentials",
                f"{cred_count} client secrets/certs - each is an independent credential-theft vector",
                "Medium"))

        # Orphaned SPs are collected and emitted AFTER the loop, aggregated. Emitting one
        # Medium signal each produced 1,069 rows - 82% of the entire signal budget for the
        # breadth/hygiene specialists - of which 993 were managed identities, which cannot
        # have owners by design. It was also filed under anomaly_type
        # "excessive_permissions", so a 0-permission SP was reported under a label meaning
        # "too many permissions", making the two indistinguishable downstream.
        if (owner_count == 0 and (perm_count > 0 or cred_count > 0)
                and not sp.get("is_managed_identity")):
            orphan_rows.append((eid, ename, perm_count, cred_count))

        # NOTE: there is deliberately no multi-tenant/foreign-SP signal here.
        # raw_sp_list is tenant-owned SPs only, so a foreignness check can never fire.
        # Foreign SPs are counted in broad_access_signals.external_sp_exposure instead;
        # their appRoles describe what they *define*, not what this tenant *granted*
        # them, so permission counts on them would be misleading rather than useful.

    # One population-level signal for orphaned SPs, plus individual signals only for the
    # ones that are ALSO over-provisioned. Managed identities are excluded above.
    if orphan_rows:
        _worst = sorted(orphan_rows, key=lambda r: (-r[2], -r[3]))
        out["sp"].append(_sig(
            "sp", _worst[0][0], _worst[0][1], "orphaned_sp_population",
            f"{len(orphan_rows)} of {len(fact_pack.raw_sp_list)} tenant-owned service "
            f"principals have NO owner while holding permissions or credentials - nobody "
            f"is accountable for their rotation or review. Most-privileged: "
            + "; ".join(f"{n} ({pc} perm/{cc} cred)" for _, n, pc, cc in _worst[:10]),
            "Medium", _count=len(orphan_rows)))
        for _eid, _name, _pc, _cc in _worst:
            if _pc >= 5 or _cc >= 3:
                out["sp"].append(_sig(
                    "sp", _eid, _name, "orphaned_sp",
                    f"Orphaned SP (no owners) with {_pc} permission(s) and {_cc} "
                    f"credential(s) - unaccountable and over-provisioned",
                    "High" if _pc >= 5 else "Medium",
                    _permission_count=_pc, _credential_count=_cc))

    # ── RBAC ──────────────────────────────────────────────────────────────────
    # Management-group assignments are enumerated individually - there are few of them
    # and each one is critical (an MG role applies to every child subscription at once).
    # Subscription-scope assignments are AGGREGATED per (principal, role): a large
    # tenant has tens of thousands, and emitting one signal each buried the useful
    # cross-subscription shape ("X is Owner in 12 subscriptions") under ~36,000 rows
    # that the prompt budget then had to sample away at random.
    owner_rows: list[dict]           = []
    principal_scopes: "dict[str, set]" = {}
    sub_agg: "dict[tuple, dict]"     = {}   # (principal, role) → subscription scopes

    def _is_mg(s: str) -> bool:
        # Case-insensitive: AzureHound emits ARM paths upper-cased, so the old
        # `"managementGroups" in scope` was always False. That mislabelled every
        # management-group assignment as "subscription scope" and rated it High
        # instead of Critical - under-rating the highest-blast-radius role in Azure.
        return "managementgroups" in (s or "").lower()

    # MG scope -> the subscriptions beneath it, so an MG-scoped role can be reported as a
    # concrete blast radius (which subscriptions) instead of an abstract "management group".
    _mg_subs_by_id = {
        k.lower(): set(v)
        for k, v in (getattr(fact_pack, "mg_descendant_subscriptions", {}) or {}).items()
    }
    mg_agg: "dict[tuple, dict]" = {}   # (principal, role) → MGs held + union of their subs
    _disabled_rbac_seen: set = set()   # emit disabled_with_role once per principal

    for r in fact_pack.raw_rbac_list:
        eid   = r["principal_id"]
        ename = r["principal_name"]
        role  = r.get("role", "")
        scope = r.get("scope", "")
        # principal_kind carries NodeKind VALUES ("AZUser", "AZServicePrincipal",
        # "AZGroup"), not display names. Comparing against ("User","ServicePrincipal",
        # "Group") was never true, so the Contributor branch below was dead: 26,948
        # broad-scope Contributor assignments across 110 principals - the single most
        # common privileged role in the tenant, including 172 at management-group
        # scope - emitted zero signals. Strip the prefix once here so no later
        # comparison can drift back out of sync.
        kind  = (r.get("principal_kind", "") or "").removeprefix("AZ")
        is_mg = _is_mg(scope)
        principal_scopes.setdefault(eid, set()).add(scope)

        # Disabled account retaining BROAD Azure-RBAC access. raw_rbac_list is already
        # broad-scope-filtered, so any disabled principal here is a dormant re-enable path.
        # The Entra-only disabled_with_role signal never caught these (disabled admins in
        # this class hold Azure RBAC, not Entra roles). Emit once per principal.
        if r.get("enabled") is False and eid not in _disabled_rbac_seen:
            _disabled_rbac_seen.add(eid)
            out["rbac"].append(_sig("rbac", eid, ename, "disabled_with_role",
                f"Disabled account {ename} retains broad Azure RBAC: {role} at {scope} - "
                f"re-enabling restores full access", "High", _role=role, _scope=scope))

        if role == "Owner":
            owner_rows.append(r)

        if is_mg:
            if role in ("Owner", "User Access Administrator") or (
                    role == "Contributor" and kind in ("User", "ServicePrincipal", "Group")):
                agg = mg_agg.setdefault((eid, role),
                                        {"name": ename, "kind": kind, "mgs": set(), "subs": set()})
                agg["mgs"].add(scope)
                # Union, not max: holding a role on two sibling MGs reaches the sum of
                # their descendants, so the union is the true blast radius.
                agg["subs"] |= _mg_subs_by_id.get(scope.lower().rstrip("/"), set())
        elif role in ("Owner", "User Access Administrator") or (
                role == "Contributor" and kind in ("User", "ServicePrincipal", "Group")):
            agg = sub_agg.setdefault((eid, role), {"name": ename, "kind": kind, "scopes": set()})
            # Key on the subscription GUID, not the raw scope string. AzureHound emits
            # the same subscription with inconsistent casing (28 of 66 scope strings in
            # a real tenant were case-variants), so counting strings reported "Owner in
            # 66 subscriptions" for a tenant that has 38.
            agg["scopes"].add(_subscription_of(scope) or scope.lower())

    # One aggregated signal per (principal, role) at management-group scope, carrying
    # the union blast radius. MG scope is the highest-impact RBAC placement in Azure,
    # so these stay Critical for Owner/UAA regardless of how many MGs are involved.
    for (eid, role), agg in mg_agg.items():
        ename, kind = agg["name"], agg["kind"]
        n_mg, n_sub = len(agg["mgs"]), len(agg["subs"])
        mg_names = ", ".join(sorted(s.rstrip("/").rsplit("/", 1)[-1] for s in agg["mgs"])[:5])
        more = f" (+{n_mg - 5} more)" if n_mg > 5 else ""
        reach = (f" - reaching all {n_sub} subscription(s) beneath them" if n_sub
                 else " - reaching every child subscription")
        if role == "Owner":
            detail = (f"{ename} ({kind}) → Owner at MANAGEMENT GROUP scope on {n_mg} MG(s) "
                      f"[{mg_names}{more}]{reach}. Full control of every resource in scope.")
            sev = "Critical"
        elif role == "User Access Administrator":
            detail = (f"{ename} ({kind}) → User Access Administrator at MANAGEMENT GROUP scope "
                      f"on {n_mg} MG(s) [{mg_names}{more}]{reach}. Can self-assign Owner in each.")
            sev = "Critical"
        else:
            detail = (f"{ename} ({kind}) → Contributor at MANAGEMENT GROUP scope on {n_mg} MG(s) "
                      f"[{mg_names}{more}]{reach}.")
            sev = "High"
        out["rbac"].append(_sig(
            "rbac", eid, ename,
            "owner_scope" if role != "Contributor" else "broad_role_assignment",
            detail, sev, _role=role, _scope=sorted(agg["mgs"])[0],
            _mg_count=n_mg, _mg_subscription_reach=n_sub))

    # Emit one aggregated signal per (principal, role) at subscription scope. The
    # subscription COUNT is the cross-subscription signal the specialist actually needs.
    for (eid, role), agg in sub_agg.items():
        n = len(agg["scopes"])
        ename, kind = agg["name"], agg["kind"]
        sample = ", ".join(sorted(agg["scopes"])[:5])
        more = f" (+{n - 5} more)" if n > 5 else ""
        if role == "Owner":
            sev = "Critical" if n >= 3 else "High"
            detail = (f"{ename} ({kind}) → Owner in {n} subscription(s): {sample}{more}"
                      + (" - cross-subscription blast radius" if n >= 2 else ""))
        elif role == "User Access Administrator":
            sev = "Critical" if n >= 3 else "High"
            detail = (f"{ename} ({kind}) → User Access Administrator in {n} subscription(s): "
                      f"{sample}{more} - can re-grant any role in each"
                      + ("; cross-subscription blast radius" if n >= 2 else ""))
        else:
            sev = "High" if (n >= 3 or kind == "Group") else "Medium"
            detail = f"{ename} ({kind}) → Contributor in {n} subscription(s): {sample}{more}"
        out["rbac"].append(_sig(
            "rbac", eid, ename,
            "owner_scope" if role != "Contributor" else "broad_role_assignment",
            detail, sev, _role=role, _scope=sorted(agg["scopes"])[0],
            _subscription_count=n))

    if len(owner_rows) >= 5:
        r0 = owner_rows[0]
        out["rbac"].append(_sig("rbac", r0["principal_id"], r0["principal_name"], "aggregate_count",
            f"{len(owner_rows)} principals hold Owner at subscription/MG scope total",
            "High"))

    for eid, scopes in principal_scopes.items():
        # Count distinct SUBSCRIPTIONS (and management groups), not distinct scope
        # strings, so the number means what the signal name claims it means.
        subs = {_subscription_of(s) or s.lower() for s in scopes}
        if len(subs) >= 3:
            node  = fact_pack.entity_index.get(eid)
            ename = node["name"] if node else eid
            mg_note = " (includes management-group scope)" if any(_is_mg(s) for s in scopes) else ""
            out["rbac"].append(_sig("rbac", eid, ename, "cross_subscription_access",
                f"{ename} holds RBAC across {len(subs)} distinct subscriptions/management groups"
                f"{mg_note}: {', '.join(sorted(subs)[:5])}",
                "Critical" if len(subs) >= 5 or mg_note else "High",
                _subscription_count=len(subs)))

    # INDIRECT cross-subscription bridges: reach a principal inherits through group
    # membership, an owned service principal, PIM eligibility, or an escalation chain -
    # which the direct-scope scan above cannot see. These are exactly the cross-subscription
    # attack paths that get missed when each subscription is looked at in isolation.
    for br in (fact_pack.cross_subscription_bridges or []):
        # Skip the leading guidance note (no id) and any direct-only bridge; the mechanism
        # carries an "inherited" marker exactly when reach exceeds directly-held RBAC.
        if not br.get("id") or "inherited" not in (br.get("mechanism") or ""):
            continue
        n_sub = br.get("subscription_count", 0)
        if n_sub < 2:
            continue
        t0 = br.get("reaches_tier0")
        sev = "Critical" if (t0 or n_sub >= 3) else "High"
        subs_txt = ", ".join(br.get("subscriptions", [])[:5])
        out["rbac"].append(_sig("rbac", br["id"], br["name"], "cross_subscription_access",
            f"{br['name']} ({br['kind']}) can reach {n_sub} subscription(s) via "
            f"{br.get('mechanism')} - {subs_txt}"
            + (" - and reaches Tier-0" if t0 else "")
            + ". Cross-subscription blast radius gained WITHOUT holding the RBAC directly.",
            sev, _subscription_count=n_sub, _cross_sub_indirect=True))

    # ── Entra ─────────────────────────────────────────────────────────────────
    ga_list: list[dict]              = []
    principal_roles: "dict[str, list]" = {}

    for r in fact_pack.raw_entra_list:
        eid   = r["principal_id"]
        ename = r["principal_name"]
        role  = r.get("role", "")
        principal_roles.setdefault(eid, []).append(role)

        if r.get("guest"):
            out["entra"].append(_sig("entra", eid, ename, "guest_with_role",
                f"Guest {ename} holds Entra role: {role}", "High", _role=role))

        if r.get("enabled") is False:
            out["entra"].append(_sig("entra", eid, ename, "disabled_with_role",
                f"Disabled account {ename} retains Entra role: {role} - re-enabling restores full privilege",
                "Medium", _role=role))

        if role == "Global Administrator":
            ga_list.append({"id": eid, "name": ename})

    if len(ga_list) > 5:
        out["entra"].append(_sig("entra", ga_list[0]["id"], ga_list[0]["name"], "ga_excess",
            f"{len(ga_list)} Global Administrators (standard ≤5): "
            f"{', '.join(p['name'] for p in ga_list[:12])}",
            "High"))

    for eid, roles in principal_roles.items():
        if len(roles) >= 3:
            node  = fact_pack.entity_index.get(eid)
            ename = node["name"] if node else eid
            out["entra"].append(_sig("entra", eid, ename, "excessive_permissions",
                f"{ename} holds {len(roles)} Entra roles simultaneously: {', '.join(roles[:6])}",
                "High"))

    # ── Groups ────────────────────────────────────────────────────────────────
    for grp in fact_pack.raw_group_list:
        eid, ename = grp["id"], grp["name"]
        mc    = grp.get("member_count", 0)
        privs = grp.get("privileges", [])
        ps    = "; ".join(f"{p.get('primitive','?')} → {p.get('target_name','?')}" for p in privs[:3])

        if grp.get("is_dynamic") and privs:
            rule = (grp.get("membership_rule") or "?")[:120]
            out["group"].append(_sig("group", eid, ename, "dynamic_group_privileged",
                f"Dynamic group '{ename}' ({mc} members) auto-grants: {ps}. Rule: [{rule}]",
                "Critical" if mc >= 20 else "High"))

        if mc >= 50:
            out["group"].append(_sig("group", eid, ename, "large_group_privileged",
                f"Group '{ename}' ({mc} members) grants: {ps}", "Critical"))
        elif mc >= 10:
            out["group"].append(_sig("group", eid, ename, "large_group_privileged",
                f"Group '{ename}' ({mc} members) grants: {ps}", "High"))
        elif grp.get("is_tier0") and privs:
            out["group"].append(_sig("group", eid, ename, "large_group_privileged",
                f"Tier-0 group '{ename}' ({mc} members) grants: {ps}", "High"))

    # ── App grants ────────────────────────────────────────────────────────────
    for ag in fact_pack.raw_app_grant_list:
        eid, ename = ag["sp_id"], ag["sp_name"]
        role  = ag.get("role_value", "")
        count = ag.get("grantee_count", 0)
        sample = ", ".join(
            g.get("name", g.get("id", "?")) for g in ag.get("sample_grantees", [])[:3]
        )

        if role in _CRITICAL_GRAPH_PERMS:
            out["app"].append(_sig("app", eid, ename, "sensitive_permission_broad",
                f"CRITICAL permission '{role}' granted to {count} app(s). Samples: {sample}",
                "Critical"))
        elif role in _DANGEROUS_GRAPH_PERMS:
            out["app"].append(_sig("app", eid, ename, "sensitive_permission_broad",
                f"High-risk permission '{role}' granted to {count} app(s). Samples: {sample}",
                "High"))
        elif count >= 10:
            out["app"].append(_sig("app", eid, ename, "broad_role_assignment",
                f"'{role}' granted to {count} applications - unusually broad grant", "High"))
        elif count >= 3:
            out["app"].append(_sig("app", eid, ename, "broad_role_assignment",
                f"'{role}' granted to {count} apps. Samples: {sample}", "Medium"))

    # ── Attack paths (graph traversal) ────────────────────────────────────────
    # Deduplicate by source: one signal per source principal using the shortest
    # path (lowest hop_count) to any tier-0 target.
    by_src: "dict[str, dict]" = {}
    for ap in fact_pack.raw_attack_paths:
        sid = ap["src_id"]
        if sid not in by_src or ap["hop_count"] < by_src[sid]["hop_count"]:
            by_src[sid] = ap

    for src_id, ap in by_src.items():
        is_guest    = ap.get("src_is_guest", False)
        is_disabled = not ap.get("src_enabled", True)
        prefix = ("Guest " if is_guest else "Disabled " if is_disabled else "")
        qualifier  = " [account disabled - re-enabling restores this path]" if is_disabled else ""
        out["paths"].append(_sig(
            "paths", src_id, ap["src_name"], "attack_path",
            f"{prefix}{ap['src_kind']} '{ap['src_name']}' → '{ap['dst_name']}' "
            f"via {ap['hop_count']}-hop path: {ap['path']}{qualifier}",
            ap["severity"],
        ))

    return out


# ── Specialist definitions (17 total) ───────────────────────────────────────

SPECIALISTS = [
    # ── 1. Privilege Escalation ──────────────────────────────────────────────
    {
        "key": "priv_esc",
        "label": "Privilege Escalation",
        "system": f"""You are a PRIVILEGE ESCALATION SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: every path by which a non-Tier-0 principal can reach Tier-0 privilege.

Look for:
• Direct/indirect role assignments granting Tier-0 (Global Admin, Privileged Role Admin, etc.)
• Ownership chains: owns app/SP → add credential → authenticate as → SP has Tier-0 role
• PIM-eligible assignments enabling self-activation with no standing assignment visible
• Group membership paths that transitively reach Tier-0
• CAN_ADD_OWNER / CAN_GRANT_ROLE / CAN_GRANT_APP_ROLE primitives
• Multi-hop chains (2–3 hops are what defenders miss - enumerate them completely)
• appRoleAssignments that function as Tier-0 equivalents
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 2. Lateral Movement ──────────────────────────────────────────────────
    {
        "key": "lateral_movement",
        "label": "Lateral Movement",
        "system": f"""You are a LATERAL MOVEMENT SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: how an attacker moves between identities after initial access.

Look for:
• Managed identity theft: who can exec on VM/AKS/Automation and steal its token
• Ownership chains: owns SP → add credential → authenticate as → leverage its access
• Password reset chains: who can reset whose password and what does that unlock
• Cross-plane movement: Entra permission → ARM resource → managed identity → higher privilege
• Credential injection into SPNs (CAN_ADD_SECRET edges)
• Chains through groups: A adds itself to B → B has CAN_ADD_OWNER on C → C is Tier-0
• Federation credential manipulation on owned SPNs
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 3. External Entry Points ─────────────────────────────────────────────
    {
        "key": "entry_points",
        "label": "External Entry Points",
        "system": f"""You are an EXTERNAL ENTRY POINT SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: initial access vectors an external attacker would target.

Look for:
• Guests/external users with elevated access or group memberships chaining to privilege
• Multi-tenant or foreign SPNs with dangerous Graph API permissions
• Apps with long-lived client secrets or certificates (credential theft targets)
• Federated credentials trusting external or overly-broad issuers (GitHub Actions, public OIDC)
• Apps with dangerous Graph permissions beyond their need (Mail.Read, User.ReadWrite.All,
  RoleManagement.ReadWrite.Directory, Application.ReadWrite.All, etc.)
• SPNs accessible from external tenants with privileged access
• Classic admins bypassing modern Conditional Access and PIM
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 4. Data Plane & Resource Access ─────────────────────────────────────
    {
        "key": "data_plane",
        "label": "Data Plane & Resource Access",
        "system": f"""You are a DATA PLANE ACCESS SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: paths to sensitive data and compute resources.

Look for:
• Key Vault accessible via legacy access policy model (not RBAC)
• Key Vault purge protection disabled - permanent secret destruction possible
• Key Vault soft delete disabled - recovery window eliminated
• Storage with public blob access or key-accessible to over-permissive principals
• VM/AKS/Automation managed identity token theft (CAN_STEAL_MANAGED_IDENTITY)
• AKS exec paths bypassing cluster RBAC (CAN_EXEC_AKS)
• Managed identities on compute with ARM roles enabling further escalation
• Compound risk: data-plane access + escalation primitive = automatic severity elevation
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 5. Identity Hygiene ──────────────────────────────────────────────────
    {
        "key": "hygiene",
        "label": "Identity Hygiene",
        "system": f"""You are an IDENTITY HYGIENE SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: misconfigurations and hygiene issues that create persistent or growing risk.

Look for:
• Disabled accounts retaining privileged roles - dormant escalation paths re-enableable at any time
• Classic/legacy Azure admins (pre-RBAC, bypass modern controls)
• SPNs with excessive password credentials - wide blast radius if any credential leaks
• Apps whose credentials are owned by multiple principals - credential-sharing risk
• Stale federated credentials pointing at defunct or overly-broad issuers
• SPNs marked as managed identity but with manually added credentials (trust model violation)
• Count-level hygiene signals: unusually high Tier-0 count, excessive guest count, etc.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 6. RBAC Governance ───────────────────────────────────────────────────
    {
        "key": "rbac_governance",
        "label": "RBAC Governance",
        "system": f"""You are an AZURE RBAC GOVERNANCE SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: Azure subscription and management-group RBAC misconfigurations.

Look for:
• Owner or Contributor assignments at subscription or management-group scope to non-service identities
• Users or groups with Owner on subscription who should only have Contributor or narrower
• Custom roles that combine dangerous action sets (e.g. `*/write` + `*/delete` + roleAssignments/write)
• Wildcard action (`*`) assignments in custom roles - implicit blast radius growth as new resource types are added
• Service principals with User Access Administrator (can re-grant any RBAC role to anyone)
• CAN_ESCALATE_RBAC edges: who can grant themselves or others roles on subscriptions
• Role assignments to overly-broad groups (all-employees, all-users) at sensitive scopes
• Assignments that grant write access to identity resources (Microsoft.Authorization/*)
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 7. Application Lifecycle & Orphan Risk ───────────────────────────────
    {
        "key": "app_lifecycle",
        "label": "Application Lifecycle & Orphan Risk",
        "system": f"""You are an APPLICATION LIFECYCLE SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: risk from poorly maintained or orphaned applications and service principals.

Look for:
• SPNs or app registrations with no owners - no one accountable for credential rotation or decommission
• Apps with active credentials but that appear to serve no legitimate principal (no obvious owners or users)
• Apps with multiple active credentials where secrets may have been shared (credential sprawl)
• Multi-tenant app registrations with an SPN in this tenant plus high-privilege Graph permissions -
  an external tenant's app registration controls this SPN's credentials
• App registrations whose service principal has Tier-0 roles but whose app-side owners are low-privilege
  users (they can add credentials to the app registration and authenticate as the SPN)
• SPNs with federated credentials whose issuer subject is overly broad (e.g. `repo:org/*:*` GitHub pattern)
• Service principals for deprecated or end-of-life Microsoft services still holding active permissions
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 8. PIM Configuration & Activation Risk ───────────────────────────────
    {
        "key": "pim_risk",
        "label": "PIM & Activation Risk",
        "system": f"""You are a PIM (Privileged Identity Management) SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: risks from how PIM-eligible assignments are configured and can be activated.

Look for:
• PIM-eligible principals who can self-activate to Tier-0 without approval or MFA requirement
  (infer from the fact that they appear in pim_eligible_shadow_admins without activation controls noted)
• Principals eligible for multiple Tier-0 roles - broader lateral options once one role is activated
• High number of PIM-eligible principals relative to the tenant's size - PIM hygiene drift
• Eligible assignments for roles that should be permanently active (e.g. Break Glass accounts)
  vs. break-glass accounts that are only eligible (risky gap if emergency activation fails)
• The combination: principal is PIM-eligible AND also has a direct CAN_ADD_SECRET or CAN_ADD_OWNER edge -
  they can quietly escalate without ever activating their eligible role through PIM's audit trail
• Guests or foreign principals with PIM eligibility - external actors can activate Tier-0 roles
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 9. Tenant Defaults & Absent Controls ─────────────────────────────────
    {
        "key": "tenant_defaults",
        "label": "Tenant Defaults & Absent Controls",
        "system": f"""You are a TENANT CONFIGURATION SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: risks arising from default Azure/Entra settings and the ABSENCE of expected controls.

USE WHAT WAS COLLECTED; DO NOT FABRICATE ABSENCE:
When a live Reader service principal ran (Track B), `external_exposure` carries IDG-*/ARG-*
rows for Conditional Access, security defaults and legacy authentication. If those rows are
present, REASON OVER THEM directly - e.g. security defaults disabled with no CA baseline, or
legacy auth left enabled, is a positively-confirmed absent-control finding, not a guess.
When they are NOT present (AzureHound-only collection, or a domain named in collection_gaps /
coverage.not_assessable_domains), that data was not collected: NEVER write "no data available
to confirm X" or "cannot assess Y" as a finding, and never infer a negative from the absence -
Azure's insecure defaults apply unless confirmed, but that is context, not an actionable gap.
Only flag issues DIRECTLY AND POSITIVELY confirmed by data in the fact pack.

Reason about what the fact pack does NOT show, not just what it does show:
• external_exposure (when present): security defaults off, no/limited Conditional Access,
  legacy authentication enabled - confirmed baseline-control gaps that magnify every identity
  finding. Cite the specific IDG-/ARG- row.
• counts: if user count is high and guest count is high relative to users, flag guest sprawl risk.
• The absence of tenant object in the collection means key tenant-level settings (user consent,
  guest invite permissions, B2B collaboration, external identity provider federation) are unknown -
  Azure's insecure defaults apply unless otherwise confirmed.
• If any hygiene_issues show disabled-but-privileged accounts, reason about whether re-enabling
  those accounts is a plausible attack path - focus on the privilege they hold, not on absent CA data.
• Classic admins in hygiene_issues signal that legacy Azure management APIs are in use -
  those bypass all modern identity controls and should be escalated.
• If there are many Tier-0 principals, flag the increased blast radius per compromised account
  and the governance overhead of reviewing all of them.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 10. Automation & DevOps Attack Surface ───────────────────────────────
    {
        "key": "devops_surface",
        "label": "Automation & DevOps Surface",
        "system": f"""You are an AUTOMATION & DEVOPS ATTACK SURFACE SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: identity risks from automation workloads, CI/CD pipelines, and DevOps integrations.

Look for:
• Automation Accounts with Run-As credentials or managed identities that have ARM-wide or Tier-0 access
• Azure DevOps or GitHub Actions SPNs with Contributor or higher on subscriptions
• Federated credentials on SPNs with subject patterns that are too broad
  (e.g. `repo:myorg/*:*` trusts any repo in the org; `environment:*` trusts all environments)
• Managed identities on VMs/AKS used for automation that have more privilege than the workload needs
• Logic App managed identities - Logic Apps can call arbitrary APIs; if the identity has high ARM/Graph
  privilege, anyone who can edit the Logic App can escalate
• SPNs used by automation tools (Terraform, Ansible, Pulumi service principals) with Owner or
  User Access Administrator roles - infrastructure-as-code pipelines are a high-value target
• Multiple automation SPNs with overlapping high-privilege roles - lateral movement between pipelines

Data: `credential_exposure` carries each SP's `federated_credentials` as {{issuer, subject}} - inspect the
subject strings for over-broad trust (`repo:org/*:*`, `environment:*`, a wildcard branch/ref). `over_permissive_apps`
and `service_principal_inventory` give the SP's Graph permissions and privilege rank; `compute_identity_exposure`
gives the managed identities on VMs/AKS/Automation/Function/Logic apps and what they can reach. Correlate a broad
FIC subject or Run-As identity with the RBAC/Graph privilege it carries - that pairing is the finding.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 11. Hybrid Identity & On-Premises Sync ───────────────────────────────
    {
        "key": "hybrid_identity",
        "label": "Hybrid Identity & On-Prem Sync",
        "system": f"""You are a HYBRID IDENTITY SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: risks that originate from or flow through on-premises identity integration.

Look for:
• The Directory Synchronization Accounts role holder - the Azure AD Connect sync account has rights
  equivalent to DCSync when combined with on-prem access; if compromised at either end, full tenant takeover
• Hybrid Identity Administrator role: can configure federation, SSPR write-back, and password hash sync;
  compromise enables on-prem → cloud escalation or cloud → on-prem persistence
• Accounts flagged as synced from on-premises (onPremisesSyncEnabled=true) that hold Tier-0 roles -
  on-prem compromise of the synced account translates directly to cloud privilege
• Service principals for ADFS / PTA / PHS / Seamless SSO with broad permissions - compromise of the
  on-prem ADFS server or PTA agent gives token-forging or authentication bypass capability
• Accounts with onPremisesImmutableId set AND Tier-0 privilege - on-prem AD admin can modify the
  immutableId to link to a cloud Tier-0 account
• The pattern: Hybrid Identity Administrator + App Admin held by the same SPN or user = full hybrid takeover
• Guest users originating from on-prem-federated tenants with elevated cloud roles
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 12. Supply Chain & Container Security ────────────────────────────────
    {
        "key": "supply_chain_container",
        "label": "Supply Chain & Container",
        "system": f"""You are a SUPPLY CHAIN & CONTAINER SECURITY SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: supply-chain attack vectors, container registry abuse, and software-delivery pipeline risks.

Look for:
• Principals with AcrPush / Contributor / Owner on container registries (CAN_PUSH_CONTAINER edges) -
  can inject malicious images that execute in any workload pulling from the registry
• Container registries with multiple non-CI/CD principals able to push - unusually wide push access
• AKS clusters that pull from registries where the push principals are broader than expected - pivot:
  push malicious image → AKS pod execution → steal cluster managed identity
• Managed identities on container workloads (AKS, Container Apps, ACI) with broad RBAC -
  the identity is the impact radius of any image-injection attack; list what it can do
• Storage accounts used for deployment artifacts (Terraform state, ARM templates, pipeline caches)
  where the blob data roles are held by many principals - compromise yields supply-chain foothold
• SPNs with federated credentials from overly-broad GitHub Actions subjects pushing to registries
• Automation Accounts or Function Apps that pull images and run them - check their managed identity privilege
• Shared Terraform / Bicep / Pulumi state storage accounts accessible to multiple teams -
  state poisoning enables infrastructure supply-chain attacks
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 13. Cross-Subscription Attacks ──────────────────────────────────────
    {
        "key": "cross_subscription",
        "label": "Cross-Subscription Attacks",
        "system": f"""You are a CROSS-SUBSCRIPTION ATTACK SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: privilege escalation and lateral movement that spans Azure subscription boundaries.

Look for:
• Management group Owner / Contributor / User Access Administrator - this role applies to ALL child
  subscriptions simultaneously. A single principal at MG scope controls the entire subscription fleet.
  This is a "silent" blast radius: the principal's power is invisible in any per-subscription review.
• Principals that appear in RBAC assignments across two or more subscriptions - they can pivot between
  subscriptions without needing new credentials. Enumerate which subscriptions and what role.
• Managed identities assigned to a resource in Subscription A that hold RBAC roles in Subscription B -
  exploitation in Sub A (via run-command, exec) yields access to Sub B's resources.
• Service principals that appear as Owners or Contributors in multiple subscriptions - an org-wide
  automation SPN is a single credential compromise away from cross-subscription takeover.
• User Access Administrator at any subscription scope: the holder can assign themselves Owner in that
  subscription AND potentially inherit MG-level assignments. Map who holds this across all subscriptions.
• Cross-subscription paths: a low-privilege identity in Sub A can reach an identity in Sub B through
  shared group membership, app ownership, or transitive RBAC paths - enumerate any such chains.
• Classic Co-Administrators: they predate the subscription model and bypass modern RBAC scope checks.
  A Co-Admin in one subscription doesn't automatically have access to others, but any foothold is dangerous.
• Subscriptions under the same management group that share a privileged group - compromise of the group
  yields simultaneous access to all subscriptions in the group.

The fact pack gives you `cross_subscription_bridges`: every principal already resolved to reach two or
more subscriptions over the FULL escalation graph, with `subscription_count` (the true blast radius),
`reaches_tier0`, and a `mechanism` telling you HOW the reach is gained. Ground your findings in this list.
Pay special attention to bridges whose mechanism says "inherited" - the principal does NOT hold the RBAC
directly; it crosses the boundary through a group it belongs to, a service principal it owns, a role it is
PIM-eligible for, or an escalation chain. These are the cross-subscription attacks a per-subscription
review never sees. For every bridge you report, name the specific subscriptions that fall together when it
is compromised and state the mechanism, so a reader understands what turns a single foothold into a
tenant-wide, multi-subscription breach.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 14. Security Misconfiguration & Resource Exposure ────────────────────
    {
        "key": "security_misconfig",
        "label": "Security Misconfiguration & Resource Exposure",
        "system": f"""You are a SECURITY MISCONFIGURATION SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: resource-level security misconfigurations that an attacker can directly exploit or that
compound with identity misconfigurations to increase blast radius.

Look for:
• Storage accounts with public blob access enabled (allowBlobPublicAccess=true) - any container set to
  public exposes data to the internet without authentication. Combined with broad Contributor RBAC, an
  attacker can stage malicious payloads or exfiltrate data silently.
• Storage accounts where multiple principals hold listKeys-capable roles (Storage Account Contributor,
  Key Operator, broad Owner/Contributor) - the shared account key bypasses per-identity Entra logging
  and enables full data-plane access. High-count holders = high exfiltration risk.
• Key Vaults with purge protection and/or soft delete disabled - an attacker with Key Vault access can
  permanently destroy secrets or keys, causing irrecoverable data loss or service outage.
• Key Vaults using legacy access policy model (enableRbacAuthorization=false) - broad, non-audited access;
  when combined with broad ARM roles, the effective data-plane permissions are hard to enumerate.
• Automation Accounts or Function Apps whose managed identities have broad RBAC - a flaw in the deployed
  code (script injection, dependency confusion, SSRF) directly escalates to their identity's privilege.
• Multiple high-privilege principals on the same resource (e.g. 3+ principals with Owner on a VM) -
  unnecessarily large attack surface; one compromised principal is enough.
• Resources with no managed identity and no clear service principal - unmanaged resources that are
  configured "by hand" tend to use shared credentials or overly broad service account passwords.
• Compounding patterns: a resource misconfiguration (public blob access) PLUS an identity misconfiguration
  (SP with Owner and a leaked secret) creates a Critical combined risk even if each is High alone.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 15. Entitlement Abuse & Delegated Permissions ────────────────────────
    {
        "key": "entitlement_delegation",
        "label": "Entitlement Abuse & Delegated Permissions",
        "system": f"""You are an ENTITLEMENT MANAGEMENT & DELEGATED PERMISSION SPECIALIST reviewing an Azure/Entra tenant.
Sole focus: risks from delegated permissions, broad application entitlements, and entitlement management
misconfigurations that allow privilege escalation or silent persistence.

Look for:
• Service principals with EntitlementManagement.ReadWrite.All - can add any user to any group,
  including Tier-0 role-assignable groups, bypassing the direct role assignment audit trail entirely.
• Service principals with PrivilegedAccess.ReadWrite.AzureADGroup - can activate PIM group memberships
  for any principal into any group. Combined with a group that holds Tier-0 roles, this is a silent
  path to Global Administrator that never shows in active role assignment logs.
• SP holding both Application.ReadWrite.All AND Groups.ReadWrite.All - can create apps, add credentials,
  and add them to any group including privileged groups. Full self-escalation in two API calls.
• Broad delegated scopes (not just application permissions): SPNs with User.ReadWrite.All can modify
  any user's profile including adding authentication methods in some tenant configurations.
• Directory.ReadWrite.All combined with any form of group or role membership write access -
  a minimal graph traversal in two hops from this SP reaches tenant administrator.
• Cross-tenant application registrations in this tenant (foreign SPNs) that hold elevated permissions -
  the controlling party is the external tenant; revocation requires coordination with a third party.
• Service principals assigned PIM group write AND currently not holding a standing Tier-0 role -
  they are one API call from activating group membership into a Tier-0 role; invisible in current
  standing-privilege reviews.
• High-count entitlement: a single SP holding 3+ dangerous Graph permissions simultaneously -
  even if individually lower-risk, the combination creates independent escalation paths.

Data: each `over_permissive_apps` entry carries `dangerous_graph_permissions` (application/app-role
permissions) AND `delegated_scopes` with `delegated_admin_consented` (the on-behalf-of OAuth2 grants).
Reason over BOTH. A tenant-wide (delegated_admin_consented = true) grant of a high-impact delegated
scope - User.ReadWrite.All, Directory.ReadWrite.All, Group.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
RoleManagement.ReadWrite.Directory - applies to every user in the tenant and is a real escalation/persistence
vector even with no application permissions. Name the SP, the scope, and whether it is admin-consented.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 16. Access Breadth & Non-Standard Posture ────────────────────────────
    {
        "key": "access_breadth",
        "label": "Access Breadth & Non-Standard Posture",
        "system": f"""You are an ACCESS BREADTH & BASELINE DEVIATION SPECIALIST reviewing an Azure/Entra tenant.

Your job is fundamentally different from the other specialists: you do NOT look for known-bad named
patterns. You look for situations where access is granted at an UNUSUAL SCALE or in a NON-STANDARD
way that deviates from least privilege - even if no individual assignment is technically a known-bad
permission.

The fact pack gives you COMPLETE VISIBILITY via four key sections. Read all four:

`subscription_rbac_all` - EVERY RBAC assignment at subscription/MG scope.
  This is the full list. Count principals per role. Look for roles held by too many people.
  Look for groups with hundreds of members assigned a role. Look for the same principal across
  multiple subscriptions. Look for service principals holding Owner or Contributor.

`entra_role_all` - EVERY Entra directory role assignment.
  The full list. Who holds Global Administrator, Security Administrator, Application Administrator?
  Are there guest users with Entra roles? Disabled accounts with roles? Count how many people
  hold each role. Standard orgs have 2-5 Global Admins; 10+ is anomalous.

`service_principal_inventory` - ALL service principals ranked by permission_count (highest first).
  This is sorted so the outliers are at the top. A SP with 8+ Graph permissions is an outlier
  regardless of which permissions they are. Examine the top SPs. Do their permissions make sense
  for what the SP is likely for (its name)? Does a CI/CD bot need Mail.ReadWrite.All?
  Does a monitoring SP need RoleManagement.ReadWrite.Directory? Mis-named or over-provisioned
  SPs are findings.

`broad_access_signals` - Statistical summaries:
  - `large_privileged_groups`: groups with ≥5 members that hold any privileged access, member count included
  - `rbac_role_spread_at_broad_scope`: role → how many principals (counts only)
  - `entra_role_spread`: role name → count
  - `graph_permission_spread`: permission → count of SPs holding it
  - `app_role_grant_spread`: app roles granted to 3+ principals

Patterns to detect (examples, not exhaustive):

• PRODUCTION SECRETS ACCESSIBLE BY HUNDREDS - If large_privileged_groups shows a group like
  "All Developers (297 members) → CanReachKVSecret on production-vault", that means 297 people
  have access to production secrets. This is almost certainly not intentional and is High severity.
  Name the group, the count, and the specific vaults.

• TOO MANY GLOBAL ADMINS - Standard: ≤5. If entra_role_all shows 10+ Global Administrators,
  flag every one of them, list their names. 11 Global Admins means 11 different phishing targets
  that each result in complete tenant compromise.

• SP WITH MISMATCHED PERMISSIONS - Check service_principal_inventory. A SP named "monitoring",
  "reporting", or "read-only" that holds write permissions (Mail.ReadWrite.All, Group.ReadWrite.All,
  User.ReadWrite.All) is almost certainly over-provisioned. Name the SP, its permissions, and why
  they don't match its apparent purpose.

• DIRECTORY-ENUMERATION-AS-DEFAULT - If 20+ SPs hold Directory.Read.All, any one of them being
  compromised gives an attacker a complete map of all users, groups, and SPs in the tenant.
  This is reconnaissance infrastructure built into the tenant itself.

• OVERPOPULATED SUBSCRIPTION ROLES - Count Owner and Contributor across subscription_rbac_all.
  10+ Owners on a subscription is not least-privilege. List them. How many are users vs. SPs?
  How many are service principals that should be using managed identities instead?

• CROSS-SUBSCRIPTION PRINCIPALS - A user or SP that appears in subscription_rbac_all with roles
  on 3+ different subscriptions is a single point of compromise for all of them. Name them.

• GUEST USERS WITH ENTRA ROLES - Any entry in entra_role_all where guest=true is suspicious.
  External parties should not hold directory roles. List any found.

• DISABLED ACCOUNTS WITH ACTIVE ROLES - entra_role_all includes enabled field. A disabled account
  (enabled=false) that still holds an Entra role is a dormant privilege that can be re-activated.

• SP WITH MANY CREDENTIALS - service_principal_inventory includes credential_count. A SP with 5+
  client secrets means 5 different credential material vectors. Even if the SP itself is low-risk,
  many credentials suggests poor lifecycle management across the board.

MANDATORY: Your findings MUST cite actual names and actual counts from the fact pack.
Do not say "many service principals" - say "20 service principals hold Directory.Read.All."
Do not say "a large group" - say "Platform Engineers (297 members) can read production Key Vault."
Vague findings without specific entities and numbers will be rejected by the architect review.

{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },

    # ── 17. Resource Exposure & Data Protection (v2 Track B) ──────────────────
    {
        "key": "resource_exposure",
        "label": "Resource Exposure & Data Protection",
        "system": f"""You are a RESOURCE EXPOSURE & DATA-PROTECTION SPECIALIST reviewing an Azure tenant.
Your input is `external_exposure`: findings from live Azure Resource Graph and Microsoft Graph collection -
the network, database, container, cache, AI-service and Conditional-Access posture that identity-graph data
cannot see. You ALSO receive the identity context (tier0_principals, broad_access_signals,
subscription_rbac_all, guest_and_foreign).

Sole focus: the highest-impact EXPOSURE risks, especially where an exposed resource meets identity access.
Do NOT restate an external_exposure finding verbatim - those are already reported deterministically. Your job
is to find the COMPOUND and the PRIORITISATION the individual findings miss:

• Internet-exposed data stores that hold or reach sensitive data - a public SQL/Cosmos/PostgreSQL/MySQL
  server, a storage account open to all networks, a Redis cache on a plaintext port - ESPECIALLY when a
  broad-RBAC, guest, or foreign-tenant principal can also reach them. Public exposure + a weak firewall +
  an over-privileged or external principal is a Critical exfiltration path even if each part is only High.
• Container-plane compromise: an AKS cluster with local admin accounts or a public API server, or a
  container registry with the admin user / anonymous pull enabled, combined with a principal that can
  reach it - supply-chain and cluster-takeover risk.
• Shared-key / local-auth data services (Service Bus, Event Hub, Cosmos, Cognitive/OpenAI) whose keys
  bypass Entra - a single leaked key is usable from anywhere the resource is publicly reachable.
• Identity-control gaps that magnify all of the above: MFA not enforced, legacy auth open, or no baseline
  protection means a phished credential reaches every exposed resource with no second factor.
• Prioritise: rank exposures by (data sensitivity/blast radius) × (reachability) × (identity weakness).
  A public database reachable by a 296-member group outranks a public dev cache nobody can escalate through.

If `external_exposure` is empty, no live Azure Resource Graph / Microsoft Graph data was collected (no Reader
service principal configured) - return no findings rather than inferring exposure from the identity graph.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}""",
    },
]


# ── Domain-pack mapping ─────────────────────────────────────────────────────
# Each specialist gets a domain-focused slice of the FactPack that contains ALL
# data relevant to that domain.  Without this, the specialists compete for the
# same global caps and each sees only a fraction of the relevant edges/apps.
_SPECIALIST_DOMAIN = {
    "priv_esc":               "attack_paths",
    "lateral_movement":       "attack_paths",
    "entry_points":           "applications",
    "data_plane":             "resources",
    "hygiene":                "identity",
    "rbac_governance":        "rbac",
    "app_lifecycle":          "applications",
    "pim_risk":               "identity",
    "tenant_defaults":        "tenant_config",  # identity core + live CA/security-defaults
    "devops_surface":         "devops",         # SP/FIC/credential + compute identities
    "hybrid_identity":        "attack_paths",  # needs escalation edges + entra roles
    "supply_chain_container": "resources",
    "cross_subscription":     "rbac",
    "security_misconfig":     "resources",
    "entitlement_delegation": "applications",
    "access_breadth":         "breadth",
    "resource_exposure":      "external",   # v2 Track B: live ARG/Graph exposure
}

# Which anomaly scanner outputs each specialist should receive.
# Specialists only get signals from scanners that are relevant to their domain,
# keeping their input compact.
_SPECIALIST_SIGNAL_SOURCES: "dict[str, list[str]]" = {
    "priv_esc":               ["entra", "rbac", "group", "paths"],
    "lateral_movement":       ["sp", "rbac", "paths"],
    "entry_points":           ["sp", "app", "group", "paths"],
    "data_plane":             ["rbac"],
    "hygiene":                ["entra", "sp"],
    "rbac_governance":        ["rbac", "entra"],
    "app_lifecycle":          ["sp", "app"],
    "pim_risk":               ["entra", "paths"],
    "tenant_defaults":        ["entra", "rbac"],
    "devops_surface":         ["sp", "rbac", "paths"],
    "hybrid_identity":        ["entra", "paths"],
    "supply_chain_container": ["sp", "rbac"],
    "cross_subscription":     ["rbac", "paths"],
    "security_misconfig":     ["rbac", "sp"],
    "entitlement_delegation": ["sp", "app"],
    "access_breadth":         ["sp", "rbac", "entra", "group", "app", "paths"],
    "resource_exposure":      ["rbac", "sp"],   # who can reach the exposed resources
}

# Minimum signal severity each specialist should receive.
# High-precision specialists (priv_esc, lateral_movement, etc.) only want
# Critical/High signals - Medium noise dilutes their attention and wastes tokens.
# Breadth/hygiene specialists need Medium and below to catch cumulative patterns.
_SPECIALIST_MIN_SEVERITY: "dict[str, frozenset]" = {
    "priv_esc":               frozenset({"Critical", "High"}),
    "lateral_movement":       frozenset({"Critical", "High"}),
    "entry_points":           frozenset({"Critical", "High"}),
    "data_plane":             frozenset({"Critical", "High"}),
    "security_misconfig":     frozenset({"Critical", "High"}),
    "supply_chain_container": frozenset({"Critical", "High"}),
    "cross_subscription":     frozenset({"Critical", "High"}),
    "hybrid_identity":        frozenset({"Critical", "High"}),
    "devops_surface":         frozenset({"Critical", "High"}),
    "pim_risk":               frozenset({"Critical", "High"}),
    "rbac_governance":        frozenset({"Critical", "High", "Medium"}),
    "app_lifecycle":          frozenset({"Critical", "High", "Medium"}),
    "tenant_defaults":        frozenset({"Critical", "High", "Medium"}),
    "entitlement_delegation": frozenset({"Critical", "High", "Medium"}),
    "hygiene":                frozenset({"Critical", "High", "Medium", "Low"}),
    "access_breadth":         frozenset({"Critical", "High", "Medium", "Low"}),
}


# ── Result dataclass ────────────────────────────────────────────────────────

@dataclass
class GenerationResult:
    findings:              list = field(default_factory=list)
    rejected:              list = field(default_factory=list)
    sonnet_raw_count:      int  = 0
    sonnet_grounded_count: int  = 0
    sonnet_model:          str  = ""   # specialists
    opus_model:            str  = ""   # synthesizer + correlator + cartographer
    haiku_model:           str  = ""   # skeptic (a Sonnet model by default)
    stage_errors:          list = field(default_factory=list)
    specialist_counts:     dict = field(default_factory=dict)
    # Specialists whose API call failed outright - their domain has NO coverage in
    # this report. Surfaced in the UI so a silent gap is never mistaken for "clean".
    failed_specialists:    list = field(default_factory=list)
    chain_findings_count:  int  = 0
    skeptic_dropped:       int  = 0
    non_assessable_dropped: int = 0   # findings suppressed for non-assessable domains
    det_rejected_keys:     set  = field(default_factory=set)
    coverage_warnings:     list = field(default_factory=list)
    chokepoints:           list = field(default_factory=list)
    remediation_roadmap:   list = field(default_factory=list)


# ── Low-level API helpers ───────────────────────────────────────────────────

def build_client(api_key: str):
    """Construct an Anthropic client. This is the ONLY place one should be built.

    PostureHound does not set any CA-bundle environment variable itself - the default
    path is simply `anthropic.Anthropic(api_key=...)` against the system trust store.

    The env-var handling below exists solely to tolerate a host where a corporate
    TLS-inspection proxy has exported SSL_CERT_FILE / REQUESTS_CA_BUNDLE globally.
    Constructing the client directly is unsafe in that case: httpx reads the variable
    at construction time and raises FileNotFoundError if it points at a file that is
    absent (e.g. a proxy agent that has since been uninstalled, leaving a stale export
    behind). That crash is what previously broke "Test AI connection" with an opaque
    HTTP 500 and silently killed the executive summary.

    Three cases, preferring the most secure that works:
      1. Cert var set and the file EXISTS  → verify against it (proxy-aware, secure).
      2. Cert var set but the file is MISSING → ignore the stale var and fall back to
         the system trust store. Verification stays ON; a bad path is a config error,
         not a reason to stop checking certificates.
      3. Nothing set → default client. This is the normal path.
    """
    import os
    import anthropic

    cert = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
    if not cert:
        return anthropic.Anthropic(api_key=api_key)

    import httpx

    def _system_trust():
        # Ignore the env var entirely (trust_env=False) so httpx cannot re-read it.
        return anthropic.Anthropic(
            api_key=api_key,
            http_client=httpx.Client(verify=True, trust_env=False),
        )

    if os.path.isfile(cert):
        try:
            import ssl
            # ssl.create_default_context, not verify=<path>: passing a string is
            # deprecated in httpx, and building the context here lets a MALFORMED
            # bundle be caught rather than crashing client construction - the same
            # failure mode as a missing file, which is what broke this originally.
            ctx = ssl.create_default_context(cafile=cert)
            return anthropic.Anthropic(api_key=api_key,
                                       http_client=httpx.Client(verify=ctx))
        except Exception:
            return _system_trust()
    # Stale/incorrect path: fall back to the system trust store rather than crashing.
    return _system_trust()


# Backwards-compatible alias - internal callers still use _client().
_client = build_client


# Models that rejected `temperature`, discovered at runtime. `temperature` is
# deprecated on the Claude 5 family (claude-sonnet-5, claude-opus-5, …) and sending
# it returns HTTP 400 "`temperature` is deprecated for this model" - which, when it was
# sent unconditionally for determinism, failed EVERY specialist, the synthesizer, the
# correlator, the skeptic and the executive summary on a default configuration.
#
# Rather than hardcode a model list that will drift, probe optimistically once per model
# per process and remember the answer: keep temperature=0 where it is supported (it does
# aid reproducibility on older models such as claude-haiku-4-5) and drop it where it is
# not. Costs at most one extra request per model, never per call.
_NO_TEMPERATURE_MODELS: set[str] = set()


def _is_temperature_unsupported(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "temperature" in msg and ("deprecat" in msg or "unsupported" in msg
                                     or "not supported" in msg)


# Per-TURN output budget. The finding volume, not this number, decides how much a stage
# ultimately writes: the continuation loop in _call_with_tools keeps continuing the turn
# until the model stops, so TOTAL output is effectively unbounded regardless of this value.
#
# The ceiling here is set just under the Anthropic SDK's non-streaming guard. The SDK
# refuses a non-streaming request whose max_tokens could take >10 min:
# expected_time = 3600 * max_tokens / 128000 > 600  ==>  max_tokens > ~21_333. A value above
# that raised "Streaming is required ..." and hard-failed every stage. 20_000 stays safely
# under it (≈16 findings per turn; the loop adds more turns as needed). A call that still
# exceeds the guard (a manual override, or a model with a lower published cap) is transparently
# streamed by create_message rather than failed.
_MAX_OUTPUT_TOKENS = 20000
_MODEL_MAX_TOKENS: dict[str, int] = {}   # model -> discovered per-request output ceiling


def _is_max_tokens_too_large(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "max_tokens" in msg and ("maximum" in msg or "exceed" in msg
                                    or "too large" in msg or "> " in msg)


def _extract_token_ceiling(exc: Exception) -> int | None:
    """Pull the allowed maximum out of an over-limit error, e.g.
    'max_tokens: 64000 > 32000, which is the maximum ...' -> 32000."""
    import re
    nums = [int(n) for n in re.findall(r"\d{3,7}", str(exc))]
    # The smallest plausible ceiling mentioned is the allowed maximum (the larger number is
    # our own request). Guard against picking an unrelated id by requiring it look like a cap.
    caps = [n for n in nums if 256 <= n <= 200000]
    return min(caps) if caps else None


def _is_streaming_required(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "streaming is required" in msg or ("streaming" in msg and "10 min" in msg)


def _final_message_streamed(client, kwargs: dict):
    """Run the request in streaming mode and return the reconstructed final Message.

    The SDK forbids a NON-streaming request whose max_tokens could exceed its 10-minute
    guard; streaming has no such limit. get_final_message() rebuilds the same Message shape
    (content blocks incl. tool_use, stop_reason) the non-streaming path returns, so callers
    are unaffected."""
    with client.messages.stream(**kwargs) as stream:
        return stream.get_final_message()


# Models whose max_tokens tripped the non-streaming 10-min guard this process - stream them
# proactively so the whole parallel burst does not each waste a rejected pre-flight.
_STREAM_MODELS: set[str] = set()


def _retryable_transient_status(exc) -> bool:
    """True for a rate-limit / overload / transient-network error worth RETRYING (as opposed to
    a prompt/size error the caller adjusts and retries differently). Running the 17 specialists
    concurrently makes a 429 (rate limit) or 529 (overloaded) far more likely than sequential -
    without a backoff+retry here that just DROPPED the specialist and lost its whole domain,
    which is the one real way parallelism hurt result quality/consistency."""
    sc = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    if sc in (429, 500, 502, 503, 529):
        return True
    name = type(exc).__name__.lower()
    if any(k in name for k in ("ratelimit", "apiconnection", "apitimeout", "overloaded",
                               "internalserver", "serviceunavailable")):
        return True
    msg = str(exc).lower()
    return any(k in msg for k in ("rate limit", "overloaded", "429", "529", "timed out",
                                  "connection error", "temporarily unavailable", "service unavailable"))


def _retry_after_seconds(exc) -> "float | None":
    """Honour a server Retry-After header when present."""
    resp = getattr(exc, "response", None)
    hdrs = getattr(resp, "headers", None) or {}
    try:
        ra = hdrs.get("retry-after") or hdrs.get("Retry-After")
        return float(ra) if ra is not None else None
    except (TypeError, ValueError):
        return None


_MAX_TRANSIENT_RETRIES = 5

# Set True for the rest of the process if the SDK/model rejects prompt caching, so callers
# stop attaching cache_control and fall back to plain (uncached) prompts.
_PROMPT_CACHE_DISABLED = False


def _is_cache_unsupported(exc: Exception) -> bool:
    m = str(exc).lower()
    return "cache_control" in m or ("cache" in m and ("unsupported" in m or "not supported" in m
                                                      or "beta" in m or "unexpected" in m))


def _strip_cache_control(kwargs: dict) -> None:
    """Remove cache_control from a request's messages/system so it can be retried plain."""
    def _clean(content):
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)
    for msg in kwargs.get("messages") or []:
        if isinstance(msg, dict):
            _clean(msg.get("content"))
    _clean(kwargs.get("system"))


def create_message(client, **kwargs):
    """client.messages.create with automatic `temperature`, `max_tokens` and streaming handling.

    - `temperature` is dropped for models that reject it (probed once, remembered).
    - `max_tokens` is clamped down when a model reports a lower published ceiling.
    - A request that exceeds the SDK's non-streaming 10-minute guard is transparently STREAMED
      (and that model is remembered so the rest of the run streams it directly) instead of
      hard-failing the stage.
    - A rate-limit (429) / overloaded (529) / transient network error is retried with
      exponential backoff (honouring Retry-After), so a specialist is not lost to a momentary
      throttle when all 17 run at once."""
    model = kwargs.get("model", "")
    # Pre-clamp to a ceiling already discovered for this model this process.
    _cap = _MODEL_MAX_TOKENS.get(model)
    if _cap and kwargs.get("max_tokens", 0) > _cap:
        kwargs["max_tokens"] = _cap
    if model in _NO_TEMPERATURE_MODELS:
        kwargs.pop("temperature", None)

    def _rec(resp):
        try:
            from . import usage as _usage
            _usage.meter.record(model, getattr(resp, "usage", None))
        except Exception:
            pass
        return resp

    def _send():
        if model in _STREAM_MODELS:
            return _rec(_final_message_streamed(client, kwargs))
        return _rec(client.messages.create(**kwargs))

    transient = 0
    for _ in range(6 + _MAX_TRANSIENT_RETRIES):   # adjustments + transient backoff retries
        try:
            return _send()
        except Exception as exc:
            if "temperature" in kwargs and _is_temperature_unsupported(exc):
                _NO_TEMPERATURE_MODELS.add(model)
                kwargs.pop("temperature", None)
                continue
            # Prompt caching unsupported by this SDK/model - strip it and never try again.
            if _is_cache_unsupported(exc):
                global _PROMPT_CACHE_DISABLED
                _PROMPT_CACHE_DISABLED = True
                _strip_cache_control(kwargs)
                continue
            # Rate-limited / overloaded / transient network: back off and retry rather than
            # dropping the whole specialist (the concurrency-driven failure mode).
            if _retryable_transient_status(exc) and transient < _MAX_TRANSIENT_RETRIES:
                transient += 1
                delay = _retry_after_seconds(exc)
                if delay is None:
                    delay = min(2.0 ** transient + random.random(), 30.0)
                time.sleep(delay)
                continue
            if _is_streaming_required(exc):
                try:
                    result = _rec(_final_message_streamed(client, kwargs))
                    _STREAM_MODELS.add(model)   # only remember once streaming actually works
                    return result
                except Exception:
                    # Streaming unavailable (old SDK / mock) - fall back to a size under the
                    # guard so the stage still runs; the continuation loop restores completeness.
                    kwargs["max_tokens"] = min(kwargs.get("max_tokens", 8192), 20000)
                    _MODEL_MAX_TOKENS[model] = kwargs["max_tokens"]
                    continue
            if _is_max_tokens_too_large(exc):
                ceiling = _extract_token_ceiling(exc)
                if ceiling is None or ceiling >= kwargs.get("max_tokens", 0):
                    ceiling = max(4096, kwargs.get("max_tokens", 8192) // 2)
                _MODEL_MAX_TOKENS[model] = ceiling
                kwargs["max_tokens"] = ceiling
                continue
            raise
    # Ran out of adjustments - one last unguarded attempt so a real error surfaces.
    return _send()


def _call_with_tools(client, model: str, system: str, user_msg: str,
                     tools: list, max_tokens: int,
                     tool_choice: dict | None = None,
                     max_continuations: int = 6,
                     trace=None, trace_stage: str = "",
                     cache_prefix: str = "") -> list[tuple[str, dict]]:
    """Call a model with tool_use. Returns list of (tool_name, input_dict).

    Output-completeness guarantee: a specialist that has more findings than fit in one
    `max_tokens` response used to have every finding past the cut-off silently dropped -
    the response stopped at `max_tokens` mid-stream and the caller only saw the tool calls
    that happened to complete first. That made "maximum results" a function of output-token
    budget, invisibly. This now detects the `max_tokens` stop and CONTINUES the turn (feeding
    the model's own emitted tool calls back as tool_results) until it stops naturally or the
    continuation budget is exhausted, so every distinct finding the model wants to record is
    collected. The model sees what it already recorded, so it resumes rather than repeats."""
    # Prompt caching: when a large prefix (e.g. the fact pack) repeats across calls, send it
    # as its own cached content block so repeated input bills at the cache-read rate. Degrades
    # gracefully - if the SDK/model rejects cache_control, create_message strips it and the flag
    # below turns it off for the rest of the run.
    if cache_prefix and not _PROMPT_CACHE_DISABLED:
        first_content: object = [
            {"type": "text", "text": cache_prefix, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": user_msg},
        ]
    else:
        first_content = (cache_prefix + "\n\n" + user_msg) if cache_prefix else user_msg
    messages: list = [{"role": "user", "content": first_content}]
    collected: list[tuple[str, dict]] = []
    for attempt in range(max_continuations + 1):
        kwargs = dict(
            model=model, max_tokens=max_tokens,
            system=system, tools=tools,
            temperature=0,
            messages=messages,
        )
        # Only force a tool on the FIRST turn - a continuation must be free to stop.
        if tool_choice and attempt == 0:
            kwargs["tool_choice"] = tool_choice
        resp = create_message(client, **kwargs)
        tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
        for b in tool_uses:
            if isinstance(getattr(b, "input", None), dict):
                collected.append((b.name, b.input))
        # Capture the model's own reasoning (the text blocks it emits alongside its tool
        # calls) into the verbose trace - this is the "how the AI thought" content.
        if trace is not None:
            reasoning = " ".join(
                getattr(b, "text", "") for b in resp.content
                if getattr(b, "type", None) == "text").strip()
            if reasoning or attempt == 0:
                trace.model(trace_stage or "model call", model, reasoning=reasoning,
                            tool_calls=len(tool_uses), system_preview=system[:300])
        if getattr(resp, "stop_reason", None) != "max_tokens":
            break
        # Truncated at the token cap. To collect the remaining findings we must continue
        # the SAME turn: append the assistant content, then a tool_result for every tool
        # call it just made (required before the model may speak again), then loop.
        if not tool_uses:
            break  # truncated with no tool call to respond to - cannot safely continue
        messages.append({"role": "assistant", "content": resp.content})
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": b.id, "content": "recorded"}
            for b in tool_uses if getattr(b, "id", None)
        ]})
    return collected


# ── Grounding validation ────────────────────────────────────────────────────

def _validate_grounding(f: dict, known_ids: set) -> tuple[bool, str | None]:
    if not isinstance(f, dict) or not f.get("title"):
        return False, "missing title / malformed"
    for ent in f.get("entities") or []:
        eid = ent.get("id") if isinstance(ent, dict) else ent
        if eid not in known_ids:
            return False, "referenced unknown entity id: %r" % (eid,)
    for hop in f.get("escalation_chain") or []:
        for key in ("from_id", "to_id"):
            hid = hop.get(key)
            if hid and hid not in known_ids:
                return False, "escalation_chain referenced unknown id: %r" % (hid,)
    sev = f.get("severity")
    if sev not in ("Critical", "High", "Medium", "Low", "Info"):
        return False, "invalid severity: %r" % (sev,)
    conf = f.get("confidence")
    if conf is not None and not isinstance(conf, (int, float)):
        return False, "invalid confidence: %r" % (conf,)
    return True, None


def _resolve_by_name(eid, known_ids: set, name_to_id: "dict | None"):
    """If `eid` is not a known id but EXACTLY matches a node name (case-insensitive) that maps
    to a single node, return that node's id - the AI referenced a real entity by its name
    instead of its fact-pack id (e.g. a container registry as 'myregistry' rather than its
    full /subscriptions/.../registries/myregistry resource id). Returns None when there is
    no unambiguous name match, so a genuinely fabricated name is still rejected."""
    if not name_to_id or not isinstance(eid, str):
        return None
    return name_to_id.get(eid.strip().lower())


def _synthesize_title(f: dict, id_to_name: "dict | None") -> "str | None":
    """A finding whose tool call was cut off at the token cap can arrive WITHOUT its title
    while still carrying real substance - a severity, entities, a reasoning body. Discarding
    it whole loses a genuine finding; instead we mint a headline from what it does contain.
    Returns a title string, or None when there is nothing substantive to name (a true husk -
    no entities and no usable text), in which case the caller still rejects it as malformed."""
    idx = id_to_name or {}

    def _nm(eid):
        info = idx.get(eid)
        nm = info.get("name") if isinstance(info, dict) else None
        return nm or None

    ents = [e for e in (f.get("entities") or []) if isinstance(e, dict)]
    subjects = [e for e in ents if e.get("relation") == "subject"] or ents
    names = [n for n in (_nm(e.get("id")) for e in subjects) if n]
    cat = (f.get("category") or "").strip()
    if names:
        head = names[0] + (f" and {len(names) - 1} other(s)" if len(names) > 1 else "")
        return f"{head} - {cat}" [:200] if cat else f"{head} - flagged exposure"[:200]
    # No resolvable entity name - fall back to the first sentence of a text field.
    for key in ("what", "summary", "reasoning"):
        txt = (f.get(key) or "").strip()
        if len(txt) >= 12:
            first = re.split(r"(?<=[.!?])\s", txt)[0].strip().rstrip(".")
            if len(first) >= 8:
                return first[:160]
    return None


def _sanitize_grounding(f: dict, known_ids: set,
                        name_to_id: "dict | None" = None,
                        id_to_name: "dict | None" = None) -> tuple[bool, str | None]:
    """Grounding with recovery. STRICT rejection threw away an entire rich finding - its
    named title, reasoning, scenario, evidence, remediation - the moment ONE of several
    entity ids failed to resolve (often a peripheral group/subscription the model mentioned
    but that was not registered). That is a large recall loss for a small grounding defect.

    This instead drops the unresolvable references and keeps the finding when a valid core
    remains: unknown entity ids are removed (the finding survives if at least one valid
    entity is left), and escalation_chain hops that reference an unknown id are dropped (the
    chain is illustrative, not load-bearing - the deterministic max-impact path owns the real
    route). A finding whose entities are ALL unknown is still rejected: that is the signature
    of a fabricated finding, and the anti-hallucination guarantee must hold. Dropped ids are
    recorded on the finding for auditability. Returns (kept, reason_if_dropped)."""
    if not isinstance(f, dict):
        return False, "missing title / malformed"
    if not f.get("title"):
        # A truncated tool call can lose the title while keeping real substance. Recover a
        # headline from the finding's own content rather than dropping genuine signal; only a
        # true husk (nothing substantive to name) still falls through as malformed.
        synth = _synthesize_title(f, id_to_name)
        if not synth:
            return False, "missing title / malformed"
        f["title"] = synth
        f["_title_synthesized"] = True
    sev = f.get("severity")
    if sev not in ("Critical", "High", "Medium", "Low", "Info"):
        return False, "invalid severity: %r" % (sev,)
    conf = f.get("confidence")
    if conf is not None and not isinstance(conf, (int, float)):
        return False, "invalid confidence: %r" % (conf,)

    ents = f.get("entities") or []
    kept_ents, dropped_ids = [], []
    recovered = False
    for ent in ents:
        eid = ent.get("id") if isinstance(ent, dict) else ent
        if eid in known_ids:
            kept_ents.append(ent)
            continue
        resolved = _resolve_by_name(eid, known_ids, name_to_id)
        if resolved and isinstance(ent, dict):
            # The AI named a real entity instead of using its id - recover it, don't reject.
            kept_ents.append({**ent, "id": resolved, "_resolved_from_name": eid})
            recovered = True
        else:
            dropped_ids.append(eid)
    # Entities were claimed but none resolve → treat as fabricated, reject outright.
    if ents and not kept_ents:
        return False, "all %d entity id(s) unknown: %r" % (len(ents), dropped_ids[:3])

    def _hop_id(hid):
        return hid if hid in known_ids else (_resolve_by_name(hid, known_ids, name_to_id) if hid else hid)

    kept_chain = []
    for hop in f.get("escalation_chain") or []:
        f_id, t_id = _hop_id(hop.get("from_id")), _hop_id(hop.get("to_id"))
        if (hop.get("from_id") is None or f_id in known_ids) and (hop.get("to_id") is None or t_id in known_ids):
            kept_chain.append({**hop, "from_id": f_id, "to_id": t_id})
        else:
            dropped_ids.extend(h for h in (hop.get("from_id"), hop.get("to_id"))
                               if h and h not in known_ids and not _resolve_by_name(h, known_ids, name_to_id))

    if dropped_ids or recovered:
        f["entities"] = kept_ents           # write back rewritten (name-resolved) + surviving ids
        f["escalation_chain"] = kept_chain
        if dropped_ids:
            f["_grounding_dropped"] = sorted({d for d in dropped_ids if d})
    return True, None


def _validate_chain_grounding(c: dict, known_ids: set) -> tuple[bool, str | None]:
    """Grounding check for attack-chain tool output."""
    if not isinstance(c, dict) or not c.get("title"):
        return False, "missing title / malformed chain"
    eid = c.get("entry_entity_id")
    if eid and eid not in known_ids:
        return False, "entry_entity_id not in fact pack: %r" % (eid,)
    for ent in c.get("entities") or []:
        _id = ent.get("id") if isinstance(ent, dict) else ent
        if _id not in known_ids:
            return False, "chain entities referenced unknown id: %r" % (_id,)
    for hop in c.get("escalation_chain") or []:
        for key in ("from_id", "to_id"):
            hid = hop.get(key)
            if hid and hid not in known_ids:
                return False, "chain escalation_chain referenced unknown id: %r" % (hid,)
    sev = c.get("severity")
    if sev not in ("Critical", "High", "Medium", "Low", "Info"):
        return False, "invalid severity: %r" % (sev,)
    return True, None


# ── Dedup ───────────────────────────────────────────────────────────────────

def _title_dedup_key(title: str) -> str:
    """Normalize a title for similarity comparison: lowercase, remove stop words, stem plurals, sort tokens."""
    import re
    stop = {"a", "an", "the", "is", "are", "and", "or", "of", "in", "to", "can",
            "has", "have", "with", "on", "at", "for", "via", "from", "by", "its",
            "their", "this", "that", "any", "all", "into", "over", "been", "be"}
    tokens = re.sub(r"[^a-z0-9 ]", " ", title.lower()).split()
    key_tokens = []
    for t in tokens:
        if t in stop or len(t) <= 2:
            continue
        # Basic plural/suffix stemming so "administrators"=="administrator", "assignments"=="assignment"
        if len(t) > 4 and t.endswith("s") and not t.endswith("ss"):
            t = t[:-1]
        key_tokens.append(t)
    key_tokens = sorted(set(key_tokens))
    return " ".join(key_tokens[:10])  # first 10 significant words, sorted


def _dedup_candidates(candidates: list[dict]) -> list[dict]:
    """Deduplicate on two axes:
    1. Same entity set + same category → keep highest-confidence version.
    2. Very similar title (≥5 shared key tokens) with overlapping entity sets → keep highest-confidence.
    """
    # Pass 1: entity-set + category dedup (exact)
    seen: dict[tuple, dict] = {}
    for f in candidates:
        ids = frozenset(
            (e.get("id") if isinstance(e, dict) else e)
            for e in (f.get("entities") or [])
        )
        cat = (f.get("category") or "").lower()
        key = (ids, cat)
        if key not in seen or (f.get("confidence") or 0) > (seen[key].get("confidence") or 0):
            seen[key] = f
    after_pass1 = list(seen.values())

    # Pass 2: title-similarity dedup - catch findings from different specialists
    # about the same issue but filed under slightly different categories.
    result: list[dict] = []
    for f in after_pass1:
        f_ids = frozenset(
            (e.get("id") if isinstance(e, dict) else e)
            for e in (f.get("entities") or [])
        )
        f_title_key = _title_dedup_key(f.get("title") or "")
        f_tokens = set(f_title_key.split())

        merged = False
        for existing in result:
            e_ids = frozenset(
                (e.get("id") if isinstance(e, dict) else e)
                for e in (existing.get("entities") or [])
            )
            e_tokens = set(_title_dedup_key(existing.get("title") or "").split())
            shared_tokens = f_tokens & e_tokens
            # Near-duplicate: shared title tokens + entity overlap
            # Lower the token bar to 3 when entity overlap is high (≥80%)
            id_union = f_ids | e_ids
            id_overlap = len(f_ids & e_ids) / len(id_union) if id_union else 0
            token_threshold = 3 if id_overlap >= 0.8 else 5
            if len(shared_tokens) >= token_threshold and id_overlap >= 0.5:
                # Keep highest confidence
                if (f.get("confidence") or 0) > (existing.get("confidence") or 0):
                    result[result.index(existing)] = f
                merged = True
                break
        if not merged:
            result.append(f)

    # Pass 3: entity-set cap - prevent N specialists each filing a separate finding
    # about the same entity combination.  For large entity sets (>3 members) keep
    # at most 2 findings; for small sets keep at most 3.
    from collections import defaultdict as _dd
    by_eset: "dict" = _dd(list)
    for f in result:
        ids = frozenset(
            (e.get("id") if isinstance(e, dict) else e)
            for e in (f.get("entities") or [])
        )
        by_eset[ids].append(f)

    sev_o = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    capped: "list[dict]" = []
    for ids, group in by_eset.items():
        cap = 2 if len(ids) > 3 else 3
        if len(group) <= cap:
            capped.extend(group)
        else:
            ranked = sorted(group, key=lambda f: (
                sev_o.get(f.get("severity", "Medium"), 2),
                -(f.get("confidence") or 0),
            ))
            capped.extend(ranked[:cap])
    return capped


# ── Prompt size budget ──────────────────────────────────────────────────────
# The model hard-fails with "prompt is too long" above 1M input tokens. A large
# tenant can push a single domain slice past that, which previously killed the
# specialist outright and produced ZERO findings for its domain - silently.
# We budget in characters (~4 chars/token) with generous headroom, then compact
# oversized packs rather than letting the request die.
_PROMPT_CHAR_BUDGET = 1_800_000          # ~450K tokens - well under the 1M ceiling
_PROMPT_CHAR_BUDGET_RETRY = 600_000      # ~150K tokens - aggressive fallback
_SECTION_FLOOR = 25                      # never shrink a section below this many items


def _compact_prompt_dict(d: dict, budget: int) -> tuple[dict, dict]:
    """Shrink the largest list sections until `d` serialises within `budget` chars.

    Returns (compacted_dict, dropped_counts). Sampling is always disclosed: every
    trimmed section records how many items were withheld in truncated_buckets, so
    the model is told it is seeing a sample rather than the whole inventory. This
    keeps a big tenant analysable instead of failing the request outright.
    """
    d = dict(d)
    dropped: dict[str, int] = {}
    # Protected keys carry meaning-per-byte (counts, notes) - never trimmed.
    protected = {"tenant_id", "counts", "truncated_buckets", "anomaly_signals_note"}

    def size() -> int:
        return len(json.dumps(d, default=str))

    if size() <= budget:
        # Already fits - but facts.py may have capped sections BEFORE the prompt was
        # built, in which case truncated_buckets holds a bare integer with nothing
        # explaining it. Returning here without the note is how a specialist read
        # "0 Owners" off a 4%-complete table and reported it as a fact.
        if d.get("truncated_buckets"):
            d["sampling_note"] = _SAMPLING_NOTE
        return d, dropped

    # Round 1: repeatedly halve whichever list section is currently largest.
    for _ in range(200):
        if size() <= budget:
            break
        candidates = [
            (len(json.dumps(v, default=str)), k)
            for k, v in d.items()
            if k not in protected and isinstance(v, list) and len(v) > _SECTION_FLOOR
        ]
        if not candidates:
            break
        _, key = max(candidates)
        cur = d[key]
        keep = max(_SECTION_FLOOR, len(cur) // 2)
        dropped[key] = dropped.get(key, 0) + (len(cur) - keep)
        d[key] = cur[:keep]

    # Round 2: still oversized - drop whole list sections, largest first.
    while size() > budget:
        candidates = [
            (len(json.dumps(v, default=str)), k)
            for k, v in d.items()
            if k not in protected and isinstance(v, list) and v
        ]
        if not candidates:
            break
        _, key = max(candidates)
        dropped[key] = dropped.get(key, 0) + len(d[key])
        d[key] = []

    if dropped:
        tb = dict(d.get("truncated_buckets") or {})
        for k, n in dropped.items():
            tb[k] = tb.get(k, 0) + n
        d["truncated_buckets"] = tb
    if d.get("truncated_buckets"):
        d["sampling_note"] = _SAMPLING_NOTE
    return d, dropped


# Explains truncated_buckets to the model. Attached whenever ANY section is sampled -
# including caps applied in facts.py - not only when _compact_prompt_dict fired. It was
# previously set inside the compaction branch only, so a pack that arrived pre-truncated
# carried a bare integer ("subscription_rbac_all": 72437) with nothing telling the model
# what it meant, next to a prompt asserting the section was complete.
_SAMPLING_NOTE = (
    "IMPORTANT: some sections below were SAMPLED because this tenant is too large to send "
    "in full. truncated_buckets lists, per section, how many ADDITIONAL items exist that "
    "you cannot see. Treat each sampled section as representative, not complete: when you "
    "find an issue in one, say in the reasoning field that the same pattern very likely "
    "extends to the withheld items and cite the withheld count. Never claim a sampled "
    "section is complete, and never conclude that an issue is ABSENT from a sampled section."
)


# ── Stage 1: specialist runner ──────────────────────────────────────────────

def _run_specialist(client, spec: dict, fact_pack: "FactPack",
                    known_ids: set, sonnet_model: str,
                    max_tokens: int,
                    anomaly_signals: "dict | None" = None,
                    collection: "dict | None" = None,
                    trace=None) -> tuple[str, list, list]:
    """Run one Sonnet specialist.

    anomaly_signals: dict[scanner_type → list[anomaly_dict]] produced by Phase 1 Python scanners.
    Each specialist receives its domain slice PLUS signals from its relevant scanners.
    Signals represent 100% inventory coverage with no caps - entity_id values in
    signals are valid fact-pack IDs the specialist can use in findings.

    collection: completeness.assess_collection() output. Passing it lets each specialist
    see which domains were never collected, so it reports them as UNASSESSED instead of
    inferring "clean" from an empty section.
    """
    domain = _SPECIALIST_DOMAIN.get(spec["key"])
    import json as _json
    domain_dict = fact_pack.to_prompt_dict(domain=domain)

    # Collection blind spots. Without this a specialist cannot distinguish "the tenant
    # has none of these" from "this was never collected" - the failure mode that had
    # pim_risk and hybrid_identity reporting clean on domains they could not see.
    _blind = [w for w in ((collection or {}).get("warnings") or [])
              if w.get("level") == "warning"]
    if _blind:
        domain_dict["collection_gaps"] = [
            {"code": w.get("code"), "detail": w.get("message")} for w in _blind
        ]
        domain_dict["collection_gaps_note"] = (
            "collection_gaps lists data that was NOT collected for this tenant. For any "
            "domain named there, an empty or absent section is UNKNOWN, not clean - do "
            "NOT report it as a passing control, and do NOT infer a negative finding from "
            "the absence. If your analysis depends on data named here, say explicitly "
            "that it could not be assessed and what collection change would fix it."
        )

    # Inject Python anomaly signals - severity-filtered per specialist.
    # Precision-focused specialists only see Critical/High to avoid noise;
    # breadth/hygiene specialists see Medium/Low for cumulative pattern detection.
    if anomaly_signals:
        min_sevs = _SPECIALIST_MIN_SEVERITY.get(spec["key"], frozenset({"Critical", "High"}))
        relevant = []
        for sc in _SPECIALIST_SIGNAL_SOURCES.get(spec["key"], []):
            relevant.extend(
                s for s in anomaly_signals.get(sc, [])
                if s.get("severity_hint") in min_sevs
            )
        if relevant:
            domain_dict["anomaly_signals"] = relevant
            domain_dict["anomaly_signals_note"] = (
                "anomaly_signals: Python scanned the COMPLETE inventory (zero truncation, "
                "zero cost) and flagged every anomaly above. entity_id values are valid fact-pack "
                "entity IDs - reference them in findings' entities[] and escalation_chain[]."
            )

    # Guard the prompt size BEFORE sending. An oversized pack used to hard-fail the
    # request, yielding zero findings for this entire domain with no visible error.
    domain_dict, _dropped = _compact_prompt_dict(domain_dict, _PROMPT_CHAR_BUDGET)

    # Augment the agent's own focus prompt with: the fact-pack reading guide for its domain
    # (grounds the weaker agents as tightly as the strong ones), the shared severity rubric
    # (consistent, anchored severity), and the checklist discipline (same coverage every run).
    system = (spec["system"]
              + _DOMAIN_READING_GUIDE.get(domain, "")
              + _SEVERITY_RUBRIC
              + _CHECKLIST_DISCIPLINE)

    def _send(dd: dict):
        payload = _json.dumps(dd, default=str)
        return _call_with_tools(
            client, sonnet_model, system,
            f"Analyse this Azure/Entra tenant fact pack for issues in your domain.\n\n{payload}",
            [_FINDING_TOOL], max_tokens,
            trace=trace, trace_stage=f"specialist: {spec['label']}",
        )

    if trace is not None:
        trace.section(f"SPECIALIST · {spec['label']}", key=spec["key"], model=sonnet_model)
    try:
        calls = _send(domain_dict)
    except Exception as exc:
        # One aggressive-compaction retry, then give up. Transport/size failures are
        # reported as stage errors (never as grounding rejections) so the report can
        # tell the user this domain was not analysed rather than implying it was clean.
        try:
            retry_dict, _ = _compact_prompt_dict(domain_dict, _PROMPT_CHAR_BUDGET_RETRY)
            calls = _send(retry_dict)
        except Exception as exc2:
            return spec["key"], [], [{
                "stage": spec["key"],
                "reason": f"{type(exc2).__name__}: {exc2}",
                "_transport_failure": True,
                "_first_error": f"{type(exc).__name__}: {exc}",
            }]

    grounded, rejected = [], []
    for name, inputs in calls:
        if name != "record_finding":
            continue
        # Recover the valid core of a finding rather than discarding it whole on one bad id,
        # and resolve entities the model referenced by NAME instead of id.
        ok, reason = _sanitize_grounding(inputs, known_ids, fact_pack.name_to_id_map(),
                                         fact_pack.entity_index)
        if ok:
            inputs["_specialist"] = spec["key"]
            # Ensure confidence is always a number so dedup comparison works.
            if inputs.get("confidence") is None:
                inputs["confidence"] = 50
            grounded.append(inputs)
            if trace is not None:
                recovered = inputs.get("_title_synthesized") or any(
                    isinstance(e, dict) and e.get("_resolved_from_name")
                    for e in (inputs.get("entities") or []))
                note = " (title recovered - tool call was truncated)" if inputs.get("_title_synthesized") else ""
                trace.candidate(spec["key"], inputs.get("title", "?"),
                                "recovered" if recovered else "kept",
                                reason=note.strip(" ()") if note else "",
                                severity=inputs.get("severity", ""), confidence=inputs.get("confidence"),
                                reasoning=inputs.get("reasoning", ""),
                                entities=len(inputs.get("entities") or []))
        else:
            rejected.append({"title": inputs.get("title", "?"), "stage": spec["key"], "reason": reason})
            if trace is not None:
                verdict = "malformed" if "unknown" not in (reason or "") else "rejected"
                # Record what the discarded call DID contain, so a malformed entry in the trace
                # is legible rather than an opaque "?" - a truncated husk vs a real loss.
                had = [x for x in (
                    f"severity={inputs.get('severity')}" if inputs.get("severity") else "",
                    f"{len(inputs.get('entities') or [])} entities" if inputs.get("entities") else "",
                    "reasoning" if (inputs.get("reasoning") or "").strip() else "",
                    "evidence" if inputs.get("evidence") else "",
                ) if x]
                full_reason = reason + (f" - had: {', '.join(had)}" if had else " - empty tool call")
                trace.candidate(spec["key"], inputs.get("title", "?"), verdict, reason=full_reason,
                                severity=inputs.get("severity", ""))
    if trace is not None:
        trace.line(f"→ {len(grounded)} kept, {len(rejected)} rejected", indent=2)
    return spec["key"], grounded, rejected


# ── Cross-domain compound synthesizer (Phase 2b) ───────────────────────────

_SYNTHESIZER_SYSTEM = f"""You are a CROSS-DOMAIN COMPOUND RISK DETECTOR reviewing an Azure/Entra tenant.

You receive confirmed findings from the domain specialists PLUS anomaly signals from a complete inventory
scan (every SP, RBAC assignment, Entra role, group, and app grant has been checked deterministically).

YOUR ONLY JOB: call record_finding for NEW compound findings that COMBINE evidence from two or more
different domains and produce a risk MORE SEVERE than any individual finding already in the list.

DO NOT:
• Re-state, re-title, summarise, or deepen any existing specialist finding.
• Produce findings that cover the same entity AND root cause as an existing finding.

DO:
• Cross-reference signals against each other to find compounding chains, for example:
  - Large privileged group (group signal) → members inherit an RBAC Owner role (rbac signal)
    → Owner at MG scope means N people are one step from complete control
  - Orphaned SP (sp signal) holds critical Graph permission (app signal) that also appears in
    a confirmed attack path → orphaned identity unlocks confirmed escalation
  - Guest user (entra signal) controls an SP that holds dangerous permissions (sp/app signals)
    → external party owns a high-value identity path
  - Principal owns Owner in 3+ subscriptions (rbac signal, cross_subscription) AND one of those
    subscriptions contains a misconfiguration finding → single compromise = multi-sub blast
  - Dynamic group (group signal) auto-assigns privilege based on a user attribute an attacker
    can manipulate → privilege escalation via group membership rule

• Cite EXACT entity names, exact permission names, exact counts from the signals.
  Vague findings without specific entities will not be accepted.
• entity_id values in anomaly_signals are valid FactPack IDs - use them in record_finding.

ALSO - call upgrade_finding for any EXISTING specialist finding whose severity is too low because
the specialist lacked cross-domain visibility:
• A High finding from domain A + a finding/signal from a DIFFERENT domain that together create
  Critical-level compound risk → call upgrade_finding(title=<exact title>, upgraded_severity="Critical", …).
• Upgrades only (never downgrades). Title must match exactly. Use sparingly - only when the
  combined risk is genuinely worse than either finding alone, not merely related.

If you see no genuine compound risks not already captured, do NOT call record_finding.
{_CONFIDENCE_GUIDANCE}
{_GROUNDING_RULES}"""


_UPGRADE_TOOL: dict = {
    "name": "upgrade_finding",
    "description": (
        "Upgrade the severity of an EXISTING specialist finding when cross-domain context makes "
        "it more severe than the originating specialist could see. Only upgrades are permitted. "
        "The title must exactly match an existing finding title."
    ),
    "input_schema": {
        "type": "object",
        "required": ["title", "upgraded_severity", "cross_domain_reason"],
        "properties": {
            "title": {
                "type": "string",
                "description": "Exact title of the existing finding to upgrade (case-sensitive)."
            },
            "upgraded_severity": {
                "type": "string",
                "enum": ["Critical", "High"],
                "description": "New severity - must be strictly higher than the current severity."
            },
            "cross_domain_reason": {
                "type": "string",
                "description": (
                    "Specific cross-domain justification: name the other domain's finding or "
                    "signal that creates the compound risk warranting the upgrade."
                )
            }
        }
    }
}


def _run_synthesizer(client, model: str, all_signals: "dict[str, list[dict]]",
                     candidates: "list[dict]", known_ids: set,
                     fact_pack: "FactPack", max_tokens: int, trace=None) -> "tuple[list, list]":
    """Phase 2b: Cross-domain compound detector (Opus recommended).

    Receives Python-computed signals (all 5 inventory types, zero cost) plus all existing
    specialist findings.  Only adds NEW compound findings - never re-reviews existing ones.
    """
    flat_signals = [s for sigs in all_signals.values() for s in sigs]

    context = {
        "tenant_id":            fact_pack.tenant_id,
        "counts":               fact_pack.counts,
        "anomaly_signals":      flat_signals,
        "broad_access_signals": fact_pack.broad_access_signals,
    }

    user_msg = (
        f"CONFIRMED SPECIALIST FINDINGS ({len(candidates)} total):\n"
        f"{json.dumps(candidates, default=str)}\n\n"
        f"INVENTORY ANOMALY SIGNALS ({len(flat_signals)} total across 5 inventory types):\n"
        f"{json.dumps(context, default=str)}\n\n"
        "Find NEW cross-domain compound findings not already captured above. "
        "Call record_finding only for genuinely new compound risks with specific entity evidence."
    )
    try:
        calls = _call_with_tools(
            client, model, _SYNTHESIZER_SYSTEM, user_msg,
            [_FINDING_TOOL, _UPGRADE_TOOL], max_tokens,
            trace=trace, trace_stage="synthesizer (compound risk)",
        )
    except Exception as exc:
        return [], [{"stage": "synthesizer", "reason": f"{type(exc).__name__}: {exc}"}], []

    grounded, rejected, upgrades = [], [], []
    for name, inputs in calls:
        if name == "record_finding":
            ok, reason = _validate_grounding(inputs, known_ids)
            if ok:
                inputs["_specialist"] = "synthesizer"
                grounded.append(inputs)
            else:
                rejected.append({"title": inputs.get("title", "?"),
                                  "stage": "synthesizer", "reason": reason})
        elif name == "upgrade_finding":
            upgrades.append(inputs)
    return grounded, rejected, upgrades




# ── Stage 4: Correlation agent ──────────────────────────────────────────────

_CORRELATOR_SYSTEM = f"""You are an ATTACK CHAIN CORRELATOR. You are given:
1. A fact pack - the ground-truth extraction from a real Azure/Entra tenant.
2. A list of confirmed security findings already reviewed by a principal architect.

Your job is NOT to find new individual issues - the specialists and architect have done that.
Your job is to identify sequences of confirmed findings that chain together into complete,
end-to-end attack paths that are more dangerous than any single finding in isolation.

What makes a valid chain:
• Finding A gives an attacker a foothold or identity (entry point, credential access, etc.)
• Finding B, starting from the identity or resource obtained in A, moves to a higher-privilege position
• Finding C (optional), from B's position, reaches critical impact (Tier-0, data exfiltration, etc.)
• The COMBINED path from A's starting point to C's final impact is the chain

Severity elevation rules:
• Two High findings that chain entry-to-Tier-0 = Critical chain
• A High entry-point + a Medium lateral movement + a High priv-esc = Critical chain
• Only elevate when the chain is truly end-to-end: external access → confirmed impact
• Medium + Medium that chains to High impact = High chain (not Critical unless it reaches Tier-0)

Be conservative. Only create a chain if:
1. Each link is directly supported by the fact pack (not just "these could relate")
2. The entry entity id is something an external or low-privilege attacker could start from
3. The connection between finding steps is unambiguous in the fact pack data

For each chain, call record_attack_chain once.
If no valid chains exist, do not call record_attack_chain.

STRICT GROUNDING: every entity id must exist in the fact pack. Never invent a connection not
supported by the data.
{_CONFIDENCE_GUIDANCE}"""


# ── Token-safe payload helpers ────────────────────────────────────────────────

def _correlator_context(fact_pack, findings: list[dict]) -> str:
    """Build a minimal grounding context for the correlator.

    The correlator chains already-grounded findings - it doesn't need raw inventory
    tables.  We extract only: tenant counts, a compact entity registry (limited to
    entities already referenced in the findings + all tier-0 entities), and the
    tier-0 list.  This is guaranteed to be small regardless of tenant size.
    """
    seen: set[str] = set()
    for f in findings:
        for e in (f.get("entities") or []):
            eid = e.get("id") if isinstance(e, dict) else e
            if eid:
                seen.add(str(eid))
        for hop in (f.get("escalation_chain") or []):
            for side in ("from", "to"):
                h = hop.get(side) or {}
                if isinstance(h, dict) and h.get("id"):
                    seen.add(str(h["id"]))

    entity_reg = {
        eid: {
            "name": info.get("name", eid),
            "kind": info.get("kind", ""),
            "tier0": "tier0" in (info.get("tags") or []),
        }
        for eid, info in fact_pack.entity_index.items()
        if eid in seen or "tier0" in (info.get("tags") or [])
    }

    ctx: dict = {
        "tenant_id": fact_pack.tenant_id,
        "counts": fact_pack.counts,
        "entity_registry": entity_reg,
        "tier0_principals": fact_pack.tier0_principals,
    }
    # The REAL escalation edges among the entities in play. Without these the
    # correlator could only re-link findings by shared id and would assert
    # connections the graph does not contain; with them it links principals that
    # actually have an abuse edge between them.
    edges = [
        {"from": _endpoint_id(e.get("src")), "to": _endpoint_id(e.get("dst")), "via": e.get("primitive")}
        for e in fact_pack.escalation_edges
        if _endpoint_id(e.get("src")) in entity_reg and _endpoint_id(e.get("dst")) in entity_reg
    ]
    if edges:
        ctx["escalation_edges"] = edges[:500]
    return json.dumps(ctx, default=str)


def _budget_json(payload: dict, max_chars: int) -> str:
    """Serialize *payload* to JSON, compacting it to fit *max_chars*.

    Delegates to _compact_prompt_dict, which spreads the trim across sections with a
    per-section floor and records what it withheld in truncated_buckets.

    The previous implementation drained the single largest list all the way to [] before
    touching the next one, and never updated truncated_buckets. That produced payloads
    where a section read `"over_permissive_apps": []` while truncated_buckets claimed 662
    items existed - so the skeptic was shown an empty table and, finding no corroborating
    evidence, downgraded legitimate Critical findings as "unverifiable". Trimming evenly
    and disclosing the sampling keeps the evidence representative instead of absent.
    """
    compacted, _ = _compact_prompt_dict(payload, max_chars)
    return json.dumps(compacted, default=str)


_CORRELATOR_MAX_CHARS = 700_000          # ~175K tokens, well inside the context window
_CORRELATOR_ENTITIES_PER_FINDING = 25


def _correlator_findings(findings: list[dict]) -> list[dict]:
    """Project findings down to what chaining actually needs.

    The correlator links findings by their entities and escalation chains; it never
    needs the prose. Sending them verbatim blew the request up - 80 candidates
    including deterministic findings carrying 449, 372 and 289 entities each (with
    aggregated evidence) reached 1,271,088 tokens against a 1,000,000 limit, so Phase 3
    failed outright and the tool reported "no multi-step chains found" on every scan.
    """
    out: list[dict] = []
    for f in findings:
        ents = f.get("entities") or []
        compact = []
        for e in ents[:_CORRELATOR_ENTITIES_PER_FINDING]:
            if isinstance(e, dict):
                compact.append({k: e[k] for k in ("id", "name", "kind") if k in e})
            else:
                compact.append({"id": str(e)})
        row = {
            "title":    f.get("title", ""),
            "severity": f.get("severity", ""),
            "category": f.get("category", ""),
            "entities": compact,
        }
        if len(ents) > _CORRELATOR_ENTITIES_PER_FINDING:
            row["entities_withheld"] = len(ents) - _CORRELATOR_ENTITIES_PER_FINDING
        # The chain is the whole point of this phase - keep it, but without nested prose.
        chain = f.get("escalation_chain") or []
        if chain:
            row["escalation_chain"] = [
                {"from": (h.get("from") or {}).get("id") if isinstance(h.get("from"), dict) else h.get("from_id"),
                 "to":   (h.get("to") or {}).get("id") if isinstance(h.get("to"), dict) else h.get("to_id"),
                 "technique": h.get("technique", "")}
                for h in chain[:12]
            ]
        # One short line of context so the model knows what the finding is about.
        gist = (f.get("summary") or f.get("what") or "").strip()
        if gist:
            row["gist"] = gist[:300]
        out.append(row)
    return out


def _endpoint_id(x):
    """The id of an escalation-edge endpoint. facts.register stores the whole entity
    DICT as src/dst, so pull its id; tolerate a bare id string too."""
    return x.get("id") if isinstance(x, dict) else x


def _unverified_hops(chain: dict, known_edges: set) -> list:
    """The chain hops that do NOT correspond to a real graph escalation edge (either
    direction). An AI chain is only 'confirmed' if every hop is a real edge; otherwise
    it may connect two real principals with a link the graph does not contain."""
    bad = []
    for hop in (chain.get("escalation_chain") or []):
        a, b = hop.get("from_id"), hop.get("to_id")
        if a and b and (a, b) not in known_edges and (b, a) not in known_edges:
            bad.append({"from_id": a, "to_id": b, "technique": hop.get("technique")})
    return bad


def _run_correlator(client, model: str, fact_pack_json: str,
                    findings: list[dict], known_ids: set,
                    max_tokens: int, on_progress,
                    known_edges: "set | None" = None,
                    edges_complete: bool = False, trace=None) -> tuple[list, list]:
    """Phase 3: find and validate multi-step attack chains across confirmed findings (Opus recommended)."""
    compact = _correlator_findings(findings)
    findings_json = json.dumps(compact, default=str)
    # Backstop: if it is still oversized (very many findings), drop the least severe
    # rows rather than letting the request fail entirely.
    if len(findings_json) + len(fact_pack_json) > _CORRELATOR_MAX_CHARS:
        rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        compact.sort(key=lambda r: rank.get(r.get("severity", ""), 5))
        budget = max(50_000, _CORRELATOR_MAX_CHARS - len(fact_pack_json))
        while len(compact) > 5 and len(json.dumps(compact, default=str)) > budget:
            compact.pop()
        findings_json = json.dumps(compact, default=str)
        if on_progress:
            on_progress(f"  Correlator input trimmed to the {len(compact)} most severe "
                        f"finding(s) to fit the context window.")
    user_msg = (
        f"FACT PACK:\n{fact_pack_json}\n\n"
        f"CONFIRMED FINDINGS ({len(compact)} total):\n{findings_json}\n\n"
        "Identify any multi-step attack chains that connect these findings. "
        "Call record_attack_chain for each valid chain."
    )
    try:
        calls = _call_with_tools(
            client, model, _CORRELATOR_SYSTEM, user_msg,
            [_CHAIN_TOOL], max_tokens,
            trace=trace, trace_stage="correlator (attack chains)",
        )
    except Exception as exc:
        if on_progress:
            on_progress(f"Correlation agent failed: {type(exc).__name__}: {exc}")
        return [], [{"stage": "correlator", "reason": f"{type(exc).__name__}: {exc}"}]

    chains, rejected = [], []
    for name, inputs in calls:
        if name != "record_attack_chain":
            continue
        ok, reason = _validate_chain_grounding(inputs, known_ids)
        if not ok:
            rejected.append({"title": inputs.get("title", "?"), "stage": "correlator", "reason": reason})
            continue
        # Edge-grounding: a chain hop must correspond to a real graph edge. When the
        # edge set is COMPLETE, a fabricated hop is a hard reject; when the edges were
        # truncated for size we cannot be certain, so we flag and cap confidence
        # instead of dropping a possibly-real chain.
        bad = _unverified_hops(inputs, known_edges) if known_edges is not None else []
        if bad and edges_complete:
            rejected.append({"title": inputs.get("title", "?"), "stage": "correlator",
                             "reason": f"escalation_chain hop is not a real graph edge: {bad[0]}"})
            continue
        if bad:
            inputs["edges_verified"] = False
            inputs["unverified_hops"] = bad
            if isinstance(inputs.get("confidence"), (int, float)):
                inputs["confidence"] = min(inputs["confidence"], 65)
        else:
            inputs["edges_verified"] = True
        chains.append(inputs)
    return chains, rejected


def _chain_to_finding(c: dict, fact_pack: FactPack) -> dict:
    """Normalise a record_attack_chain output into the standard finding shape."""
    entities = []
    for ent in c.get("entities") or []:
        eid   = ent.get("id") if isinstance(ent, dict) else ent
        known = fact_pack.entity_index.get(eid, {"id": eid, "name": eid, "kind": "Unknown"})
        role  = (ent.get("role_in_finding") if isinstance(ent, dict) else None) or ""
        if not role:
            kind = (known.get("kind") or "").replace("AZ", "").strip()
            role = f"Affected {kind.lower()}" if kind else "Affected entity"
        ment = {**known, "role_in_finding": role}
        rel = ent.get("relation") if isinstance(ent, dict) else None
        if rel in ("subject", "context"):
            ment["relation"] = rel
        entities.append(ment)
    chain = []
    for hop in c.get("escalation_chain") or []:
        chain.append({
            "from": fact_pack.entity_index.get(hop.get("from_id"), {"id": hop.get("from_id"), "name": hop.get("from_id")}),
            "to":   fact_pack.entity_index.get(hop.get("to_id"),   {"id": hop.get("to_id"),   "name": hop.get("to_id")}),
            "technique": hop.get("technique", ""),
        })
    return {
        "source":           "ai_chain",
        "title":            c["title"],
        "severity":         c.get("severity", "High"),
        "confidence":       max(0, min(100, round(c["confidence"])))
                            if isinstance(c.get("confidence"), (int, float)) else None,
        "category":         "Attack Chain",
        "entities":         entities,
        "summary":          c.get("terminal_impact", ""),
        "what":             c.get("why_more_severe_combined", ""),
        "reasoning":        c.get("step_by_step_narrative", ""),
        "why_it_matters":   c.get("terminal_impact", ""),
        "attack_scenario":  c.get("step_by_step_narrative", ""),
        "escalation_chain": chain,
        "evidence":         c.get("combined_finding_titles", []),
        "remediation":      c.get("remediation_priority", ""),
        "detection":        c.get("detection", ""),
        "review_note":      f"Chain combines: {', '.join(c.get('combined_finding_titles', []))}",
        "_specialist":      "correlator",
        "chain_components": c.get("combined_finding_titles", []),
    }


# ── Stage 5: Haiku skeptic ──────────────────────────────────────────────────

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _downgrade_severity(sev: str) -> str:
    i = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else 2
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]


_SKEPTIC_FOCUS_BY_CATEGORY: "dict[str, str]" = {
    "Privilege Escalation": (
        "FOCUS FOR THIS FINDING TYPE - Privilege Escalation:\n"
        "Verify the escalation path is technically possible right now. Check: Does the entity's "
        "account appear enabled in the fact pack? Is there a PIM activation requirement visible? "
        "Does the claimed permission/role assignment actually appear in the fact pack evidence, "
        "or is it inferred? A path that requires first compromising another account is less direct "
        "than stated - note that and downgrade if the additional step is non-trivial."
    ),
    "Attack Chain": (
        "FOCUS FOR THIS FINDING TYPE - Attack Chain:\n"
        "Every hop must be independently confirmed in the fact pack, not merely plausible. "
        "For each step: does the fact pack show the relationship exists? Would any hop require "
        "platform capabilities or additional compromise not mentioned in the finding? "
        "Multi-hop chains where each step is a separate exploit are substantially harder than "
        "single-hop - increase scrutiny proportionally with hop count."
    ),
    "Identity Hygiene": (
        "FOCUS FOR THIS FINDING TYPE - Identity Hygiene:\n"
        "Hygiene findings describe undesirable state, not necessarily active exploitability. "
        "Ask: Is the stale/orphaned account actually enabled and reachable? Does the orphaned SP "
        "have live credentials that could be stolen, or is it credential-less? Is the finding "
        "about a known service account pattern that is expected in this tenant? "
        "Stale ≠ exploitable. Only confirm if there is a realistic exploitation path."
    ),
    "External Entry Points": (
        "FOCUS FOR THIS FINDING TYPE - External Entry Points:\n"
        "Verify the external/guest entity has actionable privilege. A guest with a viewer-only "
        "role is present but not a meaningful entry point. Check: Is the account enabled? "
        "What is the actual privilege level - can the guest affect confidentiality, "
        "integrity, or availability of something sensitive? External presence alone is not a finding."
    ),
    "RBAC Governance": (
        "FOCUS FOR THIS FINDING TYPE - RBAC Governance:\n"
        "Over-permissioned RBAC is context-dependent. Is the Owner/Contributor assignment on a "
        "production subscription or a dev/sandbox scope? Does the scope indicate a management "
        "group (blast radius = all subscriptions) or a single low-value resource? "
        "A service account with Contributor for a specific workload is often expected. "
        "Only confirm if the scope and principal combination represent genuine governance risk."
    ),
    "Application Lifecycle": (
        "FOCUS FOR THIS FINDING TYPE - Application Lifecycle:\n"
        "An app with dangerous permissions but no credentials (no secrets/certs in fact pack) "
        "is substantially lower risk. Check: Does the SP have live credentials? "
        "Is the owner count actually 0 as claimed, or does the fact pack show owners? "
        "Many apps legitimately hold broad Graph permissions - does the SP's name/purpose "
        "suggest it is a known enterprise app rather than a custom or suspicious one?"
    ),
    "Cross-Subscription": (
        "FOCUS FOR THIS FINDING TYPE - Cross-Subscription:\n"
        "Verify the entity actually has confirmed RBAC assignments across multiple subscriptions - "
        "not just membership in a group that might have cross-sub access. Check: Does the fact "
        "pack show distinct subscription scopes for this entity? Is the cross-subscription "
        "access intentional for a centralized identity (automation account, security tool)?"
    ),
}

_HAIKU_SKEPTIC_SYSTEM = """You are an adversarial security reviewer. Your job: DISPROVE findings.
Given a finding and the fact pack it came from, find every reason it might be:
- Not actually exploitable given real-world Azure platform controls or tenant configuration
- Based on a misread of the fact pack (evidence cited does not support the stated claim)
- Overstated in severity (real risk but label too high)
- Already mitigated by something visible in the fact pack

Be adversarial. Default to skepticism. If you genuinely cannot find a compelling reason to
downgrade or discard, return 'confirmed' - do not invent objections.
Base your evaluation entirely on the fact pack, not on generic Azure security knowledge."""


def _apply_skeptic_verdict(finding: dict, ev: dict) -> "dict | None":
    """Turn one skeptic assessment into the kept/modified finding (or None to discard).
    Shared by the single-finding and batched skeptic paths."""
    verdict  = ev.get("verdict", "confirmed")
    adj_conf = ev.get("adjusted_confidence", finding.get("confidence"))
    if verdict == "discard":
        return None
    if verdict == "downgrade":
        _old_sev = finding.get("severity", "High")
        _new_sev = _downgrade_severity(_old_sev)
        _old_conf = finding.get("confidence")
        _reason = (ev.get("reason") or "").strip()
        _parts = [f"Severity reduced from {_old_sev} to {_new_sev} by adversarial review"]
        if isinstance(_old_conf, (int, float)) and isinstance(adj_conf, (int, float)) \
                and int(_old_conf) != int(adj_conf):
            _parts[0] += f" (confidence {int(_old_conf)}% → {int(adj_conf)}%)"
        _lead = _parts[0] + "."
        if _reason:
            _note_suffix = f"{_lead} {_reason}"
        else:
            _note_suffix = (
                f"{_lead} The reviewer did not record a rationale, so the original "
                f"{_old_sev} rating is unverified rather than disproven - re-check "
                f"this finding's evidence manually before acting on the lower severity."
            )
        return {
            **finding,
            "severity":    _new_sev,
            "confidence":  adj_conf,
            "review_note": ((finding.get("review_note") or "").strip()
                            + " " + _note_suffix).strip(),
        }
    return {**finding, "confidence": adj_conf}


_SKEPTIC_BATCH_TOOL = {
    "name": "evaluate_findings",
    "description": "Adversarially evaluate several security findings at once; return one "
                   "assessment per finding, keyed by its number.",
    "input_schema": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "integer", "description": "The finding's number."},
                        "verdict": {"type": "string", "enum": ["confirmed", "downgrade", "discard"],
                                    "description": "confirmed=valid as-is; downgrade=real but severity too high; discard=not exploitable"},
                        "reason": {"type": "string", "minLength": 60,
                                   "description": "REQUIRED, substantive: which claim you checked, what the "
                                   "fact pack does/does not support (quote the field/value), and what would "
                                   "have to be true for the original severity to hold. Shown verbatim to the analyst."},
                        "adjusted_confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                    },
                    "required": ["key", "verdict", "reason", "adjusted_confidence"],
                },
            },
        },
        "required": ["assessments"],
    },
}


def _run_skeptic_batch(client, haiku_model: str, fact_pack_json: str,
                       findings: "list[dict]", *, focus: str = "",
                       cluster_notes: "dict | None" = None, trace=None) -> "list[dict | None]":
    """Vet a batch of findings in ONE call (fact pack sent once, not per finding).

    Returns a list aligned to `findings`: each element is the kept/modified finding or None
    (discard). A finding the model omits from its response defaults to confirmed (unchanged).
    Batches are formed per-category by the caller, so `focus` is that category's lens."""
    if not findings:
        return []
    system = (_HAIKU_SKEPTIC_SYSTEM + "\n\n" + focus) if focus else _HAIKU_SKEPTIC_SYSTEM
    cluster_notes = cluster_notes or {}
    blocks = []
    for i, f in enumerate(findings):
        note = cluster_notes.get(id(f))
        blocks.append(
            f"[{i}] {f.get('severity')} · {f.get('category','')}: {f.get('title','')}"
            + (f"\n    {note}" if note else "")
            + f"\n{json.dumps(f, default=str)}"
        )
    # The fact pack is identical across every skeptic batch, so send it as a cached prefix
    # (billed at the cache-read rate after the first batch writes it).
    cache_prefix = f"FACT PACK:\n{fact_pack_json}"
    user_msg = (f"Evaluate EACH of the following {len(findings)} finding(s) against the fact pack. "
                f"Return one assessment per finding, keyed by its [number]. Be adversarial; default "
                f"to skepticism but do not invent objections.\n\n" + "\n\n".join(blocks))
    verdicts: "dict[int, dict]" = {}
    try:
        calls = _call_with_tools(
            client, haiku_model, system, user_msg, [_SKEPTIC_BATCH_TOOL],
            _MAX_OUTPUT_TOKENS, tool_choice={"type": "tool", "name": "evaluate_findings"},
            trace=trace, trace_stage=f"skeptic batch ({findings[0].get('category','?')}, {len(findings)})",
            cache_prefix=cache_prefix,
        )
        for _, payload in calls:
            for a in (payload.get("assessments") or []):
                k = a.get("key")
                if isinstance(k, int) and 0 <= k < len(findings):
                    verdicts[k] = a
    except Exception:
        return list(findings)   # transport failure → keep all unchanged (never drop blindly)
    out: "list[dict | None]" = []
    for i, f in enumerate(findings):
        ev = verdicts.get(i)
        out.append(_apply_skeptic_verdict(f, ev) if ev else f)   # omitted → confirmed
    return out


# ── Normalise regular findings ──────────────────────────────────────────────

def _generate_remediation_commands(entities: "list[dict]", category: str,
                                   signal_context: "dict | None" = None) -> "list[str]":
    """Concrete az / PowerShell commands inferred from normalized entity data.

    Returns copy-pasteable command strings. Entity IDs/names are pre-filled from
    the fact-pack entity index. Role names and scopes are filled from Phase 1
    signal_context when available; otherwise left as <PLACEHOLDER>.
    """
    if not entities:
        return []

    def _pick(kinds: "list[str]") -> "dict":
        for k in kinds:
            for e in entities:
                if e.get("kind") == k:
                    return e
        return entities[0]

    def _from_signals(pid: str, key: str, fallback: str) -> str:
        if signal_context:
            for sig in signal_context.get(pid, []):
                v = sig.get(key)
                if v:
                    return v if isinstance(v, str) else str(v)
        return fallback

    cat = (category or "").lower()

    if "rbac" in cat:
        p     = _pick(["AZUser", "AZServicePrincipal", "AZGroup"])
        pid   = p.get("id", "")
        role  = _from_signals(pid, "_role", "<ROLE>")
        scope = _from_signals(pid, "_scope", "<SCOPE>")
        lines = [f"az role assignment list --assignee \"{pid}\" --all --output table"]
        if role == "<ROLE>":
            lines.append("# Role: copy the exact role name from the finding evidence above")
        if scope == "<SCOPE>":
            lines.append("# Scope: copy the exact scope path from the finding evidence above")
        lines.append(
            f"az role assignment delete --assignee \"{pid}\" --role \"{role}\" --scope \"{scope}\""
        )
        return lines

    # "Identity Hygiene" / lifecycle findings contain "identity" but need the disable-account
    # remediation below, not Entra-role removal - exclude them so they fall through.
    if "privileged identity" in cat or ("identity" in cat and "managed" not in cat
                                        and "hygiene" not in cat and "lifecycle" not in cat):
        p         = _pick(["AZUser", "AZServicePrincipal"])
        pid       = p.get("id", "")
        role_name = _from_signals(pid, "_role", "<ROLE_NAME>")
        lines = ["# PowerShell (Microsoft Graph SDK):"]
        if role_name == "<ROLE_NAME>":
            lines.append("# Role: copy the exact Entra role display name from the finding evidence above")
        lines += [
            f"$roleId = (Get-MgDirectoryRole -Filter \"displayName eq '{role_name}'\").Id",
            f"Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleId -DirectoryObjectId \"{pid}\"",
        ]
        return lines

    if "application" in cat or "service principal" in cat:
        sp  = _pick(["AZServicePrincipal", "AZApp"])
        pid = sp.get("id", "")
        perms_raw = None
        if signal_context:
            for sig in signal_context.get(pid, []):
                pv = sig.get("_permissions")
                if pv and isinstance(pv, list):
                    perms_raw = pv
                    break
        perm_line = (f"# Permissions to revoke: {', '.join(str(x) for x in perms_raw[:5])}"
                     if perms_raw else "# Remove a specific Graph permission (fill --api-permissions with the permission GUID):")
        return [
            f"az ad app permission list --id \"{pid}\" --output table",
            perm_line,
            f"az ad app permission delete --id \"{pid}\" --api 00000003-0000-0000-c000-000000000000 --api-permissions \"<PERMISSION_GUID>\"",
            "# Rotate or delete a credential:",
            f"az ad app credential list --id \"{pid}\"",
            f"az ad app credential delete --id \"{pid}\" --key-id \"<KEY_ID>\"",
        ]

    if "group" in cat:
        grp  = _pick(["AZGroup"])
        gid  = grp.get("id", "")
        others = [e for e in entities if e.get("id") != gid and
                  e.get("kind") in ("AZUser", "AZServicePrincipal")]
        mid = others[0].get("id", "<MEMBER_ID>") if others else "<MEMBER_ID>"
        return [
            f"az ad group member list --group \"{gid}\" --output table",
            f"az ad group member remove --group \"{gid}\" --member-id \"{mid}\"",
        ]

    if "hygiene" in cat or "lifecycle" in cat:
        u   = _pick(["AZUser"])
        uid = u.get("id", "")
        return [
            f"az ad user update --id \"{uid}\" --account-enabled false",
            f"Invoke-MgInvalidateAllUserRefreshToken -UserId \"{uid}\"",
        ]

    if "guest" in cat or "cross-tenant" in cat:
        u   = _pick(["AZUser"])
        uid = u.get("id", "")
        return [
            f"Remove-MgUser -UserId \"{uid}\"",
            f"# az alternative: az ad user delete --id \"{uid}\"",
        ]

    if "key vault" in cat:
        p     = _pick(["AZUser", "AZServicePrincipal"])
        pid   = p.get("id", "")
        role  = _from_signals(pid, "_role", "<ROLE>")
        scope = _from_signals(pid, "_scope", "<KV_SCOPE>")
        return [
            "# Remove legacy access policy:",
            f"az keyvault delete-policy --name \"<VAULT_NAME>\" --object-id \"{pid}\"",
            "# Or RBAC:",
            f"az role assignment delete --assignee \"{pid}\" --role \"{role}\" --scope \"{scope}\"",
        ]

    if "managed identit" in cat:
        p     = _pick(["AZServicePrincipal", "AZUser"])
        pid   = p.get("id", "")
        role  = _from_signals(pid, "_role", "<ROLE>")
        scope = _from_signals(pid, "_scope", "<SCOPE>")
        return [
            f"az role assignment list --assignee \"{pid}\" --all --output table",
            f"az role assignment delete --assignee \"{pid}\" --role \"{role}\" --scope \"{scope}\"",
        ]

    if "attack path" in cat:
        return [
            "# Sever the first hop in the escalation_chain - see path detail in the finding.",
            "# Typical first fix: remove the group membership or RBAC role that starts the path.",
            "az ad group member list --group \"<GROUP_ID>\" --output table",
        ]

    # Fallback: generic audit for the primary entity
    p   = _pick(["AZUser", "AZServicePrincipal", "AZGroup"])
    pid = p.get("id", "")
    if pid:
        return [
            f"az role assignment list --assignee \"{pid}\" --all --output table",
        ]
    return []


# ── Path consolidation, chokepoint analysis, remediation roadmap ─────────────

def _consolidate_paths(fact_pack: "FactPack") -> "list[dict]":
    """Group raw_attack_paths by source entity into one finding per source.

    Each consolidated finding carries all paths in all_paths[] for UI expansion,
    plus pre-computed summary fields (path_count, paths_by_severity, shortest_path,
    worst_path, top_edge, best_chokepoint) so the analyst sees the full picture
    without wading through N separate path findings.
    """
    from collections import Counter, defaultdict

    if not fact_pack.raw_attack_paths:
        return []

    paths_by_src: "dict[str, list[dict]]" = defaultdict(list)
    for ap in fact_pack.raw_attack_paths:
        paths_by_src[ap["src_id"]].append(ap)

    sev_rank   = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    consolidated: "list[dict]" = []

    for src_id, paths in paths_by_src.items():
        n         = len(paths)
        worst     = max(paths, key=lambda p: p.get("path_score", 0))
        shortest  = min(paths, key=lambda p: p["hop_count"])
        sev_counts: "Counter" = Counter(p["severity"] for p in paths)
        worst_sev = next(
            (s for s in ("Critical", "High", "Medium", "Low") if sev_counts.get(s, 0) > 0),
            "Medium",
        )
        # Best path for the display: highest score first, then fewest hops
        sorted_paths = sorted(paths, key=lambda p: (
            sev_rank.get(p["severity"], 3), p["hop_count"]
        ))
        # Most dangerous primitive across all paths (from pre-computed top_edge)
        top_edge = worst.get("top_edge", "")
        unique_targets = list(dict.fromkeys(p["dst_name"] for p in sorted_paths))

        # Best chokepoint within this source's paths: the intermediate node
        # (not a User/SP, since those are principals not infrastructure) that appears
        # in the most paths.  Severs the most routes for this source.
        hop_counter: "Counter"   = Counter()
        hop_meta:    "dict"      = {}  # node_id → {name, kind}
        for p in paths:
            hops = p.get("hops", [])
            for h in hops[:-1]:          # skip final hop - tier-0 target itself
                nid   = h["to_id"]
                nkind = h.get("to_kind", "Unknown")
                if nkind in ("AZUser", "AZServicePrincipal"):
                    continue
                hop_counter[nid] += 1
                if nid not in hop_meta:
                    hop_meta[nid] = {"name": h.get("to_name", nid), "kind": nkind}

        best_choke   = hop_counter.most_common(1)
        choke_hint   = ""
        choke_cmds: "list[str]" = []
        if best_choke:
            cid, ccount = best_choke[0]
            cmeta  = hop_meta.get(cid, {"name": cid, "kind": "Unknown"})
            cname  = cmeta["name"]
            ckind  = cmeta["kind"]
            choke_hint = (
                f"Removing/restricting '{cname}' ({ckind}) severs {ccount}/{n} of these paths."
            )
            if ckind == "AZGroup":
                src_name = paths[0]["src_name"]
                choke_cmds = [
                    f"az ad group member list --group \"{cid}\" --output table",
                    f"# Removing {src_name} from {cname} severs {ccount} path(s):",
                    f"az ad group member remove --group \"{cid}\" --member-id \"{src_id}\"",
                ]
            else:
                choke_cmds = [
                    f"az role assignment list --assignee \"{cid}\" --all --output table",
                ]

        src_info = fact_pack.entity_index.get(src_id, {"id": src_id, "name": src_id, "kind": "Unknown"})
        src_ent  = {**src_info, "role_in_finding": "Attack entry point"}
        sev_str  = ", ".join(f"{v} {k}" for k, v in sev_counts.items() if v)
        is_group = src_info.get("kind") == "AZGroup"
        src_label = "group" if is_group else "identity"
        mc = paths[0].get("max_group_mc", 0) if is_group else 0
        mc_suffix = f" ({mc} member(s) affected)" if is_group and mc > 0 else ""
        summary  = (
            f"{src_info.get('name', src_id)}{mc_suffix} has {n} path(s) to tier-0 ({sev_str}). "
            f"Shortest: {shortest['hop_count']}-hop via {shortest.get('top_edge', '?')} "
            f"→ {shortest['dst_name']}."
        )
        if choke_hint:
            summary += f" {choke_hint}"
        if src_info.get("kind") == "AZUser" and paths[0].get("src_is_guest"):
            summary = "[GUEST] " + summary

        consolidated.append({
            "source":           "path_consolidation",
            "title":            (f"{src_info.get('name', src_id)}{mc_suffix} → "
                                 f"{n} path(s) to tier-0 ({worst_sev})"),
            "severity":         worst_sev,
            "confidence":       None,
            "category":         "Attack Path",
            "entities":         [src_ent],
            "summary":          summary,
            "what":             (f"{n} independent escalation route(s) from this {src_label} "
                                 f"to tier-0 target(s): {', '.join(unique_targets[:3])}."),
            "reasoning":        "",
            "why_it_matters":   (f"Any single path is sufficient for compromise. "
                                 f"An attacker controlling this identity has {n} options."),
            "attack_scenario":  shortest["path"],
            "escalation_chain": [],
            "evidence":         [p["path"] for p in sorted_paths[:10]],
            "remediation":      choke_hint or "Sever each escalation route listed in evidence.",
            "remediation_commands": choke_cmds,
            "detection":        "",
            "mitre_technique":  "T1078",
            "exploitability":   "Established",
            "review_note":      "",
            "_specialist":      "path_consolidation",
            # Extended fields - consumers can expand these for full detail
            "path_count":       n,
            "paths_by_severity": dict(sev_counts),
            "shortest_path":    shortest,
            "worst_path":       worst,
            "all_paths":        sorted_paths,
            "top_edge":         top_edge,
            "unique_targets":   unique_targets,
        })

    # Second pass: merge findings that share a display name (same named app registered
    # multiple times with different GUIDs).  E.g. 4 × "Synology Active Backup for M365"
    # with distinct object IDs all get collapsed into one finding.
    by_name: "dict[str, list[dict]]" = defaultdict(list)
    for f in consolidated:
        src_name = (f.get("entities") or [{}])[0].get("name", "")
        by_name[src_name].append(f)

    final: "list[dict]" = []
    for src_name, group in by_name.items():
        if len(group) == 1:
            final.append(group[0])
            continue
        # Merge N instances into one representative finding
        all_inst_paths: "list[dict]" = []
        all_ents: "list[dict]"       = []
        for gf in group:
            all_inst_paths.extend(gf.get("all_paths") or [])
            for e in (gf.get("entities") or []):
                all_ents.append({**e, "role_in_finding": e.get("role_in_finding") or "Attack entry point"})
        total_paths = sum(gf.get("path_count", 0) for gf in group)
        rep = dict(max(group, key=lambda gf: gf.get("path_count", 0)))
        rep["title"] = (
            f"{len(group)} instances of '{src_name}' → "
            f"{total_paths} path(s) to tier-0 ({rep['severity']})"
        )
        rep["summary"] = (
            f"{len(group)} distinct service principals share the display name '{src_name}'. "
            f"Together they account for {total_paths} path(s) to tier-0 targets. "
            f"Each instance should be investigated separately; "
            f"the presence of multiple registrations of the same app is itself a hygiene concern."
        )
        rep["path_count"] = total_paths
        rep["all_paths"]  = sorted(all_inst_paths, key=lambda p: (
            sev_rank.get(p["severity"], 3), p["hop_count"]
        ))
        rep["entities"]   = all_ents
        final.append(rep)

    return final


def _compute_chokepoints(raw_attack_paths: "list[dict]",
                         entity_index: "dict[str, dict]",
                         top_n: int = 8) -> "list[dict]":
    """Find intermediate nodes whose removal would sever the most attack paths.

    Only non-principal intermediaries (groups, role nodes) are considered - removing
    a principal from its own path means deleting the account, which is a different
    remediation class than adjusting group membership or role assignments.
    """
    from collections import Counter, defaultdict

    if not raw_attack_paths:
        return []

    total = len(raw_attack_paths)
    node_path_count: "Counter"                  = Counter()
    node_src_sets:   "dict[str, set]"           = defaultdict(set)
    node_tgt_sets:   "dict[str, set]"           = defaultdict(set)
    node_sev_counts: "dict[str, Counter]"       = defaultdict(Counter)
    node_meta:       "dict[str, dict]"          = {}

    for p in raw_attack_paths:
        hops = p.get("hops", [])
        for h in hops[:-1]:                     # all hops except the final tier-0 target
            nid   = h["to_id"]
            nkind = h.get("to_kind", "Unknown")
            if nkind in ("AZUser", "AZServicePrincipal"):
                continue
            node_path_count[nid] += 1
            node_src_sets[nid].add(p["src_id"])
            node_tgt_sets[nid].add(p["dst_id"])
            node_sev_counts[nid][p["severity"]] += 1
            if nid not in node_meta:
                known = entity_index.get(nid, {})
                node_meta[nid] = {
                    "name": h.get("to_name") or known.get("name") or nid,
                    "kind": nkind,
                }

    if not node_path_count:
        return []

    results: "list[dict]" = []
    for nid, count in node_path_count.most_common(top_n):
        meta   = node_meta.get(nid, {"name": nid, "kind": "Unknown"})
        nname  = meta["name"]
        nkind  = meta["kind"]
        sev_c  = node_sev_counts[nid]
        sources = list(node_src_sets[nid])
        targets = list(node_tgt_sets[nid])

        src_names = [
            (entity_index.get(s, {}).get("name") or s) for s in sorted(sources)[:5]
        ]
        tgt_names = list(dict.fromkeys(
            (entity_index.get(t, {}).get("name") or t) for t in targets
        ))[:5]

        if nkind == "AZGroup":
            action = (
                f"Remove high-risk members from '{nname}', or revoke privilege assignments "
                f"held by this group. Severs paths for "
                f"{len(sources)} source principal(s): {', '.join(src_names[:3])}."
            )
            # For each source that routes through this group, emit the removal command
            removal_cmds = []
            for sid in sorted(sources)[:5]:
                removal_cmds.append(
                    f"az ad group member remove --group \"{nid}\" --member-id \"{sid}\""
                )
            cmds = [
                f"# 1. Confirm current members of '{nname}':",
                f"az ad group member list --group \"{nid}\" --output table",
                "# 2. Remove each high-risk member (one per source principal):",
            ] + removal_cmds

        elif nkind == "AZRole":
            action = (
                f"Remove privileged members from Entra role '{nname}'. "
                f"Severs {count} path(s) for {len(sources)} principal(s): {', '.join(src_names[:3])}."
            )
            removal_cmds = []
            for sid in sorted(sources)[:5]:
                removal_cmds.append(
                    f"az rest --method DELETE --url "
                    f"\"https://graph.microsoft.com/v1.0/directoryRoles/{nid}/members/{sid}/$ref\""
                )
            cmds = [
                f"# 1. List current members of role '{nname}':",
                f"az rest --method GET --url "
                f"\"https://graph.microsoft.com/v1.0/directoryRoles/{nid}/members\" "
                f"--query \"value[].{{name:displayName,id:id}}\" --output table",
                "# 2. Remove each source principal from this role:",
            ] + removal_cmds

        elif nkind == "AZApp":
            action = (
                f"Restrict ownership or app-role grants on application '{nname}'. "
                f"Severs {count} path(s) for principals: {', '.join(src_names[:3])}."
            )
            removal_cmds = []
            for sid in sorted(sources)[:5]:
                removal_cmds.append(
                    f"az ad app owner remove --id \"{nid}\" --owner-object-id \"{sid}\""
                )
            cmds = [
                f"# 1. List current owners of '{nname}':",
                f"az ad app owner list --id \"{nid}\" --output table",
                "# 2. List app-role assignments:",
                f"az ad app permission list --id \"{nid}\" --output table",
                "# 3. Remove each source principal as owner:",
            ] + removal_cmds

        elif nkind in ("AZManagementGroup", "AZSubscription", "AZResourceGroup"):
            scope_prefix = {
                "AZManagementGroup": f"/providers/Microsoft.Management/managementGroups/{nid}",
                "AZSubscription":    f"/subscriptions/{nid}",
                "AZResourceGroup":   nid,
            }[nkind]
            action = (
                f"Revoke over-privileged RBAC assignments on {nkind.replace('AZ','')} '{nname}'. "
                f"Severs {count} path(s) for {len(sources)} principal(s): {', '.join(src_names[:3])}."
            )
            removal_cmds = []
            for sid in sorted(sources)[:5]:
                removal_cmds.append(
                    f"az role assignment delete --assignee \"{sid}\" "
                    f"--scope \"{scope_prefix}\""
                )
            cmds = [
                "# 1. Audit current RBAC assignments on this scope:",
                f"az role assignment list --scope \"{scope_prefix}\" --output table",
                "# 2. Delete assignments for each source principal:",
            ] + removal_cmds

        else:
            action = (
                f"Audit '{nname}' ({nkind}) - restrict its permissions or memberships "
                f"to sever {count} path(s) for: {', '.join(src_names[:3])}."
            )
            removal_cmds = []
            for sid in sorted(sources)[:5]:
                removal_cmds.append(
                    f"az role assignment delete --assignee \"{sid}\" "
                    f"--all  # verify scope before running"
                )
            cmds = [
                f"az role assignment list --assignee \"{nid}\" --all --output table",
            ] + removal_cmds

        results.append({
            "node_id":              nid,
            "node_name":            nname,
            "node_kind":            nkind,
            "path_count":           count,
            "critical_count":       sev_c.get("Critical", 0),
            "high_count":           sev_c.get("High", 0),
            "medium_count":         sev_c.get("Medium", 0),
            "coverage_pct":         round(count / total * 100, 1),
            "unique_source_count":  len(sources),
            "unique_sources":       src_names,
            "unique_targets":       tgt_names,
            "action":               action,
            "remediation_commands": cmds,
        })

    return results


def _estimate_remediation_effort(f: dict) -> str:
    """Classify a finding's remediation effort into one of four tiers.

    Weights three signals: structural category (policy vs targeted fix), entity
    count (proxy for stakeholder breadth), and command concreteness (proxy for
    analyst research needed before acting).
    """
    cat   = (f.get("category") or "").lower()
    src   = f.get("source", "")
    sev   = f.get("severity", "Medium")
    n_ent = len(f.get("entities") or [])
    pc    = f.get("path_count", 1) if src == "path_consolidation" else 1

    all_cmds      = f.get("remediation_commands") or []
    cmds          = [c for c in all_cmds if not c.startswith("#")]
    n_cmds        = len(cmds)
    has_placeholder = any(
        p in c for c in cmds for p in ("<ROLE>", "<SCOPE>", "<PLACEHOLDER>")
    )
    # A "concrete" command has real IDs/paths and no analyst fill-in required
    is_concrete   = n_cmds >= 1 and not has_placeholder

    # ── Architectural: policy or design change, no single targeted fix ─────────
    if any(k in cat for k in ("tenant default", "security misconfig", "supply chain",
                               "conditional access", "mfa policy")):
        return "architectural"

    # ── Sprint: bulk work, many stakeholders, or many open routes ─────────────
    if n_ent > 5:
        return "this_sprint"
    if pc > 5:                               # consolidated path with many routes
        return "this_sprint"
    if n_ent > 2 and any(k in cat for k in  # hygiene / lifecycle = stakeholder overhead
                         ("hygiene", "pim", "hybrid", "app lifecycle",
                          "cross-subscription", "access breadth")):
        return "this_sprint"
    if has_placeholder and n_ent > 3:        # research needed AND wide scope
        return "this_sprint"

    # ── Immediate: concrete command, few entities, high/critical severity ──────
    if is_concrete and n_cmds <= 3 and n_ent <= 2 and sev in ("Critical", "High"):
        return "immediate"

    # ── Week: targeted fix, may need stakeholder sign-off or research ──────────
    return "this_week"


def _build_remediation_roadmap(findings: "list[dict]") -> "list[dict]":
    """Group findings into effort tiers ordered from quickest win to architectural change."""
    from collections import defaultdict

    sev_rank    = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    tier_order  = ["immediate", "this_week", "this_sprint", "architectural"]
    tier_labels = {
        "immediate":    "Fix Immediately  (< 1 day - single az/PowerShell command)",
        "this_week":    "Fix This Week  (1–5 days - targeted remediation, few stakeholders)",
        "this_sprint":  "Fix This Sprint  (1–2 weeks - access review, broader stakeholders)",
        "architectural":"Architectural Change  (weeks–months - policy or design change)",
    }

    buckets: "dict[str, list]" = defaultdict(list)
    for f in findings:
        buckets[_estimate_remediation_effort(f)].append(f)

    roadmap: "list[dict]" = []
    for tier in tier_order:
        items = buckets.get(tier, [])
        if not items:
            continue
        items.sort(key=lambda f: sev_rank.get(f.get("severity", "Info"), 5))
        roadmap.append({
            "tier":       tier,
            "tier_label": tier_labels[tier],
            "count":      len(items),
            "findings":   [
                {
                    "title":    f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "category": f.get("category", ""),
                    "commands": [c for c in (f.get("remediation_commands") or [])
                                 if not c.startswith("#")][:2],
                }
                for f in items
            ],
        })
    return roadmap


def _extract_entity_context(f: dict) -> "dict[str, list[dict]]":
    """Extract subscription/MG scope from finding evidence items.

    Only scope is extracted - role names are deliberately NOT extracted from free text
    because they appear in too many contexts ("Global Administrator can reassign Contributor"
    would wrongly attribute "Global Administrator" as the entity's role). Subscription and
    management-group paths are UUID-based and unambiguous regardless of context.

    Only evidence items are searched, not summary/reasoning/attack_scenario - evidence items
    are attributed atomic facts, while explanatory fields mention roles speculatively.
    """
    import re as _re

    # Evidence items are directly attributed facts; search them one at a time so we
    # stop at the first item containing a scope (most specific match).
    evidence_items = [str(e) for e in (f.get("evidence") or [])]
    if not evidence_items:
        evidence_items = [f.get("summary", "")]

    scope: "str | None" = None
    for item in evidence_items:
        # IGNORECASE: AzureHound emits ARM paths upper-cased (/SUBSCRIPTIONS/...,
        # /PROVIDERS/MICROSOFT.MANAGEMENT/MANAGEMENTGROUPS/...), so a case-sensitive
        # pattern silently failed to extract any scope from real evidence text.
        m = _re.search(
            r'(/providers/Microsoft\.Management/managementGroups/[^\s"\'>,]+)'
            r'|(/subscriptions/[0-9a-f\-]{36}(?:/[^\s"\'>,]*)?)',
            item,
            _re.IGNORECASE,
        )
        if m:
            scope = m.group(0).rstrip(".,)")
            break

    if not scope:
        return {}

    result: "dict[str, list[dict]]" = {}
    for ent in (f.get("entities") or []):
        eid = ent.get("id") if isinstance(ent, dict) else ent
        if eid:
            result[eid] = [{"_scope": scope, "_source": "extracted"}]
    return result


def _normalise(f: dict, fact_pack: FactPack, signal_context: "dict | None" = None) -> dict:
    # Supplement Phase 1 signal_context with data extracted from the finding's own text.
    # This fills in role/scope for specialist-generated findings with no signal backing.
    _extracted = _extract_entity_context(f)
    if _extracted:
        # Phase 1 signals take precedence; extracted data fills gaps only
        _merged: "dict[str, list[dict]]" = {**_extracted, **(signal_context or {})}
    else:
        _merged = signal_context  # type: ignore[assignment]

    entities = []
    for ent in f.get("entities") or []:
        eid   = ent.get("id") if isinstance(ent, dict) else ent
        known = fact_pack.entity_index.get(eid, {"id": eid, "name": eid, "kind": "Unknown"})
        role  = (ent.get("role_in_finding") if isinstance(ent, dict) else None) or ""
        if not role:
            kind = (known.get("kind") or "").replace("AZ", "").strip()
            role = f"Affected {kind.lower()}" if kind else "Affected entity"
        # Carry the ORIGINAL entity's evidence across. Rebuilding purely from the
        # fact-pack index threw it away, so every deterministic finding that passed
        # through the AI pipeline lost the role/scope/subscription detail its rule had
        # attached - 2,167 entities on a real scan, which then rendered as the generic
        # "Affected group" placeholder because there was nothing specific left to show.
        merged_ent = {**known, "role_in_finding": role}
        if isinstance(ent, dict):
            ev = ent.get("evidence")
            if ev:
                merged_ent["evidence"] = ev
            # Carry the AI's explicit subject/context tag so the path anchors on the
            # principal the finding is ABOUT, not a helper listed for context.
            rel = ent.get("relation")
            if rel in ("subject", "context"):
                merged_ent["relation"] = rel
        entities.append(merged_ent)
    chain = []
    for hop in f.get("escalation_chain") or []:
        chain.append({
            "from": fact_pack.entity_index.get(hop.get("from_id"), {"id": hop.get("from_id"), "name": hop.get("from_id")}),
            "to":   fact_pack.entity_index.get(hop.get("to_id"),   {"id": hop.get("to_id"),   "name": hop.get("to_id")}),
            "technique": hop.get("technique", ""),
        })

    is_det_rule = f.get("_specialist") == "det_rules"

    # Derive source: deterministic rule findings keep their source even after the AI pipeline
    source = "deterministic" if is_det_rule else "ai_generated"

    # Confidence: deterministic rule findings are directly confirmed facts (95); AI findings
    # must have provided their own value; fallback to None if somehow absent.
    raw_conf = f.get("confidence")
    if isinstance(raw_conf, (int, float)):
        confidence = max(0, min(100, round(raw_conf)))
    elif is_det_rule:
        confidence = 95  # rule-based: directly confirmed from graph data
    else:
        confidence = None

    # Field fallbacks: fill empty AI text fields from other available content so no
    # finding is shown with blank sections.  Deterministic findings rely on their `what`
    # field (handled in the report renderer) so we only fill gaps for AI findings.
    _what    = (f.get("what") or "").strip()
    _summary = (f.get("summary") or "").strip()
    _reason  = (f.get("reasoning") or "").strip()
    _attack  = (f.get("attack_scenario") or "").strip()
    _why     = (f.get("why_it_matters") or "").strip()
    _evidence = [e for e in (f.get("evidence") or []) if e and str(e).strip()]

    if not is_det_rule:
        # summary: fall back to what if blank
        if not _summary and _what:
            _summary = _what[:800]
        # reasoning: fall back to what + attack_scenario if blank
        if not _reason:
            parts = [p for p in [_what, _attack] if p]
            _reason = "\n\n".join(parts)[:3000] if parts else ""
        # why_it_matters: fall back to summary or what
        if not _why:
            _why = _summary or _what
        # evidence: construct from what if completely absent
        if not _evidence and _what:
            _evidence = [_what[:500]]
        # what: fall back to summary - it is the field the report shows for the
        # plain-language description, so a blank leaves the card's body empty.
        if not _what:
            _what = _summary or _why

    # remediation: the schema marks it required with minLength, but a handful of findings
    # still arrive with it blank, and a security finding with no "how to fix" is the least
    # useful thing the report can print. Fall back to a directive built from the finding's
    # own content, naming the affected principals, rather than shipping an empty section.
    _remediation = (f.get("remediation") or "").strip()
    if not _remediation:
        _names = [e.get("name") or e.get("id") for e in entities[:3] if isinstance(e, dict)]
        _who = ", ".join(n for n in _names if n)
        _cat = (f.get("category") or "").strip()
        _remediation = (
            (f"Review and reduce the access held by {_who}"
             + (f" ({len(entities)} affected in total)" if len(entities) > 3 else "")
             + ". " if _who else "Review and reduce the access described above. ")
            + (f"This is a {_cat} issue" if _cat else "This finding")
            + " for which no automated remediation text was produced - use the attack "
              "scenario and evidence above to scope the fix, and remove or PIM-gate the "
              "privilege that makes the described path possible."
        )

    return {
        "source":           source,
        "title":            f["title"],
        "severity":         f.get("severity", "Info"),
        "confidence":       confidence,
        "category":         f.get("category", "Uncategorized"),
        "entities":         entities,
        "summary":          _summary,
        "what":             _what,
        "reasoning":        _reason,
        "why_it_matters":   _why,
        "attack_scenario":  _attack,
        "escalation_chain": chain,
        "evidence":         _evidence,
        "remediation":          _remediation,
        "remediation_commands": _generate_remediation_commands(
                                    entities, f.get("category", ""), _merged),
        "detection":            f.get("detection", ""),
        "mitre_technique":  f.get("mitre_technique", ""),
        "attack_primitive": f.get("attack_primitive", ""),
        "exploitability":   f.get("exploitability", ""),
        "review_note":      f.get("review_note", ""),
        "_specialist":      f.get("_specialist", ""),
        # Passthrough fields the rule engine sets. _normalise built a fresh dict and
        # silently dropped these, so a deterministic finding that went through the AI
        # pipeline lost them. Consequences, all user-visible:
        #   rule_id       - the AZ-* badge vanished from the card and the finding became
        #                   unsearchable by ID (34 of 41 findings on a real AI scan)
        #   best_practice - the score SKIPS best-practice findings, so losing the flag
        #                   made hygiene items start penalising the grade
        #   frameworks / references / description - CIS + MITRE mappings and links lost
        **{k: f[k] for k in ("rule_id", "best_practice", "frameworks",
                             "references", "description", "detail")
           if k in f},
    }


def _external_exposure(det_findings: list) -> list[dict]:
    """The live ARG/Graph (Track B) findings, compacted for the resource-exposure
    specialist's fact-pack slice. Identified by their ARG-/IDG- rule-id prefix; the
    identity-graph deterministic findings (AZ-*) are excluded - the specialist
    already sees those through the other slices."""
    out = []
    for f in det_findings or []:
        rid = str(f.get("rule_id") or "")
        if rid.startswith(("ARG-", "IDG-")):
            out.append({
                "rule_id": rid, "title": f.get("title"), "severity": f.get("severity"),
                "objects": [e.get("name") for e in (f.get("entities") or []) if e.get("name")][:15],
            })
    return out


# ── Attack cartographer (maximum-impact path evaluation + path plot) ────
#
# One specialist that reasons over the deterministic maximum-impact paths (computed
# from the real escalation graph in scoring.compute_max_impact_paths) and, for each
# attack: (1) writes the attacker-eye worst-case narrative and (2) names the attack-path
# plot. It never invents a path - the graph owns the route;
# the agent owns the story and the label. Every finding still gets a plot even if the
# model drops it, via the deterministic fallback in _cartographer_fallback.

_CARTOGRAPHER_TOOL = {
    "name": "map_attack",
    "description": "Record ONE numbered attack's worst-case impact narrative and a short "
                   "human-readable name for its attack-path plot. Call once per attack.",
    "input_schema": {
        "type": "object",
        "properties": {
            "key": {"type": "integer",
                    "description": "The attack's number from the list."},
            "max_impact_summary": {
                "type": "string", "minLength": 20,
                "description": "1-2 sentences: the worst outcome an attacker achieves by "
                               "walking THIS path to its target. Concrete, no hedging."},
            "plot_name": {
                "type": "string", "minLength": 3, "maxLength": 80,
                "description": "Short label for the saved attack-path query, e.g. "
                               "'Helpdesk group -> Global Admin'."},
        },
        "required": ["key", "max_impact_summary", "plot_name"],
    },
}

_CARTOGRAPHER_SYSTEM = (
    "You are an ATTACK-PATH CARTOGRAPHER for an Azure/Entra tenant. You are given a list "
    "of confirmed attacks, each already resolved to its MAXIMUM-IMPACT PATH: the highest-"
    "value target reachable from the attack's own principals over the real privilege-"
    "escalation graph, and the exact hops to reach it. The paths are ground truth - do "
    "NOT question, alter, or invent them. For each attack, do two things: (1) write a "
    "sharp 1-2 sentence worst-case narrative of what the attacker gains by walking that "
    "path to that target; (2) give the path a short, human-readable name an analyst will "
    "recognise in a saved-query list. Call the map_attack tool ONCE for EVERY "
    "attack number in the list - do not batch them and do not skip any."
)


def _cartographer_fallback_summary(path: dict) -> str:
    entry = (path.get("entry") or {}).get("name") or "the principal"
    target = (path.get("target") or {}).get("name") or "a privileged target"
    n = path.get("length") or 0
    if path.get("reaches_tier0"):
        tail = (f" reaches the Tier-0 target {target}" if n
                else f" is the Tier-0 target {target}")
    elif n:
        tail = f" escalates to {target}"
    else:
        tail = f" exposes {target}"
    step = f" in {n} step{'s' if n != 1 else ''}" if n else ""
    return f"Compromise of {entry}{tail}{step}, extending the blast radius to that objective."


def _cartographer_plot_name(path: dict) -> str:
    entry = (path.get("entry") or {}).get("name") or "entry"
    target = (path.get("target") or {}).get("name") or "target"
    if (path.get("entry") or {}).get("id") == (path.get("target") or {}).get("id"):
        return f"{target} (exposure)"[:80]
    return f"{entry} → {target}"[:80]


def _as_list(v) -> list:
    """Coerce a tool-call array field to a list. Some models (seen with Opus) return an
    array-typed tool parameter as a JSON-ENCODED STRING ('[{...}]') instead of a native
    array; iterating that string then walks characters and every item is dropped. Decode a
    stringified array so the payload is usable; return [] for anything that is not a list."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def run_attack_cartographer(client, model: str, findings: "list[dict]",
                            *, max_ai: int = 8, on_progress=None, trace=None) -> int:
    """Evaluate each finding's maximum-impact path and attach the plot metadata.

    Mutates findings in place, adding:
      max_impact_summary  - worst-case narrative (AI, deterministic fallback)
      plot_name        - label for the saved attack-path query

    Returns the count of findings the model enriched. Every finding that has a
    `max_impact_path` ends up with a summary and a plot name regardless."""
    have_paths = [f for f in findings if f.get("max_impact_path")]
    # Deterministic baseline first - guarantees full coverage.
    for f in have_paths:
        p = f["max_impact_path"]
        f.setdefault("max_impact_summary", _cartographer_fallback_summary(p))
        f.setdefault("plot_name", _cartographer_plot_name(p))
    if not have_paths or client is None:
        return 0
    # Enrich the highest-value paths with the model (Tier-0 first, then impact).
    ranked = sorted(
        have_paths,
        key=lambda f: (not f["max_impact_path"].get("reaches_tier0"),
                       -(f["max_impact_path"].get("impact") or 0),
                       {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                       .get(f.get("severity"), 5)),
    )[:max_ai]
    lines = []
    for i, f in enumerate(ranked):
        p = f["max_impact_path"]
        prims = " -> ".join(h.get("via", "?") for h in (p.get("hops") or [])) or "(direct)"
        lines.append(
            f"[{i}] {f.get('severity')}: {f.get('title')}\n"
            f"    entry: {(p.get('entry') or {}).get('name')} "
            f"({(p.get('entry') or {}).get('kind')})\n"
            f"    target: {(p.get('target') or {}).get('name')} "
            f"({(p.get('target') or {}).get('kind')})"
            f"{' [Tier-0]' if p.get('reaches_tier0') else ''}\n"
            f"    path ({p.get('length')} hop(s)): {prims}"
        )
    user_msg = ("Map these attacks. Return one plot entry per attack number.\n\n"
                + "\n\n".join(lines))
    try:
        calls = _call_with_tools(
            client, model, _CARTOGRAPHER_SYSTEM, user_msg,
            [_CARTOGRAPHER_TOOL], max_tokens=_MAX_OUTPUT_TOKENS,
            trace=trace, trace_stage="cartographer (path narration)")
    except Exception as exc:  # model/network/parse - keep the deterministic baseline
        if on_progress:
            on_progress(f"Cartographer enrichment skipped: {type(exc).__name__}: {exc}")
        return 0
    # One tool call per attack (map_attack) - the reliable pattern the specialists use.
    # The old batch tool returned an array the model stuffed into a truncated JSON string,
    # so nothing parsed and every path fell back to the deterministic summary.
    enriched = 0
    for _name, payload in calls:
        if not isinstance(payload, dict):
            continue
        idx = payload.get("key")
        if not isinstance(idx, int) or not (0 <= idx < len(ranked)):
            continue
        f = ranked[idx]
        summ = (payload.get("max_impact_summary") or "").strip()
        pname = (payload.get("plot_name") or "").strip()
        if summ:
            f["max_impact_summary"] = summ
            enriched += 1
        if pname:
            f["plot_name"] = pname[:80]
    return enriched


_COHERENCE_TOOL = {
    "name": "report_coherence",
    "description": "For each numbered finding, report whether its computed attack path "
                   "tells the same attack its description does, and correct the "
                   "declared attack primitive when the wrong first move was chosen.",
    "input_schema": {
        "type": "object",
        "properties": {
            "assessments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "integer", "description": "The finding's number."},
                        "matches": {"type": "boolean",
                                    "description": "True if the path's first move and target "
                                    "represent the SAME attack the description does."},
                        "issue": {"type": "string", "maxLength": 240,
                                  "description": "If matches=false, ONE sentence naming the specific "
                                  "discrepancy, e.g. 'description is an Azure RBAC self-escalation but "
                                  "the path shows an Entra directory-role grant'. Empty if matches=true."},
                        "corrected_primitive": {"type": "string", "enum": ATTACK_PRIMITIVES + [""],
                                  "description": "When the first move is wrong, the attack_primitive that "
                                  "matches THIS finding's description; empty otherwise."},
                    },
                    "required": ["key", "matches"],
                },
            },
        },
        "required": ["assessments"],
    },
}

_COHERENCE_SYSTEM = (
    "You are the final QA reviewer for an Azure identity-posture report. For each finding you "
    "get its description and scenario, its computed maximum-impact attack path (first move -> "
    "hops -> target), and the attack_primitive the analyst declared. Your ONE job: confirm the "
    "path tells the SAME "
    "attack the description does. The load-bearing check is the FIRST move: it must be the same "
    "action, on the same plane, that the scenario opens with. These are DIFFERENT attacks and "
    "must never be confused: an Azure RBAC self-escalation (User Access Administrator / Owner / "
    "Contributor granting a higher AZURE role) vs an Entra directory-role grant vs a password "
    "reset vs a Key Vault secret read vs a managed-identity theft. When the first move is the "
    "wrong one, set matches=false and give the corrected_primitive that fits the description. "
    "Do not nitpick wording or severity - only flag a genuine mismatch of the attack itself. "
    "Be strict and literal; a plausible-looking but wrong path is exactly what you must catch."
)


def run_coherence_check(client, model: str, findings: "list[dict]",
                        *, max_ai: int = 80, on_progress=None, trace=None) -> dict:
    """Final coherence gate: have the model check each finding's attack path
    against the finding's own description BEFORE the report is written, and RESOLVE every
    divergence rather than merely disclosing it:

      • wrong first move / plane  -> return a corrected attack_primitive; the caller
        re-anchors and recomputes the path (`corrected`).
      • right primitive, divergent route -> mark for path-narration realignment; the
        caller regenerates the path summary from the deterministic computed path so the
        report reads coherently, with no leftover discrepancy note (`realigned`).

    Only a mismatch it can neither re-anchor nor realign is left flagged (should be ~0).
    Never raises. Returns {checked, corrected, realigned, flagged}.
    """
    escalating = [f for f in findings if (f.get("max_impact_path") or {}).get("hops")]
    if not escalating or client is None:
        return {"checked": 0, "corrected": [], "flagged": 0}
    ranked = sorted(
        escalating,
        key=lambda f: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
                       .get(f.get("severity"), 5),
                       -((f.get("max_impact_path") or {}).get("impact") or 0)),
    )[:max_ai]
    lines = []
    for i, f in enumerate(ranked):
        p = f["max_impact_path"]
        prims = " -> ".join(h.get("via", "?") for h in (p.get("hops") or [])) or "(direct)"
        lines.append(
            f"[{i}] {f.get('severity')}: {f.get('title')}\n"
            f"    description: {(f.get('what') or f.get('summary') or '')[:280]}\n"
            f"    scenario: {(f.get('attack_scenario') or '')[:280]}\n"
            f"    declared primitive: {f.get('attack_primitive') or '(none)'}\n"
            f"    computed path: {(p.get('entry') or {}).get('name')} "
            f"--[{prims}]--> {(p.get('target') or {}).get('name')} "
            f"({(p.get('target') or {}).get('kind')})"
        )
    user_msg = ("Review each finding for path <-> description coherence. "
                "Flag only genuine mismatches of the attack itself.\n\n" + "\n\n".join(lines))
    try:
        calls = _call_with_tools(
            client, model, _COHERENCE_SYSTEM, user_msg, [_COHERENCE_TOOL],
            max_tokens=_MAX_OUTPUT_TOKENS,
            tool_choice={"type": "tool", "name": "report_coherence"},
            trace=trace, trace_stage="coherence gate")
    except Exception as exc:  # model/network/parse - never block the report
        if on_progress:
            on_progress(f"Coherence check skipped: {type(exc).__name__}: {exc}")
        return {"checked": 0, "corrected": [], "flagged": 0}
    corrected, realigned, flagged = [], [], 0
    for _name, payload in calls:
        if not isinstance(payload, dict):
            continue
        for a in _as_list(payload.get("assessments")):
            if not isinstance(a, dict):
                continue
            idx = a.get("key")
            if not isinstance(idx, int) or not (0 <= idx < len(ranked)):
                continue
            f = ranked[idx]
            if a.get("matches", True):
                continue
            issue = (a.get("issue") or "").strip()
            cp = (a.get("corrected_primitive") or "").strip()
            if cp and cp in ATTACK_PRIMITIVES and cp != f.get("attack_primitive"):
                # Plane-level error: the declared first move is on the wrong plane. The
                # gate's correction is authoritative and must win over the structural
                # object-anchor when the path is recomputed. Re-anchoring then re-narrates
                # a coherent path, so no discrepancy note is left behind.
                f["attack_primitive"] = cp
                f["_anchor_from_primitive"] = True
                f.pop("coherence_note", None)
                corrected.append(f)
            elif cp and cp not in ATTACK_PRIMITIVES:
                # The gate wanted a DIFFERENT primitive but named one outside the enum, so
                # we cannot re-anchor and must not guess. This is the only residual case:
                # disclose it honestly rather than realign to a path the gate distrusts.
                if issue:
                    f["coherence_note"] = issue
                    flagged += 1
            else:
                # Route divergence: primitive/plane is right (empty or unchanged), but the
                # narrated route names a different intermediary/target than the computed
                # max-impact path. The computed path is deterministic ground truth, so
                # RESOLVE the divergence by realigning the path narration to it - never
                # leave the reader a note to reconcile. The caller regenerates
                # max_impact_summary from the actual path.
                f["_recohere_summary"] = True
                f.pop("coherence_note", None)
                if issue:
                    f["_coherence_issue"] = issue   # retained for telemetry, not rendered
                realigned.append(f)
    if on_progress:
        on_progress(f"Coherence gate: reviewed {len(ranked)} attack path(s) against their "
                    f"descriptions - {len(corrected)} re-anchored, {len(realigned)} "
                    f"path-narration realigned, {flagged} left flagged.")
    return {"checked": len(ranked), "corrected": corrected,
            "realigned": realigned, "flagged": flagged}


def _finalize_deterministic(result, fact_pack, log):
    """Emit the deterministic outputs that never depend on the AI phases: the
    consolidated attack paths (the fully-grounded BFS chains), chokepoints, and the
    remediation roadmap. Runs on EVERY exit - including when no AI candidate survived
    - so a mass specialist failure can never drop the cheapest, most valuable output
    (the deterministic attack paths) in the exact case it matters most."""
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    consolidated_paths = _consolidate_paths(fact_pack)
    if consolidated_paths:
        consolidated_paths.sort(key=lambda f: sev_order.get(f.get("severity", "Info"), 5))
        # Dedup: drop AI/chain findings whose entities a consolidated path already
        # covers (only Attack-Chain/Escalation categories; domain findings stay).
        _consol_src_ids: set = {
            (_e.get("id") if isinstance(_e, dict) else _e)
            for _pf in consolidated_paths
            for _e in (_pf.get("entities") or [])
        }
        _OVERLAP_CATS = {"Attack Chain", "Privilege Escalation", "Attack Path"}
        if _consol_src_ids:
            _before = len(result.findings)
            result.findings = [
                _f for _f in result.findings
                if not (
                    _f.get("category") in _OVERLAP_CATS
                    and any(
                        ((_e.get("id") if isinstance(_e, dict) else _e) in _consol_src_ids)
                        for _e in (_f.get("entities") or [])
                    )
                )
            ]
            _dropped = _before - len(result.findings)
            if _dropped:
                log(f"Path dedup: removed {_dropped} AI finding(s) covered by consolidated paths.")
        result.findings = consolidated_paths + result.findings
        log(f"Path consolidation: {len(consolidated_paths)} source group(s) added.")

    result.chokepoints = _compute_chokepoints(fact_pack.raw_attack_paths, fact_pack.entity_index)
    if result.chokepoints:
        log(f"Chokepoints: top {len(result.chokepoints)} intermediate node(s) identified.")

    result.remediation_roadmap = _build_remediation_roadmap(result.findings)
    if result.remediation_roadmap:
        tier_summary = ", ".join(f"{t['count']} {t['tier']}" for t in result.remediation_roadmap)
        log(f"Remediation roadmap: {tier_summary}.")

    _suppressed = []
    if result.skeptic_dropped:        _suppressed.append(f"{result.skeptic_dropped} dropped by skeptic")
    if result.non_assessable_dropped: _suppressed.append(f"{result.non_assessable_dropped} non-assessable suppressed")
    log(f"Done: {len(result.findings)} findings "
        f"({result.chain_findings_count} chains, {', '.join(_suppressed) or 'none dropped'}, "
        f"{len(result.rejected)} rejected).")
    return result


# ── Main entry point ────────────────────────────────────────────────────────

def generate_findings(fact_pack: FactPack, api_key: str, *,
                      sonnet_model: str = DEFAULT_SONNET_MODEL,
                      opus_model:   str = DEFAULT_OPUS_MODEL,
                      haiku_model:  str = DEFAULT_HAIKU_MODEL,
                      # No artificial output ceiling: request the model's per-turn maximum
                      # (auto-clamped by create_message if a model's real limit is lower), and
                      # the continuation loop in _call_with_tools makes the TOTAL output
                      # unbounded - a specialist writes as many findings as it actually has,
                      # never as many as a budget allows.
                      max_tokens:   int = _MAX_OUTPUT_TOKENS,
                      on_progress=None,
                      det_findings: list | None = None,
                      collection: dict | None = None,
                      trace=None) -> GenerationResult:
    """Python anomaly signals → Sonnet specialists → Opus synthesizer → Opus correlator → Sonnet skeptic.

    Phase 1  - Pure Python scans ALL SP, RBAC, Entra role, group, and app-grant inventory
               (uncapped, zero cost, zero hallucination).  Produces deterministic anomaly
               signals with grounded entity IDs.
    Phase 2  - The Sonnet specialists run in parallel, each receiving a domain-focused
               FactPack slice PLUS relevant Python anomaly signals as grounding context.
    Phase 2b - Opus cross-domain compound synthesizer finds NEW risks that span ≥2 domains
               and are more severe than any individual specialist finding.
    Phase 3  - Opus correlation agent finds multi-step attack chains across all findings.
    Phase 4  - Sonnet/Haiku skeptic adversarially evaluates all Critical/High findings.
    """
    known  = fact_pack.known_ids()
    result = GenerationResult(sonnet_model=sonnet_model, opus_model=opus_model,
                              haiku_model=haiku_model)

    # v2 Track B: expose the live ARG/Graph findings to the fact pack so the
    # resource_exposure specialist reasons over the tenant's full attack surface.
    if det_findings:
        fact_pack.external_exposure = _external_exposure(det_findings)

    def log(msg: str) -> None:
        # on_progress is the job appender, which itself mirrors into the trace - so the
        # phase lines already reach the trace; the trace object is used here only for the
        # richer per-stage/per-candidate/model-reasoning entries.
        if on_progress:
            on_progress(msg)

    client = _client(api_key)

    # ── Coverage check ────────────────────────────────────────────────────────
    _cov: list[str] = []
    if not fact_pack.raw_sp_list:
        _cov.append(
            "No Service Principal data - SP findings will be absent. "
            "Ensure AzureHound was run with Application.Read.All permissions.")
    if not fact_pack.raw_rbac_list:
        _cov.append(
            "No RBAC assignment data - subscription/MG findings will be absent. "
            "Ensure AzureHound was run with Reader role at sub/MG scope.")
    if not fact_pack.raw_entra_list:
        _cov.append(
            "No Entra role assignment data - directory/identity findings will be absent. "
            "Ensure AzureHound was run with Directory.Read.All or RoleManagement.Read.All.")
    if not fact_pack.raw_group_list:
        _cov.append(
            "No privileged group data - group-based escalation paths may be absent.")
    if not fact_pack.tier0_principals:
        _cov.append(
            "No tier-0 principals identified - verify Global Administrator / Owner roles "
            "are present in the collected data.")
    for _w in _cov:
        log(f"[COVERAGE WARNING] {_w}")
    result.coverage_warnings = _cov

    # ── Phase 1: Deterministic anomaly signals - zero AI cost, 100% coverage ───
    total_items = (
        len(fact_pack.raw_sp_list) + len(fact_pack.raw_rbac_list) +
        len(fact_pack.raw_entra_list) + len(fact_pack.raw_group_list) +
        len(fact_pack.raw_app_grant_list)
    )
    log(f"Phase 1: Python anomaly signals - scanning {total_items} inventory items (zero cost)…")
    all_signals = _compute_anomaly_signals(fact_pack)
    total_signals = sum(len(v) for v in all_signals.values())
    parts = ", ".join(f"{len(v)} {k}" for k, v in all_signals.items() if v)
    path_count = len(fact_pack.raw_attack_paths)
    path_note  = f", {path_count} attack path(s)" if path_count else ""
    if getattr(fact_pack, "attack_paths_capped", False):
        path_note += " [cap hit - deeper paths may exist]"
    log(f"Phase 1 done: {total_signals} anomaly signals ({parts or 'none'}){path_note}.")

    # Build entity → signals index for remediation command generation
    signal_context: dict[str, list[dict]] = {}
    for _sigs in all_signals.values():
        for _s in _sigs:
            _eid = _s.get("entity_id")
            if _eid:
                signal_context.setdefault(_eid, []).append(_s)

    # ── Phase 2: Sonnet specialists in parallel ────────────────────────────
    # Skip the resource-exposure specialist when no live Azure Resource Graph /
    # Microsoft Graph data was collected (no Reader service principal) - it would
    # spend an API call analysing an empty slice. Recorded as never-ran, not 0.
    to_run = list(SPECIALISTS)
    if not fact_pack.external_exposure:
        to_run = [s for s in SPECIALISTS if s["key"] != "resource_exposure"]
        if len(to_run) < len(SPECIALISTS):
            result.specialist_counts["resource_exposure"] = None
            log("  Resource Exposure & Data Protection: skipped - no live Azure "
                "Resource Graph / Microsoft Graph data (no Reader service principal).")
    # Cap concurrency: the specialists are INDEPENDENT (each gets its own domain slice and
    # never reads another's output), so running them in parallel does not change any single
    # agent's reasoning - only speed. But firing all 17 requests at once maximises the chance of
    # a 429/overload, and a throttled specialist that isn't retried loses its whole domain. A
    # modest cap keeps most of the speed while easing rate-limit pressure; create_message also
    # retries transient throttles. So results are as complete as sequential, far faster.
    workers = min(_SPECIALIST_MAX_CONCURRENCY, len(to_run))
    log(f"Phase 2: {len(to_run)} specialists, {workers} at a time ({sonnet_model})…")
    all_candidates: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_run_specialist, client, spec, fact_pack, known,
                        sonnet_model, max_tokens, all_signals, collection, trace): spec
            for spec in to_run
        }
        for future in as_completed(futures):
            spec = futures[future]
            try:
                key, grounded, rejected = future.result()
                # Split transport/size failures from genuine grounding rejections.
                # Conflating them told the user "rejected for referencing entities not
                # in this tenant" when in fact the domain was never analysed at all.
                transport = [r for r in rejected if r.get("_transport_failure")]
                grounding = [r for r in rejected if not r.get("_transport_failure")]
                result.rejected.extend(grounding)
                all_candidates.extend(grounded)
                if transport:
                    reason = transport[0].get("reason", "unknown error")
                    result.stage_errors.append(
                        f"{spec['label']} ({key}) did not run: {reason}")
                    result.failed_specialists.append({
                        "key": key, "label": spec["label"], "reason": reason})
                    result.specialist_counts[key] = None   # None = never ran (≠ 0 found)
                    log(f"  {spec['label']}: FAILED - {reason}")
                else:
                    result.specialist_counts[key] = len(grounded)
                    if not grounded and not grounding:
                        # Ran to completion, made no record_finding calls: a genuinely clean
                        # domain, not a failure. Say so plainly so the trace is unambiguous.
                        log(f"  {spec['label']}: 0 finding(s) - ran clean, nothing to flag in this domain.")
                    else:
                        log(f"  {spec['label']}: {len(grounded)} finding(s)"
                            + (f", {len(grounding)} rejected." if grounding else "."))
            except Exception as exc:
                err = f"{spec['label']} ({spec['key']}) did not run: {type(exc).__name__}: {exc}"
                result.stage_errors.append(err)
                result.failed_specialists.append({
                    "key": spec["key"], "label": spec["label"],
                    "reason": f"{type(exc).__name__}: {exc}"})
                result.specialist_counts[spec["key"]] = None
                log(f"  {spec['label']}: FAILED - {exc}")

    # Canonical ordering before anything consumes the candidate list. The specialists
    # run under as_completed(), so arrival order depends on which API call returns
    # first - and _dedup_candidates keeps the FIRST of two equal-confidence duplicates.
    # That made the surviving copy of a duplicated finding vary between runs of the same
    # input. Sorting here removes concurrency as a source of output variance; it does not
    # (and cannot) remove model sampling variance.
    all_candidates.sort(key=lambda f: (
        str(f.get("_specialist") or ""),
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(f.get("severity"), 5),
        str(f.get("title") or ""),
        ",".join(sorted(
            (e.get("id") if isinstance(e, dict) else str(e)) or ""
            for e in (f.get("entities") or [])
        )),
    ))

    # raw = everything the specialists proposed; grounded = what survived grounding. At this
    # point result.rejected holds only the specialist-stage rejections (the correlator has
    # not run yet), so their difference is the real grounding drop, not always zero.
    result.sonnet_grounded_count = len(all_candidates)
    result.sonnet_raw_count      = len(all_candidates) + len(result.rejected)
    log(f"Phase 2 done: {len(all_candidates)} grounded candidates.")

    # Include deterministic rule findings (Haiku skeptic will vet Critical/High ones)
    if det_findings:
        det_added = 0
        for df in det_findings:
            ok, _ = _validate_grounding(df, known)
            if ok:
                df.setdefault("_specialist", "det_rules")
                # Deterministic rules are certainties, not guesses. Give them a top
                # confidence so that when an AI specialist reports the SAME issue, dedup
                # keeps the deterministic copy (with its rule_id, best_practice flag and CIS
                # frameworks) instead of the AI paraphrase. Without this the AI copy won -
                # dropping best_practice (which then wrongly penalised the score) and, when
                # the categories differed, letting the merge re-add the det finding as a
                # second copy (a double count). Non-AI findings never show a % confidence,
                # so this changes only dedup precedence, not the report.
                df.setdefault("confidence", 100)
                all_candidates.append(df)
                det_added += 1
        if det_added:
            log(f"  + {det_added} deterministic rule findings included.")

    # ── Phase 2b: Opus cross-domain compound synthesizer ────────────────────
    log(f"Phase 2b: Cross-domain compound synthesizer ({opus_model})…")
    synth_findings, synth_rejected, synth_upgrades = _run_synthesizer(
        client, opus_model, all_signals, all_candidates, known, fact_pack, max_tokens, trace=trace)
    result.rejected.extend(synth_rejected)
    if synth_findings:
        all_candidates.extend(synth_findings)
        log(f"  Synthesizer: {len(synth_findings)} new cross-domain compound finding(s).")
    else:
        log("  Synthesizer: no additional compound risks identified.")
    # Apply synthesizer-suggested severity upgrades to existing findings.
    # The synthesizer sees all specialist outputs simultaneously - it can spot
    # when a High from specialist A + evidence from specialist B warrants Critical.
    if synth_upgrades:
        _sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        _upgraded = 0
        for _upg in synth_upgrades:
            _upg_title = _upg.get("title", "")
            _new_sev   = _upg.get("upgraded_severity", "")
            _reason    = _upg.get("cross_domain_reason", "")
            if not (_upg_title and _new_sev):
                continue
            for _cand in all_candidates:
                if _cand.get("title") == _upg_title:
                    _curr = _cand.get("severity", "Medium")
                    if _sev_rank.get(_new_sev, 99) < _sev_rank.get(_curr, 99):
                        _cand["severity"] = _new_sev
                        _cand["review_note"] = (
                            (_cand.get("review_note") or "")
                            + f" [Synthesizer upgraded {_curr}→{_new_sev}: {_reason}]"
                        )
                        _upgraded += 1
                    break
        if _upgraded:
            log(f"  Synthesizer upgraded severity of {_upgraded} existing finding(s).")

    # Dedup (entity-set+category exact, then title-similarity) before correlator
    if len(all_candidates) > 1:
        pre = len(all_candidates)
        all_candidates = _dedup_candidates(all_candidates)
        if len(all_candidates) < pre:
            log(f"Dedup: {pre} → {len(all_candidates)} candidates.")

    if not all_candidates:
        # No AI candidate survived - but the deterministic BFS attack paths are the
        # cheapest, most valuable output and must still ship. Skip only the AI phases.
        log("No AI candidates; emitting deterministic attack paths + chokepoints only.")
        return _finalize_deterministic(result, fact_pack, log)

    # ── Build payloads for Phases 3 + 4 ─────────────────────────────────────
    #
    # Correlator (Phase 3): uses a purpose-built minimal context derived solely
    # from entities already referenced in the confirmed findings plus tier-0.
    # This is O(findings × entities) - bounded regardless of tenant size.
    #
    # Skeptic (Phase 4): uses the stripped fact pack (bulk inventory tables
    # removed) further capped at 800 K chars (~200 K tokens) so a single
    # skeptic call always fits inside Sonnet's 200 K-token context window.
    correlator_json = _correlator_context(fact_pack, all_candidates)

    _BULK_SECTIONS = frozenset({
        "subscription_rbac_all",       # sub-level RBAC assignments (can be 80 k+ entries)
        "entra_role_all",              # all Entra directory role assignments
        "service_principal_inventory", # raw SP list
    })
    full_payload   = fact_pack.to_prompt_dict(domain=None)
    stripped       = {k: v for k, v in full_payload.items() if k not in _BULK_SECTIONS}
    fact_pack_json = _budget_json(stripped, max_chars=800_000)  # hard 200 K-token cap

    # ── Phase 3: Opus correlator - multi-step attack chains ──────────────────
    log(f"Phase 3: Correlation agent ({opus_model}) - finding multi-step attack chains…")
    # Real escalation edges, so a chain hop can be verified against the graph rather
    # than trusted. Only a HARD reject when the edge set is complete (not truncated).
    known_edges = {(_endpoint_id(e.get("src")), _endpoint_id(e.get("dst")))
                   for e in fact_pack.escalation_edges
                   if _endpoint_id(e.get("src")) and _endpoint_id(e.get("dst"))}
    edges_complete = not fact_pack.truncated.get("escalation_edges")
    chains_raw, chain_rejected = _run_correlator(
        client, opus_model, correlator_json, all_candidates, known, max_tokens, on_progress,
        known_edges=known_edges, edges_complete=edges_complete, trace=trace)
    result.rejected.extend(chain_rejected)
    chain_findings_list = [_chain_to_finding(c, fact_pack) for c in chains_raw]
    if chain_findings_list:
        log(f"  {len(chain_findings_list)} attack chain(s) found.")
    else:
        log("  No multi-step chains found.")

    # ── Phase 4: Haiku skeptic - Critical/High + clustered-entity Medium/Low ──
    # Count how many findings each entity appears in across the full candidate set.
    # An entity in 3+ findings is "hot" - Medium/Low findings referencing it go to
    # the skeptic so chained lower-severity risks can't bypass review.
    _entity_count: dict[str, int] = {}
    for _f in all_candidates + chains_raw:
        for _ent in _f.get("entities") or []:
            _eid = _ent.get("id") if isinstance(_ent, dict) else _ent
            if _eid:
                _entity_count[_eid] = _entity_count.get(_eid, 0) + 1
    hot_entities = {eid for eid, n in _entity_count.items() if n >= 3}

    def _has_hot(f: dict) -> bool:
        return any(
            (ent.get("id") if isinstance(ent, dict) else ent) in hot_entities
            for ent in (f.get("entities") or [])
        )

    high_regular = [f for f in all_candidates if f.get("severity") in ("Critical", "High")]
    lower_hot    = [f for f in all_candidates
                    if f.get("severity") not in ("Critical", "High") and _has_hot(f)]
    lower_cold   = [f for f in all_candidates
                    if f.get("severity") not in ("Critical", "High") and not _has_hot(f)]
    high_chains  = [c for c in chains_raw if c.get("severity") in ("Critical", "High")]
    low_chains   = [c for c in chains_raw if c.get("severity") not in ("Critical", "High")]

    skeptic_targets = high_regular + lower_hot + high_chains

    # Build entity → all-findings cluster map so lower_hot findings get cluster context.
    # The skeptic needs to know it's reviewing one of N findings about the same entity.
    _entity_to_cluster: dict[str, list[dict]] = {}
    if lower_hot:
        for _eid in hot_entities:
            _cluster = [
                _f for _f in all_candidates + chains_raw
                if any(
                    ((_e.get("id") if isinstance(_e, dict) else _e) == _eid)
                    for _e in (_f.get("entities") or [])
                )
            ]
            if _cluster:
                _entity_to_cluster[_eid] = _cluster

    if skeptic_targets:
        hot_note = f", {len(lower_hot)} lower-sev clustered" if lower_hot else ""
        # Batch the skeptic by CATEGORY (fact pack sent once per batch, not per finding),
        # preserving each category's adversarial focus lens. One call per category (chunked
        # at 12) instead of one per finding - ~107 calls collapse to ~a dozen.
        _CHUNK = 12
        # Tag each target with kind (regular/chain) and a compact cluster note for lower_hot.
        _kinds: dict = {}
        _cluster_notes: dict = {}
        for f in high_regular:
            _kinds[id(f)] = "regular"
        for f in lower_hot:
            _kinds[id(f)] = "regular"
            hot_eids = [(_e.get("id") if isinstance(_e, dict) else _e)
                        for _e in (f.get("entities") or [])
                        if (_e.get("id") if isinstance(_e, dict) else _e) in hot_entities]
            n = len(_entity_to_cluster.get(hot_eids[0], [])) if hot_eids else 0
            if n > 1:
                _cluster_notes[id(f)] = (f"(1 of {n} findings on a shared hot entity - chained "
                                         f"lower-severity risks can combine into a higher one)")
        for c in high_chains:
            _kinds[id(c)] = "chain"
        # Group by category, then chunk.
        by_cat: dict = {}
        for f in skeptic_targets:
            by_cat.setdefault(f.get("category", ""), []).append(f)
        batches: list[list[dict]] = []
        for cat, fs in by_cat.items():
            for i in range(0, len(fs), _CHUNK):
                batches.append(fs[i:i + _CHUNK])
        log(f"Phase 4: Skeptic pass on {len(skeptic_targets)} finding(s) "
            f"({len(high_regular) + len(high_chains)} Critical/High{hot_note}) in "
            f"{len(batches)} batch(es) ({haiku_model})…")
        vetted_regular: list[dict] = []
        vetted_chains:  list[dict] = []
        with ThreadPoolExecutor(max_workers=min(6, len(batches))) as pool:
            fut_map = {
                pool.submit(_run_skeptic_batch, client, haiku_model, fact_pack_json, batch,
                            focus=_SKEPTIC_FOCUS_BY_CATEGORY.get(batch[0].get("category", ""), ""),
                            cluster_notes=_cluster_notes, trace=trace): batch
                for batch in batches
            }
            for fut in as_completed(fut_map):
                batch = fut_map[fut]
                outcomes = fut.result()
                for src, outcome in zip(batch, outcomes):
                    if outcome is None:
                        result.skeptic_dropped += 1
                    elif _kinds.get(id(src)) == "chain":
                        vetted_chains.append(outcome)
                    else:
                        vetted_regular.append(outcome)

        if result.skeptic_dropped:
            log(f"  Skeptic dropped {result.skeptic_dropped} finding(s).")
        high_regular = vetted_regular   # contains survived high + survived lower_hot
        high_chains  = vetted_chains

    # ── Drop non-assessable-domain findings ───────────────────────────────────
    # Remove any finding that is purely about a domain AzureHound cannot collect
    # (MFA, CA, sign-in logs, NSG, encryption, diagnostic logging). These findings
    # cannot be confirmed from the fact pack and are misleading in the report.
    _na_before = len(high_regular) + len(lower_cold)
    _track_b = bool(fact_pack.external_exposure)
    high_regular = [f for f in high_regular if not _is_non_assessable_finding(f, _track_b)]
    lower_cold   = [f for f in lower_cold   if not _is_non_assessable_finding(f, _track_b)]
    result.non_assessable_dropped = _na_before - (len(high_regular) + len(lower_cold))
    if result.non_assessable_dropped:
        log(f"  Suppressed {result.non_assessable_dropped} finding(s) about non-assessable domains.")

    # ── Normalise, merge, sort ────────────────────────────────────────────────
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    normalised  = [_normalise(f, fact_pack, signal_context) for f in (high_regular + lower_cold)]
    norm_chains = ([_chain_to_finding(c, fact_pack) for c in high_chains] +
                   [_chain_to_finding(c, fact_pack) for c in low_chains])
    all_findings = normalised + norm_chains
    # Drop findings that have no entities AND no meaningful text - these are
    # incomplete model outputs that provide nothing actionable to the analyst.
    _before_empty = len(all_findings)
    all_findings = [
        f for f in all_findings
        if f.get("entities")
        or (f.get("summary") or f.get("what") or f.get("why_it_matters") or "").strip()
    ]
    _empty_dropped = _before_empty - len(all_findings)
    if _empty_dropped:
        log(f"  Dropped {_empty_dropped} finding(s) with no entities and no description.")
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "Info"), 5))
    result.findings            = all_findings
    result.chain_findings_count = len(norm_chains)

    return _finalize_deterministic(result, fact_pack, log)
