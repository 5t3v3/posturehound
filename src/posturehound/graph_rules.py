"""Identity-config rules over Microsoft Graph data (PostureHound v2, Track B).

Tenant-level analysis of Conditional Access posture and security defaults -
the identity-plane controls AzureHound and Resource Graph cannot see. Each rule
follows the same discipline as the rest of the codebase: it fires only on a
confirmed weakness, treats not-collected as UNCONFIRMED (never a clean pass), and
respects mitigating controls (security defaults enforce MFA, so a tenant using
them is not flagged for missing CA-based MFA).

run_graph_rules(GraphResult) -> (finding_dicts, not_assessed), matching the
deterministic finding dict shape.
"""
from __future__ import annotations

_TIER = "Privileged Identity"


def _ent(id_, name, **evidence):
    return {"id": id_, "name": name, "kind": "Identity Configuration", "evidence": evidence}


def _finding(rule_id, title, severity, entities, description, remediation, detail):
    return {
        "source": "deterministic", "rule_id": rule_id, "title": title,
        "severity": severity, "category": _TIER, "best_practice": False,
        "entities": entities, "affected_count": len(entities),
        "what": description, "why_it_matters": detail.get("why", description),
        "attack_scenario": detail.get("scenario", ""), "escalation_chain": [], "evidence": [],
        "remediation": remediation, "detection": detail.get("detection", ""),
        "detail": detail, "references": [], "frameworks": detail.get("frameworks", {}),
    }


def _enabled_policies(gr):
    return [p for p in gr.ca_policies if str(p.get("state", "")).lower() == "enabled"]


def _requires_mfa(policy) -> bool:
    gc = policy.get("grantControls") or {}
    controls = [str(c).lower() for c in (gc.get("builtInControls") or [])]
    if "mfa" in controls:
        return True
    # Modern policies require MFA through an *authentication strength* rather than
    # the built-in 'mfa' control. Any authentication strength is MFA-or-stronger, so
    # a policy that sets one is enforcing MFA. Missing this read the built-in control
    # alone and falsely reported "MFA not enforced" on tenants using auth strengths.
    strength = gc.get("authenticationStrength")
    if isinstance(strength, dict) and (strength.get("id") or strength.get("displayName")):
        return True
    return False


def _is_tenant_wide(policy) -> bool:
    """A policy only enforces its control TENANT-WIDE if it targets all users and all
    cloud apps. A policy scoped to one app or a handful of users must not be read as
    tenant-wide protection, otherwise a narrow MFA policy silently suppresses the
    'MFA not enforced' finding."""
    cond = policy.get("conditions") or {}
    inc_users = [str(x).lower() for x in ((cond.get("users") or {}).get("includeUsers") or [])]
    inc_apps = [str(x).lower() for x in
                ((cond.get("applications") or {}).get("includeApplications") or [])]
    return "all" in inc_users and "all" in inc_apps


def _blocks_legacy(policy) -> bool:
    cond = policy.get("conditions") or {}
    client_types = [str(c).lower() for c in (cond.get("clientAppTypes") or [])]
    legacy = {"exchangeactivesync", "other"}
    gc = policy.get("grantControls") or {}
    blocks = "block" in [str(c).lower() for c in (gc.get("builtInControls") or [])]
    return blocks and bool(legacy & set(client_types)) and _is_tenant_wide(policy)


def _user_consent_state(pol) -> "tuple[bool, list, str]":
    """Classify the tenant's user-application-consent setting from authorizationPolicy.
    Returns (restricted, permissionGrantPoliciesAssigned, human label). Restricted means ordinary
    users either cannot consent at all, or only to low-impact permissions from verified publishers
    (microsoft-user-default-low), the CIS 1.11 pass states. Anything else (the legacy 'consent to
    all apps' policy, or a custom policy) is treated as unrestricted and surfaced for review."""
    dur = (pol or {}).get("defaultUserRolePermissions") or {}
    assigned = dur.get("permissionGrantPoliciesAssigned") or []
    self_grants = [a for a in assigned if str(a).startswith("ManagePermissionGrantsForSelf.")]
    if not self_grants:
        return True, assigned, "users cannot consent to applications"
    if all(a == "ManagePermissionGrantsForSelf.microsoft-user-default-low" for a in self_grants):
        return True, assigned, "users may consent only to low-impact permissions from verified publishers"
    if any(a == "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" for a in self_grants):
        return False, assigned, "users may consent to ALL applications (legacy, unrestricted)"
    return False, assigned, "a custom user-consent policy is assigned, verify it is restrictive"


def run_graph_rules(gr) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    not_assessed: list[dict] = []
    if gr is None:
        return findings, not_assessed

    ca_ok = gr.collected.get("conditionalAccess")
    sd_ok = gr.collected.get("securityDefaults")
    enabled = _enabled_policies(gr) if ca_ok else []
    # Security defaults enforce MFA AND block legacy auth tenant-wide, so a tenant
    # using them must not be flagged for either being "not enforced".
    sd_on = gr.security_defaults_enabled is True

    # ---- IDG-001: MFA not enforced tenant-wide -----------------------------
    if ca_ok or sd_ok:
        # Only a TENANT-WIDE MFA policy counts, one scoped to a single app or a few
        # users does not mean MFA is enforced for everyone (and must not suppress this).
        mfa_policy = any(_requires_mfa(p) and _is_tenant_wide(p) for p in enabled) if ca_ok else False
        if sd_on or mfa_policy:
            pass  # MFA is enforced by security defaults or a CA policy, good.
        elif ca_ok and sd_ok:
            findings.append(_finding(
                "IDG-001", "Multi-factor authentication is not enforced tenant-wide", "High",
                [_ent("mfa-enforcement", "MFA enforcement", confirmed=True,
                      security_defaults="disabled",
                      note="no enabled Conditional Access policy requires MFA and security "
                           "defaults are off")],
                "Neither security defaults nor any enabled Conditional Access policy requires "
                "multi-factor authentication, so accounts, including administrators, can sign "
                "in with a password alone.",
                "Enable a Conditional Access policy requiring MFA for all users (at minimum for "
                "privileged roles), or enable security defaults for smaller tenants.",
                {"summary": "MFA is not enforced for sign-in.",
                 "why": "Without MFA a single phished or sprayed password is a full account "
                        "takeover. It is the highest-leverage identity control and its absence "
                        "underlies most cloud-identity compromises.",
                 "scenario": "An attacker phishes or password-sprays a user; with no MFA the "
                             "password alone grants access, and if the account is privileged it "
                             "is immediate escalation.",
                 "impact": "Password-only compromise of any account, including admins.",
                 "steps": ["Create a Conditional Access policy requiring MFA for all users.",
                           "At minimum require MFA for all privileged directory roles.",
                           "For small tenants without CA licensing, enable security defaults."],
                 "detection": "Microsoft Graph: no enabled conditionalAccess policy with "
                              "grantControls.builtInControls containing 'mfa', and "
                              "identitySecurityDefaultsEnforcementPolicy.isEnabled == false.",
                 "frameworks": {"CIS Azure": "1.1.x", "MITRE ATT&CK": "T1078", "Azure Threat Matrix": "AZT202"}}))
        else:
            not_assessed.append({"rule_id": "IDG-001",
                                 "title": "MFA enforcement", "reason": "partial Graph data "
                                 "(Conditional Access or security defaults not collected)",
                                 "needs": ["Microsoft Graph: Policy.Read.All"]})
    else:
        not_assessed.append({"rule_id": "IDG-001", "title": "MFA enforcement",
                             "reason": "Microsoft Graph not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})

    # ---- IDG-002: legacy authentication not blocked ------------------------
    # Security defaults block legacy auth, so don't fire when they are on (this was a
    # false positive: a tenant with defaults ON but no CA policy was flagged).
    if ca_ok and not sd_on:
        if not any(_blocks_legacy(p) for p in enabled):
            findings.append(_finding(
                "IDG-002", "Legacy authentication is not blocked", "Medium",
                [_ent("legacy-auth", "Legacy authentication", confirmed=True,
                      note="no enabled Conditional Access policy blocks legacy auth clients")],
                "No enabled Conditional Access policy blocks legacy authentication protocols "
                "(POP, IMAP, SMTP, older Office, Exchange ActiveSync). Legacy auth cannot enforce "
                "MFA, so it is the standard bypass attackers use against password-spray defences.",
                "Create a Conditional Access policy that blocks legacy authentication clients for "
                "all users.",
                {"summary": "Legacy authentication protocols are not blocked.",
                 "why": "Legacy auth clients cannot perform MFA, so they are the route attackers "
                        "use to defeat MFA and lockout controls with password spraying.",
                 "scenario": "An attacker sprays passwords against a legacy endpoint (IMAP/SMTP), "
                             "which never prompts for MFA, and authenticates with a valid password.",
                 "impact": "MFA and modern-auth controls are bypassable via legacy protocols.",
                 "steps": ["Create a CA policy blocking legacy authentication for all users.",
                           "Roll it out in report-only first to find dependent apps.",
                           "Migrate any legitimate legacy clients to modern auth."],
                 "detection": "Microsoft Graph: no enabled conditionalAccess policy with a block "
                              "control covering clientAppTypes 'exchangeActiveSync'/'other'. "
                              "Review sign-in logs for legacy-auth sign-ins.",
                 "frameworks": {"CIS Azure": "1.x", "MITRE ATT&CK": "T1110.003", "Azure Threat Matrix": "AZT202"}}))
    else:
        not_assessed.append({"rule_id": "IDG-002", "title": "Legacy authentication blocking",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})

    # ---- IDG-003: CA policies present but not enforcing --------------------
    if ca_ok:
        # Anything that is not explicitly "enabled" is not actually enforcing -
        # includes disabled, report-only, and any unrecognised/future state, which
        # is surfaced for review rather than silently assumed to be enforcing.
        inactive = [p for p in gr.ca_policies
                    if str(p.get("state", "")).lower() != "enabled"]
        if inactive:
            findings.append(_finding(
                "IDG-003", "Conditional Access policies exist but are not enforced", "Low",
                [_ent(p.get("id", "?"), p.get("displayName", p.get("id", "?")),
                      confirmed=True, state=p.get("state"),
                      note=f"policy state is '{p.get('state')}', not enforcing")
                 for p in inactive],
                "One or more Conditional Access policies are disabled or in report-only mode, so "
                "the protection they describe is not actually applied. Report-only is appropriate "
                "for staging, but a long-lived report-only or disabled policy is a control that "
                "looks present but does nothing.",
                "Review each non-enforcing policy: enable the ones that should protect the tenant, "
                "and remove or document the ones intentionally left off.",
                {"summary": "Conditional Access policies are disabled or report-only.",
                 "why": "A policy that is not enforced provides no protection while giving a false "
                        "impression of coverage; attackers are unaffected by a report-only rule.",
                 "scenario": "An admin believes MFA/legacy-auth controls are in place, but the "
                             "relevant policy is report-only, so the attack it was meant to stop "
                             "still succeeds.",
                 "impact": "Believed controls are not actually applied.",
                 "steps": ["Enable policies that should be enforcing.",
                           "Remove or document intentionally-disabled policies.",
                           "Keep report-only only for short staging windows."],
                 "detection": "Microsoft Graph: conditionalAccess policies with state 'disabled' "
                              "or 'enabledForReportingButNotEnforced'.",
                 "frameworks": {"Best Practice": "Control enforcement"}}))

    # ---- IDG-004: no baseline identity protection at all -------------------
    if ca_ok and sd_ok:
        if not gr.ca_policies and gr.security_defaults_enabled is not True:
            findings.append(_finding(
                "IDG-004", "The tenant has no baseline identity protection", "High",
                [_ent("baseline", "Identity baseline", confirmed=True,
                      note="no Conditional Access policies and security defaults are off")],
                "There are no Conditional Access policies and security defaults are disabled, so "
                "the tenant enforces no MFA, no legacy-auth blocking and no risk-based controls "
                "for any user. Sign-in is password-only for everyone, including administrators.",
                "Enable security defaults immediately (small tenants) or build a Conditional "
                "Access baseline requiring MFA and blocking legacy auth (licensed tenants).",
                {"summary": "No Conditional Access policies exist and security defaults are off.",
                 "why": "The tenant has no identity-security baseline whatsoever. Every account, "
                        "including Global Administrators, can sign in with a password alone, and "
                        "legacy protocols that bypass MFA are open. This is the weakest possible "
                        "identity posture.",
                 "scenario": "An attacker password-sprays or phishes any account and signs in with "
                             "no second factor; an admin account is immediate tenant takeover.",
                 "impact": "Password-only access to the entire tenant, admins included.",
                 "steps": ["Enable security defaults now if unlicensed for Conditional Access.",
                           "Otherwise build a CA baseline: require MFA for all users, block legacy "
                           "auth, and require MFA for admins with no exclusions.",
                           "Verify break-glass accounts before enforcing."],
                 "detection": "Microsoft Graph: zero conditionalAccess policies and "
                              "identitySecurityDefaultsEnforcementPolicy.isEnabled == false.",
                 "frameworks": {"CIS Azure": "1.1.x", "MITRE ATT&CK": "T1078", "Azure Threat Matrix": "AZT202"}}))

    # ---- IDG-005: user consent to applications not restricted (CIS 1.11) -----
    ap_ok = gr.collected.get("authorizationPolicy")
    if ap_ok and gr.authorization_policy is not None:
        restricted, assigned, label = _user_consent_state(gr.authorization_policy)
        if not restricted:
            findings.append(_finding(
                "IDG-005", "User consent to applications is not restricted", "Medium",
                [_ent("user_consent", "User application consent", confirmed=True,
                      permissionGrantPoliciesAssigned=assigned, note=label)],
                "Ordinary (non-admin) users can grant applications access to organisational data on "
                "their own behalf: " + label + ". This is the illicit-consent / OAuth-phishing "
                "surface, a user tricked into approving a malicious application hands it their "
                "Microsoft Graph permissions with no admin review.",
                "Restrict user consent to verified publishers and low-impact permissions "
                "(microsoft-user-default-low), or disable user consent entirely and route all "
                "application consent through an admin-consent request workflow.",
                {"summary": "Users can consent to applications without admin review (" + label + ").",
                 "why": "User consent lets any employee grant an app access to data in their context "
                        "without an administrator ever seeing it. It is the primary vector for "
                        "OAuth consent-phishing: the attacker never steals a password or trips MFA, "
                        "the victim simply approves a convincing app.",
                 "scenario": "An attacker sends an OAuth consent-phishing link for a malicious "
                             "multi-tenant app requesting Mail.Read / Files.Read. A user approves "
                             "it; the app now reads their mailbox and files via Graph with a "
                             "long-lived token, no credential theft and no admin visibility.",
                 "impact": "Illicit application consent: organisational data handed to "
                           "attacker-controlled apps by ordinary users, invisible to admins.",
                 "steps": ["Entra ID > Enterprise applications > Consent and permissions > User "
                           "consent settings: choose 'Allow user consent for apps from verified "
                           "publishers, for selected permissions' or disable user consent.",
                           "Enable the admin-consent request workflow so users request and admins "
                           "approve app access.",
                           "Review existing user-consented grants (oauth2PermissionGrants) for "
                           "anything unexpected."],
                 "detection": "Microsoft Graph /policies/authorizationPolicy: "
                              "defaultUserRolePermissions.permissionGrantPoliciesAssigned is empty "
                              "or only 'microsoft-user-default-low' when restricted; a legacy or "
                              "custom ManagePermissionGrantsForSelf policy means user consent is open.",
                 "frameworks": {"CIS Azure": "1.11", "MITRE ATT&CK": "T1528", "Azure Threat Matrix": "AZT501"}}))
    elif ap_ok is False:
        not_assessed.append({"rule_id": "IDG-005", "title": "User consent to applications",
                             "reason": "authorization policy not collected (grant the SP Policy.Read.All)",
                             "needs": ["Microsoft Graph authorizationPolicy"]})

    return findings, not_assessed


# Static catalog of the MS-Graph (identity-config) rules, for the Rule Library viewer. These are
# emitted inline by run_graph_rules (they depend on collected CA/security-defaults data), so this
# list mirrors their metadata for the catalog. Keep in sync with the emitters above.
GRAPH_RULES_CATALOG = [
    {"id": "IDG-001", "title": "Multi-factor authentication is not enforced tenant-wide",
     "severity": "High", "category": "Privileged Identity", "best_practice": False,
     "description": "Neither security defaults nor any enabled Conditional Access policy requires MFA for users, so accounts (including admins) can sign in with a password alone.",
     "remediation": "Require MFA via a Conditional Access policy for all users (at minimum, all privileged roles), or enable security defaults for smaller tenants.",
     "frameworks": {"CIS Azure": "1.1.1", "MITRE ATT&CK": "T1078", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-002", "title": "Legacy authentication is not blocked",
     "severity": "Medium", "category": "Privileged Identity", "best_practice": False,
     "description": "No control blocks legacy authentication protocols (which cannot enforce MFA), leaving an MFA-bypass path open.",
     "remediation": "Block legacy authentication with a Conditional Access policy, or enable security defaults.",
     "frameworks": {"CIS Azure": "1.1.2", "MITRE ATT&CK": "T1110.003", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-003", "title": "Conditional Access policies exist but are not enforced",
     "severity": "Low", "category": "Best Practice", "best_practice": True,
     "description": "Conditional Access policies are present but disabled or report-only, so they provide no active protection.",
     "remediation": "Move validated Conditional Access policies from report-only to enabled.",
     "frameworks": {"CIS Azure": "1.1.x", "Best Practice": "Control enforcement"}},
    {"id": "IDG-004", "title": "The tenant has no baseline identity protection",
     "severity": "High", "category": "Privileged Identity", "best_practice": False,
     "description": "No Conditional Access policies exist and security defaults are off, the weakest possible identity posture.",
     "remediation": "Enable security defaults, or build a Conditional Access baseline requiring MFA and blocking legacy auth.",
     "frameworks": {"CIS Azure": "1.1.1", "MITRE ATT&CK": "T1078", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-005", "title": "User consent to applications is not restricted",
     "severity": "Medium", "category": "Applications & Service Principals", "best_practice": False,
     "description": "Ordinary users can grant applications access to organisational data without admin review, the illicit-consent / OAuth consent-phishing surface.",
     "remediation": "Restrict user consent to verified publishers and low-impact permissions, or disable it and use an admin-consent request workflow.",
     "frameworks": {"CIS Azure": "1.11", "MITRE ATT&CK": "T1528", "Azure Threat Matrix": "AZT501"}},
]
