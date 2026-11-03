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


def _priv_role_template_ids() -> "set[str]":
    """Privileged Entra directory-role template GUIDs (lowercased). Conditional Access targets
    admins by these template ids in includeRoles / excludeRoles."""
    from . import constants as C
    return {str(k).lower() for k in C.PRIVILEGED_ENTRA_ROLE_TEMPLATES}


def _critical_role_template_ids() -> "set[str]":
    """The critical Tier-0 role template GUIDs (Global Admin, Privileged Role Admin, ...)."""
    from . import constants as C
    crit = {n.lower() for n in C.CRITICAL_ENTRA_ROLE_NAMES}
    return {str(tid).lower() for tid, name in C.TIER0_ENTRA_ROLE_TEMPLATES.items()
            if str(name).lower() in crit}


def _covers_admins(policy, priv: "set[str]") -> bool:
    """True when the policy's scope actually reaches administrators for all cloud apps: it
    targets all users (admins included) OR a privileged directory role, AND applies to all
    cloud applications. A policy scoped to a single app does not protect admin sign-in generally."""
    cond = policy.get("conditions") or {}
    users = cond.get("users") or {}
    inc_users = [str(x).lower() for x in (users.get("includeUsers") or [])]
    inc_roles = {str(x).lower() for x in (users.get("includeRoles") or [])}
    apps = cond.get("applications") or {}
    inc_apps = [str(x).lower() for x in (apps.get("includeApplications") or [])]
    user_match = ("all" in inc_users) or bool(inc_roles & priv)
    return user_match and ("all" in inc_apps)


def _excludes_admins(policy, crit: "set[str]") -> bool:
    """True when the policy carves privileged roles OUT of its scope via excludeRoles, so the
    admins it appears to cover can actually sign in without the control. (A single break-glass
    account is normally excluded by excludeUsers, which we cannot resolve and so never flag.)"""
    users = (policy.get("conditions") or {}).get("users") or {}
    exc_roles = {str(x).lower() for x in (users.get("excludeRoles") or [])}
    return bool(exc_roles & crit)


def _requires_compliant_device(policy) -> bool:
    """True when the policy requires a compliant (Intune-managed) or hybrid-joined device."""
    gc = policy.get("grantControls") or {}
    controls = {str(c).lower() for c in (gc.get("builtInControls") or [])}
    return bool(controls & {"compliantdevice", "domainjoineddevice"})


def _is_risk_based(policy) -> bool:
    """True when the policy conditions on Identity Protection sign-in risk or user risk."""
    cond = policy.get("conditions") or {}
    return bool(cond.get("signInRiskLevels") or cond.get("userRiskLevels"))


def _blocks(policy) -> bool:
    gc = policy.get("grantControls") or {}
    return "block" in [str(c).lower() for c in (gc.get("builtInControls") or [])]


def _conditions_on_location(policy) -> bool:
    """True when the policy actually conditions on named locations / geography, i.e. it names
    specific include locations beyond the implicit 'all', or carves out excluded locations."""
    loc = (policy.get("conditions") or {}).get("locations") or {}
    inc = [str(x).lower() for x in (loc.get("includeLocations") or [])]
    exc = [str(x).lower() for x in (loc.get("excludeLocations") or [])]
    return bool(exc) or bool([x for x in inc if x not in ("", "all")])


def _blocks_device_code(policy) -> bool:
    """True when the policy blocks the device-code authentication flow. transferMethods is a
    comma-separated string (Graph) or a list depending on the API surface."""
    af = (policy.get("conditions") or {}).get("authenticationFlows") or {}
    tm = af.get("transferMethods")
    methods = ([m.strip().lower() for m in tm.split(",")] if isinstance(tm, str)
               else [str(m).lower() for m in (tm or [])])
    return "devicecodeflow" in methods and _blocks(policy)


def _targets_app(policy, appid: str) -> bool:
    apps = (policy.get("conditions") or {}).get("applications") or {}
    inc = [str(x).lower() for x in (apps.get("includeApplications") or [])]
    return appid.lower() in inc or "all" in inc


def _targets_user_action(policy, action: str) -> bool:
    apps = (policy.get("conditions") or {}).get("applications") or {}
    actions = [str(x).lower() for x in (apps.get("includeUserActions") or [])]
    return action.lower() in actions


def _ca_detail_finding(rid, title, cis, note, description, remediation,
                       why, scenario, impact, steps, detection, attack="T1078.004"):
    """Build a Low-severity identity-config finding for a specific-Conditional-Access control."""
    return _finding(
        rid, title, "Low",
        [_ent(rid.lower(), title, confirmed=True, note=note)],
        description, remediation,
        {"summary": title + ".", "why": why, "scenario": scenario, "impact": impact,
         "steps": steps, "detection": detection,
         "frameworks": {"CIS Azure": cis, "MITRE ATT&CK": attack, "Azure Threat Matrix": "AZT202"}})


# Well-known Conditional Access targets (stable Microsoft identifiers).
_AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"   # Microsoft Azure Management
_ADMIN_PORTALS_APP = "microsoftadminportals"                   # CA special target value
_REGISTER_DEVICE_ACTION = "urn:user:registerdevice"


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

    # ---- IDG-010: administrators not covered by an MFA Conditional Access policy ----
    # Distinct from IDG-001 (no MFA for ANYONE): this is the subtler, very common gap where MFA
    # IS configured but administrators are not actually protected - the policy is scoped to a
    # single app / a subset of users (so admins aren't included), or privileged roles are
    # explicitly excluded. Only fires when at least one enabled MFA policy exists (otherwise
    # IDG-001 owns the "no MFA at all" case) and security defaults are off.
    if ca_ok and not sd_on:
        priv = _priv_role_template_ids()
        crit = _critical_role_template_ids()
        mfa_enabled = [p for p in enabled if _requires_mfa(p)]
        admin_covered = any(_covers_admins(p, priv) and not _excludes_admins(p, crit)
                            for p in mfa_enabled)
        if mfa_enabled and not admin_covered:
            excluded = any(_excludes_admins(p, crit) for p in mfa_enabled)
            why = ("privileged roles are explicitly excluded from the MFA policy"
                   if excluded else
                   "no enabled MFA policy covers administrators for all cloud apps "
                   "(the MFA policies are scoped to specific apps or a subset of users)")
            findings.append(_finding(
                "IDG-010", "Administrators are not covered by MFA", "High",
                [_ent("admin-mfa", "Administrator MFA coverage", confirmed=True,
                      enabled_mfa_policies=[p.get("displayName", p.get("id", "?")) for p in mfa_enabled],
                      note=why)],
                "Multi-factor authentication is configured in the tenant, but no enabled Conditional "
                "Access policy actually enforces it for administrators: " + why + ". Administrators "
                "are the highest-value accounts, so an MFA baseline that does not cover them leaves "
                "the most dangerous sign-ins protected by password alone.",
                "Add (or widen) a Conditional Access policy that requires MFA for all privileged "
                "directory roles across all cloud apps, and remove any admin-role exclusions.",
                {"summary": "MFA exists but does not cover administrators.",
                 "why": "Admins are the accounts worth attacking. If the MFA baseline is scoped so "
                        "that privileged roles are not included, or explicitly excludes them, a "
                        "phished or sprayed admin password is a full compromise despite MFA being "
                        "'enabled' in the tenant.",
                 "scenario": "An attacker password-sprays a Global Administrator. MFA is configured "
                             "for a line-of-business app but the admin's sign-in is out of scope (or "
                             "the GA role is excluded), so the password alone succeeds.",
                 "impact": "Privileged accounts can sign in with a password alone despite MFA existing.",
                 "steps": ["Create a Conditional Access policy requiring MFA for all privileged "
                           "directory roles, targeting All cloud apps.",
                           "Remove privileged roles from any excludeRoles on MFA policies.",
                           "Keep only break-glass accounts excluded, via excludeUsers, and monitor them."],
                 "detection": "Microsoft Graph conditionalAccess policies: no enabled MFA policy "
                              "whose users include All (or a privileged role) and applications include "
                              "All without excluding privileged roles.",
                 "frameworks": {"CIS Azure": "1.1.3", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}}))

    # ---- IDG-011: admins not required to use a compliant/managed device ----
    # A hardening layer beyond MFA: privileged sign-in should require a compliant or hybrid-joined
    # device, so a phished admin credential cannot be replayed from an attacker's machine. Fires
    # only when admin CA already exists (an enabled policy covers admins) but none requires a
    # managed device - so it is the 'you have admin CA, add device compliance' refinement, not a
    # duplicate of IDG-010.
    if ca_ok and not sd_on:
        priv = _priv_role_template_ids()
        admin_policies = [p for p in enabled if _covers_admins(p, priv)]
        if admin_policies and not any(_requires_compliant_device(p) for p in admin_policies):
            findings.append(_finding(
                "IDG-011", "Administrator sign-in does not require a managed device", "Medium",
                [_ent("admin-device", "Administrator device compliance", confirmed=True,
                      note="no Conditional Access policy covering admins requires a compliant or "
                           "hybrid-joined device")],
                "Conditional Access covers administrators, but no policy requires their sign-in to come "
                "from a compliant (Intune-managed) or hybrid-joined device. A phished or stolen admin "
                "credential (plus an MFA token relay) can then be used from any attacker-controlled "
                "machine; a device requirement ties privileged access to hardware the organisation "
                "manages.",
                "Add a Conditional Access grant requiring a compliant or hybrid Entra-joined device "
                "for all privileged directory roles.",
                {"summary": "Admins are not required to sign in from a managed device.",
                 "why": "MFA alone does not bind a session to trusted hardware. Requiring a managed "
                        "device for admins stops credential/token replay from an attacker's own "
                        "machine, raising the bar on the most valuable accounts.",
                 "scenario": "An attacker phishes an admin and relays the MFA prompt, then signs in "
                             "from their own host; a device-compliance grant would have blocked it.",
                 "impact": "Privileged access is not bound to organisation-managed hardware.",
                 "steps": ["Add a CA grant 'Require device to be marked as compliant' OR 'Require "
                           "hybrid Azure AD joined device' for all privileged roles.",
                           "Validate admin workstations are enrolled before enforcing."],
                 "detection": "Microsoft Graph conditionalAccess: no enabled policy covering admins "
                              "with grantControls.builtInControls containing compliantDevice/domainJoinedDevice.",
                 "frameworks": {"CIS Azure": "1.x", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}}))

    # ---- IDG-012: no risk-based Conditional Access (Identity Protection not enforced) ----
    if ca_ok and not sd_on:
        if not any(_is_risk_based(p) for p in enabled):
            findings.append(_finding(
                "IDG-012", "No risk-based Conditional Access policy", "Medium",
                [_ent("risk-ca", "Risk-based Conditional Access", confirmed=True,
                      note="no enabled policy keys on sign-in risk or user risk")],
                "No enabled Conditional Access policy acts on Entra Identity Protection risk: there is "
                "no policy conditioned on sign-in risk or user risk (to force MFA, a password change, "
                "or block). Risk signals (impossible travel, leaked credentials, anonymous IP, "
                "token-replay heuristics) are therefore computed but never enforced, so a detected "
                "compromise triggers no automatic control.",
                "Create Conditional Access policies that require MFA on medium/high sign-in risk and a "
                "secure password change on high user risk (requires Entra ID P2).",
                {"summary": "Identity Protection risk is not enforced by any Conditional Access policy.",
                 "why": "Identity Protection detects compromise (leaked creds, impossible travel, "
                        "anonymous/TOR sign-ins). Without a risk-based CA policy those detections are "
                        "informational only, the attacker is not challenged or blocked in real time.",
                 "scenario": "Identity Protection flags a sign-in as high-risk (leaked credential), but "
                             "with no risk-based policy the sign-in proceeds and the account is used.",
                 "impact": "Detected account compromise triggers no automatic containment.",
                 "steps": ["Create a CA policy: sign-in risk medium+ requires MFA.",
                           "Create a CA policy: user risk high requires secure password change.",
                           "Requires Entra ID P2 licensing for the risk conditions."],
                 "detection": "Microsoft Graph conditionalAccess: no enabled policy with "
                              "conditions.signInRiskLevels or conditions.userRiskLevels set.",
                 "frameworks": {"CIS Azure": "1.2.x", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}}))

    # ---- IDG-013: no exclusionary geographic access policy (CIS 2.2.2) ------
    if not ca_ok:
        not_assessed.append({"rule_id": "IDG-013", "title": "Geographic access policy",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})
    elif not any(_conditions_on_location(p) for p in enabled):
        findings.append(_ca_detail_finding(
            "IDG-013", "No exclusionary geographic access policy", "2.2.2",
            "no enabled Conditional Access policy conditions on named locations / geography",
            "No enabled Conditional Access policy conditions on named locations, so sign-ins are not "
            "constrained by geography. An exclusionary location policy (allow only expected countries, "
            "or block high-risk ones) shrinks where a stolen credential can be used from.",
            "Define named locations and a Conditional Access policy that blocks or steps up sign-ins "
            "from unexpected countries/regions.",
            "Credentials are usable from anywhere in the world; a geographic policy limits sign-in to "
            "the regions the organisation actually operates from, cutting off the bulk of remote attacker IPs.",
            "An attacker with a phished credential signs in from a country the organisation never "
            "operates in; with no geographic policy the sign-in is not challenged on location.",
            "Sign-ins are not constrained by geography.",
            ["Define named locations for the countries/regions you operate in.",
             "Create a CA policy to block or step up sign-ins from other locations.",
             "Roll out in report-only first to catch legitimate travel."],
            "Microsoft Graph conditionalAccess: no enabled policy with conditions.locations set."))

    # ---- IDG-014: device-code authentication flow not blocked (CIS 2.2.3) ----
    if not ca_ok:
        not_assessed.append({"rule_id": "IDG-014", "title": "Device-code flow policy",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})
    elif not any(_blocks_device_code(p) for p in enabled):
        findings.append(_ca_detail_finding(
            "IDG-014", "Device-code authentication flow is not blocked", "2.2.3",
            "no enabled Conditional Access policy blocks the device-code authentication flow",
            "No enabled Conditional Access policy blocks the device-code authentication flow. "
            "Device-code flow is a frequent phishing vector: the attacker starts a device-code "
            "sign-in and tricks a user into entering the code, yielding a fully authenticated token.",
            "Create a Conditional Access policy that blocks the device-code authentication flow for "
            "all users except the specific scenarios that require it.",
            "Device-code flow lets an attacker drive the sign-in and have the victim complete it, so a "
            "single phished code produces real tokens; blocking it removes that path tenant-wide.",
            "An attacker sends a target a device-code prompt; the user enters the code believing it is "
            "legitimate, and the attacker receives authenticated tokens.",
            "Device-code phishing is possible tenant-wide.",
            ["Create a CA policy with the device-code flow condition set to Block.",
             "Scope out only the service accounts / devices that genuinely need it.",
             "Monitor sign-in logs for device-code authentications."],
            "Microsoft Graph conditionalAccess: no enabled block policy covering the device-code "
            "authentication flow."))

    # ---- IDG-015: MFA not required for the Azure management API (CIS 2.2.7) ----
    if not ca_ok:
        not_assessed.append({"rule_id": "IDG-015", "title": "MFA for Azure management API",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})
    elif not sd_on and not any(_requires_mfa(p) and _targets_app(p, _AZURE_MGMT_APP_ID) for p in enabled):
        findings.append(_ca_detail_finding(
            "IDG-015", "MFA is not required for the Azure management API", "2.2.7",
            "no enabled Conditional Access policy requires MFA for the Microsoft Azure Management API",
            "No enabled Conditional Access policy (and no security defaults) requires MFA for the "
            "Microsoft Azure Management API, which backs the Azure portal, CLI, PowerShell and ARM. "
            "Control-plane access to every subscription is then reachable with a password alone.",
            "Create a Conditional Access policy requiring MFA for the 'Microsoft Azure Management' "
            "cloud app for all users.",
            "The Azure management API is the control plane for all resources. Requiring MFA there means "
            "a stolen password alone cannot create, read or destroy cloud resources.",
            "An attacker with a leaked credential calls ARM / the Azure CLI and manages resources "
            "because MFA was never required for the management API.",
            "Azure control-plane access is possible with a password alone.",
            ["Create a CA policy targeting the Microsoft Azure Management app.",
             "Require MFA (or an authentication strength) for all users on that app.",
             "Validate automation/service principals use workload identities, not excluded users."],
            "Microsoft Graph conditionalAccess: no enabled MFA policy targeting app "
            "797f4846-ba00-4fd7-ba43-dac1f8f63013."))

    # ---- IDG-016: MFA not required for the Microsoft admin portals (CIS 2.2.8) ----
    if not ca_ok:
        not_assessed.append({"rule_id": "IDG-016", "title": "MFA for admin portals",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})
    elif not sd_on and not any(_requires_mfa(p) and _targets_app(p, _ADMIN_PORTALS_APP) for p in enabled):
        findings.append(_ca_detail_finding(
            "IDG-016", "MFA is not required for the Microsoft admin portals", "2.2.8",
            "no enabled Conditional Access policy requires MFA for the Microsoft Admin Portals",
            "No enabled Conditional Access policy (and no security defaults) requires MFA for the "
            "Microsoft Admin Portals target (Entra, Microsoft 365, Exchange, Intune admin centers). "
            "Administrative consoles are then reachable with a password alone.",
            "Create a Conditional Access policy requiring MFA for the 'Microsoft Admin Portals' target "
            "for all users.",
            "The admin portals are where tenant configuration is changed. Requiring MFA for them keeps "
            "a stolen admin password from directly reconfiguring the tenant.",
            "An attacker with a phished admin password opens the Entra admin center and changes "
            "configuration because MFA was never required for the admin portals.",
            "Administrative portals are reachable with a password alone.",
            ["Create a CA policy targeting the Microsoft Admin Portals.",
             "Require MFA (or an authentication strength) for all users.",
             "Keep only monitored break-glass accounts excluded."],
            "Microsoft Graph conditionalAccess: no enabled MFA policy targeting the MicrosoftAdminPortals target."))

    # ---- IDG-017: MFA not required to register / join devices (CIS 2.22) ----
    if not ca_ok:
        not_assessed.append({"rule_id": "IDG-017", "title": "MFA for device registration",
                             "reason": "Conditional Access policies not collected",
                             "needs": ["Microsoft Graph: Policy.Read.All"]})
    elif not sd_on and not any(_requires_mfa(p) and _targets_user_action(p, _REGISTER_DEVICE_ACTION)
                               for p in enabled):
        findings.append(_ca_detail_finding(
            "IDG-017", "MFA is not required to register or join devices", "2.22",
            "no enabled Conditional Access policy requires MFA for the register/join-device user action",
            "No enabled Conditional Access policy (and no security defaults) requires MFA for the "
            "register-or-join-device user action. A phished or sprayed password can then enroll an "
            "attacker-controlled device into the tenant, which can become a trusted factor.",
            "Create a Conditional Access policy requiring MFA for the 'Register or join devices' user "
            "action.",
            "Device registration/join can turn a stolen password into a persistent, trusted device "
            "identity. Requiring MFA for the action stops an attacker from enrolling their own device.",
            "An attacker with a stolen password joins their own device to the tenant, gaining a "
            "trusted device factor and a persistence foothold.",
            "Attacker-controlled devices can be registered with a password alone.",
            ["Create a CA policy for the 'Register or join devices' user action.",
             "Require MFA (or an authentication strength) for it.",
             "Review registered devices for unexpected enrollments."],
            "Microsoft Graph conditionalAccess: no enabled MFA policy covering the "
            "urn:user:registerdevice user action."))

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

    # ---- IDG-006..009: tenant self-service / external-access defaults (authorizationPolicy) ----
    # These fields are part of the same authorizationPolicy object as user consent, and each is a
    # distinct breach-surface default that ships permissive and is routinely left unchanged.
    if ap_ok and gr.authorization_policy is not None:
        ap = gr.authorization_policy
        dur = ap.get("defaultUserRolePermissions") or {}

        # IDG-006: any user can register applications (OAuth app persistence + consent-phishing).
        if dur.get("allowedToCreateApps") is True:
            findings.append(_finding(
                "IDG-006", "Any user can register applications", "High",
                [_ent("app-registration", "Application registration", confirmed=True,
                      allowedToCreateApps=True)],
                "The tenant lets every non-admin user register (create) Entra application objects "
                "and service principals. Combined with open user consent this is a self-service "
                "foothold-and-persistence primitive: an attacker who phishes any one account can "
                "stand up an app, add a credential and keep long-lived Graph access that survives a "
                "password reset.",
                "Set 'Users can register applications' to No (Entra ID > Users > User settings), and "
                "delegate app registration to a scoped Application Developer role where needed.",
                {"summary": "Every user can create application registrations.",
                 "why": "Attacker-controlled app registrations are a primary persistence and "
                        "consent-phishing mechanism; allowing all users to create them removes the "
                        "admin review that would catch a malicious app.",
                 "scenario": "An attacker who compromises any user registers a multi-tenant app, adds "
                             "a client secret, and uses it for durable Graph access and consent "
                             "phishing, independent of the original account's password.",
                 "impact": "Self-service application persistence and expanded consent-phishing surface.",
                 "steps": ["Entra ID > Users > User settings: set 'Users can register applications' to No.",
                           "Grant the Application Developer role only to users who need it.",
                           "Review recently created app registrations and their owners/credentials."],
                 "detection": "Microsoft Graph /policies/authorizationPolicy: "
                              "defaultUserRolePermissions.allowedToCreateApps == true.",
                 "frameworks": {"CIS Azure": "1.14", "MITRE ATT&CK": "T1098.001", "Azure Threat Matrix": "AZT501"}}))

        # IDG-007: guest invitations are open to non-admins (external-access sprawl).
        invites = str(ap.get("allowInvitesFrom") or "").strip()
        inv_l = invites.lower()
        if inv_l in ("everyone", "adminsguestinvitersandallmembers"):
            sev = "High" if inv_l == "everyone" else "Medium"
            who = ("everyone, including guests themselves" if inv_l == "everyone"
                   else "all member users")
            findings.append(_finding(
                "IDG-007", "Guest invitations are not restricted to admins", sev,
                [_ent("guest-invite", "Guest invitation policy", confirmed=True,
                      allowInvitesFrom=invites)],
                f"Guest (B2B) invitations can be sent by {who}, not only administrators or a scoped "
                "inviter role. Unrestricted invitation lets any account (or an existing guest) pull "
                "external identities into the tenant, growing the external-access surface with no "
                "oversight and enabling social-engineering footholds.",
                "Restrict guest invitations to administrators and the Guest Inviter role (Entra ID > "
                "External Identities > External collaboration settings).",
                {"summary": f"Guest invitations can be sent by {who}.",
                 "why": "Every invited guest is external access into the tenant; letting all users "
                        "(or guests) invite removes governance over who gains access and is a common "
                        "path to guest sprawl and stealth external footholds.",
                 "scenario": "An attacker controlling one member account, or a single malicious guest, "
                             "invites further attacker-controlled external accounts, expanding "
                             "footholds without any admin approval.",
                 "impact": "Ungoverned growth of external (guest) access into the tenant.",
                 "steps": ["External Identities > External collaboration settings: set invitations to "
                           "'Only users assigned to specific admin roles' or admins + Guest Inviter.",
                           "Review current guests and remove stale/unknown external accounts.",
                           "Pair with restricted guest access permissions (see IDG-008)."],
                 "detection": "Microsoft Graph /policies/authorizationPolicy: allowInvitesFrom is "
                              "'everyone' or 'adminsGuestInvitersAndAllMembers'.",
                 "frameworks": {"CIS Azure": "1.15", "MITRE ATT&CK": "T1136.003", "Azure Threat Matrix": "AZT501"}}))

        # IDG-008: guest users are not access-restricted (guests see the directory like members).
        guest_role = str(ap.get("guestUserRoleId") or "").strip().lower()
        _RESTRICTED_GUEST = "2af84b1e-32c8-42b7-82bc-daa82404023b"
        _MEMBER_LIKE_GUEST = "a0b1b346-4d3e-4e8b-98f8-753987be4970"   # "same as member user"
        if guest_role and guest_role != _RESTRICTED_GUEST:
            sev = "High" if guest_role == _MEMBER_LIKE_GUEST else "Medium"
            lvl = ("the same directory access as full member users"
                   if guest_role == _MEMBER_LIKE_GUEST
                   else "the default (not restricted) level of guest directory access")
            findings.append(_finding(
                "IDG-008", "Guest user access is not restricted", sev,
                [_ent("guest-access", "Guest access level", confirmed=True,
                      guestUserRoleId=guest_role)],
                f"Guest (external) users are granted {lvl}, so they can enumerate users, groups, "
                "group memberships, applications and service principals across the directory. That "
                "reconnaissance maps admins, privileged groups and app owners for a targeted attack.",
                "Set guest access to 'Restricted access' (Entra ID > External Identities > External "
                "collaboration settings > Guest user access restrictions).",
                {"summary": f"Guests have {lvl}.",
                 "why": "Broad guest directory access hands external accounts the reconnaissance they "
                        "need, who the admins are, which groups are privileged, who owns which app, "
                        "turning a single compromised or malicious guest into a tenant map.",
                 "scenario": "An attacker holding one guest account enumerates the directory to locate "
                             "Global Admins, role-assignable groups and app owners, then targets them "
                             "directly.",
                 "impact": "Directory-wide reconnaissance from any external guest account.",
                 "steps": ["External collaboration settings > Guest user access: choose 'Restricted "
                           "access (guests cannot enumerate directory objects)'.",
                           "Audit existing guests and their group memberships.",
                           "Restrict who can invite guests (see IDG-007)."],
                 "detection": "Microsoft Graph /policies/authorizationPolicy: guestUserRoleId is not "
                              "the Restricted Guest User role (2af84b1e-32c8-42b7-82bc-daa82404023b).",
                 "frameworks": {"CIS Azure": "1.16", "MITRE ATT&CK": "T1087.004", "Azure Threat Matrix": "AZT501"}}))

        # IDG-009: any user can create tenants (shadow-tenant / data-exfil governance gap).
        if dur.get("allowedToCreateTenants") is True:
            findings.append(_finding(
                "IDG-009", "Any user can create Entra tenants", "Low",
                [_ent("tenant-creation", "Tenant creation", confirmed=True,
                      allowedToCreateTenants=True)],
                "Every non-admin user can create new Entra ID tenants. User-created tenants are "
                "outside the organisation's governance, logging and Conditional Access, and can be "
                "used to move or host data beyond security oversight.",
                "Set 'Restrict non-admin users from creating tenants' to Yes (Entra ID > Users > "
                "User settings).",
                {"summary": "Non-admin users can create new tenants.",
                 "why": "Shadow tenants created by users are ungoverned: no CA, no logging, no DLP, a "
                        "blind spot that can host exfiltrated data or rogue apps.",
                 "scenario": "A user (or an attacker in a user's session) spins up a personal tenant "
                             "and uses it to stage access or data outside the org's monitoring.",
                 "impact": "Ungoverned shadow tenants outside security and compliance controls.",
                 "steps": ["Entra ID > Users > User settings: set 'Restrict non-admin users from "
                           "creating tenants' to Yes."],
                 "detection": "Microsoft Graph /policies/authorizationPolicy: "
                              "defaultUserRolePermissions.allowedToCreateTenants == true.",
                 "frameworks": {"CIS Azure": "1.x", "Best Practice": "Tenant governance"}}))

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
    {"id": "IDG-006", "title": "Any user can register applications",
     "severity": "High", "category": "Applications & Service Principals", "best_practice": False,
     "description": "Every non-admin user can create application registrations and service principals, a self-service persistence and consent-phishing primitive.",
     "remediation": "Set 'Users can register applications' to No and delegate via the Application Developer role.",
     "frameworks": {"CIS Azure": "1.14", "MITRE ATT&CK": "T1098.001", "Azure Threat Matrix": "AZT501"}},
    {"id": "IDG-007", "title": "Guest invitations are not restricted to admins",
     "severity": "High", "category": "Guest & Cross-Tenant", "best_practice": False,
     "description": "All members (or everyone, including guests) can invite external guests, growing external access to the tenant with no admin oversight.",
     "remediation": "Restrict guest invitations to administrators and the Guest Inviter role.",
     "frameworks": {"CIS Azure": "1.15", "MITRE ATT&CK": "T1136.003", "Azure Threat Matrix": "AZT501"}},
    {"id": "IDG-008", "title": "Guest user access is not restricted",
     "severity": "Medium", "category": "Guest & Cross-Tenant", "best_practice": False,
     "description": "Guests can enumerate users, groups, apps and service principals across the directory, handing external accounts tenant reconnaissance.",
     "remediation": "Set guest access to 'Restricted access' in External collaboration settings.",
     "frameworks": {"CIS Azure": "1.16", "MITRE ATT&CK": "T1087.004", "Azure Threat Matrix": "AZT501"}},
    {"id": "IDG-009", "title": "Any user can create Entra tenants",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "Non-admin users can create new Entra tenants that sit outside the organisation's governance, logging and Conditional Access.",
     "remediation": "Set 'Restrict non-admin users from creating tenants' to Yes.",
     "frameworks": {"CIS Azure": "1.x", "Best Practice": "Tenant governance"}},
    {"id": "IDG-010", "title": "Administrators are not covered by MFA",
     "severity": "High", "category": "Privileged Identity", "best_practice": False,
     "description": "MFA is configured but no enabled Conditional Access policy enforces it for administrators (scoped to specific apps/users, or privileged roles are excluded), so admin sign-in is password-only.",
     "remediation": "Require MFA for all privileged directory roles across all cloud apps, and remove any admin-role exclusions (keep only break-glass accounts excluded via excludeUsers).",
     "frameworks": {"CIS Azure": "1.1.3", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-011", "title": "Administrator sign-in does not require a managed device",
     "severity": "Medium", "category": "Privileged Identity", "best_practice": False,
     "description": "Conditional Access covers admins but no policy requires a compliant or hybrid-joined device, so a phished admin credential can be replayed from any attacker machine.",
     "remediation": "Require a compliant or hybrid Entra-joined device for all privileged directory roles.",
     "frameworks": {"CIS Azure": "1.x", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-012", "title": "No risk-based Conditional Access policy",
     "severity": "Medium", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy acts on Identity Protection sign-in or user risk, so detected account compromise triggers no automatic MFA/password-change/block.",
     "remediation": "Add CA policies that require MFA on medium/high sign-in risk and a secure password change on high user risk (needs Entra ID P2).",
     "frameworks": {"CIS Azure": "1.2.x", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-013", "title": "No exclusionary geographic access policy",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy conditions on named locations / geography, so a stolen credential is usable from anywhere in the world.",
     "remediation": "Define named locations and a Conditional Access policy that blocks or steps up sign-ins from unexpected countries/regions.",
     "frameworks": {"CIS Azure": "2.2.2", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-014", "title": "Device-code authentication flow is not blocked",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy blocks the device-code authentication flow, a common phishing vector that yields fully authenticated tokens.",
     "remediation": "Create a Conditional Access policy that blocks the device-code authentication flow except where genuinely required.",
     "frameworks": {"CIS Azure": "2.2.3", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-015", "title": "MFA is not required for the Azure management API",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy (and no security defaults) requires MFA for the Microsoft Azure Management API, so the cloud control plane is reachable with a password alone.",
     "remediation": "Require MFA via Conditional Access for the 'Microsoft Azure Management' cloud app for all users.",
     "frameworks": {"CIS Azure": "2.2.7", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-016", "title": "MFA is not required for the Microsoft admin portals",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy (and no security defaults) requires MFA for the Microsoft Admin Portals, so administrative consoles are reachable with a password alone.",
     "remediation": "Require MFA via Conditional Access for the 'Microsoft Admin Portals' target for all users.",
     "frameworks": {"CIS Azure": "2.2.8", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
    {"id": "IDG-017", "title": "MFA is not required to register or join devices",
     "severity": "Low", "category": "Privileged Identity", "best_practice": False,
     "description": "No enabled Conditional Access policy (and no security defaults) requires MFA for the register/join-device action, so a stolen password can enroll an attacker-controlled device.",
     "remediation": "Require MFA via Conditional Access for the 'Register or join devices' user action.",
     "frameworks": {"CIS Azure": "2.22", "MITRE ATT&CK": "T1078.004", "Azure Threat Matrix": "AZT202"}},
]
