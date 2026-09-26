"""Standalone external assessment report.

Renders a scan into a self-contained, print-ready HTML document (and, where
weasyprint is available, a PDF) meant to be handed to a team that does NOT run
this tool. Everything tool-specific is stripped: no product name, no graph-tool
references, no external URLs, no in-app navigation. The layout is a classic
security-report: cover, executive summary, contents, findings by severity, and
a separate hardening-recommendations section.

Design lives in _CSS. `render_html` is pure and dependency-free; `render_pdf`
lazily imports weasyprint and raises PdfEngineUnavailable if it cannot load, so
the web layer can fall back to serving the HTML for the browser to print.
"""
from __future__ import annotations

import html
import re
from collections import Counter
from datetime import datetime, timezone


class PdfEngineUnavailable(RuntimeError):
    """weasyprint (or a native library it needs) could not be imported."""


# --------------------------------------------------------------------------- sanitising
# This report leaves the building. Scrub every trace of the tooling that made it
# - a graph-tool name in a finding title is a support question for a team that
# has no access to it.
_SANI = [
    (r"PostureHound", "this assessment"),
    # No URLs in an externally-shared report - a link back to a tool the reader
    # cannot reach is noise. Real findings carry none; this guards AI-emitted ones.
    (r"https?://\S+", "the vendor documentation"),
]
_ROLE_WORDS = {
    "serviceprincipal": "service principal", "managementgroup": "management group",
    "keyvault": "key vault", "storageaccount": "storage account",
    "containerregistry": "container registry", "functionapp": "function app",
    "virtualmachine": "virtual machine",
}
_KIND = {
    "AZServicePrincipal": "Service Principal", "AZGroup": "Group", "AZUser": "User",
    "AZRole": "Directory Role", "AZApp": "Application", "AZSubscription": "Subscription",
    "AZManagementGroup": "Management Group", "AZKeyVault": "Key Vault",
    "AZStorageAccount": "Storage Account", "AZContainerRegistry": "Container Registry",
    "AZFunctionApp": "Function App", "AZVM": "Virtual Machine", "AZBase": "Object",
    "AZUnknown": "Object",
}
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}
_SEV_PREFIX = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Info": "I"}


def _sani(t):
    if not isinstance(t, str):
        return t
    for pat, rep in _SANI:
        t = re.sub(pat, rep, t, flags=re.I)
    return re.sub(r"\s{2,}", " ", t).strip()


def _esc(x) -> str:
    return html.escape(_sani(str(x if x is not None else ""))).strip()


def _kind(k) -> str:
    return _KIND.get(k or "", (k or "Object").removeprefix("AZ"))


def _clean_role(r):
    r = _sani(r or "")
    for a, b in _ROLE_WORDS.items():
        r = re.sub(a, b, r, flags=re.I)
    r = _clean_kinds(r)
    return (r[:1].upper() + r[1:]) if r else ""


def _detail(f):
    return f.get("detail") if isinstance(f.get("detail"), dict) else {}


def _field(f, *keys):
    detail = _detail(f)
    for src in (f, detail):
        for k in keys:
            v = src.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def _describe(f):
    """(description, business_impact) guaranteed distinct.

    Deterministic findings duplicate `what`/`why_it_matters` but carry separate
    summary/impact/why in their detail dict; AI findings differ at top level.
    """
    d = _detail(f)
    desc = _field(f, "what", "summary") or d.get("summary", "")
    for cand in (d.get("impact"), f.get("why_it_matters"), d.get("why"),
                 f.get("summary"), d.get("summary")):
        if isinstance(cand, str) and cand.strip() and cand.strip() != desc.strip():
            return desc, cand.strip()
    return desc, ""


# Per-entity evidence: the deterministic rules and AI analysts attach WHY each
# object is in the finding - the role it holds, the group it inherits it through,
# the permission, the scope. The report used to drop all of it and show a generic
# "Affected user", which is why a group-membership finding never named the group.
# These render that evidence compactly.
_EV_SKIP = {"confirmed", "group_id", "adder_id", "identity", "target_id",
            "joinable_by", "assignment_count", "role_count", "own_count",
            "vault_count", "subscription_count", "management_group_count",
            "vm_assignment_count", "credential_count", "total_global_admins"}
_EV_PRIORITY = ["note", "role", "roles", "group", "path", "permission", "appRole",
                "assignments", "scope", "subscription", "subscriptions",
                "management_groups", "vaults", "vault", "owns", "vm_assignments",
                "roles", "via", "reason", "impact", "key_permissions"]
_EV_LABEL = {
    "note": "", "role": "Role", "roles": "Roles", "group": "Via group",
    "path": "Membership", "permission": "Permission", "appRole": "App role",
    "assignments": "Assignments", "scope": "Scope", "subscription": "Subscription",
    "subscriptions": "Subscriptions", "management_groups": "Management groups",
    "vaults": "Key vaults", "vault": "Key vault", "owns": "Owns",
    "vm_assignments": "VM roles", "via": "Via", "reason": "Reason", "impact": "Impact",
    "key_permissions": "Key permissions", "registry": "Registry", "account": "Account",
    "cluster": "Cluster", "networkAcls_defaultAction": "Network default action",
    "allowSharedKeyAccess": "Shared-key access", "enablePurgeProtection": "Purge protection",
    "enableSoftDelete": "Soft delete", "enableRbacAuthorization": "RBAC authorization",
    "signInAudience": "Sign-in audience", "assignment_required": "Assignment required",
    "steals_identity": "Steals identity", "via_resource": "Via resource",
}


_KIND_RE = re.compile(r"\bAZ(" + "|".join(k[2:] for k in _KIND) + r")\b")


def _clean_kinds(t: str) -> str:
    # "(AZGroup)" -> "(group)"; bare "AZGroup with 296 members" -> "Group with …"
    t = re.sub(r"\(AZ(\w+)\)", lambda m: f"({_kind('AZ' + m.group(1)).lower()})", t)
    return _KIND_RE.sub(lambda m: _kind("AZ" + m.group(1)), t)


def _fmt_ev_value(v) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        out = []
        for x in v[:6]:
            if isinstance(x, dict):
                out.append(x.get("vault") or x.get("name") or x.get("subscription")
                           or "; ".join(f"{a} {b}" for a, b in x.items()))
            else:
                out.append(str(x))
        s = ", ".join(o for o in out if o)
        if len(v) > 6:
            s += f", +{len(v) - 6} more"
        return s
    return str(v)


def _entity_detail(e) -> str:
    """A compact, human-readable summary of why this object is in the finding,
    built from its evidence dict (role, group/membership, permission, scope…)."""
    ev = e.get("evidence") if isinstance(e.get("evidence"), dict) else {}
    ordered = [k for k in _EV_PRIORITY if k in ev]
    ordered += [k for k in ev if k not in ordered and k not in _EV_SKIP
                and not k.endswith(("_id", "_withheld"))]
    parts = []
    for k in ordered:
        if len(parts) >= 5:
            break
        val = _fmt_ev_value(ev[k])
        if not val:
            continue
        label = _EV_LABEL.get(k, k.replace("_", " "))
        parts.append(f"{label}: {val}" if label else val)
    return _clean_kinds(" · ".join(parts))


def _entity_cell(e) -> str:
    """The right-hand cell for an affected object: its specific role/evidence.
    Prefers the concrete evidence; keeps a substantive role_in_finding (AI writes
    rich ones); drops the generic 'Affected <kind>' when evidence is present."""
    detail = _entity_detail(e)
    role = _clean_role(e.get("role_in_finding") or "")
    generic = role.lower().startswith("affected ")
    if detail and role and not generic:
        return html.escape(role) + " · " + _esc(detail)
    if detail:
        return _esc(detail)
    return html.escape(role)


# --------------------------------------------------------------------------- fragments
def _sev_chip(sev):
    return f'<span class="chip chip-{_esc(sev).lower()}">{_esc(sev)}</span>'


_ENTITY_TABLE_LIMIT = 25   # above this, switch to a compact list so one finding
                           # with hundreds of members does not run for many pages


def _entity_rows(f):
    """Every affected object, de-duplicated. Small sets get a full table; large
    sets (e.g. a 296-member group) get a compact, grouped-by-role name list so
    nothing is dropped but the report stays readable."""
    seen, ents = set(), []
    for e in (f.get("entities") or []):
        key = (e.get("name") or "").lower(), (e.get("id") or "").lower()
        if key in seen:
            continue
        seen.add(key)
        ents.append(e)
    if not ents:
        return ""

    if len(ents) <= _ENTITY_TABLE_LIMIT:
        rows = "".join(
            f'<tr><td class="ent-name">{_esc(e.get("name") or e.get("id") or "-")}</td>'
            f'<td class="ent-kind">{_esc(_kind(e.get("kind")))}</td>'
            f'<td class="ent-role">{_entity_cell(e)}</td></tr>'
            for e in ents)
        return ('<table class="ent"><thead><tr><th>Affected object</th><th>Type</th>'
                f'<th>Role &amp; how it is held</th></tr></thead><tbody>{rows}</tbody></table>')

    # Compact: group names by (type, shared detail) so a shared role/group becomes
    # the heading - e.g. all members inheriting a role through the same group.
    from collections import OrderedDict
    groups: "OrderedDict[tuple, list]" = OrderedDict()
    for e in ents:
        detail = _entity_detail(e) or _clean_role(e.get("role_in_finding") or "")
        g = (_kind(e.get("kind")), detail)
        groups.setdefault(g, []).append(_esc(e.get("name") or e.get("id") or "-"))
    blocks = [f'<div class="ent-compact-head">{len(ents)} affected objects</div>']
    for (typ, detail), names in groups.items():
        label = html.escape(typ) + (f" · {_esc(detail)}" if detail else "")
        blocks.append(f'<div class="ent-grp"><div class="ent-grp-lab">{label} '
                      f'<span class="ent-grp-n">({len(names)})</span></div>'
                      f'<div class="ent-grp-names">{", ".join(names)}</div></div>')
    return f'<div class="ent-compact">{"".join(blocks)}</div>'


def _attack_path(f):
    """Render the finding's escalation chain as a node-and-edge line diagram.

    Each hop is {from:{name,kind}, to:{name,kind}, technique}. The final `to`
    is the Tier-0 objective. Nodes flow left-to-right with the technique labelled
    on each connector; the diagram wraps within the card on narrow pages.
    """
    chain = f.get("escalation_chain") or []
    if not chain:
        return ""
    nodes = []
    first = chain[0].get("from") or {}
    nodes.append((first.get("name") or "?", first.get("kind"), False))
    for i, hop in enumerate(chain):
        to = hop.get("to") or {}
        nodes.append((to.get("name") or "?", to.get("kind"), i == len(chain) - 1))

    seq = []
    for i, (name, k, is_target) in enumerate(nodes):
        if i > 0:
            tech = _esc(chain[i - 1].get("technique") or "")
            seq.append(f'<div class="pconn"><span class="pc-line"></span>'
                       f'<span class="pc-lab">{tech}</span></div>')
        cls = "pnode" + (" pnode-target" if is_target else (" pnode-start" if i == 0 else ""))
        tag = ('<span class="pn-badge">Tier-0 objective</span>' if is_target else
               ('<span class="pn-badge pn-badge-start">Entry point</span>' if i == 0 else ""))
        seq.append(f'<div class="{cls}"><div class="pn-main"><span class="pn-name">{_esc(name)}</span>'
                   f'<span class="pn-kind">{_esc(_kind(k))}</span></div>{tag}</div>')
    return (f'<div class="f-sec"><div class="f-lab">Attack path to tier-0 '
            f'({len(chain)} hop{"s" if len(chain) != 1 else ""})</div>'
            f'<div class="pathdiag">{"".join(seq)}</div></div>')


def _max_impact_block(f):
    """The finding's worst-case outcome: the maximum-impact path through the
    escalation graph. Rendered as a plain business artifact - the objective reached
    and the route to it - with no tooling references (this is the shareable report)."""
    p = f.get("max_impact_path")
    if not p:
        return ""
    entry = (p.get("entry") or {}).get("name") or "the affected principal"
    target = (p.get("target") or {}).get("name") or "a privileged target"
    summ = (f.get("max_impact_summary") or "").strip()
    line = _esc(summ) if summ else (
        f"Worst case: compromise of {_esc(entry)} leads to {_esc(target)}.")
    if p.get("reaches_tier0"):
        line += ' <span class="mi-t0">This path reaches a tier-0 objective - full tenant takeover.</span>'
    diagram = ""
    hops = p.get("hops") or []
    # Draw the route only when the finding has no escalation-chain diagram already,
    # so the two don't duplicate on the same card.
    if hops and not (f.get("escalation_chain") or []):
        nodes = [((p.get("entry") or {}).get("name") or "?",
                  (p.get("entry") or {}).get("kind"), False)]
        for i, h in enumerate(hops):
            to = h.get("to") or {}
            nodes.append((to.get("name") or "?", to.get("kind"), i == len(hops) - 1))
        seq = []
        for i, (name, k, is_target) in enumerate(nodes):
            if i > 0:
                seq.append(f'<div class="pconn"><span class="pc-line"></span>'
                           f'<span class="pc-lab">{_esc(hops[i - 1].get("via") or "")}</span></div>')
            cls = "pnode" + (" pnode-target" if is_target else (" pnode-start" if i == 0 else ""))
            tag = ('<span class="pn-badge">Objective</span>' if is_target else
                   ('<span class="pn-badge pn-badge-start">Entry point</span>' if i == 0 else ""))
            seq.append(f'<div class="{cls}"><div class="pn-main"><span class="pn-name">{_esc(name)}</span>'
                       f'<span class="pn-kind">{_esc(_kind(k))}</span></div>{tag}</div>')
        diagram = f'<div class="pathdiag">{"".join(seq)}</div>'
    return (f'<div class="f-sec"><div class="f-lab">Maximum impact</div>'
            f'<p>{line}</p>{diagram}</div>')


def _commands_block(f):
    cmds = [c for c in (f.get("remediation_commands") or [])
            if isinstance(c, str) and c.strip()]
    if not cmds:
        return ""
    lines = "\n".join(_esc(c) for c in cmds[:6])
    return f'<div class="cmd-label">Verification commands</div><pre class="cmd">{lines}</pre>'


def _finding_block(f):
    what, why = _describe(f)
    scenario = _field(f, "attack_scenario", "scenario")
    remediation = _field(f, "remediation")
    detection = _field(f, "detection")
    mitre = _field(f, "mitre_technique") or (f.get("frameworks") or {}).get("MITRE ATT&CK", "")

    meta = []
    if f.get("category"):
        meta.append(f'<span class="meta-tag">{_esc(f["category"])}</span>')
    if mitre:
        meta.append(f'<span class="meta-tag mono">MITRE {_esc(mitre)}</span>')

    parts = [
        f'<section class="finding" id="{f["_id"]}">',
        '<div class="f-head">',
        f'<div class="f-id">{f["_id"]}</div>',
        f'<h3 class="f-title">{_esc(f["title"])}</h3>',
        f'<div class="f-sev">{_sev_chip(f.get("severity"))}</div>',
        '</div>',
        f'<div class="f-meta">{"".join(meta)}</div>' if meta else "",
    ]
    if what:
        parts.append(f'<div class="f-sec"><div class="f-lab">Description</div><p>{_esc(what)}</p></div>')
    if why:
        parts.append(f'<div class="f-sec"><div class="f-lab">Business impact</div><p>{_esc(why)}</p></div>')
    if scenario:
        parts.append(f'<div class="f-sec"><div class="f-lab">Attack scenario</div><p>{_esc(scenario)}</p></div>')
    parts.append(_attack_path(f))
    parts.append(_max_impact_block(f))
    ents = _entity_rows(f)
    if ents:
        parts.append(f'<div class="f-sec"><div class="f-lab">Affected objects</div>{ents}</div>')
    if remediation:
        parts.append(f'<div class="f-sec"><div class="f-lab">Recommended remediation</div>'
                     f'<p>{_esc(remediation)}</p>{_commands_block(f)}</div>')
    if detection:
        parts.append(f'<div class="f-sec"><div class="f-lab">Detection guidance</div><p>{_esc(detection)}</p></div>')
    parts.append('</section>')
    return "".join(parts)


def _hardening_block(f):
    """A lighter card for best-practice items: description + remediation only."""
    what, _ = _describe(f)
    remediation = _field(f, "remediation")
    parts = [
        f'<section class="finding hardening" id="{f["_id"]}">',
        '<div class="f-head">',
        f'<div class="f-id">{f["_id"]}</div>',
        f'<h3 class="f-title">{_esc(f["title"])}</h3>',
        f'<div class="f-sev">{_sev_chip(f.get("severity"))}</div>',
        '</div>',
    ]
    if f.get("category"):
        parts.append(f'<div class="f-meta"><span class="meta-tag">{_esc(f["category"])}</span></div>')
    if what:
        parts.append(f'<div class="f-sec"><div class="f-lab">Recommendation</div><p>{_esc(what)}</p></div>')
    if remediation:
        parts.append(f'<div class="f-sec"><div class="f-lab">How to apply</div>'
                     f'<p>{_esc(remediation)}</p>{_commands_block(f)}</div>')
    parts.append('</section>')
    return "".join(parts)


# --------------------------------------------------------------------------- document
def render_html(scan: dict) -> str:
    """Render a scan dict into a self-contained external report (HTML string)."""
    non_path = [f for f in scan.get("findings", []) if f.get("source") != "path_consolidation"]
    security = [f for f in non_path if not f.get("best_practice")]
    hardening = [f for f in non_path if f.get("best_practice")]

    security.sort(key=lambda f: (_SEV_RANK.get(f.get("severity"), 9),
                                 -(f.get("confidence") or 0), f.get("title", "")))
    hardening.sort(key=lambda f: f.get("title", ""))
    # Severity-coded ids that reset per group, so the id itself tells you the
    # severity: C-01 (critical), H-01 (high), M-01 (medium), L-01 (low). Hardening
    # items use HR- to avoid colliding with High's H-.
    counters: dict = {}
    for f in security:
        p = _SEV_PREFIX.get(f.get("severity"), "F")
        counters[p] = counters.get(p, 0) + 1
        f["_id"] = f"{p}-{counters[p]:02d}"
    for i, f in enumerate(hardening, 1):
        f["_id"] = f"HR-{i:02d}"

    # Cover / executive counts include hardening items, matching the AI summary totals.
    sev_counts = Counter(f.get("severity") for f in non_path)
    total = len(non_path)
    score = scan.get("score", {})
    grade = score.get("grade", "-")
    gcls = (grade or "na").lower()
    scoreval = score.get("score", 0)

    created = scan.get("_created_at")
    date_str = (datetime.fromtimestamp(created, tz=timezone.utc) if created
                else datetime.now(timezone.utc)).strftime("%d %B %Y")
    tenant = (scan.get("tenant_id") or "").split("/")[-1] or "Unknown tenant"
    exec_summary = (scan.get("ai_executive_summary") or "").strip()
    n_subs = len(scan.get("subscriptions") or [])

    # ---- table of contents
    toc_rows = "".join(
        f'<tr><td class="toc-id">{f["_id"]}</td>'
        f'<td class="toc-sev">{_sev_chip(f.get("severity"))}</td>'
        f'<td class="toc-title"><a href="#{f["_id"]}">{_esc(f["title"])}</a></td>'
        f'<td class="toc-pg"><a href="#{f["_id"]}"></a></td></tr>'
        for f in security)
    if hardening:
        toc_rows += ('<tr class="toc-group"><td colspan="4">Hardening recommendations</td></tr>')
        toc_rows += "".join(
            f'<tr><td class="toc-id">{f["_id"]}</td><td class="toc-sev"></td>'
            f'<td class="toc-title"><a href="#{f["_id"]}">{_esc(f["title"])}</a></td>'
            f'<td class="toc-pg"><a href="#{f["_id"]}"></a></td></tr>'
            for f in hardening)

    # ---- severity summary cells
    sev_summary = "".join(
        f'<div class="sev-cell sev-{sv.lower()}"><div class="sev-n">{sev_counts.get(sv,0)}</div>'
        f'<div class="sev-l">{sv}</div></div>'
        for sv in ["Critical", "High", "Medium", "Low"])

    # ---- findings by severity
    sections = []
    for sv in _SEV_ORDER:
        grp = [f for f in security if f.get("severity") == sv]
        if not grp:
            continue
        sections.append(f'<h2 class="sev-head sev-head-{sv.lower()}" id="sec-{sv.lower()}">'
                        f'{sv} severity findings <span class="sev-count">{len(grp)}</span></h2>')
        sections.extend(_finding_block(f) for f in grp)
    findings_html = "".join(sections)

    hardening_html = ""
    if hardening:
        hardening_html = ('<section class="page-sec findings-start">'
                          '<h2 class="sec-h" id="hardening">Hardening recommendations</h2>'
                          '<p class="section-intro">Configuration improvements that reduce risk '
                          'but are not, on their own, exploitable findings.</p>'
                          + "".join(_hardening_block(f) for f in hardening) + '</section>')

    exec_paras = "".join(f"<p>{_esc(p)}</p>" for p in exec_summary.split("\n") if p.strip())

    doc = _TEMPLATE.format(
        css=_CSS, grade=_esc(grade), gcls=gcls, score=_esc(scoreval),
        tenant=_esc(tenant), date=_esc(date_str), total=total,
        c=sev_counts.get("Critical", 0), h=sev_counts.get("High", 0),
        m=sev_counts.get("Medium", 0), lo=sev_counts.get("Low", 0),
        subs=n_subs, sev_summary=sev_summary, exec_paras=exec_paras,
        toc_rows=toc_rows, findings=findings_html, hardening=hardening_html,
        attackmap=_attackmap_section(scan),
    )
    return doc


def _attackmap_section(scan: dict) -> str:
    """Tenant attack map for the shareable report: every attack's worst-case path,
    ranked by impact. No tooling references - this is the route an attacker takes, in
    plain terms, for a team with no access to the analysis tool."""
    am = (scan.get("attack_map") or {})
    paths = am.get("paths") or []
    cs_block = _crosssub_block(scan)   # cross-subscription reach is folded in here, not a menu
    if not paths and not cs_block:
        return ""
    t0 = am.get("tier0_count", 0)
    rows = "".join(
        f'<tr><td class="am-name">{_esc((p.get("entry") or {}).get("name"))}</td>'
        f'<td class="am-arrow">&rarr;</td>'
        f'<td class="am-name">{_esc((p.get("target") or {}).get("name"))}</td>'
        f'<td>{_esc(_kind((p.get("target") or {}).get("kind")))}</td>'
        f'<td class="am-t0">{"Yes" if p.get("reaches_tier0") else "-"}</td>'
        f'<td class="cs-num">{p.get("length", 0)}</td>'
        f'<td>{_sev_chip(p.get("severity") or "")}</td></tr>'
        for p in paths[:40])
    paths_block = (
        f'<p class="section-intro">Every finding is an attack with a worst case. Each row is a '
        f"maximum-impact path: the highest-value target reachable from that attack's own principals "
        f"across the identity and access graph. Paths marked as reaching a tier-0 objective are "
        f"complete tenant-takeover routes. {am.get('count', len(paths))} path(s) in total; {t0} reach "
        f"a tier-0 objective.</p>"
        f'<table class="cs-table"><thead><tr><th>Entry point</th><th></th><th>Objective</th><th>Type</th>'
        f'<th>Tier-0</th><th>Hops</th><th>Severity</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>") if paths else ""
    return f"""<section class="page-sec findings-start">
  <h2 class="sec-h" id="attackmap">Attack map</h2>
  {paths_block}
  {cs_block}
</section>"""


def _crosssub_block(scan: dict) -> str:
    """Cross-subscription bridges, rendered INSIDE the attack map (not as a separate
    section/menu): the principals whose compromise spans more than one subscription, and
    the connections they create. Returns inner HTML only - empty when there are no bridges."""
    cs = ((scan.get("analytics") or {}).get("cross_subscription")) or {}
    bridges = cs.get("bridges") or []
    if not bridges:
        return ""
    links = cs.get("links") or []
    t0 = sum(1 for b in bridges if b.get("reaches_tier0"))
    brows = "".join(
        f'<tr><td class="cs-name">{_esc(b.get("name"))}</td>'
        f'<td>{_esc(_kind(b.get("kind")))}</td>'
        f'<td class="cs-num">{b.get("subscription_count", 0)}</td>'
        f'<td class="cs-roles">{_esc(", ".join((b.get("roles") or [])[:3]))}'
        f'{" (via management group)" if b.get("via_management_group") else ""}'
        f'{" (inherited access)" if b.get("indirect") else ""}</td>'
        f'<td class="cs-t0">{"Yes" if b.get("reaches_tier0") else "-"}</td>'
        f'<td class="cs-num">{b.get("blast_radius", 0)}</td></tr>'
        for b in bridges[:25])
    lrows = "".join(
        f'<tr><td>{_esc(l.get("a"))} &harr; {_esc(l.get("b"))}</td>'
        f'<td class="cs-num">{l.get("principal_count", 0)}</td>'
        f'<td class="cs-num">{l.get("max_blast", 0)}</td></tr>'
        for l in links[:20])
    links_block = (
        f'<div class="f-lab" style="margin-top:5mm">Subscription connections '
        f'(top {min(len(links), 20)} of {len(links)})</div>'
        f'<table class="cs-table"><thead><tr><th>Connected subscriptions</th>'
        f'<th>Bridging principals</th><th>Max blast</th></tr></thead>'
        f'<tbody>{lrows}</tbody></table>') if lrows else ""
    return f"""
  <h3 class="am-subhead" style="margin-top:7mm">Cross-subscription blast radius</h3>
  <p class="section-intro">Some of these attacks do not stop at one subscription. A principal whose access
    spans more than one - held directly, granted by a management-group role, or inherited through a group
    it belongs to, an account it owns, or an escalation path - is a bridge: compromising it extends the
    blast radius across every subscription it touches. {cs.get('bridge_count', len(bridges))} bridging
    principal(s) across {cs.get('subscription_count', 0)} subscription(s); {t0} reach a tier-0 target.</p>
  <div class="f-lab">Bridging principals (top {min(len(bridges), 25)} of {len(bridges)})</div>
  <table class="cs-table"><thead><tr><th>Principal</th><th>Type</th><th>Subs</th><th>Roles</th>
    <th>Tier-0</th><th>Blast</th></tr></thead><tbody>{brows}</tbody></table>
  {links_block}"""


def render_pdf(scan: dict) -> bytes:
    """Render a scan to PDF bytes via weasyprint.

    Raises PdfEngineUnavailable if weasyprint (or a native lib it needs) is not
    importable, so callers can fall back to serving the HTML for browser print.
    """
    try:
        from weasyprint import HTML  # noqa: PLC0415 (lazy: heavy import + optional dep)
    except Exception as e:  # ImportError, or OSError from a missing native lib
        raise PdfEngineUnavailable(str(e)) from e
    return HTML(string=render_html(scan)).write_pdf()


_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Azure Identity Posture Assessment</title>
<style>{css}</style></head>
<body>

<div class="cover">
  <div class="cover-band"></div>
  <div class="cover-body">
    <div class="cover-kicker">Security Assessment</div>
    <h1 class="cover-title">Azure Identity<br>Posture Assessment</h1>
    <div class="cover-sub">Entra ID &amp; Azure resource-plane identity review</div>
    <div class="cover-grade">
      <div class="grade-badge grade-{gcls}">{grade}</div>
      <div class="grade-meta"><div class="grade-score">{score}<span>/100</span></div>
        <div class="grade-cap">Posture score</div></div>
    </div>
    <table class="cover-meta">
      <tr><td>Environment</td><td>Tenant {tenant}</td></tr>
      <tr><td>Assessment date</td><td>{date}</td></tr>
      <tr><td>Findings</td><td>{total} ({c} critical, {h} high, {m} medium, {lo} low)</td></tr>
      <tr><td>Scope</td><td>{subs} subscription(s), identity &amp; resource plane</td></tr>
    </table>
  </div>
  <div class="cover-foot">
    <span class="classif">Confidential</span>
    <span>Prepared for internal distribution</span>
  </div>
</div>

<section class="page-sec">
  <h2 class="sec-h" id="exec">Executive summary</h2>
  <div class="exec-grid">
    <div class="exec-badge grade-{gcls}">
      <div class="eb-grade">{grade}</div><div class="eb-cap">Overall grade</div>
    </div>
    <div class="sev-summary">{sev_summary}</div>
  </div>
  <div class="exec-text">{exec_paras}</div>
  <div class="exec-note">This report presents {total} findings across the assessed
    environment, ordered by severity. Each finding states the exposure, its business impact,
    a plausible attack scenario, the affected objects, and recommended remediation.</div>
</section>

<section class="page-sec toc-page">
  <h2 class="sec-h" id="toc">Contents</h2>
  <table class="toc">
    <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th class="tr">Page</th></tr></thead>
    <tbody>{toc_rows}</tbody>
  </table>
</section>

<section class="page-sec findings-start">
  <h2 class="sec-h" id="findings">Findings</h2>
  {findings}
</section>

{attackmap}

{hardening}

</body></html>"""


_CSS = r"""/* ===== Azure Identity Posture Assessment - print stylesheet (weasyprint) ===== */

:root{
  --ink:#141a26; --head:#0d1320; --muted:#6a7686; --faint:#9aa4b2;
  --brand:#1f3a5f; --brand-2:#2c5a8a; --line:#dce2ec; --panel:#f5f7fa;
  --crit:#b3261e; --high:#c05621; --med:#b7791f; --low:#2b6cb0;
}

/* ---- paged media ---------------------------------------------------------- */
@page{
  size:A4;
  margin:20mm 17mm 18mm 17mm;
  @top-left{
    content:"Azure Identity Posture Assessment";
    font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size:7.5pt; letter-spacing:.3pt; color:#9aa4b2;
    padding-bottom:3mm;
  }
  @top-right{
    content:"Confidential";
    font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size:7.5pt; letter-spacing:1pt; text-transform:uppercase; color:#b3261e;
    padding-bottom:3mm;
  }
  @bottom-left{
    content:"Identity security assessment \2014 internal distribution";
    font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size:7.5pt; color:#9aa4b2; padding-top:3mm;
  }
  @bottom-right{
    content:"Page " counter(page) " of " counter(pages);
    font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;
    font-size:7.5pt; color:#6a7686; padding-top:3mm;
  }
}
/* hairline rules in the margins, drawn via border on the page box is not
   possible; instead the first content block carries a top rule (see .sec-h). */

@page cover{
  margin:0;
  @top-left{content:none} @top-right{content:none}
  @bottom-left{content:none} @bottom-right{content:none}
}

/* ---- base ----------------------------------------------------------------- */
*{box-sizing:border-box}
body{
  font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;
  color:var(--ink); font-size:9.6pt; line-height:1.5; margin:0;
  hyphens:manual;
}
h1,h2,h3{color:var(--head); margin:0}
p{margin:0 0 6pt}
a{color:inherit; text-decoration:none}
.mono{font-family:"SFMono-Regular",Menlo,Consolas,monospace}

/* ---- cover ---------------------------------------------------------------- */
.cover{page:cover; position:relative; height:297mm; width:210mm;
  page-break-after:always; overflow:hidden}
.cover-band{position:absolute; top:0; left:0; right:0; height:96mm;
  background:linear-gradient(150deg,#1f3a5f 0%,#16293f 100%)}
.cover-band::after{content:""; position:absolute; left:0; right:0; bottom:0;
  height:4mm; background:var(--crit)}
.cover-body{position:absolute; top:118mm; left:22mm; right:22mm}
.cover-kicker{position:absolute; top:-82mm; left:0; color:#a8c6e6;
  font-size:9pt; letter-spacing:3.5pt; text-transform:uppercase; font-weight:600}
.cover-title{position:absolute; top:-70mm; left:0; right:0;
  font-family:Georgia,"Times New Roman",serif; font-weight:600;
  font-size:33pt; line-height:1.12; color:#fff; letter-spacing:.2pt}
.cover-sub{position:absolute; top:-34mm; left:0; color:#cdd9e8; font-size:11pt}
.cover-grade{display:flex; align-items:center; gap:7mm; margin-top:6mm}
.grade-badge{width:26mm; height:26mm; border-radius:4mm; color:#fff;
  font-family:Georgia,serif; font-size:30pt; font-weight:700;
  display:flex; align-items:center; justify-content:center}
.grade-meta .grade-score{font-size:20pt; font-weight:700; color:var(--head)}
.grade-meta .grade-score span{font-size:11pt; color:var(--muted); font-weight:400}
.grade-meta .grade-cap{font-size:8.5pt; letter-spacing:1.5pt; text-transform:uppercase;
  color:var(--muted)}
.cover-meta{margin-top:11mm; border-collapse:collapse; width:100%; font-size:10pt}
.cover-meta td{padding:3.2mm 0; border-bottom:.4pt solid var(--line); vertical-align:top}
.cover-meta td:first-child{color:var(--muted); width:38mm; font-size:8.5pt;
  letter-spacing:.5pt; text-transform:uppercase; padding-top:3.7mm}
.cover-foot{position:absolute; bottom:16mm; left:22mm; right:22mm;
  display:flex; justify-content:space-between; align-items:center;
  border-top:.6pt solid var(--line); padding-top:4mm;
  font-size:8.5pt; color:var(--muted)}
.classif{color:var(--crit); font-weight:700; letter-spacing:1.5pt; text-transform:uppercase}

/* grade colours */
.grade-a,.grade-b{background:#2f855a}
.grade-c{background:#b7791f}
.grade-d{background:#c05621}
.grade-f,.grade-na{background:#b3261e}

/* ---- section headers ------------------------------------------------------ */
.page-sec{padding-top:2mm}
.findings-start,.toc-page{page-break-before:always}
.sec-h{font-family:Georgia,"Times New Roman",serif; font-size:19pt; font-weight:600;
  color:var(--brand); padding-bottom:3mm; margin-bottom:6mm;
  border-bottom:1.4pt solid var(--brand); break-after:avoid; page-break-after:avoid}

/* ---- executive summary ---------------------------------------------------- */
.exec-grid{display:flex; gap:6mm; align-items:stretch; margin-bottom:7mm}
.exec-badge{width:34mm; border-radius:3mm; color:#fff; text-align:center;
  padding:6mm 0; display:flex; flex-direction:column; justify-content:center}
.exec-badge .eb-grade{font-family:Georgia,serif; font-size:34pt; font-weight:700; line-height:1}
.exec-badge .eb-cap{font-size:7.5pt; letter-spacing:1.5pt; text-transform:uppercase;
  margin-top:2mm; opacity:.9}
.sev-summary{flex:1; display:flex; gap:3mm}
.sev-cell{flex:1; border:.6pt solid var(--line); border-radius:2.5mm; padding:4mm 2mm;
  text-align:center; background:var(--panel)}
.sev-cell .sev-n{font-size:22pt; font-weight:700; line-height:1}
.sev-cell .sev-l{font-size:8pt; letter-spacing:1pt; text-transform:uppercase;
  color:var(--muted); margin-top:1.5mm}
.sev-critical .sev-n{color:var(--crit)} .sev-critical{border-top:2.4pt solid var(--crit)}
.sev-high .sev-n{color:var(--high)} .sev-high{border-top:2.4pt solid var(--high)}
.sev-medium .sev-n{color:var(--med)} .sev-medium{border-top:2.4pt solid var(--med)}
.sev-low .sev-n{color:var(--low)} .sev-low{border-top:2.4pt solid var(--low)}
.exec-text{font-size:10pt; line-height:1.62; text-align:justify}
.exec-text p{margin-bottom:7pt}
.exec-note{margin-top:6mm; padding:4mm 5mm; background:var(--panel);
  border-left:2.4pt solid var(--brand-2); font-size:9pt; color:#37414f; border-radius:0 2mm 2mm 0}

/* ---- contents ------------------------------------------------------------- */
.toc{width:100%; border-collapse:collapse; font-size:9.2pt}
.toc thead th{text-align:left; font-size:7.5pt; letter-spacing:1pt; text-transform:uppercase;
  color:var(--muted); border-bottom:.8pt solid var(--line); padding:0 3mm 2.5mm}
.toc th.tr{text-align:right}
.toc td{padding:2.4mm 3mm; border-bottom:.4pt solid #eef1f6; vertical-align:top}
.toc-id{font-family:Menlo,monospace; font-size:8pt; color:var(--muted); width:14mm; white-space:nowrap}
.toc-sev{width:20mm}
.toc-title{color:var(--ink)}
.toc-pg{text-align:right; color:var(--muted); font-size:8.5pt; width:12mm}
.toc-pg a::before{content:target-counter(attr(href), page)}

/* ---- severity group heads ------------------------------------------------- */
/* Each severity group opens on a fresh page (except the first, which sits under
   the "Findings" title). */
.sev-head{font-size:13pt; font-weight:700; margin:0 0 4mm; padding:2.5mm 4mm;
  border-radius:2mm; color:#fff; break-before:page; page-break-before:always;
  page-break-after:avoid; break-after:avoid; break-inside:avoid}
.sev-head-critical{background:var(--crit)}
.sev-head-high{background:var(--high)}
.sev-head-medium{background:var(--med)}
.sev-head-low{background:var(--low)}
.sev-head .sev-count{float:right; opacity:.85; font-weight:600}
.findings-start .sev-head:first-of-type{margin-top:4mm}
/* the first severity heading sits under the "Findings" title, not on its own page
   (:first-of-type fails here because the .sec-h is also an h2) */
.sec-h + .sev-head{break-before:avoid; page-break-before:avoid}

/* ---- finding -------------------------------------------------------------- */
/* One finding per page: each starts on a fresh page. The first finding in a
   group stays with its heading (so the heading is never stranded); a finding
   taller than a page still flows onto the next. */
.finding{border:.6pt solid var(--line); border-radius:2.5mm; padding:5mm 6mm 4mm;
  margin-bottom:5mm; break-inside:auto; break-before:page; page-break-before:always}
.sev-head + .finding, .section-intro + .finding{
  break-before:avoid; page-break-before:avoid}
.f-head{display:flex; align-items:baseline; gap:3mm; margin-bottom:2mm;
  break-after:avoid; break-inside:avoid; page-break-after:avoid}
.f-id{font-family:Menlo,monospace; font-size:8.5pt; color:var(--muted); white-space:nowrap}
.f-title{flex:1; font-size:12pt; font-weight:700; color:var(--head); line-height:1.28}
.am-subhead{font-size:13pt; font-weight:600; color:var(--head)}
.f-sev{white-space:nowrap}
.f-meta{margin-bottom:3.5mm; break-after:avoid; page-break-after:avoid}
.meta-tag{display:inline-block; font-size:7.5pt; color:#48525f; background:var(--panel);
  border:.5pt solid var(--line); border-radius:2mm; padding:1mm 2.4mm; margin-right:2mm; margin-bottom:1.5mm}
.meta-tag.mono{font-family:Menlo,monospace; letter-spacing:.2pt}
.f-sec{margin-bottom:3.5mm}
.f-lab{font-size:7.5pt; letter-spacing:1.2pt; text-transform:uppercase; color:var(--brand-2);
  font-weight:700; margin-bottom:1.5mm; break-after:avoid; page-break-after:avoid}
.f-sec p{margin:0; font-size:9.4pt; line-height:1.5; text-align:justify; orphans:3; widows:3}

/* affected-object table */
.ent{width:100%; border-collapse:collapse; font-size:8.6pt; margin-top:1mm}
.ent thead{display:table-header-group}   /* repeat header when the table breaks */
.ent tr{break-inside:avoid; page-break-inside:avoid}
.ent thead th{text-align:left; font-size:7pt; letter-spacing:.6pt; text-transform:uppercase;
  color:var(--muted); border-bottom:.6pt solid var(--line); padding:1.5mm 3mm 1.5mm 0}
.ent td{padding:1.6mm 3mm 1.6mm 0; border-bottom:.4pt solid #eef1f6; vertical-align:top}
.ent-name{font-weight:600; color:var(--head)}
.ent-kind{color:var(--muted); white-space:nowrap; width:32mm}
.ent-role{color:#48525f}

/* verification commands */
.cmd-label{font-size:7pt; letter-spacing:1pt; text-transform:uppercase; color:var(--muted);
  margin:2.5mm 0 1mm}
.cmd{font-family:Menlo,Consolas,monospace; font-size:8pt; line-height:1.5;
  background:#f0f3f7; border:.5pt solid var(--line); border-radius:2mm; padding:2.5mm 3mm;
  color:#2a3441; white-space:pre-wrap; word-break:break-all; margin:0}

/* severity chips */
.chip{display:inline-block; font-size:7.5pt; font-weight:700; letter-spacing:.5pt;
  text-transform:uppercase; padding:1mm 2.6mm; border-radius:10mm; color:#fff}
.chip-critical{background:var(--crit)} .chip-high{background:var(--high)}
.chip-medium{background:var(--med)} .chip-low{background:var(--low)}
.chip-info{background:#6a7686}

/* attack-path diagram (vertical kill-chain) - block layout; weasyprint balloons
   flex-item heights, so nodes are plain blocks with an absolutely-placed badge. */
.pathdiag{margin-top:2mm; break-inside:avoid}
.pnode{position:relative; width:118mm; max-width:100%;
  border:.7pt solid var(--brand-2); background:#eef3f9; border-radius:2mm; padding:2mm 26mm 2mm 3.5mm}
.pn-name{display:block; font-size:9pt; font-weight:700; color:var(--head); line-height:1.25}
.pn-kind{display:block; font-size:6.6pt; letter-spacing:.5pt; text-transform:uppercase; color:var(--muted)}
.pn-badge{position:absolute; right:3.5mm; top:50%; transform:translateY(-50%);
  font-size:6.4pt; letter-spacing:.6pt; text-transform:uppercase; color:var(--crit);
  border:.5pt solid var(--crit); border-radius:8mm; padding:.6mm 2.2mm; font-weight:700}
.pn-badge-start{color:var(--brand-2); border-color:var(--brand-2)}
.pnode-target{border-color:var(--crit); background:#fbecea}
.pnode-target .pn-name{color:var(--crit)}
.pnode-start{border-color:var(--brand); background:#eaf0f7}
.pconn{position:relative; height:8mm; margin-left:10mm; padding-left:6mm}
.pconn .pc-line{position:absolute; left:0; top:0; height:100%; border-left:1.3pt solid #93a7bc}
.pconn .pc-line::after{content:"\25BC"; position:absolute; left:-1.35mm; bottom:-.3mm;
  color:#93a7bc; font-size:7pt}
.pconn .pc-lab{position:absolute; left:6mm; top:50%; transform:translateY(-50%);
  font-family:Menlo,monospace; font-size:7pt; color:#4d5866;
  background:var(--panel); border:.4pt solid var(--line); border-radius:1.5mm; padding:.4mm 2mm}

/* compact affected-object list (large sets) */
.ent-compact{margin-top:1mm}
.ent-compact-head{font-size:8pt; font-weight:700; color:var(--head); margin-bottom:1.5mm}
.ent-grp{margin-bottom:2mm}
.ent-grp-lab{font-size:7pt; letter-spacing:.5pt; text-transform:uppercase; color:var(--brand-2);
  font-weight:700; margin-bottom:.6mm}
.ent-grp-n{color:var(--muted); font-weight:600}
.ent-grp-names{font-size:8pt; line-height:1.55; color:#37414f; word-break:break-word}

/* TOC subsection heading */
.toc-group td{padding-top:4mm; font-size:7.5pt; letter-spacing:1pt; text-transform:uppercase;
  color:var(--brand); font-weight:700; border-bottom:.8pt solid var(--line)}
.section-intro{font-size:9pt; color:var(--muted); margin:-2mm 0 5mm}
.hardening{border-left:2.4pt solid var(--low)}

/* cross-subscription tables */
.cs-table{width:100%; border-collapse:collapse; font-size:8.4pt; margin-top:1.5mm}
.cs-table thead th{text-align:left; font-size:7pt; letter-spacing:.5pt; text-transform:uppercase;
  color:var(--muted); border-bottom:.6pt solid var(--line); padding:1.6mm 3mm 1.6mm 0}
.cs-table td{padding:1.6mm 3mm 1.6mm 0; border-bottom:.4pt solid #eef1f6; vertical-align:top}
.cs-table tr{break-inside:avoid}
.cs-name{font-weight:600; color:var(--head)}
.cs-num{text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; width:16mm}
.cs-roles{color:#48525f}
.cs-t0{font-weight:700; color:var(--crit)}
.am-name{font-weight:600; color:var(--head)}
.am-arrow{color:var(--muted); padding:0 1mm}
.am-t0{font-weight:700; color:var(--crit)}
.mi-t0{font-weight:600; color:var(--crit)}
"""
