"""Azure DevOps work-item integration (opt-in addon).

Creates one ADO work item (default type: Feature) from a PostureHound finding, optionally
linked under a parent Epic, assigned to a person. Config is non-secret (Settings); the PAT is
env-only (PH_ADO_PAT) and is passed in explicitly, this module never reads or persists it.

HTTP is injectable (an httpx.Client can be supplied) so tests drive it with httpx.MockTransport
and no network, mirroring azure_arg/azure_graph.
"""
from __future__ import annotations

import base64
import datetime
import re
from typing import Any
from urllib.parse import quote, unquote

API_VERSION = "7.0"

# Remediation SLA window (weeks from creation) by severity. The user selects the severity and the
# target date is derived from this table, the tighter the severity, the sooner it is due.
SLA_WEEKS = {"Critical": 2, "High": 4, "Medium": 8, "Low": 12, "Info": 12}
# Severity -> ADO Priority (1 highest .. 4 lowest); Priority exists on Feature/Epic/Story/Bug.
_PRIORITY = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 4}
# Severity -> the Microsoft.VSTS.Common.Severity picklist value, set ONLY on types that carry it.
_SEVERITY_FIELD = {"Critical": "1 - Critical", "High": "2 - High", "Medium": "3 - Medium",
                   "Low": "4 - Low", "Info": "4 - Low"}
_SEVERITY_FIELD_TYPES = {"bug", "issue"}
# A Bug's main content field on its form is Repro Steps (Microsoft.VSTS.TCM.ReproSteps), not
# Description; the same formatted HTML is mirrored there for Bug work items. (The Basic-process
# "Issue" type has no Repro Steps field, so it is not included.)
_REPRO_STEPS_TYPES = {"bug"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


def _norm_severity(severity: str | None) -> str:
    s = (severity or "").strip().capitalize()
    return s if s in SLA_WEEKS else "Info"


def sla_weeks_for(severity: str | None) -> int:
    """Weeks until the remediation target date, by severity."""
    return SLA_WEEKS[_norm_severity(severity)]


def sla_target_date(severity: str | None, *, today: "datetime.date | None" = None) -> str:
    """The remediation target (SLA) date for a severity, as an ISO date string. Critical = 2
    weeks out, High = 4, Medium = 8, Low/Info = 12, derived purely from the severity."""
    today = today or datetime.date.today()
    return (today + datetime.timedelta(weeks=sla_weeks_for(severity))).isoformat()


class AdoError(RuntimeError):
    """A configuration or API error surfaced to the user (never contains the PAT)."""


def _client(client=None):
    if client is not None:
        return client
    import httpx
    return httpx.Client(timeout=30)


def _auth_header(pat: str) -> dict:
    token = base64.b64encode(f":{pat}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _base(cfg: dict) -> tuple[str, str]:
    org = (cfg.get("ado_org_url") or "").strip().rstrip("/")
    # A project pasted from a browser URL can arrive percent-encoded (e.g. "Sec%20Ops"). ADO
    # project names cannot contain a literal '%', so decoding here is safe and idempotent, and it
    # prevents the caller's quote() from double-encoding it into a 404 ("Sec%2520Ops").
    project = unquote((cfg.get("ado_project") or "").strip())
    if not org or not project:
        raise AdoError("Azure DevOps org URL and project must be configured in Settings.")
    if not org.lower().startswith("https://"):
        raise AdoError("The Azure DevOps org URL must be an https:// address.")
    return org, project


def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _block(v: Any) -> str:
    """Escape a value and preserve its line breaks as <br> for the ADO HTML description."""
    return _esc(v).replace("\n", "<br>")


# The ADO Description renders HTML but strips <style>/class, so every rule is inline. These neutral
# borders and a light label fill render cleanly on ADO's white work-item canvas.
_T_WRAP = ("border-collapse:collapse;width:100%;font-family:'Segoe UI',Arial,sans-serif;"
           "font-size:13px;line-height:1.5")
_T_LABEL = ("padding:7px 11px;border:1px solid #d9d9d9;background:#f5f6f8;font-weight:600;"
            "text-align:left;vertical-align:top;white-space:nowrap;width:180px")
_T_VALUE = "padding:7px 11px;border:1px solid #d9d9d9;text-align:left;vertical-align:top"
_T_HEAD = ("padding:5px 9px;border:1px solid #d9d9d9;background:#f5f6f8;font-weight:600;"
           "text-align:left;vertical-align:top")
_T_CELL = "padding:5px 9px;border:1px solid #d9d9d9;text-align:left;vertical-align:top"
_T_MONO = "font-family:Consolas,'Courier New',monospace;font-size:12px;word-break:break-all"
_LIST = "margin:0;padding-left:18px"
_CODE = ("margin:0;padding:8px 10px;background:#f5f6f8;border:1px solid #d9d9d9;border-radius:3px;"
         "font-family:Consolas,'Courier New',monospace;font-size:12px;white-space:pre-wrap;"
         "word-break:break-all")


def _entity_role(e: dict) -> str:
    """The scope / role / config evidence that locates an affected object for the fixer: a specific
    role_in_finding, else a couple of concrete evidence values, else empty (mirrors the report cell)."""
    r = str(e.get("role_in_finding") or "").strip()
    if r and not re.match(r"affected(\s|$)", r, re.I):
        return r
    ev = e.get("evidence")
    if isinstance(ev, dict):
        parts = [f"{k}: {v}" for k, v in list(ev.items())[:3]
                 if v not in (None, "", [], {}) and str(k).lower() not in ("confirmed", "subscription")]
        return "; ".join(parts)[:200]
    if isinstance(ev, str):
        return ev[:200]
    return ""


def _kv_row(label: str, value: str) -> str:
    """One label/value row of the main two-column description table (label pre-escaped/literal)."""
    return f'<tr><td style="{_T_LABEL}">{label}</td><td style="{_T_VALUE}">{value}</td></tr>'


def _nested_table(headers: "list[str]", rows: "list[list[str]]") -> str:
    """A bordered sub-table (pre-escaped cells) for the affected-objects / grouped-finding data."""
    head = "".join(f'<th style="{_T_HEAD}">{h}</th>' for h in headers)
    body = "".join("<tr>" + "".join(f'<td style="{_T_CELL}">{c}</td>' for c in r) + "</tr>"
                   for r in rows)
    return f'<table style="{_T_WRAP}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def map_finding(finding: dict, cfg: dict, *, severity: str | None = None) -> dict:
    """Turn a finding into ADO work-item fields: {title, html, tags}. A user-selected severity
    overrides the finding's own, so the work item's title, tags and SLA reflect the triage call.

    The description is a structured work item: a summary line (severity / priority / SLA / rule),
    then Why it matters, Impact, Attack scenario, numbered Remediation steps (the review-first and
    scope-down points when present), the per-identity finding list for a service-principal group,
    affected objects with their evidence, Acceptance criteria and Detection, so the assignee can
    reproduce the issue and knows exactly when it is done."""
    sev = _norm_severity(severity) if severity else (str(finding.get("severity") or "").strip() or "Info")
    target = sla_target_date(sev)
    rule_id = finding.get("rule_id")
    title = f"[{sev}] {finding.get('title') or rule_id or 'Finding'}"
    title = title[:255]                                   # ADO title hard limit

    # The report card pulls several sections from the rule catalog `detail` when the finding does
    # not carry its own, so mirror that precedence here, the ticket reads the same as the report.
    detail = finding.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    why = finding.get("why_it_matters") or detail.get("why") or finding.get("description") or ""
    impact = finding.get("impact") or detail.get("impact") or ""
    scenario = finding.get("attack_scenario") or detail.get("scenario") or ""
    detection = finding.get("detection") or detail.get("detection") or ""
    points = [str(p) for p in (finding.get("remediation_points") or []) if str(p).strip()]
    rem = finding.get("remediation") or ""
    grouped = finding.get("_grouped") or []
    ents = finding.get("entities") or []
    evidence = [str(e) for e in (finding.get("evidence") or []) if str(e).strip()]
    # Concrete fix material for the owning team: the exact commands and the authoritative doc links.
    commands = [str(c) for c in (finding.get("remediation_commands")
                                 or detail.get("commands") or []) if str(c).strip()]
    references = [r for r in (finding.get("references") or detail.get("references") or [])
                  if isinstance(r, str) and r.strip().lower().startswith("http")]

    # The whole description is one two-column (field / detail) table so it reads as a clean,
    # reviewable work item; the tabular data (affected objects, grouped findings) uses sub-tables.
    rows = [
        _kv_row("Severity", _esc(sev)),
        _kv_row("Priority", f"{_PRIORITY[sev]} <span style='color:#777'>(1 highest &ndash; 4 lowest)</span>"),
        _kv_row("Target date (SLA)", f"{_esc(target)} ({sla_weeks_for(sev)} weeks)"),
    ]
    if rule_id:
        rows.append(_kv_row("Rule", _esc(rule_id)))
    if finding.get("category"):
        rows.append(_kv_row("Category", _esc(finding.get("category"))))
    if why:
        rows.append(_kv_row("Why it matters", _block(why)))
    if impact:
        rows.append(_kv_row("Impact", _block(impact)))
    if scenario:
        rows.append(_kv_row("Attack scenario", _block(scenario)))

    # Remediation: the ordered review-first / scope-down points when present, else the one-liner.
    if points:
        rem_html = (f'<ol style="{_LIST}">'
                    + "".join(f"<li>{_block(p)}</li>" for p in points) + "</ol>")
        rows.append(_kv_row("Remediation steps", rem_html))
    elif rem:
        rows.append(_kv_row("Remediation", _block(rem)))

    # The exact commands the owning team runs to fix it (az / PowerShell / portal), copy-pasteable.
    if commands:
        rows.append(_kv_row("Remediation commands",
                            f'<pre style="{_CODE}">{_esc(chr(10).join(commands[:40]))}</pre>'))

    # Service-principal group: a table of the individual findings to clear on this one identity.
    if grouped:
        g_rows = []
        for g in grouped[:50]:
            if not isinstance(g, dict):
                continue
            g_rows.append([_esc(g.get("severity") or ""), _esc(g.get("rule_id") or ""),
                           _esc(g.get("title") or ""), _esc(g.get("evidence") or "")])
        if len(grouped) > 50:
            g_rows.append([f"… and {len(grouped) - 50} more", "", "", ""])
        if g_rows:
            rows.append(_kv_row("Findings to remediate on this identity",
                                _nested_table(["Severity", "Rule", "Finding", "Evidence"], g_rows)))
    else:
        # Affected objects: Name / Type / Scope-or-role / Resource id, so the owning team can locate
        # the exact object (which subscription, which role assignment, which scope) and fix it.
        e_rows = []
        show_id = False
        for e in ents[:50]:
            if isinstance(e, dict):
                nm = e.get("name") or e.get("id") or ""
                kind = (e.get("kind") or "").replace("AZ", "")
                role = _entity_role(e)
                rid = str(e.get("id") or "")
                rid_cell = rid if rid and rid != nm else ""      # hide when the id is just the name
                if rid_cell:
                    show_id = True
                e_rows.append([_esc(nm), _esc(kind), _esc(role),
                               f'<span style="{_T_MONO}">{_esc(rid_cell)}</span>' if rid_cell else ""])
        if len(ents) > 50:
            e_rows.append([f"… and {len(ents) - 50} more", "", "", ""])
        if e_rows:
            headers = ["Name", "Type", "Scope / role"] + (["Resource id"] if show_id else [])
            if not show_id:
                e_rows = [r[:3] for r in e_rows]
            rows.append(_kv_row(f"Affected objects ({len(ents)})",
                                _nested_table(headers, e_rows)))

        # Evidence (individual findings only): drop lines that merely restate an affected-object
        # name already shown above, so it appears only when it adds a scope / role / config value.
        if evidence:
            _norm = lambda s: re.sub(r"\s*\([^)]*\)\s*$", "", str(s)).strip().lower()
            ent_names = {_norm(e.get("name") or e.get("id") or "")
                         for e in ents if isinstance(e, dict)}
            ent_names.discard("")
            extra = [e for e in evidence if _norm(e) not in ent_names]
            if extra:
                ev_html = (f'<ul style="{_LIST}">'
                           + "".join(f"<li>{_block(e)}</li>" for e in extra[:20]))
                if len(extra) > 20:
                    ev_html += f"<li>… and {len(extra) - 20} more</li>"
                ev_html += "</ul>"
                rows.append(_kv_row("Evidence", ev_html))

    # Acceptance criteria: an unambiguous definition of done for the assignee.
    done_scope = "these findings" if grouped else (f"this finding ({_esc(rule_id)})" if rule_id
                                                   else "this finding")
    acc_html = (f'<ul style="{_LIST}">'
                "<li>The flagged access is removed, or scoped to the minimum the workload "
                "demonstrably needs, following the remediation steps above.</li>"
                f"<li>A re-scan no longer reports {done_scope}.</li></ul>")
    rows.append(_kv_row("Acceptance criteria", acc_html))

    if detection:
        rows.append(_kv_row("Detection &amp; monitoring", _block(detection)))

    fw = finding.get("frameworks") or {}
    fw_str = ", ".join(f"{_esc(k)}: {_esc(v)}" for k, v in fw.items()) if isinstance(fw, dict) else ""
    if fw_str:
        rows.append(_kv_row("Frameworks", fw_str))

    # Authoritative guidance the owning team can follow (Microsoft Learn / CIS, etc.).
    if references:
        ref_html = (f'<ul style="{_LIST}">' + "".join(
            f'<li><a href="{_esc(r)}" rel="noopener">{_esc(r)}</a></li>' for r in references[:10]) + "</ul>")
        rows.append(_kv_row("References", ref_html))

    html = f'<table style="{_T_WRAP}"><tbody>' + "".join(rows) + "</tbody></table>"

    tags = []
    for t in (cfg.get("ado_tags") or "").split(","):
        t = t.strip()
        if t:
            tags.append(t)
    tags += ["PostureHound", sev]
    if finding.get("rule_id"):
        tags.append(str(finding["rule_id"]))
    # de-dup, preserve order
    seen, out = set(), []
    for t in tags:
        if t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return {"title": title, "html": html, "tags": out}


def build_patch(finding: dict, cfg: dict, *, assignee: str = "",
                parent_epic: str = "", severity: str | None = None,
                work_item_type: str = "Feature") -> list[dict]:
    """The JSON-Patch document sent to ADO to create the work item."""
    sev = _norm_severity(severity) if severity else (str(finding.get("severity") or "").strip() or "Info")
    m = map_finding(finding, cfg, severity=sev)
    org, project = _base(cfg)
    # The SLA / remediation target date, derived from the selected severity. ADO date fields are
    # DateTime, so send a full ISO-8601 instant (midnight UTC), a date-only string can silently fail
    # to populate on some processes.
    sla_dt = sla_target_date(sev) + "T00:00:00Z"
    ops = [
        {"op": "add", "path": "/fields/System.Title", "value": m["title"]},
        {"op": "add", "path": "/fields/System.Description", "value": m["html"]},
        {"op": "add", "path": "/fields/System.Tags", "value": "; ".join(m["tags"])},
        # Standard Target Date (available on Feature/Epic/User Story/Bug), set to the severity SLA.
        {"op": "add", "path": "/fields/Microsoft.VSTS.Scheduling.TargetDate", "value": sla_dt},
        # Priority (1 highest .. 4 lowest) tracks severity and exists on every common type.
        {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": _PRIORITY[sev]},
    ]
    # Optional custom SLA field: orgs whose process has its own "SLA Due Date" (or similar) field map
    # its reference name in Settings (ado_sla_field, e.g. "Custom.SLADueDate"); it gets the SAME
    # severity-driven date as Target Date, so both read identically.
    sla_field = (cfg.get("ado_sla_field") or "").strip()
    if sla_field:
        fld = sla_field if sla_field.startswith("/fields/") else f"/fields/{sla_field}"
        ops.append({"op": "add", "path": fld, "value": sla_dt})
    # The dedicated Severity picklist exists only on Bug/Issue; setting it on a Feature 400s,
    # so it is added only when the target type carries it.
    if (work_item_type or "").strip().lower() in _SEVERITY_FIELD_TYPES:
        ops.append({"op": "add", "path": "/fields/Microsoft.VSTS.Common.Severity",
                    "value": _SEVERITY_FIELD[sev]})
    # A Bug surfaces its content in the Repro Steps field, not Description, so mirror the SAME
    # formatted HTML there for Bug work items. Description stays set too, for other views / queries.
    if (work_item_type or "").strip().lower() in _REPRO_STEPS_TYPES:
        ops.append({"op": "add", "path": "/fields/Microsoft.VSTS.TCM.ReproSteps",
                    "value": m["html"]})
    area = (cfg.get("ado_area_path") or "").strip()
    if area:
        ops.append({"op": "add", "path": "/fields/System.AreaPath", "value": area})
    assignee = (assignee or "").strip()
    if assignee:
        ops.append({"op": "add", "path": "/fields/System.AssignedTo", "value": assignee})
    parent_epic = (parent_epic or "").strip()
    if parent_epic:
        if not parent_epic.isdigit():
            raise AdoError("Parent Epic must be a numeric work-item id.")
        ops.append({"op": "add", "path": "/relations/-", "value": {
            "rel": "System.LinkTypes.Hierarchy-Reverse",
            "url": f"{org}/{project}/_apis/wit/workItems/{parent_epic}",
        }})
    return ops


def create_work_item(cfg: dict, pat: str, finding: dict, *, assignee: str = "",
                     parent_epic: str = "", severity: str | None = None, client=None) -> dict:
    """Create the work item in ADO. Returns {id, url, type, assignee, parent_epic, severity,
    target_date}. A user-selected `severity` drives the title, priority and the SLA target date."""
    if not pat:
        raise AdoError("No Azure DevOps PAT. Set the PH_ADO_PAT environment variable.")
    org, project = _base(cfg)
    wit = (cfg.get("ado_work_item_type") or "Feature").strip() or "Feature"
    sev = _norm_severity(severity) if severity else (str(finding.get("severity") or "").strip() or "Info")
    patch = build_patch(finding, cfg, assignee=assignee, parent_epic=parent_epic,
                        severity=sev, work_item_type=wit)
    url = f"{org}/{quote(project)}/_apis/wit/workitems/${quote(wit)}?api-version={API_VERSION}"
    headers = {**_auth_header(pat), "Content-Type": "application/json-patch+json"}
    c = _client(client)
    try:
        resp = c.post(url, json=patch, headers=headers)
    except Exception as e:                                # network / TLS
        raise AdoError(f"Could not reach Azure DevOps: {e}") from e
    if resp.status_code == 401 or resp.status_code == 203:
        raise AdoError("Azure DevOps rejected the PAT (401). Check PH_ADO_PAT scope (Work Items: Read & Write).")
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except Exception:
            detail = (resp.text or "")[:200]
        raise AdoError(f"Azure DevOps returned {resp.status_code}: {detail}")
    data = resp.json()
    wid = data.get("id")
    html_url = (((data.get("_links") or {}).get("html") or {}).get("href")
                or f"{org}/{quote(project)}/_workitems/edit/{wid}")
    return {"id": wid, "url": html_url, "type": wit,
            "assignee": assignee.strip(), "parent_epic": parent_epic.strip(),
            "severity": sev, "target_date": sla_target_date(sev)}


def delete_work_item(cfg: dict, pat: str, work_item_id, *, destroy: bool = False, client=None) -> dict:
    """Delete a work item in Azure DevOps so the finding can be re-raised. Soft-deletes to the project
    Recycle Bin by default (recoverable); destroy=True removes it permanently. Returns {id, destroyed}.
    A 404 is treated as already-gone (success), so a stale local record can always be cleared."""
    if not pat:
        raise AdoError("No Azure DevOps PAT. Set the PH_ADO_PAT environment variable.")
    if not str(work_item_id).strip().isdigit():
        raise AdoError("Invalid work-item id.")
    org, project = _base(cfg)
    url = (f"{org}/{quote(project)}/_apis/wit/workitems/{work_item_id}"
           f"?api-version={API_VERSION}" + ("&destroy=true" if destroy else ""))
    c = _client(client)
    try:
        resp = c.delete(url, headers=_auth_header(pat))
    except Exception as e:                                # network / TLS
        raise AdoError(f"Could not reach Azure DevOps: {e}") from e
    if resp.status_code == 404:
        return {"id": int(work_item_id), "destroyed": destroy}   # already gone; clear the local record
    if resp.status_code in (401, 203):
        raise AdoError("Azure DevOps rejected the PAT (401). Check PH_ADO_PAT scope (Work Items: Read & Write).")
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = resp.json().get("message", "")
        except Exception:
            detail = (resp.text or "")[:200]
        raise AdoError(f"Azure DevOps returned {resp.status_code}: {detail}")
    return {"id": int(work_item_id), "destroyed": destroy}


def test_connection(cfg: dict, pat: str, client=None) -> dict:
    """Validate the org/project/PAT by reading the project. Returns {ok, project} or raises."""
    if not pat:
        raise AdoError("No Azure DevOps PAT. Set the PH_ADO_PAT environment variable.")
    org, project = _base(cfg)
    url = f"{org}/_apis/projects/{quote(project)}?api-version={API_VERSION}"
    c = _client(client)
    try:
        resp = c.get(url, headers=_auth_header(pat))
    except Exception as e:
        raise AdoError(f"Could not reach Azure DevOps: {e}") from e
    if resp.status_code in (401, 203):
        raise AdoError("Azure DevOps rejected the PAT (401). Check the token and its scope.")
    if resp.status_code == 404:
        raise AdoError(f"Project '{project}' not found at {org}.")
    if resp.status_code >= 400:
        raise AdoError(f"Azure DevOps returned {resp.status_code}.")
    name = ""
    try:
        name = resp.json().get("name", project)
    except Exception:
        name = project
    return {"ok": True, "project": name}
