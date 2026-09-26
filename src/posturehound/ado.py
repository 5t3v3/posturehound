"""Azure DevOps work-item integration (opt-in addon).

Creates one ADO work item (default type: Feature) from a PostureHound finding, optionally
linked under a parent Epic, assigned to a person. Config is non-secret (Settings); the PAT is
env-only (PH_ADO_PAT) and is passed in explicitly - this module never reads or persists it.

HTTP is injectable (an httpx.Client can be supplied) so tests drive it with httpx.MockTransport
and no network, mirroring azure_arg/azure_graph.
"""
from __future__ import annotations

import base64
from typing import Any
from urllib.parse import quote

API_VERSION = "7.0"


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
    project = (cfg.get("ado_project") or "").strip()
    if not org or not project:
        raise AdoError("Azure DevOps org URL and project must be configured in Settings.")
    if not org.lower().startswith("https://"):
        raise AdoError("The Azure DevOps org URL must be an https:// address.")
    return org, project


def _esc(v: Any) -> str:
    s = "" if v is None else str(v)
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def map_finding(finding: dict, cfg: dict) -> dict:
    """Turn a finding into ADO work-item fields: {title, html, tags}."""
    sev = str(finding.get("severity") or "").strip() or "Info"
    title = f"[{sev}] {finding.get('title') or finding.get('rule_id') or 'Finding'}"
    title = title[:255]                                   # ADO title hard limit

    why = finding.get("why_it_matters") or finding.get("description") or ""
    rem = finding.get("remediation") or ""
    ents = finding.get("entities") or []
    ent_lines = []
    for e in ents[:50]:
        if isinstance(e, dict):
            nm = e.get("name") or e.get("id") or ""
            kind = (e.get("kind") or "").replace("AZ", "")
            ent_lines.append(f"<li>{_esc(nm)}{(' - ' + _esc(kind)) if kind else ''}</li>")
    more = len(ents) - 50
    if more > 0:
        ent_lines.append(f"<li>… and {more} more</li>")
    fw = finding.get("frameworks") or {}
    fw_str = ", ".join(f"{_esc(k)}: {_esc(v)}" for k, v in fw.items()) if isinstance(fw, dict) else ""

    parts = [f"<p><b>Severity:</b> {_esc(sev)}"]
    if finding.get("rule_id"):
        parts[0] += f" &nbsp;·&nbsp; <b>Rule:</b> {_esc(finding.get('rule_id'))}"
    parts[0] += "</p>"
    if why:
        parts.append(f"<p><b>Why it matters:</b> {_esc(why)}</p>")
    if rem:
        parts.append(f"<p><b>Remediation:</b> {_esc(rem)}</p>")
    if ent_lines:
        parts.append("<p><b>Affected objects:</b></p><ul>" + "".join(ent_lines) + "</ul>")
    if fw_str:
        parts.append(f"<p><b>Frameworks:</b> {fw_str}</p>")
    html = "".join(parts)

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
                parent_epic: str = "") -> list[dict]:
    """The JSON-Patch document sent to ADO to create the work item."""
    m = map_finding(finding, cfg)
    org, project = _base(cfg)
    ops = [
        {"op": "add", "path": "/fields/System.Title", "value": m["title"]},
        {"op": "add", "path": "/fields/System.Description", "value": m["html"]},
        {"op": "add", "path": "/fields/System.Tags", "value": "; ".join(m["tags"])},
    ]
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
                     parent_epic: str = "", client=None) -> dict:
    """Create the work item in ADO. Returns {id, url, type, assignee, parent_epic}."""
    if not pat:
        raise AdoError("No Azure DevOps PAT. Set the PH_ADO_PAT environment variable.")
    org, project = _base(cfg)
    wit = (cfg.get("ado_work_item_type") or "Feature").strip() or "Feature"
    patch = build_patch(finding, cfg, assignee=assignee, parent_epic=parent_epic)
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
            "assignee": assignee.strip(), "parent_epic": parent_epic.strip()}


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
