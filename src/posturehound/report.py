"""Enterprise analyst-console report generator (single self-contained file).

Design: a security analyst's console grounded in the tool's own world - attack
graphs and privilege-escalation lineage. Technical artifacts (object ids, edges,
evidence) are set in monospace; human narrative in a sans face. The signature
element is the Attack Paths view: every finding.s maximum-impact path, the cross-
subscription bridges. All values are escaped; the page ships with no external
requests so it works offline and within a strict CSP.
"""
from __future__ import annotations

import json


def _regroup_path_findings(result: dict) -> dict:
    """Consolidate path_consolidation findings where multiple individual-user
    entries all start with MemberOf to the same group into one group-level finding.
    This fixes old scans saved before the group-source BFS change, so every
    report view gets the consolidated presentation regardless of scan age.
    """
    from collections import defaultdict, Counter

    findings = result.get("findings", [])
    path_f   = [f for f in findings if f.get("source") == "path_consolidation"]
    other_f  = [f for f in findings if f.get("source") != "path_consolidation"]
    if not path_f:
        return result

    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

    # Bucket findings: if ALL paths for a finding start with MemberOf to the
    # same group, that group is the "effective source" → group by group_id.
    group_buckets: dict = defaultdict(list)   # group_id → [(finding, ginfo)]
    keep_as_is:    list = []

    for f in path_f:
        all_paths = f.get("all_paths") or []
        if not all_paths:
            keep_as_is.append(f)
            continue

        first_groups: set = set()
        ginfo_map:    dict = {}
        for ap in all_paths:
            hops = ap.get("hops") or []
            if hops and hops[0].get("edge") == "MemberOf":
                gid = hops[0].get("to_id", "")
                first_groups.add(gid)
                if gid and gid not in ginfo_map:
                    ginfo_map[gid] = {"id": gid,
                                      "name": hops[0].get("to_name", gid),
                                      "kind": "AZGroup"}
            else:
                first_groups.add("")   # sentinel: not a group-starting path

        if len(first_groups) == 1 and "" not in first_groups:
            gid = next(iter(first_groups))
            group_buckets[gid].append((f, ginfo_map.get(gid, {"id": gid,
                                                               "name": gid,
                                                               "kind": "AZGroup"})))
        else:
            keep_as_is.append(f)

    merged: list = []
    for group_id, bucket in group_buckets.items():
        ginfo      = bucket[0][1]
        group_name = ginfo.get("name", group_id)
        member_count = len(bucket)

        # Build unique paths stripped of the leading MemberOf hop.
        seen_keys:     set  = set()
        merged_paths:  list = []

        for f, _ in bucket:
            for ap in (f.get("all_paths") or []):
                hops = ap.get("hops") or []
                if hops and hops[0].get("edge") == "MemberOf":
                    stripped = hops[1:]
                else:
                    stripped = hops

                if stripped:
                    key = tuple((h.get("from_id",""), h.get("edge",""),
                                 h.get("to_id","")) for h in stripped)
                else:
                    # 1-hop: group IS the tier-0 target
                    key = ("__tier0__", group_id, ap.get("dst_id",""))

                if key in seen_keys:
                    continue
                seen_keys.add(key)

                new_ap = dict(ap)
                new_ap["src_id"]   = group_id
                new_ap["src_name"] = group_name
                new_ap["src_kind"] = "AZGroup"

                if stripped:
                    new_ap["hops"]      = stripped
                    new_ap["hop_count"] = len(stripped)
                    parts = [stripped[0].get("from_name", group_name)]
                    for h in stripped:
                        parts.append(f"-[{h['edge']}]→ {h.get('to_name','?')}")
                    new_ap["path"] = " ".join(parts)
                else:
                    # Group is directly tier-0: show as 0-hop membership note
                    new_ap["hops"]      = []
                    new_ap["hop_count"] = 0
                    new_ap["path"]      = f"{group_name} → [direct Tier-0 membership]"
                    new_ap["top_edge"]  = "MemberOf"

                merged_paths.append(new_ap)

        if not merged_paths:
            keep_as_is.extend(f for f, _ in bucket)
            continue

        merged_paths.sort(key=lambda p: (
            sev_rank.get(p.get("severity", "Medium"), 2), p.get("hop_count", 0)))

        worst_sev   = min((p.get("severity","Medium") for p in merged_paths),
                         key=lambda s: sev_rank.get(s, 4))
        sev_counts  = Counter(p.get("severity","Medium") for p in merged_paths)
        n           = len(merged_paths)
        worst       = max(merged_paths, key=lambda p: p.get("path_score", 0))
        shortest    = min(merged_paths, key=lambda p: p.get("hop_count", 999))
        unique_tgts = list(dict.fromkeys(p.get("dst_name","") for p in merged_paths))
        sev_str     = ", ".join(f"{v} {k}" for k, v in sev_counts.items() if v)

        merged.append({
            "source":        "path_consolidation",
            "title":         (f"{group_name} ({member_count} member(s)) → "
                              f"{n} path(s) to tier-0 ({worst_sev})"),
            "severity":      worst_sev,
            "confidence":    None,
            "category":      "Attack Path",
            "entities":      [{**ginfo, "role_in_finding": "Attack entry point"}],
            "summary": (
                f"{group_name} ({member_count} member(s)) has {n} path(s) to "
                f"tier-0 ({sev_str}). "
                f"Shortest: {shortest.get('hop_count','?')}-hop via "
                f"{shortest.get('top_edge','?')} → {shortest.get('dst_name','?')}."
            ),
            "what": (f"{n} independent escalation route(s) from this group to "
                     f"tier-0 target(s): {', '.join(unique_tgts[:3])}."),
            "reasoning": "",
            "why_it_matters": (
                f"Any single path is sufficient for compromise. "
                f"An attacker controlling any of the {member_count} member(s) "
                f"of {group_name} has {n} escalation option(s)."
            ),
            "attack_scenario":      shortest.get("path", ""),
            "escalation_chain":     [],
            "evidence":             [p.get("path","") for p in merged_paths[:10]],
            "remediation":          (f"Remove the group’s privileged access or "
                                     f"restrict {group_name} membership."),
            "remediation_commands": [],
            "detection":            "",
            "mitre_technique":      "T1078",
            "exploitability":       "Established",
            "review_note":          "",
            "_specialist":          "path_consolidation",
            "path_count":           n,
            "paths_by_severity":    dict(sev_counts),
            "shortest_path":        shortest,
            "worst_path":           worst,
            "all_paths":            merged_paths,
            "top_edge":             worst.get("top_edge", ""),
            "unique_targets":       unique_tgts,
            "member_count":         member_count,
        })

    # Second consolidation: collapse findings that share the SAME SET of terminal chokepoints
    # (each an edge → Tier-0 target). This subsumes two cases with one rule:
    #   * single-edge dupes  - many principals with one shared route (e.g. CanAddMember on a group);
    #   * identical cohorts   - principals with the exact same multi-route profile (e.g. 12 members
    #                           of the same two Tier-0 groups, or 7 SPs that can add members to the
    #                           same 9 groups).
    # The MemberOf pass above already folds pure membership chains; a principal with a UNIQUE
    # escalation profile stays its own finding.
    _EDGE_PHRASE = {"CanAddMember": "add-member rights on", "CanAddOwner": "add-owner rights on",
                    "CanGrantRole": "role-grant rights on", "CanAddSecret": "credential-add rights on",
                    "CanResetPassword": "password-reset rights on", "Owns": "ownership of",
                    "MemberOf": "membership in"}

    def _phrase(edge: str, name: str) -> str:
        return f"{_EDGE_PHRASE.get(edge, edge or 'a direct edge to')} '{name}'"

    def _chokepoint_sig(f: dict):
        pairs = set()
        for ap in (f.get("all_paths") or []):
            hops = ap.get("hops") or []
            if hops:
                pairs.add((hops[-1].get("edge") or "", ap.get("dst_id") or "", ap.get("dst_name") or ""))
        return frozenset(pairs)

    sig_buckets: dict = defaultdict(list)
    leftover: list = []
    for f in keep_as_is:
        sig = _chokepoint_sig(f)
        (sig_buckets[sig].append(f) if sig else leftover.append(f))

    edge_merged: list = []
    for sig, bucket in sig_buckets.items():
        if len(bucket) < 2:                       # unique profile → keep individual
            leftover.extend(bucket)
            continue
        pairs = sorted(sig, key=lambda x: (x[2] or "").lower())
        ents: list = []
        all_p: list = []
        for bf in bucket:
            for e in (bf.get("entities") or []):
                ents.append({**e, "role_in_finding": "Attack entry point"})
            all_p.extend(bf.get("all_paths") or [])
        worst_sev = min((bf.get("severity", "Medium") for bf in bucket),
                        key=lambda s: sev_rank.get(s, 4))
        n = len(bucket)
        k = len(pairs)
        tgt_names = list(dict.fromkeys(p[2] for p in pairs))
        if k == 1:
            edge, _did, dname = pairs[0]
            via = _phrase(edge, dname)
            title = f"{n} principals → tier-0 via {via} ({worst_sev})"
            summary = (f"{n} distinct principals each reach Tier-0 in one step through {via}. "
                       f"One chokepoint, {n} entry points - fixing '{dname}' closes all {n} routes.")
            what = f"{n} principals hold {via} the Tier-0 asset."
            why = (f"The blast radius is {n} accounts wide but the remediation is single-point: "
                   f"restrict {via}.")
            remediation = f"Restrict who holds {via}, or reduce what it grants."
        else:
            shown = ", ".join(_phrase(e, nm) for e, _i, nm in pairs[:4]) + (f" +{k - 4} more" if k > 4 else "")
            title = f"{n} principals share the same {k}-route escalation to tier-0 ({worst_sev})"
            summary = (f"{n} distinct principals have the identical escalation profile ({k} routes): "
                       f"{shown}. Same cohort, same fix - remediate these {k} chokepoints once "
                       f"instead of triaging {n} look-alike findings.")
            what = f"{n} principals each reach Tier-0 through the same {k} chokepoint(s)."
            why = (f"{n} accounts share one blast radius; closing the {k} shared chokepoint(s) "
                   f"neutralises the whole cohort.")
            remediation = f"Remediate the {k} shared chokepoint(s): " + "; ".join(
                _phrase(e, nm) for e, _i, nm in pairs[:6])
        edge_merged.append({
            "source": "path_consolidation", "category": "Attack Path", "severity": worst_sev,
            "confidence": None, "title": title, "entities": ents, "summary": summary, "what": what,
            "reasoning": "", "why_it_matters": why,
            "attack_scenario": (all_p[0].get("path", "") if all_p else ""),
            "escalation_chain": [], "evidence": [p.get("path", "") for p in all_p[:15]],
            "remediation": remediation, "remediation_commands": [], "detection": "",
            "mitre_technique": "T1078", "exploitability": "Established", "review_note": "",
            "_specialist": "path_consolidation", "path_count": n,
            "paths_by_severity": dict(Counter(p.get("severity", "Medium") for p in all_p)),
            "shortest_path": (all_p[0] if all_p else None),
            "worst_path": (all_p[0] if all_p else None), "all_paths": all_p,
            "top_edge": (pairs[0][0] if pairs else ""), "unique_targets": tgt_names, "member_count": n,
        })

    result = dict(result)
    result["findings"] = other_f + leftover + edge_merged + merged
    return result


def _synthesize_path_findings(result: dict) -> dict:
    """Build Attack-Path findings from the deterministic `attack_paths` list.

    Attack paths are computed by the deterministic pipeline (scoring.compute_attack_paths)
    and stored on every scan, but the Attack Paths tab was gated solely on
    `path_consolidation` findings and `chokepoints`, both of which only the AI pipeline
    produces. So a scan run without an API key stored 100 paths (90 Critical) and 10
    chokepoints and then hid all of them - the single largest piece of value lost when
    AI is unavailable. This converts the stored paths into the same shape the AI path
    findings use, so the existing view (and _regroup_path_findings) works unchanged.
    """
    from collections import Counter

    paths = result.get("attack_paths") or []
    existing = [f for f in (result.get("findings") or [])
                if f.get("source") == "path_consolidation"]
    if not paths or existing:
        return result   # nothing to do, or the AI already produced them

    by_entry: dict[str, list[dict]] = {}
    for p in paths:
        eid = p.get("entry_id") or p.get("entry") or ""
        if eid:
            by_entry.setdefault(eid, []).append(p)

    def _as_path(p: dict) -> dict:
        hops = p.get("hops") or []
        chain = ""
        if hops:
            chain = hops[0].get("from_name", "")
            for h in hops:
                chain += f" -[{h.get('primitive','?')}]→ {h.get('to_name','?')}"
        return {
            "src_id":     p.get("entry_id", ""),
            "src_name":   p.get("entry", ""),
            "src_kind":   p.get("entry_kind", ""),
            "dst_id":     p.get("target_id", ""),
            "dst_name":   p.get("target", ""),
            "hop_count":  p.get("length", len(hops)),
            "top_edge":   (hops[0].get("primitive", "") if hops else ""),
            "severity":   "Critical" if p.get("critical") else "High",
            "path":       chain or f"{p.get('entry','?')} → {p.get('target','?')}",
            # Shorter paths are more exploitable; used only for worst-path selection.
            "path_score": 10 - min(p.get("length", 1), 9),
            # Carry the hops in the shape _regroup_path_findings reads (edge/from_id/
            # to_id) so its group-collapse actually triggers. compute_attack_paths emits
            # {from,to,primitive}; without this remap the regroup saw no hops and left
            # every member of a big Tier-0 group (e.g. 291 Developers) as its
            # own path finding instead of one group-level cluster.
            "hops": [{"from_id": h.get("from", ""), "to_id": h.get("to", ""),
                      "from_name": h.get("from_name", ""), "to_name": h.get("to_name", ""),
                      "edge": h.get("primitive", "")} for h in hops],
        }

    synthesized: list[dict] = []
    for eid, group in by_entry.items():
        mapped = sorted((_as_path(p) for p in group),
                        key=lambda x: (x["severity"] != "Critical", x["hop_count"]))
        sev_counts = Counter(m["severity"] for m in mapped)
        worst_sev = "Critical" if sev_counts.get("Critical") else "High"
        shortest = min(mapped, key=lambda m: m["hop_count"])
        worst = max(mapped, key=lambda m: m["path_score"])
        targets = list(dict.fromkeys(m["dst_name"] for m in mapped))
        first = group[0]
        n = len(mapped)
        sev_str = ", ".join(f"{v} {k}" for k, v in sev_counts.items() if v)
        ent = {"id": eid, "name": first.get("entry", eid),
               "kind": first.get("entry_kind", "Unknown"),
               "role_in_finding": "Attack entry point"}
        synthesized.append({
            "source": "path_consolidation", "category": "Attack Path",
            "title": (f"{first.get('entry', eid)} → {n} path(s) to tier-0 ({worst_sev})"),
            "severity": worst_sev, "confidence": None,
            "entities": [ent],
            "summary": (f"{first.get('entry', eid)} has {n} escalation path(s) to a "
                        f"tier-0 target ({sev_str}). Shortest: "
                        f"{shortest['hop_count']}-hop via {shortest['top_edge']} → "
                        f"{shortest['dst_name']}."),
            "what": (f"{n} independent escalation route(s) to tier-0 target(s): "
                     f"{', '.join(targets[:3])}."),
            "reasoning": "",
            "why_it_matters": ("Any single path is sufficient for compromise - an attacker "
                               f"controlling this principal has {n} escalation option(s)."),
            "attack_scenario": shortest["path"],
            "escalation_chain": [],
            "evidence": [m["path"] for m in mapped[:10]],
            "remediation": ("Break the shortest path first: remove the privilege or "
                            "membership that the first hop depends on."),
            "remediation_commands": [], "detection": "",
            "mitre_technique": "T1078", "exploitability": "Established",
            "review_note": "",
            "_specialist": "deterministic_paths",
            "path_count": n, "paths_by_severity": dict(sev_counts),
            "shortest_path": shortest, "worst_path": worst, "all_paths": mapped,
            "top_edge": worst["top_edge"], "unique_targets": targets,
            "member_count": 1,
        })

    result = dict(result)
    result["findings"] = list(result.get("findings") or []) + synthesized
    # Surface the deterministic chokepoints under the key and field names the view reads.
    # analytics.choke_points carries {id, name: "Display (AZKind)", paths_through}; the
    # view expects node_name/node_kind/path_count/coverage_pct/unique_source_count.
    if not result.get("chokepoints"):
        chokes = ((result.get("analytics") or {}).get("choke_points") or [])
        total = len(paths) or 1
        mapped_chokes = []
        for c in chokes:
            raw = str(c.get("name") or c.get("node_name") or "?")
            name, kind = raw, str(c.get("kind") or c.get("node_kind") or "")
            if raw.endswith(")") and "(" in raw:          # "Platform Engineers (AZGroup)"
                name, _, tail = raw.rpartition(" (")
                kind = kind or tail[:-1]
            cid = c.get("id") or c.get("node_id") or ""
            # Count traversals of the STORED path set, not analytics.paths_through, which
            # is computed over the uncapped traversal (817 on this tenant) while the
            # report only holds 100. Mixing the two showed "324 paths" beside a "100 total
            # routes" tile. Fall back to the analytics figure only if nothing matches.
            traversing = [p for p in paths
                          if any(h.get("to") == cid or h.get("from") == cid
                                 for h in (p.get("hops") or []))]
            through = len(traversing)
            full = int(c.get("paths_through") or 0)
            srcs = sorted({p.get("entry", "") for p in traversing} - {""})
            mapped_chokes.append({
                "node_name": name, "node_kind": kind, "node_id": cid,
                "path_count": through,
                "coverage_pct": round(100 * min(through, total) / total),
                "unique_source_count": len(srcs),
                "unique_sources": srcs[:12],
                "critical_count": sum(1 for p in traversing if p.get("critical")),
                "high_count": 0,
                "action": (
                    f"Reduce privilege on or restrict membership of {name} - hardening it "
                    f"severs more paths than any single downstream fix."
                    + (f" It sits on {through} of the {total} route(s) shown here."
                       if through else "")
                    + (f" Across the full uncapped graph traversal it appears on {full} "
                       f"path(s); only {total} routes are retained in this report, so its "
                       f"paths above may be a subset." if full > through else "")),
                "remediation_commands": [],
            })
        if mapped_chokes:
            result["chokepoints"] = mapped_chokes
    return result


def finalize_findings(result: dict) -> dict:
    """The single authoritative consolidation of a scan's findings.

    Synthesizes Attack-Path findings from the deterministic `attack_paths` (so no-API-key
    scans still get them), then collapses the per-principal path rows into one finding per
    shared chokepoint. Every consumer - the interactive findings API, the HTML/PDF report,
    the history count, the scan diff - must see findings THROUGH here, so the on-screen list
    can never again disagree with the report. In practice this is enforced at the two store
    chokepoints (`save_scan` on write, `get_scan` on read); callers that build a result
    without going through the store (the CLI) call this directly.

    Idempotent: a `_paths_consolidated` marker makes a second call a no-op, so applying it at
    write time AND read time (and defensively in the renderers) is safe and cheap.
    """
    if not isinstance(result, dict) or result.get("_paths_consolidated"):
        return result
    result = _regroup_path_findings(_synthesize_path_findings(result))
    # Give every non-AI finding a concrete, entity-grounded summary + evidence list so a
    # no-AI report reads specifically, not as a generic rule dump. Deterministic and
    # idempotent; skips AI and attack-path findings (which carry their own narrative).
    from . import describe
    for _f in result.get("findings") or []:
        describe.enrich(_f)
    # Order findings worst-first. Synthesis/regroup append path findings out of order,
    # so re-sort the whole list by severity here at the single chokepoint (stable, so
    # ties keep run_rules' rule-id order). Every consumer then gets severity order.
    _sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings = result.get("findings")
    if isinstance(findings, list):
        result["findings"] = sorted(
            findings, key=lambda f: _sev_rank.get((f or {}).get("severity"), 5))
    result["_paths_consolidated"] = True
    return result


def render_html(result: dict, nonce: str | None = None) -> str:
    result = finalize_findings(result)   # no-op when the store already finalized it
    data = json.dumps(result, ensure_ascii=False).replace("<", "\\u003c")
    nonce_attr = f' nonce="{nonce}"' if nonce else ""
    return (_SHELL
            .replace("__NONCE_ATTR__", nonce_attr)
            .replace("/*__CSS__*/", _CSS)
            .replace("//__JS__", _JS)
            .replace('"__POSTUREHOUND_DATA__"', data))


_SHELL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PostureHound - Identity Posture</title>
<style>/*__CSS__*/</style></head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand"><span class="mark"><svg viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" width="26" height="26" aria-hidden="true"><defs><linearGradient id="phbg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#F09432"/><stop offset="100%" stop-color="#C05C08"/></linearGradient></defs><rect width="32" height="32" rx="8" fill="url(#phbg)"/><ellipse cx="9" cy="21" rx="4" ry="10" fill="#0b0d14"/><ellipse cx="23" cy="21" rx="4" ry="10" fill="#0b0d14"/><circle cx="16" cy="13" r="9.5" fill="#0b0d14"/><circle cx="12" cy="12" r="2.4" fill="#F09432"/><circle cx="20" cy="12" r="2.4" fill="#F09432"/><circle cx="12" cy="12" r="0.9" fill="#0b0d14"/><circle cx="20" cy="12" r="0.9" fill="#0b0d14"/><ellipse cx="16" cy="19.5" rx="3" ry="2.2" fill="#5a2a04"/></svg></span>
      <div><div class="brand-name">PostureHound</div><div class="brand-sub">identity posture</div></div></div>
    <nav id="nav"></nav>
    <div class="side-foot" id="sideFoot"></div>
  </aside>
  <main class="main">
    <header class="topbar" id="topbar"></header>
    <div class="view" id="view"></div>
  </main>
</div>
<div id="toast" class="reporttoast" role="status"></div>
<script__NONCE_ATTR__>const DATA = "__POSTUREHOUND_DATA__";
//__JS__
</script></body></html>"""


_CSS = """
:root{
 --bg:#0A0C12; --surface:#11151F; --raised:#171C29; --hover:#1E2433;
 --border:#242C3D; --border-2:#323B50;
 --tx:#EAEDF4; --tx2:#9BA5BC; --tx3:#5C667E;
 --accent:#D98A4B; --accent-dim:#7a5430;
 --crit:#F25C70; --high:#FF914D; --med:#F2C14E; --low:#5B9CF0; --info:#7A849A; --good:#3FC8A0;
 --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
 --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,system-ui,sans-serif;
}
*{box-sizing:border-box} html,body{margin:0}
body{background:var(--bg);color:var(--tx);font-family:var(--sans);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--low);text-decoration:none} a:hover{text-decoration:underline}
.mono{font-family:var(--mono)}
.app{display:grid;grid-template-columns:248px 1fr;min-height:100vh}

.sidebar{background:var(--surface);border-right:1px solid var(--border);position:sticky;top:0;height:100vh;display:flex;flex-direction:column;padding:20px 14px}
.brand{display:flex;gap:11px;align-items:center;padding:6px 8px 18px}
.brand .mark svg{display:block;flex:none}
.brand-name{font-weight:650;letter-spacing:.2px}
.brand-sub{font-size:11px;color:var(--tx3);letter-spacing:.08em;text-transform:uppercase}
#nav{display:flex;flex-direction:column;gap:2px;margin-top:6px}
.navitem{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:8px;color:var(--tx2);cursor:pointer;border:1px solid transparent;font-weight:500}
.navitem:hover{background:var(--hover);color:var(--tx)}
.navitem.active{background:var(--raised);color:var(--tx);border-color:var(--border-2)}
.navitem .ico{width:16px;text-align:center;color:var(--tx3)}
.navitem.active .ico{color:var(--accent)}
.navitem .ct{margin-left:auto;font-size:11px;color:var(--tx3);font-family:var(--mono)}
.side-foot{margin-top:auto;padding:12px 10px 2px;border-top:1px solid var(--border);color:var(--tx3);font-size:11.5px;font-family:var(--mono);line-height:1.7}

.main{min-width:0}
.topbar{position:sticky;top:0;z-index:5;background:rgba(10,12,18,.82);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:16px;padding:14px 28px}
.topbar h1{font-size:15px;font-weight:600;margin:0;white-space:nowrap;flex:none}
.topbar .tenant{color:var(--tx3);font-family:var(--mono);font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;flex-shrink:1}
.topbar .spacer{margin-left:auto}
.gradechip{display:flex;align-items:center;gap:8px;padding:5px 12px;border:1px solid var(--border-2);border-radius:999px;background:var(--raised);font-size:12.5px;color:var(--tx2)}
.homelink{color:var(--tx2);font-size:13px;font-weight:600;padding:5px 11px;border:1px solid var(--border-2);border-radius:8px;white-space:nowrap}
.homelink:hover{color:var(--tx);border-color:var(--accent-dim)}
.pdfbtn{background:var(--accent);border:0;color:#1a0f06;font-weight:700;padding:7px 14px;border-radius:8px;cursor:pointer;font-size:12.5px}
.pdfbtn:hover{filter:brightness(1.07)}
button{font-family:var(--sans)}
.ghost{background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--tx2);padding:3px 9px;font-size:12px;cursor:pointer;font-family:var(--sans);transition:border-color .15s,color .15s}
.ghost:hover{border-color:var(--border-2);color:var(--tx)}
.ghost.copied{border-color:var(--good);color:var(--good)}
.gradechip b{font-size:14px}
.view{padding:26px 28px 80px;max-width:1180px}

h2.section{font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--tx3);margin:34px 0 14px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px}
.muted{color:var(--tx2)} .small{font-size:12.5px}

.hero{display:grid;grid-template-columns:auto 1fr;gap:26px;align-items:center}
.ring{position:relative;width:128px;height:128px;flex:none}
.ring .grade{position:absolute;top:0;left:0;right:0;bottom:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring .glet{font-size:44px;font-weight:700;line-height:1}
.ring .gsc{font-size:12px;color:var(--tx3);font-family:var(--mono);margin-top:2px}
.posture h1{font-size:22px;margin:0 0 8px;font-weight:650;letter-spacing:-.01em}
.posture p{margin:0;color:var(--tx2);max-width:62ch}
.ai-tag{display:inline-flex;gap:6px;align-items:center;font-size:11px;color:var(--accent);border:1px solid var(--accent-dim);border-radius:6px;padding:1px 7px;margin-bottom:8px;font-weight:600;letter-spacing:.03em}

.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:18px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:11px;padding:14px 15px}
.tile .n{font-size:26px;font-weight:680;font-family:var(--mono);letter-spacing:-.02em}
.tile .l{color:var(--tx3);font-size:11.5px;margin-top:3px;text-transform:uppercase;letter-spacing:.05em}

.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;border:1px solid var(--border);margin:6px 0 12px}
.sevbar > span{cursor:pointer;transition:filter .15s} .sevbar > span:hover{filter:brightness(1.18)}
.sevleg{display:flex;flex-wrap:wrap;gap:14px}
.sevleg .it{display:flex;align-items:center;gap:7px;cursor:pointer;color:var(--tx2);font-size:12.5px;padding:3px 6px;border-radius:6px}
.sevleg .it:hover{background:var(--hover);color:var(--tx)}
.dot{width:9px;height:9px;border-radius:3px;flex:none}
.sevleg .it b{font-family:var(--mono);color:var(--tx)}

.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.maximpact{border-left:3px solid var(--crit)}
.maximpact .path{font-family:var(--mono);font-size:12.5px;color:var(--tx2);margin-top:8px}
.cov{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.cov ul{margin:6px 0 0;padding-left:18px;color:var(--tx2)} .cov li{margin:3px 0}
.cov .na li{color:var(--tx3)}

.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.search{flex:1;min-width:200px;background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:9px 12px;color:var(--tx);font-family:var(--sans)}
.search::placeholder{color:var(--tx3)}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{padding:6px 11px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--tx2);cursor:pointer;font-size:12.5px;font-weight:550;display:flex;gap:7px;align-items:center}
.chip:hover{background:var(--hover);color:var(--tx)} .chip.on{border-color:var(--border-2);background:var(--raised);color:var(--tx)}
.chip-path{border-color:rgba(242,92,112,.35);color:var(--crit)} .chip-path:hover{background:rgba(242,92,112,.1);color:var(--crit)}
.chip .c{font-family:var(--mono);font-size:11px;color:var(--tx3)}

.finding{border:1px solid var(--border);border-radius:11px;margin-bottom:9px;background:var(--surface);overflow:hidden}
.finding.bp{opacity:.92}
.fhead{display:flex;flex-wrap:wrap;align-items:center;gap:9px 13px;padding:13px 15px;cursor:pointer}
.fhead:hover{background:var(--hover)}
.sevtick{width:4px;align-self:stretch;border-radius:3px;flex:none;margin:-13px 0;margin-right:2px}
.fhead .rid{font-family:var(--mono);font-size:11.5px;color:var(--tx3);min-width:96px}
.fhead .ftitle{font-weight:560;flex:1 1 300px;overflow-wrap:break-word}
.fhead .ftags{margin-left:auto;flex:1 1 auto;min-width:0;display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;align-items:center}
.fcopy{border:1px solid var(--border);background:var(--raised);color:var(--tx2);border-radius:6px;padding:3px 9px;font-size:11px;line-height:1.35;cursor:pointer;white-space:nowrap}
.fcopy:hover{background:var(--hover);color:var(--tx)}
.fcopy.copied{color:#4ecf8f;border-color:#4ecf8f}
.sevtag{font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:6px;color:#0A0C12;letter-spacing:.02em}
.cattag{font-size:11px;color:var(--tx3);font-family:var(--mono);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px}
.fcount{font-size:11px;color:var(--tx2);font-family:var(--mono);background:var(--raised);border:1px solid var(--border);padding:2px 8px;border-radius:6px}
.chev{color:var(--tx3);transition:transform .2s;font-size:11px}
.finding.open .chev{transform:rotate(90deg)}
.fbody{display:none;border-top:1px solid var(--border);padding:18px 18px 20px;background:var(--bg)}
.finding.open .fbody{display:block}
.fbody h4{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--tx3);margin:18px 0 7px;font-weight:650}
.fbody h4:first-child{margin-top:0}
.fbody p{margin:0;color:var(--tx);max-width:78ch}
.kvs{display:flex;flex-wrap:wrap;gap:7px;margin:4px 0 2px}
.fw{font-size:11px;color:var(--tx2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;font-family:var(--mono)}
.steps{margin:0;padding-left:0;list-style:none;counter-reset:s}
.steps li{counter-increment:s;position:relative;padding:7px 0 7px 34px;border-bottom:1px solid var(--border);color:var(--tx)}
.steps li:last-child{border-bottom:0}
.steps li::before{content:counter(s);position:absolute;left:0;top:6px;width:22px;height:22px;border-radius:6px;background:var(--raised);border:1px solid var(--border-2);font-family:var(--mono);font-size:11px;color:var(--accent);display:flex;align-items:center;justify-content:center}
.etable{width:100%;border-collapse:collapse;margin-top:4px;font-size:12.5px}
.etable th{text-align:left;color:var(--tx3);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:6px 10px;border-bottom:1px solid var(--border)}
.etable td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.etable td.nm{font-family:var(--mono);color:var(--tx)} .etable td.kd{font-family:var(--mono);color:var(--tx3)}
.etable td.ev{font-family:var(--mono);color:var(--tx2);font-size:11.5px}
.detect{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:11px 13px;color:var(--tx2);font-size:12.5px}
.aibox{border:1px solid var(--accent-dim);background:linear-gradient(180deg,rgba(217,138,75,.06),transparent);border-radius:9px;padding:13px 15px;margin-top:6px}
.aibox .ah{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px}
.aibox.empty{border-style:dashed;border-color:var(--border-2);background:none}
.aibox.empty .ah{color:var(--tx3)}

.rankrow{display:flex;align-items:center;gap:9px;padding:6px 0;border-bottom:1px solid var(--border)}
.rankrow:last-child{border-bottom:0}
.rankrow .ix{font-family:var(--mono);color:var(--accent);font-size:12px;width:18px}
.rankrow .nm{font-size:12.5px} .rankrow .v{margin-left:auto;font-family:var(--mono);font-size:11.5px;color:var(--tx2)}

.reporttoast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);background:var(--raised);border:1px solid var(--border-2);border-radius:10px;padding:10px 18px;font-size:13px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:60}
.reporttoast.show{opacity:1}
.statuspill{display:inline-block;font-size:10px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--raised);color:var(--tx3);border:1px solid var(--border-2)}
.statuspill.st-New{color:var(--tx3)}
.statuspill.st-Acknowledged{color:var(--low);border-color:var(--low)}
.statuspill.st-InProgress{color:var(--med);border-color:var(--med)}
.statuspill.st-Resolved{color:var(--good);border-color:var(--good)}
.statuspill.st-RiskAccepted{color:var(--tx2);border-color:var(--border-2)}
.statussel{background:var(--bg);border:1px solid var(--border-2);border-radius:8px;padding:6px 10px;color:var(--tx);font-size:12.5px;font-family:inherit}
.roadrow{display:flex;gap:14px;align-items:flex-start;padding:12px 0;border-top:1px solid var(--border)}
.roadrow:first-of-type{border-top:0}
.roadmain{flex:1}
.roadstatus{flex:0 0 auto}

.banner{border-radius:11px;padding:13px 15px;margin-bottom:14px;border:1px solid var(--border-2);background:var(--raised)}
.banner.warn{border-color:var(--high);background:rgba(255,145,76,.07)}
.banner.ai{border-color:var(--accent-dim);background:rgba(217,138,75,.07)}
.srctag{font-size:10.5px;padding:2px 8px;border-radius:999px;font-weight:600;white-space:nowrap}
.srctag.ai{background:rgba(217,138,75,.16);color:var(--accent)}
.srctag.path{background:rgba(242,92,112,.14);color:var(--crit)}
.pathf .fhead{border-left:3px solid var(--crit)}
.pathconsolcard .pathlist{overflow-x:auto}
.pathrow td{padding:5px 8px;border-bottom:1px solid var(--border);font-size:12px}
.chokerow{border-bottom:1px solid var(--border);padding:8px 0}
.chokerow:last-child{border-bottom:none}
.chokehead{display:flex;align-items:center;gap:6px;flex-wrap:wrap;cursor:pointer;user-select:none}
.chokedetail{display:none;padding:8px 0 4px 26px}
.chokerow.open .chokedetail{display:block}
.cmdblock{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-top:6px}
.roadmain{flex:1;min-width:0}
.srctag.det{background:rgba(91,179,224,.14);color:var(--low)}
.chaingraph{background:var(--raised);border:1px solid var(--border);border-radius:10px;padding:14px 18px;margin:6px 0 14px}
.reasoning{background:var(--raised);border-left:3px solid var(--accent);border-radius:6px;padding:11px 14px;font-size:13px;line-height:1.6;color:var(--tx2);white-space:pre-wrap}
.reviewnote{background:rgba(217,138,75,.08);border:1px solid var(--accent-dim);border-radius:8px;padding:9px 13px;margin-bottom:12px;font-size:12.5px;color:var(--tx2)}
.confbadge{font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.confbadge.high{background:rgba(86,192,138,.14);color:var(--good)}
.confbadge.mid{background:rgba(232,194,87,.14);color:var(--med)}
.confbadge.low{background:rgba(242,92,112,.14);color:var(--crit)}
.confbadge.verified{background:rgba(91,179,224,.14);color:var(--low)}
.tierbadge{font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
.tierbadge.tb-vf{background:rgba(91,179,224,.16);color:var(--low)}
.tierbadge.tb-cor{background:rgba(86,192,138,.16);color:var(--good)}
.tierbadge.tb-sup{background:rgba(232,194,87,.16);color:var(--med)}
.tierbadge.tb-lead{background:rgba(242,92,112,.16);color:var(--crit)}
.vlabel{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:2px 0 4px}
.vbtn{font-size:12px;font-weight:600;padding:5px 12px;border-radius:6px;border:1px solid var(--border);background:var(--bg2,transparent);color:var(--tx2);cursor:pointer}
.vbtn:hover{border-color:var(--tx3)}
.vbtn.tp.on{background:rgba(86,192,138,.18);color:var(--good);border-color:var(--good)}
.vbtn.fp.on{background:rgba(242,92,112,.18);color:var(--crit);border-color:var(--crit)}
.vbtn.un.on{background:rgba(232,194,87,.18);color:var(--med);border-color:var(--med)}
.adobox,.adowi{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:2px 0 4px}
.adobox input{background:var(--bg);border:1px solid var(--border-2);border-radius:8px;padding:6px 10px;color:var(--tx);font-size:12.5px;font-family:inherit;min-width:190px}
.adocreate{font-size:12px;font-weight:600;padding:6px 14px;border-radius:6px;border:1px solid var(--accent);background:var(--accent);color:#1a0f06;cursor:pointer}
.adocreate:hover{filter:brightness(1.07)}.adocreate:disabled{opacity:.55;cursor:default}
.adolink{font-size:12.5px;font-weight:600;color:var(--accent);text-decoration:none}.adolink:hover{text-decoration:underline}
.vhint{font-size:11px;color:var(--tx3)}
.qgrid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.qgrid .qspan{grid-column:1 / -1}
@media(max-width:820px){.qgrid{grid-template-columns:1fr}}
.qtr{display:flex;align-items:center;gap:10px;margin:7px 0}
.qtl{width:120px;flex:none}
.qbar{flex:1;height:9px;background:var(--border);border-radius:999px;overflow:hidden}
.qbfill{height:100%;border-radius:999px}
.qbfill.tbf-vf{background:var(--low)} .qbfill.tbf-cor{background:var(--good)} .qbfill.tbf-sup{background:var(--med)} .qbfill.tbf-lead{background:var(--crit)}
.qtn{width:88px;text-align:right;font-size:12px;color:var(--tx2);font-variant-numeric:tabular-nums}
.qbig{font-size:32px;font-weight:800;color:var(--good);margin:8px 0 4px}
.qbigu{font-size:13px;font-weight:500;color:var(--tx3);margin-left:8px}
.qok{color:var(--good);font-size:13px;margin:8px 0 0} .qwarn{color:var(--med);font-size:13px;margin:8px 0 0}
.qoverall{font-size:15px} .qspan h3,.qgrid h3{margin-top:0}
.bhtiles{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:4px}
.bhtile{background:var(--raised);border:1px solid var(--border);border-radius:10px;padding:10px 16px;min-width:120px}
.bhtile .n{font-size:22px;font-weight:700;color:var(--tx);font-family:var(--mono)}
.bhtile .l{font-size:11px;color:var(--tx3);margin-top:2px}
.section-head h2{font-size:19px;font-weight:600;margin:0 0 4px}
.section-sub{color:var(--tx3);font-size:13px;margin:0;max-width:80ch;line-height:1.55}
.cardh{font-size:14px;font-weight:600;margin:0 0 10px}
.csbtable th{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--tx3);font-weight:600;text-align:left;padding:6px 10px;border-bottom:1px solid var(--border)}
.csbtable td{padding:7px 10px;border-bottom:1px solid var(--border-2);font-size:13px;vertical-align:top}
.csbtable td.nm{font-weight:600;color:var(--tx)}
.mg-tag{font-size:10px;font-weight:600;color:var(--accent);border:1px solid var(--border-2);border-radius:5px;padding:1px 5px;margin-left:4px;white-space:nowrap}
.t0-yes{color:var(--crit);font-weight:600;font-size:12px}
.bhtile-hi .n{color:#c46fff}
/* maximum-impact path block */
.miblock{background:linear-gradient(90deg,rgba(196,111,255,.05),transparent);border:1px solid var(--border-2);border-left:3px solid rgba(196,111,255,.5);border-radius:0 8px 8px 0;padding:10px 14px;margin:12px 0}
.miblock.mi-crit{border-left-color:var(--crit);background:linear-gradient(90deg,rgba(255,90,90,.06),transparent)}
.mi-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;margin-bottom:8px}
.mi-label{font-size:12px;font-weight:700;letter-spacing:.02em;color:var(--tx)}
.mi-t0{font-size:11px;font-weight:700;color:var(--crit);border:1px solid rgba(255,90,90,.4);border-radius:5px;padding:1px 6px}
.mi-subs{font-size:11px;font-weight:700;color:var(--accent);border:1px solid var(--border-2);border-radius:5px;padding:1px 6px;white-space:nowrap}
.xsubbadge{font-size:10.5px;font-weight:700;padding:2px 9px;border-radius:999px;background:rgba(120,160,255,.14);color:var(--accent);white-space:nowrap}
.xsub-inline{color:var(--accent);font-weight:700;white-space:nowrap}
.mi-chain{display:flex;flex-wrap:wrap;align-items:center;gap:5px;margin-bottom:6px}
.mi-node{background:var(--raised);border:1px solid var(--border-2);border-radius:6px;padding:3px 9px;font-size:12.5px;white-space:normal;overflow-wrap:break-word;max-width:100%}
.mi-node.mi-entry{border-color:var(--border-2)}
.mi-node.mi-tgt{border-color:rgba(196,111,255,.5);color:#c46fff;font-weight:600}
.mi-crit .mi-node.mi-tgt{border-color:rgba(255,90,90,.5);color:var(--crit)}
.mi-edge{font-size:10.5px;color:var(--tx3);position:relative;padding:0 3px}
.mi-edge:before{content:'→ ';color:var(--tx3)}
.mi-summary{font-size:12.5px;color:var(--tx2);margin:6px 0}
.mi-cohnote{font-size:12px;color:var(--sev-high,#d97706);margin:6px 0;line-height:1.5}
.mi-arrow{color:var(--tx3);text-align:center}
.techsummary{border:1px solid var(--border-2);border-radius:10px;overflow:hidden;margin:10px 0 16px;background:#05070C}
.techhead{display:flex;align-items:center;justify-content:space-between;padding:9px 14px;background:var(--raised);border-bottom:1px solid var(--border-2)}
.techlabel{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--tx3)}
.techconf{font-size:11px;font-family:var(--mono);color:var(--accent)}
.techbody{padding:13px 15px;font-size:13px;line-height:1.65;color:var(--tx2);white-space:pre-wrap}
.reviewnote .rnl{display:block;font-size:10.5px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--accent);margin-bottom:3px}
.banner h3{margin:0 0 6px;font-size:12.5px;display:flex;align-items:center;gap:8px}
.banner h3 .bi{color:var(--high)}
.banner ul{margin:0;padding-left:18px;color:var(--tx2);font-size:12.5px}
.banner li{margin:3px 0}
.banner .wl{font-family:var(--mono);font-size:10px;color:var(--tx3);margin-right:6px}
.pathitem{display:block;width:100%;text-align:left;border:1px solid var(--border);background:var(--raised);border-radius:9px;padding:10px 11px;margin-bottom:7px;cursor:pointer;color:var(--tx)}
.pathitem:hover{border-color:var(--border-2)} .pathitem.sel{border-color:var(--crit);background:rgba(242,92,112,.08)}
.pathitem .pe{font-size:12.5px;font-weight:600} .pathitem .pt{font-family:var(--mono);font-size:11px;color:var(--tx3);margin-top:2px}
.pathitem .pb{display:flex;gap:8px;align-items:center;margin-top:6px}
.pbadge{font-size:10px;font-family:var(--mono);padding:1px 7px;border-radius:5px;border:1px solid var(--border-2);color:var(--tx2)}
.pbadge.crit{color:var(--crit);border-color:var(--crit)}
.pathdetail{margin-top:12px}
.hop{display:flex;align-items:flex-start;gap:11px;padding:9px 0;border-bottom:1px solid var(--border)}
.hop:last-child{border-bottom:0}
.hop .hx{font-family:var(--mono);color:var(--accent);font-size:11px;width:20px;flex:none;padding-top:2px}
.hop .hn{font-family:var(--mono);font-size:12.5px}
.hop .hp{display:inline-block;font-size:11px;color:var(--crit);font-family:var(--mono);border:1px solid var(--crit);border-radius:5px;padding:0 6px;margin:3px 0}
.hop .harrow{color:var(--tx3);margin:0 6px}
.catbars{display:flex;flex-direction:column;gap:7px;margin-top:4px}
.catrow{display:flex;align-items:center;gap:10px;font-size:12.5px}
.catrow .cl{width:210px;color:var(--tx2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.catrow .ct{flex:1;height:8px;background:var(--raised);border-radius:5px;overflow:hidden}
.catrow .cf{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent-dim))}
.catrow .cv{font-family:var(--mono);font-size:11.5px;color:var(--tx2);width:24px;text-align:right}

:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
@media (max-width:920px){
 .app{grid-template-columns:1fr} .sidebar{position:static;height:auto;flex-direction:row;flex-wrap:wrap;align-items:center}
 #nav{flex-direction:row;flex-wrap:wrap;margin:0} .side-foot{display:none} .brand{padding-bottom:0}
 .two,.cov{grid-template-columns:1fr}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
@media print{
 @page{margin:18mm 18mm 22mm;size:A4 portrait}
 html,body{font-size:11.5pt;line-height:1.55;background:#fff;color:#111}
 *{box-shadow:none!important;transition:none!important}
 .sidebar,.topbar,.navitem,.pdfbtn,.homelink,.fcopy{display:none!important}
 .app,.main{display:block}
 .main{margin:0;padding:0}
 .view{padding:0;max-width:none}
 /* suppress screen-only chrome */
 .toolbar{display:none!important}
 /* expand all findings */
 .finding .fbody{display:block!important}
 /* cards & tiles */
 .card{border:1px solid #ddd;background:#fff;break-inside:avoid}
 .tile{border:1px solid #ddd;background:#fff}
 .finding{break-inside:avoid;page-break-inside:avoid;border:1px solid #ddd;background:#fff;margin-bottom:8pt}
 /* severity color bars: keep colored ticks, neutralise backgrounds */
 .sevtick{print-color-adjust:exact;-webkit-print-color-adjust:exact}
 .sevtag{print-color-adjust:exact;-webkit-print-color-adjust:exact;color:#fff!important}
 /* links */
 a[href]{color:#1a56b0}
 /* section headings */
 h2.section{border-bottom:1.5px solid #ddd;padding-bottom:3pt;margin-top:20pt}
 /* override dark text vars to black */
 .muted,.tx2,.tx3{color:#444!important}
 .mono{font-family:ui-monospace,Menlo,Consolas,monospace}
 .two,.cov{grid-template-columns:1fr 1fr}
 /* finding titles: show full text in print (remove line-clamp) */
 .fhead .ftitle{display:block!important;overflow:visible!important;-webkit-line-clamp:unset!important}
 .cattag{white-space:normal!important;overflow:visible!important;text-overflow:clip!important;max-width:none!important}
 /* detection boxes */
 .detect{border:1px solid #ddd;background:#f8f8f8;color:#333}
 /* reasoning */
 .reasoning,.techbody{background:#f8f8f8;color:#333}
 .techsummary{border:1px solid #ddd;background:#f8f8f8}
}
"""


_JS = r"""
const SEV = {Critical:'var(--crit)',High:'var(--high)',Medium:'var(--med)',Low:'var(--low)',Info:'var(--info)'};
const ORD = ['Critical','High','Medium','Low','Info'];
const $ = (s,r=document)=>r.querySelector(s);
const qa = (s,r=document)=>Array.prototype.slice.call(r.querySelectorAll(s));
const el = (t,c,h)=>{const e=document.createElement(t);if(c)e.className=c;if(h!=null)e.innerHTML=h;return e;};
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]));
function toast(msg){ const t=$('#toast'); if(!t) return; t.textContent=msg; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2400); }
// Render one evidence value. Arrays of objects (e.g. a rule's list of {vault,subscription})
// must never fall through to Array.join, which stringifies each object as "[object Object]";
// pull a human label from each item and cap the list so a broad finding does not dump
// hundreds of entries into the cell.
function fmtEvVal(v){
  if(Array.isArray(v)){
    const parts=v.map(x=>{
      if(x&&typeof x==='object') return x.vault||x.name||x.id||Object.values(x).find(z=>typeof z==='string')||'';
      return x;
    }).filter(x=>x!==''&&x!=null);
    const shown=parts.slice(0,8);
    return shown.join(', ')+(parts.length>shown.length?` +${parts.length-shown.length} more`:'');
  }
  if(v&&typeof v==='object') return JSON.stringify(v);
  return v;
}
function fmtEv(o){if(!o||typeof o!=='object')return '';return Object.keys(o).map(k=>{
  return `<span class="tk">${esc(k)}</span> ${esc(fmtEvVal(o[k]))}`;}).join('&nbsp;&nbsp;');}

// Recompute severity counts from findings, excluding path_consolidation
// (those are shown separately in the Attack Paths tab - not in the main badge).
const counts = (()=>{
  const c={Critical:0,High:0,Medium:0,Low:0,Info:0};
  for(const f of DATA.findings){
    if(f.source==='path_consolidation') continue;
    if(c[f.severity]!==undefined) c[f.severity]++;
  }
  return c;
})();
const realF = DATA.findings.filter(f=>!f.best_practice && f.source!=='path_consolidation');
const bpF = DATA.findings.filter(f=>f.best_practice && f.source!=='path_consolidation');
const HAS_SCAN_ID = !!DATA._scan_id;
const OPEN_COUNT = DATA.findings.filter(f=>f.source!=='path_consolidation'&&!(f.status==='Resolved'||f.status==='Risk Accepted')).length;
const PH_CHOKES = DATA.chokepoints || [];
const PATH_FINDINGS = DATA.findings.filter(f=>f.source==='path_consolidation');
const HAS_PATHS = PATH_FINDINGS.length > 0 || PH_CHOKES.length > 0;
function copyText(txt, btn){
  navigator.clipboard.writeText(txt).then(()=>{
    if(!btn) return;
    const orig = btn.textContent;
    btn.textContent = '✓ Copied'; btn.classList.add('copied');
    setTimeout(()=>{btn.textContent=orig;btn.classList.remove('copied');}, 1800);
  }).catch(()=>{});
}
// Build a clean plain-text version of one finding card for the per-finding Copy button.
// The card body is display:none when collapsed and interactive controls add noise, so we
// clone it, force it open, strip buttons/selects/chevrons, and read the laid-out innerText.
function findingPlainText(card){
  const clone = card.cloneNode(true);
  clone.classList.add('open');                                  // reveal the collapsed body
  clone.querySelectorAll('button, select, .chev').forEach(n=>n.remove());
  clone.style.cssText = 'position:fixed;left:-99999px;top:0;display:block;width:820px';
  document.body.appendChild(clone);
  const txt = (clone.innerText || clone.textContent || '');
  clone.remove();
  return txt.replace(/[ \t]+\n/g,'\n').replace(/\n{3,}/g,'\n\n').trim();
}
function wireFindingCopy(card){
  const cb = card.querySelector('.fcopy');
  if(!cb) return;
  cb.onclick = (e)=>{ e.stopPropagation(); copyText(findingPlainText(card), cb); };
}
document.addEventListener('click', function(e){
  var btn = e.target.closest('[data-action]');
  if(!btn) return;
  if(btn.dataset.action === 'copy') copyText(btn.dataset.copytext, btn);
  else if(btn.dataset.action === 'goto-paths'){ e.preventDefault(); go('paths'); }
  else if(btn.dataset.action === 'toggle-paths'){
    var wrap = btn.closest('.pathconsolcard');
    if(wrap){ wrap.classList.toggle('expanded'); btn.textContent = wrap.classList.contains('expanded') ? '▲ Collapse paths' : '▼ Expand all paths'; }
  }
  else if(btn.dataset.action === 'toggle-choke'){
    var row = btn.closest('.chokerow');
    if(row){ row.classList.toggle('open'); btn.textContent = row.classList.contains('open') ? '▲' : '▼'; }
  }
});
// Cross-subscription blast radius is woven into the Attack Paths view and inline on every
// finding ("⇄ N subs") rather than living in its own menu.
const CROSSSUB = (DATA.analytics&&DATA.analytics.cross_subscription)||{};
const ATTACKMAP = DATA.attack_map || {paths:[],count:0,tier0_count:0};
const HAS_ATTACKMAP = (ATTACKMAP.paths||[]).length>0;
const NAV = [
 {id:'overview', label:'Overview', ico:'\u25C7'},
 {id:'findings', label:'Findings', ico:'\u25A4', ct:DATA.findings.filter(f=>f.source!=='path_consolidation').length},
 // One unified escalation view (max-impact paths + cross-subscription bridges + consolidated
 // routes + chokepoints). Shows whenever any of those exist.
 ...((HAS_ATTACKMAP||HAS_PATHS)?[{id:'paths', label:'Attack Paths', ico:'\u2316', ct:ATTACKMAP.count||PATH_FINDINGS.length||PH_CHOKES.length}]:[]),
 // Interactive graph explorer for this scan \u2014 reuses the live app's graph view (needs the
 // scan id + running server), so it only appears on a server-rendered report.
 ...(HAS_SCAN_ID?[{id:'graph', label:'Attack Graph', ico:'\u25c8'}]:[]),
 ...(HAS_SCAN_ID?[{id:'roadmap', label:'Action Plan', ico:'\u2611', ct:OPEN_COUNT}]:[]),
 {id:'quality', label:'Quality', ico:'\u25C9'},
 {id:'coverage', label:'Coverage', ico:'\u25F0'},
 ...((DATA.ai_usage&&DATA.ai_usage.total)?[{id:'usage', label:'AI Usage', ico:'\u25B0',
   ct:'$'+((DATA.ai_usage.estimated_cost_usd||0).toFixed(2))}]:[]),
];
let state = {section:(location.hash||'').replace('#','') || 'overview', sev:'all', q:'', bp:false, paths:false};
if(state.section==='attackmap') state.section='paths';   // Attack Map merged into Attack Paths
if(!NAV.find(n=>n.id===state.section)) state.section='overview';
function renderNav(){
 const n=$('#nav'); n.innerHTML='';
 NAV.forEach(it=>{const d=el('div','navitem'+(state.section===it.id?' active':''));
  d.innerHTML=`<span class="ico">${it.ico}</span><span>${it.label}</span>`+(it.ct!=null?`<span class="ct">${it.ct}</span>`:'');
  d.tabIndex=0; d.onclick=()=>go(it.id); d.onkeydown=e=>{if(e.key==='Enter')go(it.id);}; n.appendChild(d);});
 $('#sideFoot').innerHTML = `v${esc(DATA.tool_version)}<br>${esc(DATA.ingest_summary.total_records)} records<br>read-only`
   + (DATA._scan_id?`<br><a href="/api/scans/${esc(DATA._scan_id)}/collection" download="scan-${esc(DATA._scan_id)}-collection.json" style="color:var(--tx3)">⬇ collection JSON</a>`:'');
}
function topbar(){
 const g=DATA.score.grade, sc=DATA.score.score;
 const col=sc<40?'var(--crit)':sc<75?'var(--med)':'var(--good)';
 const genDate=new Date().toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});
 $('#topbar').innerHTML =
  `<a class="homelink" href="/" title="Back to PostureHound">\u2190 PostureHound</a>`+
  `<h1>Azure Identity Posture</h1>`+
  `<span class="tenant">tenant ${esc(DATA.tenant_id||'\u2014')} \u00B7 ${esc(genDate)}</span>`+
  `<span class="spacer"></span>`+
  `<span class="gradechip">grade <b style="color:${col}">${esc(g)}</b><span class="mono">${sc}/100</span></span>`+
  `<span class="gradechip" style="color:var(--crit)">${counts.Critical}\u00D7 critical</span>`+
  `<span class="gradechip" style="color:var(--high)">${counts.High}\u00D7 high</span>`+
  `<button class="pdfbtn" id="pdfbtn" title="Download the shareable assessment report as a PDF (no tool branding or links \u2014 safe to send to another team)">\u2193 Export PDF</button>`;
 var pb=$('#pdfbtn'); if(pb) pb.onclick=downloadPdf;
}
function downloadPdf(){
 // Open the shareable external report (server-rendered PDF): no tool branding,
 // no graph links, no URLs - the version handed to another team. The PDF route
 // is this page's path plus ".pdf": /api/scans/<id>/report -> .../report.pdf
 window.open(location.pathname+'.pdf','_blank','noopener');
}
function go(s){state.section=s;renderNav();render();window.scrollTo(0,0);}

function postureStatement(){
 if(DATA.ai_executive_summary) return esc(DATA.ai_executive_summary);
 const a=DATA.analytics, mi=a.maximum_impact_chain;
 let s=`This tenant scores <b>${DATA.score.grade}</b> (${DATA.score.score}/100). `;
 s+=`${counts.Critical} critical and ${counts.High} high findings were identified across ${realF.length} active issues. `;
 s+=`${a.tier0.length} principals hold Tier-0 privilege. `;
 if(mi) s+=`The largest single escalation entry point is <b>${esc(mi.principal)}</b>, which can reach ${mi.reachable_privileged_count} privileged target(s). `;
 s+=`${bpF.length} best-practice recommendations are listed separately as low priority.`;
 return s;
}
function ring(){
 const sc=DATA.score.score, r=56, c=2*Math.PI*r, off=c*(1-sc/100);
 const col=sc<40?'var(--crit)':sc<75?'var(--med)':'var(--good)';
 return `<div class="ring"><svg width="128" height="128" viewBox="0 0 128 128">
   <circle cx="64" cy="64" r="${r}" fill="none" stroke="var(--border)" stroke-width="10"/>
   <circle cx="64" cy="64" r="${r}" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round"
     stroke-dasharray="${c}" stroke-dashoffset="${off}" transform="rotate(-90 64 64)"/></svg>
   <div class="grade"><div class="glet" style="color:${col}">${esc(DATA.score.grade)}</div><div class="gsc">${sc}/100</div></div></div>`;
}
function sevBar(){
 const tot=ORD.reduce((s,k)=>s+counts[k],0)||1;
 const segs=ORD.filter(k=>counts[k]).map(k=>`<span style="width:${counts[k]/tot*100}%;background:${SEV[k]}" title="${k}: ${counts[k]}" data-sev="${k}"></span>`).join('');
 const leg=ORD.map(k=>`<span class="it" data-sev="${k}"><span class="dot" style="background:${SEV[k]}"></span>${k} <b>${counts[k]}</b></span>`).join('');
 return `<div class="sevbar">${segs}</div><div class="sevleg">${leg}</div>`;
}
function catBreakdown(){
 const cats=DATA.analytics.findings_by_category||{};
 const max=Math.max.apply(null,[1].concat(Object.keys(cats).map(k=>cats[k])));
 return '<div class="catbars">'+Object.keys(cats).map(k=>`<div class="catrow"><span class="cl">${esc(k)}</span><span class="ct"><span class="cf" style="width:${cats[k]/max*100}%"></span></span><span class="cv">${cats[k]}</span></div>`).join('')+'</div>';
}
// Consolidated post-scan health banner: the single authoritative "did this scan
// complete healthily?" signal, so a crashed AI stage or missing source can never
// read as "just a few findings".
function scanHealthBanner(){
 const h=DATA.scan_health; if(!h||h.status==='ok'||!((h.warnings||[]).length)) return '';
 const crit=h.status==='critical';
 const items=(h.warnings||[]).map(w=>`<li><span class="wl">${esc((w.level||'').toUpperCase())}</span>${esc(w.message)}</li>`).join('');
 return `<div class="banner warn" style="${crit?'border-color:var(--crit);background:rgba(242,92,112,.07)':''}">
   <h3><span class="bi">${crit?'⛔':'⚠'}</span> Scan health: ${crit?'INCOMPLETE - this scan is missing results':'warnings'}</h3>
   <ul>${items}
   <li class="muted">This banner appears whenever a stage failed silently. Absence of findings in an affected area does <b>not</b> mean the tenant is clean there.</li></ul></div>`;
}
function aiBanner(){
 if(DATA.ai_error) return `<div class="banner warn"><h3><span class="bi">\u2726</span> AI finding generation failed</h3>
   <ul><li>${esc(DATA.ai_error)}</li>
   <li class="muted">Check: the <code>anthropic</code> package is installed, the API key is valid, and it can access both configured models. The findings below are the deterministic safety-net set only.</li></ul></div>`;
 if(DATA.ai_enabled) return `<div class="banner ai"><h3><span class="bi">\u2726</span> AI review \u00B7 ${esc(DATA.ai_sonnet_model||'Sonnet')} specialists \u2192 ${esc(DATA.ai_haiku_model||'Haiku')} (skeptic)</h3>
   <ul><li>${DATA.ai_sonnet_raw_count||0} candidate finding(s) proposed by specialist analysts${(()=>{const u=DATA.ai_rejected_ungrounded, m=DATA.ai_rejected_malformed, parts=[]; if(u)parts.push(`${u} rejected as ungrounded (referencing entities not in this tenant)`); if(m)parts.push(`${m} discarded as malformed model output`); if(!parts.length && DATA.ai_rejected_count)parts.push(`${DATA.ai_rejected_count} discarded`); return parts.length?`; ${parts.join(', ')}`:'';})()}.</li>
   <li>${DATA.ai_generated_count||0} AI-generated + ${DATA.deterministic_finding_count||0} deterministic safety-net findings (marked \u2699) in this report. Attack-path findings are shown separately in the Attack Paths tab.</li>
   ${(DATA.ai_trace_id&&DATA._scan_id)?`<li>\u2726 <a href="/api/scans/${esc(DATA._scan_id)}/trace" download="scan-${esc(DATA._scan_id)}-ai-trace.log">Download the full AI reasoning trace</a> (verbose, how each specialist thought \u00b7 <a href="/api/scans/${esc(DATA._scan_id)}/trace?format=jsonl" download>.jsonl</a>).</li>`:''}</ul></div>`;
 return '';
}
// Analysis-gap banner: when a specialist's API call failed, its whole attack domain
// has NO coverage in this report. Staying silent about that reads as "nothing found
// here", which is the most dangerous thing a security report can imply.
function analysisGapBanner(){
 const failed=DATA.ai_failed_specialists||[];
 const errs=(DATA.ai_stage_errors||[]).filter(e=>!failed.some(f=>String(e).includes(f.key)));
 if(!failed.length&&!errs.length) return '';
 const items=failed.map(f=>`<li><span class="wl">NO COVERAGE</span><b>${esc(f.label||f.key)}</b> - this domain was not analysed. ${esc(f.reason||'')}</li>`)
   .concat(errs.map(e=>`<li><span class="wl">ERROR</span>${esc(String(e))}</li>`)).join('');
 return `<div class="banner warn"><h3><span class="bi">⚠</span> Incomplete analysis - ${failed.length?`${failed.length} attack domain(s) were not assessed`:'stage errors occurred'}</h3>
   <ul>${items}
   <li class="muted">Findings for the affected domain(s) are absent from this report. Absence here does <b>not</b> mean the tenant is clean in those areas - re-run the scan to obtain full coverage.</li></ul></div>`;
}
function collectionBanner(){
 const c=DATA.collection||{}; const ws=c.warnings||[];
 if(!ws.length) return '';
 const hasWarn=ws.some(w=>w.level==='warning');
 const items=ws.map(w=>`<li><span class="wl">${esc((w.level||'').toUpperCase())}</span>${esc(w.message)}</li>`).join('');
 return `<div class="banner${hasWarn?' warn':''}">
   <h3><span class="bi">${hasWarn?'\u26A0':'\u2139'}</span> Collection health \u2014 ${hasWarn?'results may be incomplete':'notes'}</h3>
   <ul>${items}</ul></div>`;
}
function renderOverview(){
 const a=DATA.analytics, mi=a.maximum_impact_chain;
 const tiles=[['Tier-0 principals',a.tier0.length],['Critical',counts.Critical],
   ['High',counts.High],['Active findings',realF.length],
   ['Best-practice',bpF.length],['Records analysed',DATA.ingest_summary.total_records]];
 const aiTag = DATA.ai_enabled ? `<span class="ai-tag">\u2726 AI summary \u00B7 ${esc(DATA.ai_model||'Haiku')}</span><br>` : '';
 const choke=(a.choke_points||[]).slice(0,6).map((c,i)=>`<div class="rankrow"><span class="ix">${i+1}</span><span class="nm">${esc(c.name)}</span><span class="v">${c.paths_through} links</span></div>`).join('')||'<div class="muted small">none</div>';
 const v=$('#view'); v.innerHTML=`
  ${scanHealthBanner()}
  ${aiBanner()}
  ${analysisGapBanner()}
  ${collectionBanner()}
  <div class="card"><div class="hero">${ring()}
    <div class="posture">${aiTag}<h1>Posture summary</h1><p>${postureStatement()}</p></div></div>
    <div style="margin-top:18px">${sevBar()}</div></div>
  <div class="tiles">${tiles.map(t=>`<div class="tile"><div class="n">${t[1]}</div><div class="l">${t[0]}</div></div>`).join('')}</div>
  <h2 class="section">Highest-impact exposure</h2>
  <div class="two">
   <div class="card maximpact"><div class="muted small">Maximum-impact entry point</div>
     ${mi?`<div style="font-size:17px;font-weight:600;margin-top:4px">${esc(mi.principal)}</div>
     <div class="path">${esc(mi.kind)} \u00B7 reaches ${mi.reachable_privileged_count} privileged target(s)${mi.already_tier0?' \u00B7 already Tier-0':''}</div>
     <div class="small muted" style="margin-top:8px">Remediating the privileges of this principal removes the most exposure at once.</div>`:'<div class="muted">No escalation entry point reached privilege.</div>'}
     ${(CROSSSUB.bridge_count||0)>0?`<div class="xsub-hi" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)"><span class="xsubbadge">\u21C4 ${CROSSSUB.bridge_count} cross-subscription bridge(s)</span> <span class="small muted">span ${CROSSSUB.subscription_count||0} subscription(s)${(function(){var t=(CROSSSUB.bridges||[]).filter(function(b){return b.reaches_tier0;}).length;return t?' \u00B7 '+t+' reach Tier-0':'';})()} \u2014 see Attack Paths</span></div>`:''}</div>
   <div class="card"><div class="muted small" style="margin-bottom:6px">Most-connected principals \u2014 priority remediation targets</div>${choke}</div>
  </div>
  <h2 class="section">Findings by category</h2>
  <div class="card">${catBreakdown()}</div>
  <h2 class="section">Assessment coverage</h2>
  <div class="card cov">
   <div><div class="muted small">Assessed from this collection</div><ul>${DATA.coverage.assessed_kinds.slice(0,12).map(k=>`<li class="mono">${esc(k)}</li>`).join('')}</ul></div>
   <div class="na"><div class="muted small">Not assessable from AzureHound \u2014 verify separately</div><ul>${DATA.coverage.not_assessable_domains.map(d=>`<li>${esc(d)}</li>`).join('')}</ul></div>
  </div>`;
 qa('[data-sev]',v).forEach(e=>e.onclick=()=>{state.sev=e.dataset.sev;state.bp=false;go('findings');});
}

function matchF(f){
 if(f.source==='path_consolidation' && !state.paths) return false;
 if(state.bp && !f.best_practice) return false;
 if(!state.bp && !state.paths && state.sev!=='all' && f.severity!==state.sev) return false;
 if(state.q){
   // Search across everything the card actually shows, including entity names - a user
   // who can see "AZ-RBAC-002" or a principal's name on screen expects to find it.
   const ents=(f.entities||[]).slice(0,50).map(e=>e.name||'').join(' ');
   const h=[f.rule_id,f.title,f.category,f.what,f.summary,f.severity,ents]
     .filter(Boolean).join(' ').toLowerCase();
   if(!h.includes(state.q.toLowerCase().trim())) return false;
 }
 return true;
}
function chainSVG(chain){
 if(!chain || !chain.length) return '';
 const validChain=chain.filter(h=>h&&h.from&&h.to);
 if(!validChain.length) return '';
 const W=680, rowH=52, pad=14, H=validChain.length*rowH+pad*2;
 let y=pad+22;
 const rows=validChain.map((h,i)=>{
   const fromN=esc((h.from.name||h.from.id)||''), toN=esc((h.to.name||h.to.id)||''), tech=esc(h.technique||'');
   const row=`<g transform="translate(0,${y})">
     <circle cx="18" cy="0" r="6" fill="var(--low)"/>
     <text x="34" y="4" font-size="12.5" fill="var(--tx)">${fromN}</text>
     <text x="34" y="20" font-size="10.5" fill="var(--accent)">${tech}</text>
     <line x1="10" y1="8" x2="10" y2="${rowH-8}" stroke="var(--border-2)" stroke-width="2" ${i===chain.length-1?'display="none"':''}/>
   </g>`;
   y+=rowH; return row;
 }).join('');
 const last=validChain[validChain.length-1];
 const lastLabel=`<g transform="translate(0,${y})"><circle cx="18" cy="0" r="7" fill="var(--crit)"/>
   <text x="34" y="4" font-size="12.5" font-weight="700" fill="var(--crit)">${esc((last.to.name||last.to.id)||'')}</text></g>`;
 return `<svg viewBox="0 0 ${W} ${y+30}" width="100%" style="max-width:520px" xmlns="http://www.w3.org/2000/svg">${rows}${lastLabel}</svg>`;
}
function pathConsolBlock(f){
 if(f.source!=='path_consolidation') return '';
 const all = f.all_paths || [];
 const by = f.paths_by_severity || {};
 const sevOrder = ['Critical','High','Medium','Low'];
 const sevPills = sevOrder.filter(s=>by[s]).map(s=>`<span class="sevtag" style="background:${SEV[s]};margin-right:4px">${by[s]}× ${s}</span>`).join('');
 const pathRows = all.map((p,i)=>`
   <tr class="pathrow">
     <td style="font-weight:600;white-space:nowrap">#${i+1}</td>
     <td><span class="sevtag" style="background:${SEV[p.severity]};font-size:11px">${esc(p.severity)}</span></td>
     <td class="mono small">${p.hop_count} hop${p.hop_count!==1?'s':''}</td>
     <td class="mono small" style="color:var(--accent)">${esc(p.top_edge||'')}</td>
     <td class="small">→ ${esc(p.dst_name||'')}</td>
     <td class="mono small muted" style="font-size:10px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.path||'')}</td>
   </tr>`).join('');
 return `<div class="pathconsolcard" style="margin-top:10px">
   <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
     <span style="font-size:12.5px;font-weight:700;color:var(--accent)">◣ ${all.length} attack path${all.length!==1?'s':''} from this ${((f.entities||[])[0]||{}).kind==='AZGroup'?'group':'identity'}</span>
     <span style="margin-left:4px">${sevPills}</span>
     ${all.length>2?`<button class="ghost" style="margin-left:auto;padding:4px 10px;font-size:12px" data-action="toggle-paths">▼ Expand all paths</button>`:''}
   </div>
   <div class="pathlist" style="display:none">
     <table class="etable" style="font-size:12px"><thead><tr><th>#</th><th>Sev</th><th>Hops</th><th>Top edge</th><th>Target</th><th>Path</th></tr></thead>
     <tbody>${pathRows}</tbody></table>
   </div>
 </div>`;
}
function fmtScenario(sc){
 if(!sc) return '<p>-</p>';
 const parts=sc.split(/(?=\b\d+\.\s)/);
 if(parts.length<2) return '<p>'+esc(sc)+'</p>';
 const items=parts.map(function(s){return '<li>'+esc(s.replace(/^\d+\.\s*/,''))+'</li>';}).join('');
 return '<ol class="steps">'+items+'</ol>';
}
// Global subscription GUID → name map built from DATA.subscriptions at render time.
// Populated on page load; falls back to short GUID display if name not found.
const SUB_MAP = DATA.subscriptions || {};
const SUB_GUID_RE = /\/subscriptions\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
function _subName(guid){ const g=guid.toLowerCase(); const n=SUB_MAP[g]||SUB_MAP[guid]; return (n&&n!==g&&n!==guid)?n:guid; }
function extractSubscriptions(f){
 const subs=new Set();
 for(const e of (f.entities||[])){
  const ev=e.evidence||{};
  // Pre-computed subscription names from rules (new scans)
  if(Array.isArray(ev.subscriptions)) ev.subscriptions.forEach(s=>s&&s!=='unknown'&&subs.add(s));
  if(ev.subscription&&typeof ev.subscription==='string'&&ev.subscription!=='unknown') subs.add(ev.subscription);
  // Parse subscription GUID from ARM-path entity IDs (works for all scans, all finding types)
  const m=SUB_GUID_RE.exec(e.id||'');
  if(m) subs.add(_subName(m[1]));
 }
 return [...subs].sort();
}
// Maximum-impact path: the worst outcome this attack reaches through the real
// escalation graph. Computed server-side
// (scoring.compute_max_impact_paths), so it is present on every finding.
function maxImpactBlock(f){
 const p=f.max_impact_path; if(!p) return '';
 const hops=p.hops||[];
 const t0 = p.reaches_tier0
   ? `<span class="mi-t0">◆ reaches Tier-0</span>` : '';
 const nsub = f.subscription_reach_count||0;
 const subsList = (f.subscription_reach||[]).slice(0,12).join(', ');
 const subsBadge = nsub>=2
   ? `<span class="mi-subs" title="${esc('Compromising this reaches '+nsub+' subscriptions'+(subsList?': '+subsList:''))}">⇄ spans ${nsub} subscriptions</span>` : '';
 // entry → via → … → target chain
 let chainHtml='';
 if(hops.length){
   // A managed-identity-theft hop carries the compute resource (VM/app) the code runs on;
   // render it as an intermediate node so the path reads principal → resource → identity,
   // matching the "execute code on a VM" scenario instead of hiding the resource.
   const hopHtml=(h,last)=>{
     if(h.via_resource){
       return `<span class="mi-edge">${esc(h.via_how||'run code on')}</span>`
         + `<span class="mi-node">${esc(h.via_resource.name||'?')}</span>`
         + `<span class="mi-edge">steal managed identity (IMDS)</span>`
         + `<span class="mi-node${last?' mi-tgt':''}">${esc((h.to&&h.to.name)||'?')}</span>`;
     }
     return `<span class="mi-edge">${esc(h.via||'')}</span>`
       + `<span class="mi-node${last?' mi-tgt':''}">${esc((h.to&&h.to.name)||'?')}</span>`;
   };
   chainHtml = `<span class="mi-node mi-entry">${esc((p.entry&&p.entry.name)||'?')}</span>`
     + hops.map((h,i)=>hopHtml(h,i===hops.length-1)).join('');
 } else {
   chainHtml = `<span class="mi-node mi-tgt">${esc((p.target&&p.target.name)||'?')}</span>`
     + `<span class="small muted"> (exposure point - no onward escalation collected)</span>`;
 }
 const summary = f.max_impact_summary?`<div class="mi-summary">${esc(f.max_impact_summary)}</div>`:'';
 // A residual coherence note: the AI QA gate flagged a path/description discrepancy it
 // could not auto-correct. Show it so the reader is not misled by the path above.
 const cohNote = f.coherence_note
   ? `<div class="mi-cohnote" title="Flagged by the automated coherence review">⚠ ${esc(f.coherence_note)}</div>` : '';
 return `<div class="miblock${p.reaches_tier0?' mi-crit':''}">
   <div class="mi-head"><span class="mi-label">⌖ Maximum-impact path</span>${t0}${subsBadge}</div>
   <div class="mi-chain">${chainHtml}</div>
   ${summary}${cohNote}
 </div>`;
}
function findingCard(f){
 const d=f.detail||{}, col=SEV[f.severity];
 const isAI = f.source==='ai_generated';
 const isPath = f.source==='path_consolidation';
 // Role/evidence cell: prefer a SPECIFIC role_in_finding, then the entity's concrete
 // evidence, and only fall back to the generic "Affected <kind>" placeholder last.
 // Previously role_in_finding won unconditionally, and api.py backfills it with that
 // placeholder - so every entity in every deterministic finding displayed "Affected
 // group" and the actual role, scope and assignment counts were never shown at all.
 const _evCell=e=>{
   const r=(e.role_in_finding||'').trim();
   const specific=r&&!/^Affected(\s|$)/i.test(r);
   if(specific) return esc(r);
   const ev=fmtEv(e.evidence);
   if(ev) return ev;
   return r?esc(r):'<span class="muted small">-</span>';
 };
 const ents=(f.entities||[]).slice(0,30).map(e=>`<tr><td class="nm">${esc(e.name)}</td><td class="kd">${esc((e.kind||'').replace('AZ',''))}</td><td class="ev">${_evCell(e)}</td></tr>`).join('');
 const affectedSubs=extractSubscriptions(f);
 const subSection=affectedSubs.length?`<h4>Affected subscriptions (${affectedSubs.length})</h4><table class="etable"><thead><tr><th>Subscription</th></tr></thead><tbody>${affectedSubs.map(s=>`<tr><td class="nm">${esc(s)}</td></tr>`).join('')}</tbody></table>`:'';
 const steps=(d.steps||[]).map(s=>`<li>${esc(s)}</li>`).join('');
 const FW=f.frameworks||{}; const fws=Object.keys(FW).map(k=>`<span class="fw">${esc(k)} · ${esc(FW[k])}</span>`).join('');
 const refs=(f.references||[]).filter(r=>/^https?:\/\//i.test(String(r))).map(r=>`<a href="${esc(r)}" rel="noopener noreferrer" target="_blank">reference ↗</a>`).join(' &nbsp; ');
 const _evRaw=f.evidence||[]; const _ev=Array.isArray(_evRaw)?_evRaw:(typeof _evRaw==='string'?(()=>{try{const p=JSON.parse(_evRaw);return Array.isArray(p)?p:[];}catch(e){return [];}})():[]); const evidenceList=_ev.map(e=>`<li>${esc(e)}</li>`).join('');
 const sourceTag = isPath
   ? `<span class="srctag path">◣ Attack Path</span>`
   : isAI
   ? `<span class="srctag ai" title="AI-generated · ${esc(DATA.ai_sonnet_model||'Sonnet')} → ${esc(DATA.ai_opus_model||'')} → ${esc(DATA.ai_haiku_model||'Haiku')} skeptic">✦ AI</span>`
   : `<span class="srctag det" title="Deterministic safety-net rule">⚙ det</span>`;
 const confBadge = isAI && typeof f.confidence==='number'
   ? `<span class="confbadge ${f.confidence>=80?'high':f.confidence>=50?'mid':'low'}">${f.confidence}% confidence</span>`
   : (!isAI&&!isPath) ? `<span class="confbadge verified">✓ Verified fact</span>` : '';
 const _TIER={verified_fact:['Verified fact','vf'],corroborated:['Corroborated','cor'],supported:['Supported','sup'],lead:['Lead','lead']};
 const _tb=_TIER[f.quality_tier];
 const tierBadge = (_tb && !isPath) ? `<span class="tierbadge tb-${_tb[1]}" title="Evidence tier${typeof f.effective_confidence==='number'?' · effective confidence '+f.effective_confidence+'%':''}${f.needs_review?' · flagged for analyst review':''}">${_tb[0]}${f.needs_review?' ⚠':''}</span>` : '';
 const crossSubBadge = (f.subscription_reach_count||0)>=2
   ? `<span class="xsubbadge" title="${esc('Compromise spans '+f.subscription_reach_count+' subscriptions'+((f.subscription_reach||[]).length?': '+(f.subscription_reach||[]).slice(0,12).join(', '):''))}">⇄ ${f.subscription_reach_count} subs</span>` : '';
 const chain = chainSVG(f.escalation_chain);
 // Strip legacy content-free placeholders left in already-stored scans:
 //   "[Skeptic downgraded: ]"          - empty reason
 //   "[Skeptic downgraded severity]"   - bare label, no rationale
 // Newer scans carry a full sentence explaining the transition, so nothing is lost.
 const _rn = (f.review_note || '')
   .replace(/\[Skeptic downgraded:\s*\]/g, '')
   .replace(/\[Skeptic downgraded severity\]/g, '')
   .trim();
 const reviewNote = isAI && _rn
   ? `<div class="reviewnote"><span class="rnl">Review note</span>${esc(_rn)}</div>` : '';
 // Lead with the finding's OWN concrete summary (entity-grounded, built deterministically
 // for non-AI findings too), then the knowledge-base summary, then the generic description.
 const plainSummary = f.summary || d.summary || f.what || '-';
 const technicalNarrative = isAI && f.reasoning ? f.reasoning : null;
 const status = f.status || 'New';
 const statusBadge = HAS_SCAN_ID ? `<span class="statuspill st-${status.replace(/\s+/g,'')}">${esc(status)}</span>` : '';
 const statusControl = HAS_SCAN_ID ? `<h4>Remediation status</h4>
   <select class="statussel" data-key="${esc(f._finding_key||'')}">
     ${STATUSES.map(s=>`<option value="${s}" ${s===status?'selected':''}>${s}</option>`).join('')}
   </select>` : '';
 const _vl=((DATA._validation||{})[f._finding_key||'']||{}).verdict||'';
 const valControl = (HAS_SCAN_ID && !isPath) ? `<h4>Analyst validation</h4>
   <div class="vlabel" data-key="${esc(f._finding_key||'')}">
     <button class="vbtn tp${_vl==='true_positive'?' on':''}" data-v="true_positive">✓ True positive</button>
     <button class="vbtn fp${_vl==='false_positive'?' on':''}" data-v="false_positive">✗ False positive</button>
     <button class="vbtn un${_vl==='unsure'?' on':''}" data-v="unsure">? Unsure</button>
     <span class="vhint">records ground truth for the precision harness</span>
   </div>` : '';
 // Azure DevOps addon (opt-in): only when enabled + fully configured. Shows a link if a work
 // item already exists for this finding, else a Create button + assignee + parent-epic inputs.
 const _ado = DATA._ado || {};
 const _wi = (DATA._workitems||{})[f._finding_key||''];
 const adoControl = (HAS_SCAN_ID && _ado.enabled && _ado.configured && !isPath) ? (
   _wi ? `<h4>Azure DevOps</h4><div class="adowi" data-key="${esc(f._finding_key||'')}">
       <a class="adolink" href="${esc(_wi.url||'#')}" target="_blank" rel="noopener">✓ Work item #${esc(String(_wi.id||''))} ↗</a>
       ${_wi.assignee?`<span class="muted small"> · ${esc(_wi.assignee)}</span>`:''}</div>`
   : `<h4>Azure DevOps</h4><div class="adobox" data-key="${esc(f._finding_key||'')}">
       <input class="adoassignee" type="text" placeholder="assignee (email / UPN)" value="${esc(_ado.default_assignee||'')}" autocomplete="off">
       <input class="adoepic" type="text" placeholder="parent Epic id (optional)" value="${esc(_ado.default_parent_epic||'')}" autocomplete="off">
       <button class="adocreate" type="button" data-key="${esc(f._finding_key||'')}">Create ${esc(_ado.work_item_type||'Feature')}</button>
       <span class="adostatus muted small"></span></div>`
 ) : '';
 const cmds = (f.remediation_commands||[]);
 const cmdBlock = cmds.length ? `<h4>Remediation commands</h4><div class="cmdblock"><pre class="mono small" style="white-space:pre-wrap;margin:0">${esc(cmds.join('\n'))}</pre><button class="ghost" style="margin-top:6px;padding:4px 10px;font-size:12px" data-action="copy" data-copytext="${esc(cmds.join('\n'))}">Copy commands</button></div>` : '';
 return `<div class="finding${f.best_practice?' bp':''}${isPath?' pathf':''}" data-id="${esc(f.rule_id||f.title)}">
  <div class="fhead"><span class="sevtick" style="background:${col}"></span>
    ${f.rule_id?`<span class="rid">${esc(f.rule_id)}</span>`:''}<span class="ftitle">${esc(f.title)}</span>
    <span class="ftags">${statusBadge}${crossSubBadge}${confBadge}${sourceTag}<span class="cattag">${esc(f.category)}</span>
      <span class="fcount">${f.path_count?f.path_count+' paths':(f.affected_count||(f.entities||[]).length)+' affected'}</span>
      ${tierBadge}
      <span class="sevtag" style="background:${col}">${esc(f.severity)}</span>
      <button class="fcopy" type="button" title="Copy this finding as plain text">⧉ Copy</button>
      <span class="chev">▶</span></span></div>
  <div class="fbody">
    ${reviewNote}
    <h4>Summary</h4><p>${esc(plainSummary)}</p>
    ${HAS_SCAN_ID?(()=>{
      // Deep-link to the attack graph plotting THIS finding's own path (entry -> its target),
      // not a generic path to Tier-0. Fall back to focusing the entry node when the finding has
      // no computed path (e.g. an exposure finding whose target is itself).
      const mp=f.max_impact_path||{}; const eid=(mp.entry||{}).id; const tid=(mp.target||{}).id;
      const base='/#/graph/'+encodeURIComponent(DATA._scan_id);
      let href;
      if(eid&&tid&&(mp.length||0)>0&&tid!==eid){href=base+'/'+encodeURIComponent(eid)+'/'+encodeURIComponent(tid);}
      else{const e0=(f.entities||[])[0]&&(f.entities||[])[0].id; href=e0?base+'/'+encodeURIComponent(e0):base;}
      return '<p style="margin:8px 0 0"><a href="'+href+'" target="_blank" style="font-size:12.5px;color:var(--accent)">◆ View in attack graph ↗</a></p>';
    })():''}
    ${pathConsolBlock(f)}
    ${technicalNarrative?`<div class="techsummary">
      <div class="techhead"><span class="techlabel">⚙ Technical Summary</span>${isAI?`<span class="techconf">${typeof f.confidence==='number'?f.confidence+'% confidence':''}</span>`:''}</div>
      <div class="techbody">${esc(technicalNarrative)}</div>
    </div>`:''}
    ${statusControl}
    ${valControl}
    ${adoControl}
    <h4>Why it matters</h4><p>${esc(d.why || f.why_it_matters || '-')}</p>
    <h4>Attack scenario</h4>${fmtScenario(f.attack_scenario||d.scenario||'')}
    ${chain?`<h4>Escalation / lateral-movement path</h4><div class="chaingraph">${chain}</div>`:''}
    ${maxImpactBlock(f)}
    <h4>Affected entities (${(f.entities||[]).length})</h4>
    <table class="etable"><thead><tr><th>Entity</th><th>Type</th><th>Role / evidence</th></tr></thead><tbody>${ents}</tbody></table>
    ${subSection}
    ${evidenceList?`<h4>Evidence</h4><ul class="steps">${evidenceList}</ul>`:''}
    <h4>How to fix</h4><ol class="steps">${steps||'<li>'+esc(f.remediation||'-')+'</li>'}</ol>
    ${cmdBlock}
    <h4>Detection &amp; monitoring</h4><div class="detect">${esc(d.detection || f.detection || '-')}</div>
    <h4>Frameworks &amp; references</h4><div class="kvs">${fws||'<span class="muted small">-</span>'}</div>
    <div class="small" style="margin-top:8px">${refs}</div>
  </div></div>`;
}
const STATUSES = ['New','Acknowledged','In Progress','Resolved','Risk Accepted'];
async function updateStatus(key, status){
 const r = await fetch(`/api/scans/${DATA._scan_id}/findings/${key}/status`, {
   method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'status='+encodeURIComponent(status)
 });
 return r.ok;
}
async function labelFinding(key, verdict){
 const r = await fetch(`/api/scans/${DATA._scan_id}/validation/${key}`, {
   method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'verdict='+encodeURIComponent(verdict)
 });
 if(!r.ok) return null;
 const j = await r.json();
 DATA._validation = j.labels || {};   // keep local mirror fresh for re-renders
 return j.metrics;
}
function paintFindings(){
 const list=$('#flist');
 // Always present findings worst-first. ORD is the severity order; ties keep their
 // stored order (stable sort), which is rule-id order within a severity.
 const sevRank=s=>{const i=ORD.indexOf(s);return i<0?ORD.length:i;};
 const items=DATA.findings.filter(matchF)
   .map((f,i)=>[f,i])
   .sort((a,b)=>(sevRank(a[0].severity)-sevRank(b[0].severity))||(a[1]-b[1]))
   .map(x=>x[0]);
 list.innerHTML=items.length?items.map(findingCard).join(''):'<div class="card muted">No findings match this filter.</div>';
 qa('.finding',list).forEach(c=>{c.querySelector('.fhead').onclick=()=>c.classList.toggle('open'); wireFindingCopy(c);});
 qa('.statussel',list).forEach(sel=>{
   sel.addEventListener('click', e=>e.stopPropagation());
   sel.onchange=async()=>{
     const key=sel.dataset.key, newStatus=sel.value;
     const ok=await updateStatus(key, newStatus);
     if(ok){
       const f=DATA.findings.find(x=>x._finding_key===key); if(f) f.status=newStatus;
       const badge=sel.closest('.finding').querySelector('.statuspill');
       if(badge){badge.className='statuspill st-'+newStatus.replace(/\s+/g,'');badge.textContent=newStatus;}
     }
   };
 });
 qa('.vlabel',list).forEach(box=>{
   box.addEventListener('click', e=>e.stopPropagation());
   qa('.vbtn',box).forEach(btn=>{
     btn.onclick=async()=>{
       const key=box.dataset.key, want=btn.dataset.v;
       const on=btn.classList.contains('on');
       const verdict = on ? 'clear' : want;   // click an active button to clear it
       const m=await labelFinding(key, verdict);
       if(m!==null){ qa('.vbtn',box).forEach(b=>b.classList.remove('on')); if(!on) btn.classList.add('on'); }
     };
   });
 });
 qa('.adobox',list).forEach(box=>{
   box.addEventListener('click', e=>e.stopPropagation());
   const btn=box.querySelector('.adocreate'), st=box.querySelector('.adostatus');
   if(btn) btn.onclick=async()=>{
     btn.disabled=true; st.textContent='Creating…'; st.style.color='';
     try{
       const assignee=(box.querySelector('.adoassignee').value||'').trim();
       const epic=(box.querySelector('.adoepic').value||'').trim();
       const r=await fetch(`/api/scans/${DATA._scan_id}/findings/${box.dataset.key}/workitem`,{
         method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
         body:'assignee='+encodeURIComponent(assignee)+'&parent_epic='+encodeURIComponent(epic)});
       const j=await r.json();
       if(!r.ok) throw new Error(j.detail||'Failed to create work item');
       const wi=j.workitem||{};
       (DATA._workitems=DATA._workitems||{})[box.dataset.key]=wi;   // so re-renders show the link
       box.innerHTML=`<a class="adolink" href="${wi.url||'#'}" target="_blank" rel="noopener">✓ Work item #${wi.id||''} ↗</a>`
         +(wi.assignee?` <span class="muted small">· ${wi.assignee}</span>`:'')
         +(j.created===false?' <span class="muted small">(already existed)</span>':'');
     }catch(e){ st.textContent=e.message; st.style.color='var(--crit)'; btn.disabled=false; }
   };
 });
}
function renderFindings(){
 const nonPathF = DATA.findings.filter(f=>f.source!=='path_consolidation');
 const chips=[['all','All',nonPathF.length],...ORD.map(s=>[s,s,counts[s]])];
 const v=$('#view'); v.innerHTML=`
  ${scanHealthBanner()}
  ${aiBanner()}
  ${analysisGapBanner()}
  <div class="toolbar">
    <input class="search" id="q" placeholder="Search findings \u2014 title, category\u2026" value="${esc(state.q)}">
    <div class="chips" id="chips">
     ${chips.map(c=>`<span class="chip${!state.bp&&!state.paths&&state.sev===c[0]?' on':''}" data-sev="${c[0]}">${c[1]} <span class="c">${c[2]}</span></span>`).join('')}
     <span class="chip${state.bp?' on':''}" data-bp="1">Best practice <span class="c">${bpF.length}</span></span>
     ${HAS_PATHS?`<span class="chip chip-path" data-gopaths="1">\u25E3 Attack Paths <span class="c">${PATH_FINDINGS.length||PH_CHOKES.length}</span></span>`:''}
    </div>
  </div>
  <div id="flist"></div>`;
 paintFindings();
 $('#q').oninput=e=>{state.q=e.target.value;paintFindings();};
 qa('.chip',v).forEach(ch=>ch.onclick=()=>{
   if(ch.dataset.gopaths){ go('paths'); return; }
   if(ch.dataset.bp){state.bp=true;state.sev='all';}
   else{state.bp=false;state.sev=ch.dataset.sev;}
   renderFindings();});
}
async function renderRoadmap(){
 const v=$('#view'); v.innerHTML='<div class="muted">Loading action plan\u2026</div>';
 let rm=null;
 try{ const r=await fetch(`/api/scans/${DATA._scan_id}/roadmap`); rm=await r.json(); }catch(e){}
 if(!rm){ v.innerHTML='<div class="card muted">Could not load the action plan.</div>'; return; }
 const bucketMeta = {
   now:{label:'Now \u2014 Critical', hint:'Fix immediately. These are direct paths to Tier-0 or active exposure.', col:'var(--crit)'},
   next:{label:'Next \u2014 High', hint:'Address this sprint. Real risk, not yet an active Tier-0 path.', col:'var(--high)'},
   backlog:{label:'Backlog \u2014 Medium/Low', hint:'Track and schedule; lower urgency.', col:'var(--low)'},
 };
 const section = (key)=>{
   const items=rm[key]||[];
   const rows = items.length ? items.map(i=>`
     <div class="roadrow">
       <div class="roadmain">
         <span class="srctag ${i.source==='ai_generated'?'ai':'det'}" style="margin-right:6px">${i.source==='ai_generated'?'\u2726':'\u2699'}</span>
         <b>${esc(i.title)}</b>
         <span class="muted small" style="display:block;margin-top:3px">${esc(i.category||'')} \u00B7 ${i.affected_count} affected</span>
         ${i.remediation?`<div class="small" style="margin-top:6px;line-height:1.5">${esc(i.remediation)}</div>`:''}
       </div>
       <select class="statussel roadstatus" data-key="${esc(i.key)}">${STATUSES.map(s=>`<option value="${s}" ${s===i.status?'selected':''}>${s}</option>`).join('')}</select>
     </div>`).join('')
     : `<div class="muted small" style="padding:10px 0">Nothing open in this bucket.</div>`;
   return `<div class="card" style="margin-bottom:14px">
     <h1 style="font-size:14px;margin:0 0 2px;color:${bucketMeta[key].col}">${bucketMeta[key].label} <span class="muted" style="font-weight:400">(${items.length})</span></h1>
     <p class="sub" style="margin:0 0 10px;font-size:12.5px">${bucketMeta[key].hint}</p>
     ${rows}
   </div>`;
 };
 v.innerHTML = `<div class="card" style="margin-bottom:14px"><h1 style="font-size:16px;margin:0 0 4px">Action plan</h1>
   <p class="sub" style="margin:0">A single prioritised remediation list, generated from every open finding. Resolved and risk-accepted items are excluded automatically as you update their status.</p></div>`
   + section('now') + section('next') + section('backlog');
 qa('.roadstatus',v).forEach(sel=>sel.onchange=async()=>{
   const ok=await updateStatus(sel.dataset.key, sel.value);
   if(ok){ toast('Status updated.'); if(sel.value==='Resolved'||sel.value==='Risk Accepted') renderRoadmap(); }
 });
}

// Cross-subscription blast radius is no longer a separate menu - it is woven into the
// Attack Paths view (and surfaced inline on every finding as "⇄ N subs"). This builds the two
// bridge/connection cards embedded within the Attack Paths view.
function crossSubCards(){
 const cs=CROSSSUB;
 const bridges=cs.bridges||[], links=cs.links||[];
 if(!bridges.length && !links.length) return '';
 const gainCell=b=>{
   if(b.member_count!=null){
     const inh=b.inherited_bridge_members?` (+${b.inherited_bridge_members} inherit only via this group)`:'';
     return `<span class="mg-tag" title="This group holds cross-subscription RBAC, so every member inherits the reach">group → ${b.member_count} member(s)${inh}</span> ${esc((b.roles||[]).slice(0,2).join(', '))}${b.via_management_group?' <span class="mg-tag">via MG</span>':''}`;
   }
   if(!b.indirect)
     return `<span class="mg-tag" title="Holds cross-subscription RBAC directly">direct RBAC</span> ${esc((b.roles||[]).slice(0,3).join(', '))}${(b.roles||[]).length>3?' +'+((b.roles.length)-3):''}${b.via_management_group?' <span class="mg-tag">via MG</span>':''}`;
   return `<span class="mg-tag" title="Bridges by combining grants no single group provides - membership of several groups, an owned service principal, or PIM eligibility">combines grants</span> ${esc((b.roles||[]).slice(0,2).join(', '))}${b.via_management_group?' <span class="mg-tag">via MG</span>':''}`;
 };
 const bridgeRows=bridges.slice(0,60).map(b=>`<tr>
   <td class="nm">${esc(b.name)}</td>
   <td class="small muted">${esc((b.kind||'').replace('AZ',''))}</td>
   <td style="text-align:center"><b>${b.subscription_count}</b></td>
   <td class="small">${gainCell(b)}</td>
   <td style="text-align:center">${b.reaches_tier0?'<span class="t0-yes">● yes</span>':'<span class="muted">-</span>'}</td>
   <td style="text-align:right"><span class="mono">${b.member_count!=null?b.member_count:b.blast_radius}</span></td>
  </tr>`).join('');
 const linkRows=links.slice(0,40).map(l=>`<tr>
   <td class="nm">${esc(l.a)} <span class="muted">⇄</span> ${esc(l.b)}</td>
   <td style="text-align:center"><b>${l.principal_count}</b></td>
   <td class="small muted">${esc((l.principals||[]).slice(0,3).join(', '))}${(l.principals||[]).length>3?'…':''}</td>
   <td style="text-align:right"><span class="mono">${l.max_blast}</span></td>
  </tr>`).join('');
 return `
  <div class="card" style="margin-top:16px">
   <h3 class="cardh">Cross-subscription bridges <span class="muted small">(top ${Math.min(bridges.length,60)} of ${bridges.length}, groups first - the highest-leverage fix - then direct holders, then grant-combiners)</span></h3>
   <p class="small muted" style="margin:2px 0 10px">Principals with STANDING access to more than one subscription - held directly, granted by a management-group role, or inherited through a group or owned service principal. Groups are listed first because fixing one group severs the reach for all its members. (Escalation-only reach - a principal that can only escalate to an admin who spans subscriptions - is an attack path, shown under Attack Paths, not a standing bridge here.)</p>
   <div style="overflow-x:auto"><table class="etable csbtable"><thead><tr>
     <th>Principal</th><th>Type</th><th style="text-align:center">Subs</th><th>How the reach is gained</th>
     <th style="text-align:center">Reaches Tier-0</th><th style="text-align:right">Members / blast</th>
    </tr></thead><tbody>${bridgeRows}</tbody></table></div>
  </div>
  ${linkRows?`<div class="card" style="margin-top:16px">
   <h3 class="cardh">Subscription connections <span class="muted small">(top ${Math.min(links.length,40)} of ${links.length} pairs, by shared bridging principals)</span></h3>
   <div style="overflow-x:auto"><table class="etable csbtable"><thead><tr>
     <th>Connected subscriptions</th><th style="text-align:center">Bridging principals</th><th>Examples</th><th style="text-align:right">Max blast</th>
    </tr></thead><tbody>${linkRows}</tbody></table></div>
  </div>`:''}`;
}

function renderCoverage(){
 const v=$('#view');
 const coll=DATA.collection||{};
 const ws=coll.warnings||[];
 const sig=coll.signals||{};
 const kinds=DATA.coverage.assessed_kinds||[];
 const notAssessable=DATA.coverage.not_assessable_domains||[];
 const unconsumed=coll.unconsumed_kinds||[];
 const hasWarn=ws.some(w=>w.level==='warning');
 const warnBanner=ws.length?`<div class="banner${hasWarn?' warn':''}">
   <h3><span class="bi">${hasWarn?'⚠':'ℹ'}</span> Collection health - ${hasWarn?'results may be incomplete':'notes'}</h3>
   <ul>${ws.map(w=>`<li><span class="wl">${esc((w.level||'').toUpperCase())}</span>${esc(w.message)}</li>`).join('')}</ul></div>`:'';
 const sigRows=[
   ['Tenant ID',sig.tenant?'✓ Present':'✗ Missing'],
   ['Users',sig.users||0],
   ['Applications',sig.applications||0],
   ['Service principals',sig.service_principals||0],
   ['Subscriptions',sig.subscriptions||0],
   ['Key Vaults',sig.key_vaults||0],
   ['Entra role assignments',sig.entra_roles_present?'✓ Present':'✗ Not collected'],
   ['Azure RBAC assignments',sig.rbac_assignments_present?'✓ Present':'✗ Not collected'],
   ['KV access policies',sig.kv_policies_present?'✓ Present':'✗ Not collected'],
 ].map(([k,val])=>`<tr><td>${esc(k)}</td><td class="mono small">${esc(String(val))}</td></tr>`).join('');

 // Full set of AzureHound record types PostureHound knows about
 const ALL_KINDS=[
   'AZTenant','AZManagementGroup','AZSubscription','AZResourceGroup',
   'AZUser','AZGroup','AZServicePrincipal','AZApp','AZDevice','AZRole',
   'AZVM','AZManagedCluster','AZKeyVault','AZStorageAccount',
   'AZAutomationAccount','AZFunctionApp','AZLogicApp','AZWebApp',
   'AZVMScaleSet','AZContainerRegistry',
 ];
 const assessedSet=new Set(kinds);
 const unconsumedSet=new Set(unconsumed);
 const assessedCount=ALL_KINDS.filter(k=>assessedSet.has(k)).length;
 const missingCount=ALL_KINDS.filter(k=>!assessedSet.has(k)&&!unconsumedSet.has(k)).length;
 const checklist=ALL_KINDS.map(k=>{
   if(assessedSet.has(k))
     return `<li style="margin:4px 0;display:flex;align-items:center;gap:8px"><span style="color:var(--good);font-size:13px">✓</span><span class="mono small">${esc(k)}</span></li>`;
   if(unconsumedSet.has(k))
     return `<li style="margin:4px 0;display:flex;align-items:center;gap:8px"><span style="color:var(--med);font-size:13px">⊘</span><span class="mono small">${esc(k)}</span><span class="muted" style="font-size:11px">collected, not evaluated</span></li>`;
   return `<li style="margin:4px 0;display:flex;align-items:center;gap:8px"><span style="color:var(--tx3);font-size:13px">✗</span><span class="mono small" style="color:var(--tx3)">${esc(k)}</span><span class="muted" style="font-size:11px">not in collection</span></li>`;
 }).join('');

 // Per-analyst coverage. Distinguishes three states that look identical in a plain
 // count: analysed-and-found-issues, analysed-and-clean, and never-ran. The last one
 // is a coverage gap, not a clean bill of health.
 const specCounts=DATA.ai_specialist_counts||{};
 const failedMap={}; (DATA.ai_failed_specialists||[]).forEach(f=>failedMap[f.key]=f);
 const specKeys=Object.keys(specCounts);
 const LABELS={priv_esc:'Privilege escalation',lateral_movement:'Lateral movement',entry_points:'External entry points',
   data_plane:'Data plane',hygiene:'Identity hygiene',rbac_governance:'RBAC governance',app_lifecycle:'Application lifecycle',
   pim_risk:'PIM risk',tenant_defaults:'Tenant defaults',devops_surface:'DevOps surface',hybrid_identity:'Hybrid identity',
   supply_chain_container:'Supply chain / container',cross_subscription:'Cross-subscription',security_misconfig:'Security misconfiguration',
   entitlement_delegation:'Entitlement delegation',access_breadth:'Access breadth'};
 const ranSpecs=specKeys.filter(k=>specCounts[k]!==null&&specCounts[k]!==undefined).length;
 const specRows=specKeys.sort((a,b)=>{
    const fa=failedMap[a]?0:1, fb=failedMap[b]?0:1;
    if(fa!==fb) return fa-fb;
    return (specCounts[b]||0)-(specCounts[a]||0);
  }).map(k=>{
   const n=specCounts[k];
   if(failedMap[k]||n===null||n===undefined)
     return `<tr><td>${esc(LABELS[k]||k)}</td><td class="mono small" style="color:var(--crit)">✗ did not run</td></tr>`;
   if(n===0)
     return `<tr><td>${esc(LABELS[k]||k)}</td><td class="mono small muted">✓ analysed · no issues</td></tr>`;
   return `<tr><td>${esc(LABELS[k]||k)}</td><td class="mono small" style="color:var(--good)">✓ analysed · ${n} finding${n===1?'':'s'}</td></tr>`;
  }).join('');
 const specPanel=specKeys.length?`<div class="card" style="margin-top:18px">
    <h2 class="section" style="margin-top:0">Analyst coverage</h2>
    <div class="muted small" style="margin-bottom:12px">${ranSpecs}/${specKeys.length} specialist analysts completed${Object.keys(failedMap).length?` · <span style="color:var(--crit)">${Object.keys(failedMap).length} did not run - those domains are unassessed</span>`:''}</div>
    <table class="etable"><tbody>${specRows}</tbody></table>
   </div>`:'';

 // Threat-technique coverage: which adversary tactics the tenant's live findings span,
 // grouped by the Azure Threat Matrix tactic stamped on every finding. This turns the
 // per-finding technique chips into a portfolio view - where the exposure concentrates.
 const TACTIC_ORDER=['Reconnaissance','Initial Access','Execution','Persistence',
   'Privilege Escalation','Credential Access','Impact'];
 const tacF=(DATA.findings||[]).filter(f=>!f.best_practice&&f.source!=='path_consolidation');
 const byTactic={}; tacF.forEach(f=>{const t=f.atrm_tactic; if(t){(byTactic[t]=byTactic[t]||[]).push(f);}});
 const worst=fs=>{const o={Critical:0,High:1,Medium:2,Low:3,Info:4};return fs.reduce((m,f)=>Math.min(m,o[f.severity]??4),4);};
 const SEVCLR=['var(--crit)','var(--sev-high,#d97706)','var(--med)','var(--good)','var(--tx3)'];
 const tacticRows=TACTIC_ORDER.map(t=>{
    const fs=byTactic[t]||[];
    if(!fs.length)
      return `<tr><td>${esc(t)}</td><td class="mono small" style="color:var(--tx3)">- no findings</td></tr>`;
    const clr=SEVCLR[worst(fs)];
    return `<tr><td>${esc(t)}</td><td class="mono small" style="color:${clr}">● ${fs.length} finding${fs.length===1?'':'s'}</td></tr>`;
  }).join('');
 const coveredTactics=TACTIC_ORDER.filter(t=>(byTactic[t]||[]).length).length;
 const tacticPanel=tacF.length?`<div class="card" style="margin-top:18px">
    <h2 class="section" style="margin-top:0">Threat technique coverage</h2>
    <div class="muted small" style="margin-bottom:12px">Findings span ${coveredTactics}/${TACTIC_ORDER.length} Azure attack tactics · every finding is mapped to MITRE ATT&CK and the Azure Threat Matrix (ATRM)</div>
    <table class="etable"><tbody>${tacticRows}</tbody></table>
   </div>`:'';

 // Deterministic checks that could not run: the node kind was present but the
 // specific data the check reads (a control property, relationship records) was
 // never collected. Surfacing these is the difference between "control OK" and
 // "control never assessed" - a silent empty result must not read as a clean pass.
 const na=(DATA.not_assessed||[]);
 const naRows=na.slice().sort((a,b)=>(a.rule_id||'').localeCompare(b.rule_id||''))
   .map(n=>`<tr><td class="mono small">${esc(n.rule_id||'')}</td><td class="small">${esc(n.title||'')}</td><td class="mono small muted">${esc(n.reason||'')}</td></tr>`).join('');
 const naPanel=na.length?`<div class="card" style="margin-top:18px">
    <h2 class="section" style="margin-top:0">Checks not assessed</h2>
    <div class="muted small" style="margin-bottom:12px">${na.length} deterministic check${na.length===1?'':'s'} could not run - the required data was not in this collection. These are <b>not</b> clean passes; re-collect the missing attributes to assess them.</div>
    <table class="etable"><thead><tr><th>Check</th><th>Title</th><th>Reason</th></tr></thead><tbody>${naRows}</tbody></table>
   </div>`:'';

 v.innerHTML=`
  ${warnBanner}
  ${analysisGapBanner()}
  <div class="two">
   <div class="card">
    <h2 class="section" style="margin-top:0">Collection statistics</h2>
    <table class="etable"><tbody>${sigRows}</tbody></table>
    ${notAssessable.length?`<div style="margin-top:16px"><h3 class="section">Not assessable from AzureHound</h3><ul style="margin:0;padding-left:18px;color:var(--tx3)">${notAssessable.map(d=>`<li class="small" style="margin:3px 0">${esc(d)}</li>`).join('')}</ul></div>`:''}
   </div>
   <div class="card">
    <h2 class="section" style="margin-top:0">Record type coverage</h2>
    <div class="muted small" style="margin-bottom:12px">${assessedCount}/${ALL_KINDS.length} types assessed${missingCount?' · '+missingCount+' not in collection':''}</div>
    <ul style="margin:0;padding:0;list-style:none">${checklist}</ul>
   </div>
  </div>
  ${tacticPanel}
  ${specPanel}
  ${naPanel}`;
}
function renderCmdList(cmds){
 if(!cmds||!cmds.length) return '';
 return `<pre class="mono small" style="white-space:pre-wrap;margin:4px 0 2px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:8px 10px;font-size:11.5px">${esc(cmds.join('\n'))}</pre><button class="ghost" style="padding:3px 9px;font-size:11px" data-action="copy" data-copytext="${esc(cmds.join('\n'))}">Copy</button>`;
}
function renderPaths(){
 // Unified escalation view: the per-finding maximum-impact paths, the cross-subscription
 // bridges, the consolidated multi-route source identities, and the chokepoints. Remediation
 // prioritisation lives solely under Action Plan, so it is intentionally not repeated here.
 const v=$('#view');
 const am=ATTACKMAP; const mpaths=am.paths||[];
 const xsubPaths=(am.cross_subscription_count!=null)?am.cross_subscription_count:mpaths.filter(p=>(p.subscription_reach_count||0)>=2).length;
 const tiles=[
   {n:am.count||0, l:'Maximum-impact paths', hi:true},
   {n:am.tier0_count||0, l:'Paths reaching Tier-0', crit:true},
   {n:CROSSSUB.bridge_count||xsubPaths||0, l:'Cross-subscription bridges', hi:true},
   {n:PH_CHOKES.length, l:'Chokepoints', hi:true},
 ];
 const tileHtml=tiles.map(t=>`<div class="bhtile${t.crit?' bhtile-hi':''}"><div class="n"${t.crit?' style="color:var(--crit)"':(t.hi?' style="color:var(--accent)"':'')}>${esc(String(t.n))}</div><div class="l">${esc(t.l)}</div></div>`).join('');
 // 1) Maximum-impact paths - each finding's worst-case route to its highest-value target.
 const rows=mpaths.slice(0,120).map(p=>{
   const via=(p.hops||[]).map(h=>h.via).filter(Boolean).join(' → ')||'direct';
   const col=SEV[p.severity]||'var(--muted)';
   return `<tr>
     <td class="nm">${esc((p.entry&&p.entry.name)||'?')}<div class="small muted">${esc(((p.entry&&p.entry.kind)||'').replace('AZ',''))}</div></td>
     <td class="mi-arrow">→</td>
     <td class="nm">${esc((p.target&&p.target.name)||'?')}<div class="small muted">${esc(((p.target&&p.target.kind)||'').replace('AZ',''))}${(p.subscription_reach_count||0)>=2?` · <span class="xsub-inline" title="${esc('Spans '+p.subscription_reach_count+' subscriptions'+((p.subscription_reach||[]).length?': '+(p.subscription_reach||[]).join(', '):''))}">⇄ ${p.subscription_reach_count} subs</span>`:''}</div></td>
     <td style="text-align:center">${p.reaches_tier0?'<span class="t0-yes">◆ yes</span>':'<span class="muted">-</span>'}</td>
     <td style="text-align:center">${p.length}</td>
     <td class="small muted">${esc(via)}</td>
     <td><span class="sevtag" style="background:${col}">${esc(p.severity||'')}</span></td>
    </tr>`;}).join('');
 const miSection=mpaths.length?`<div class="card" style="margin-top:16px">
   <h3 class="cardh">Maximum-impact paths <span class="muted small">(top ${Math.min(mpaths.length,120)} of ${mpaths.length}, ranked by impact then Tier-0 reach)</span></h3>
   <div style="overflow-x:auto"><table class="etable csbtable"><thead><tr>
     <th>Entry point</th><th></th><th>Objective</th><th style="text-align:center">Tier-0</th><th style="text-align:center">Hops</th><th>Route</th><th>Severity</th>
    </tr></thead><tbody>${rows}</tbody></table></div>
  </div>`:'';
 // 2) Cross-subscription bridges (folded in, not a separate menu).
 const csSection=crossSubCards();
 // 3) Consolidated routes by source identity - every independent route per source.
 const consolSection=PATH_FINDINGS.length?`<h2 class="section">Consolidated routes by source (${PATH_FINDINGS.length})</h2>
   <p class="muted small" style="margin:-6px 0 10px">Each source identity below reaches Tier-0 by several independent routes; expand a card for every route it can take.</p>
   <div id="pathflist">${PATH_FINDINGS.map(findingCard).join('')}</div>`:'';
 // 4) Chokepoints - the nodes that sever the most paths per fix.
 const chokeRows=PH_CHOKES.map((c,i)=>`
  <div class="chokerow">
   <div class="chokehead">
    <span class="ix">${i+1}</span>
    <span style="font-weight:600">${esc(c.node_name)}</span>
    <span class="muted small" style="margin-left:4px">${esc(c.node_kind||'')}</span>
    <span class="badge gD" style="margin-left:8px">${c.path_count} path${c.path_count!==1?'s':''}</span>
    <span class="muted small" style="margin-left:4px">${c.coverage_pct}% of paths</span>
    <span class="badge gC" style="margin-left:6px">${c.unique_source_count} source${c.unique_source_count!==1?'s':''}</span>
    ${c.critical_count?`<span class="badge gF" style="margin-left:4px">${c.critical_count}×Crit</span>`:''}
    ${c.high_count?`<span class="badge gD" style="margin-left:4px">${c.high_count}×High</span>`:''}
    <button class="ghost" style="margin-left:auto;padding:3px 8px;font-size:11px;min-width:26px" data-action="toggle-choke">▼</button>
   </div>
   <div class="chokedetail">
    <p class="small" style="margin:6px 0">${esc(c.action||'')}</p>
    <div class="muted small" style="margin-bottom:4px">Affects: ${(c.unique_sources||[]).map(s=>`<code class="mono" style="font-size:11px">${esc(s)}</code>`).join(', ')}</div>
    ${renderCmdList(c.remediation_commands)}
   </div>
  </div>`).join('');
 const chokeSection=PH_CHOKES.length?`<h2 class="section">Chokepoints - highest-leverage remediation</h2>
   <div class="card" style="margin-bottom:14px">
    <p class="muted small" style="margin:0 0 10px">Intermediate nodes appearing in the most attack paths. Hardening one severs every path that runs through it, so it removes the most risk per action taken.</p>
    ${chokeRows}
   </div>`:'';
 v.innerHTML=`
  <div class="section-head"><h2>Attack Paths</h2>
   <p class="section-sub">The tenant's full privilege-escalation picture: each finding's maximum-impact route to its worst reachable target, the principals that bridge subscriptions, the consolidated multi-route source identities, and the chokepoints that sever the most paths per fix. Paths reaching Tier-0 are full tenant-takeover routes.</p></div>
  <div class="bhtiles" style="margin:14px 0 4px">${tileHtml}</div>
  ${miSection}
  ${csSection}
  ${consolSection}
  ${chokeSection}`;
 qa('.finding',v).forEach(c=>{c.querySelector('.fhead').onclick=()=>c.classList.toggle('open'); wireFindingCopy(c);});
 qa('.pathconsolcard.expanded',v).forEach(pc=>{var pl=pc.querySelector('.pathlist');if(pl)pl.style.display='block';});
}
function tierRow(lbl,cls,n,tot){const pct=tot?Math.round(100*n/tot):0;return `<div class="qtr"><span class="qtl"><span class="tierbadge tb-${cls}">${lbl}</span></span><div class="qbar"><div class="qbfill tbf-${cls}" style="width:${pct}%"></div></div><span class="qtn">${n} · ${pct}%</span></div>`;}
function pctCI(seg){if(!seg||!seg.labeled) return '<span class="muted">not yet labeled</span>';const p=Math.round(seg.precision*100);const lo=Math.round(seg.ci95[0]*100),hi=Math.round(seg.ci95[1]*100);return `<b>${p}%</b> <span class="muted small">(95% CI ${lo}–${hi}%, n=${seg.labeled})</span>`;}
async function renderQuality(){
 const v=$('#view');
 const QT=DATA.quality_tiers||{}, RP=DATA.recall_proxy||{};
 const real=DATA.findings.filter(f=>f.source!=='path_consolidation');
 const tot=real.length;
 const tiers=[['verified_fact','Verified fact','vf'],['corroborated','Corroborated','cor'],['supported','Supported','sup'],['lead','Lead','lead']];
 // recompute tier counts over the shown (non-rollup) set for an honest denominator
 const tc={}; real.forEach(f=>{tc[f.quality_tier]=(tc[f.quality_tier]||0)+1;});
 const needs=real.filter(f=>f.needs_review).length;
 v.innerHTML=`
  <div class="phead"><h2>Result quality</h2><p class="sub">Evidence-based trust tiers, an independent-corroboration view, a recall proxy, and a measured-precision harness you drive by labeling findings.</p></div>
  <div class="qgrid">
    <div class="card">
      <h3>Evidence tiers <span class="muted small">(${tot} findings)</span></h3>
      ${tiers.map(t=>tierRow(t[1],t[2],tc[t[0]]||0,tot)).join('')}
      <p class="muted small" style="margin-top:10px">Verified fact = a config observation read straight from Azure. Corroborated = an identity attack path independently corroborated by graph analysis. Supported = grounded with partial support. Lead = low-confidence hypothesis for review.</p>
      ${needs?`<p class="qwarn">⚠ ${needs} finding(s) flagged for analyst review.</p>`:'<p class="qok">✓ No findings flagged for review.</p>'}
    </div>
    <div class="card">
      <h3>Recall proxy <span class="muted small">(false-negative signal)</span></h3>
      <div class="qbig">${RP.unexplained_entry_count||0}<span class="qbigu">/ ${RP.tier0_reaching_entries||0} tier-0 paths unexplained</span></div>
      ${(RP.unexplained_entry_count||0)===0?'<p class="qok">✓ Every tier-0 escalation path passes through a flagged entity - no orphaned paths.</p>':`<p class="qwarn">Possible blind spots: ${esc((RP.unexplained_samples||[]).slice(0,6).join(', '))}</p>`}
      <p class="muted small">${esc(RP.note||'')}</p>
    </div>
    <div class="card qspan">
      <h3>Measured precision <span class="muted small">(from analyst labels)</span></h3>
      <div id="qmetrics"><span class="muted">Loading…</span></div>
      <p class="muted small" style="margin-top:8px">Open a finding and use the <b>Analyst validation</b> buttons to label it True / False / Unsure. Precision updates live, with a 95% Wilson confidence interval so a small sample is never over-claimed. A deterministic 30-finding sample is suggested below as a worklist.</p>
      <div id="qsample"></div>
    </div>
  </div>`;
 try{
   const r=await fetch(`/api/scans/${DATA._scan_id}/validation`); const j=await r.json();
   const m=j.metrics||{};
   const bytier=(m.by_tier||{}); const bysrc=(m.by_source||{});
   $('#qmetrics').innerHTML=`
     <div class="qoverall">Overall precision: ${pctCI(m.overall)} &nbsp;·&nbsp; <span class="muted">${m.labeled||0} of ${m.labelable_findings||0} labeled${m.unsure?', '+m.unsure+' unsure':''}</span></div>
     <table class="etable" style="margin-top:10px"><thead><tr><th>Segment</th><th>Precision (95% CI)</th></tr></thead><tbody>
     ${['verified_fact','corroborated','supported','lead'].filter(t=>bytier[t]).map(t=>`<tr><td class="nm">${t.replace('_',' ')}</td><td>${pctCI(bytier[t])}</td></tr>`).join('')}
     ${['deterministic','ai_generated','ai_chain'].filter(s=>bysrc[s]).map(s=>`<tr><td class="nm">${s.replace('_',' ')}</td><td>${pctCI(bysrc[s])}</td></tr>`).join('')}
     </tbody></table>`;
   const keys=j.sample||[]; const byk={}; real.forEach(f=>byk[f._finding_key]=f);
   const _tcls=f=>({verified_fact:'vf',corroborated:'cor',supported:'sup',lead:'lead'})[f.quality_tier]||'sup';
   const rows=keys.map(k=>byk[k]).filter(Boolean).map(f=>{const lb=((j.labels||{})[f._finding_key]||{}).verdict||''; return `<tr><td class="nm"><a href="#findings" data-jump="${esc(f._finding_key)}">${esc((f.title||'').slice(0,70))}</a></td><td><span class="tierbadge tb-${_tcls(f)}">${esc((f.quality_tier||'').replace('_',' '))}</span></td><td>${lb?'<b>'+esc(lb.replace('_',' '))+'</b>':'<span class="muted">unlabeled</span>'}</td></tr>`;}).join('');
   $('#qsample').innerHTML=`<h4 style="margin-top:14px">Suggested labeling worklist (${keys.length})</h4><table class="etable"><thead><tr><th>Finding</th><th>Tier</th><th>Your label</th></tr></thead><tbody>${rows}</tbody></table>`;
 }catch(e){ $('#qmetrics').innerHTML='<span class="muted">Live metrics unavailable.</span>'; }
}
function renderGraph(){
  const v=$('#view');
  const sid=encodeURIComponent(DATA._scan_id||'');
  // Embed the live app's graph explorer (fcose layout, prebuilt queries, blast radius, node
  // detail) scoped to THIS scan. embed=1 strips the app chrome so only the explorer shows.
  v.innerHTML=`<div class="section-head"><h2>Attack Graph</h2></div>
    <p class="muted" style="margin:0 0 12px;font-size:13px">Interactive escalation map for this scan - every route to Tier-0. Click a node or edge for its details; use the left panel for prebuilt queries, blast radius and saved views. <a href="/#/graph/${sid}" target="_blank" style="color:var(--accent)">Open full screen ↗</a></p>
    <div style="border:1px solid var(--border);border-radius:12px;overflow:hidden;background:var(--bg)">
      <iframe src="/?embed=1#/graph/${sid}" title="Attack graph for this scan" loading="lazy"
        style="width:100%;height:calc(100vh - 210px);min-height:560px;border:0;display:block"></iframe>
    </div>`;
}
function renderUsage(){
  const v=$('#view'); const u=DATA.ai_usage;
  if(!u||!u.total){ v.innerHTML='<div class="section-head"><h2>AI Usage</h2></div><p class="muted">No AI usage recorded for this scan (it was run without AI analysis).</p>'; return; }
  const t=u.total; const models=Object.keys(u.by_model||{}).sort();
  const fmt=n=>(n||0).toLocaleString();
  const usd=n=>'$'+(n||0).toFixed(4);
  const rows=models.map(m=>{const d=u.by_model[m];
    return `<tr><td class="mono">${esc(m)}</td><td>${d.calls}</td><td>${fmt(d.in)}</td><td>${fmt(d.out)}</td><td>${fmt(d.cache_read)}</td><td>${fmt(d.cache_write)}</td><td>${usd(d.cost)}</td></tr>`;}).join('');
  v.innerHTML=`<div class="section-head"><h2>AI Usage</h2></div>
    <p class="muted" style="margin:0 0 14px;font-size:13px">Token counts are exact (reported by the API). The dollar figure is an <b>estimate</b> = tokens × the rate table in <span class="mono">usage.py</span> - confirm it against your current Anthropic pricing.</p>
    <div class="statgrid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px">
      <div class="statbox card" style="margin:0"><div class="statnum" style="font-size:26px;font-weight:700">${usd(u.estimated_cost_usd)}</div><div class="muted small">Estimated cost</div></div>
      <div class="statbox card" style="margin:0"><div class="statnum" style="font-size:26px;font-weight:700">${t.calls}</div><div class="muted small">AI calls</div></div>
      <div class="statbox card" style="margin:0"><div class="statnum" style="font-size:26px;font-weight:700">${fmt(u.total_tokens)}</div><div class="muted small">Total tokens</div></div>
      <div class="statbox card" style="margin:0"><div class="statnum" style="font-size:26px;font-weight:700">${fmt(t.in)} / ${fmt(t.out)}</div><div class="muted small">Input / output</div></div>
    </div>
    <div class="tablewrap"><table><thead><tr><th>Model</th><th>Calls</th><th>Input</th><th>Output</th><th>Cache read</th><th>Cache write</th><th>Est. cost</th></tr></thead>
      <tbody>${rows}<tr style="font-weight:700;border-top:2px solid var(--border-2)"><td>Total</td><td>${t.calls}</td><td>${fmt(t.in)}</td><td>${fmt(t.out)}</td><td>${fmt(t.cache_read)}</td><td>${fmt(t.cache_write)}</td><td>${usd(t.cost)}</td></tr></tbody></table></div>`;
}
function render(){({overview:renderOverview,findings:renderFindings,paths:renderPaths,attackmap:renderPaths,graph:renderGraph,roadmap:renderRoadmap,quality:renderQuality,coverage:renderCoverage,usage:renderUsage}[state.section]||renderOverview)();}
renderNav();topbar();render();
"""
