"""Top-level orchestration: collection -> full assessment result."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import ingest
from .derive import derive
from .model import Graph, NodeKind
from .normalize import build_graph
from .rules import run_rules
from .rules.knowledge import detail_for
from .scoring import Analytics, PostureScore, compute_analytics, compute_attack_graph, compute_attack_paths, compute_score

__version__ = "2.1.0"


def assess_bytes(raw: bytes, *, source: str = "<upload>") -> dict[str, Any]:
    _, result = assess_bytes_with_graph(raw, source=source)
    return result


def _blast_radius_top(g, analytics):
    """Top entry points by blast radius, each carrying the structured blast summary (PRD v2.1
    Workstream B): tenant takeover first, then Tier-0 reached, then weighted resource reach. Only
    the top candidates are enriched (the full structured blast is O(BFS) per principal)."""
    from . import paths
    cand = sorted(analytics.blast_radius.items(), key=lambda kv: -kv[1])[:15]
    rows = []
    for nid, reach in cand:
        n = g.node(nid)
        if n is not None and not paths.is_entry_point(n):
            continue   # holders of critical Tier-0 are listed separately as "already tenant-level"
        br = paths.blast_radius(g, nid)
        rows.append({
            "id": nid, "name": g.display(nid),
            "kind": n.kind.value if n else "Unknown",
            "reachable_privileged": reach,
            "reachable_count": br.get("reachable_count", 0),
            "tenant_takeover": br.get("tenant_takeover", False),
            "tier0_reached": len(br.get("tier0_reached", [])),
            "counts_by_kind": br.get("counts_by_kind", {}),
        })
    _res = {"AZKeyVault", "AZStorageAccount", "AZManagedCluster", "AZContainerRegistry",
            "AZSubscription", "AZVM", "DataSink"}
    rows.sort(key=lambda r: (not r["tenant_takeover"], -r["tier0_reached"],
                             -sum(v for k, v in r["counts_by_kind"].items() if k in _res),
                             -r["reachable_count"]))
    return rows


def _config_from_ing(ing):
    """Extract the identity-plane (IDG) and resource-plane (ARG) config carried in a collection,
    so EVERY entry point (single file, bytes, many) runs the config-plane rules, not only
    assess_many. None when absent (a plain AzureHound dump)."""
    from . import azure_arg, azure_graph
    return (azure_graph.graph_result_from_records(ing.records),
            azure_arg.arg_result_from_records(ing.records))


def assess_bytes_with_graph(raw: bytes, *, source: str = "<upload>",
                            on_progress=None) -> tuple[Graph, dict[str, Any]]:
    ing = ingest.parse_bytes(raw, source=source)
    g = build_graph(ing)
    ic, rc = _config_from_ing(ing)
    return g, _assess(g, on_progress=on_progress, identity_config=ic, resource_config=rc)


def assess_file(path: str | Path) -> dict[str, Any]:
    ing = ingest.parse_file(path)
    ic, rc = _config_from_ing(ing)
    return _assess(build_graph(ing), identity_config=ic, resource_config=rc)


def assess_many(blobs: list[tuple[bytes, str]]) -> dict[str, Any]:
    """Assess several collection files merged into one graph (e.g. ad.json + rm.json)."""
    _, result = assess_many_with_graph(blobs)
    return result


def assess_many_with_graph(blobs: list[tuple[bytes, str]], *, on_progress=None,
                           extra_tier0: "set[str] | None" = None) -> tuple[Graph, dict[str, Any]]:
    if on_progress:
        on_progress(f"Parsing {len(blobs)} file(s)...")
    ing = ingest.parse_many(blobs)
    g = build_graph(ing)
    if on_progress:
        total = g.ingest_summary.get("total_records", "?") if g.ingest_summary else "?"
        on_progress(f"Parsed {total} records across {len(list(g.nodes()))} entities and {len(list(g.edges()))} relationships.")
    # Identity-plane config (Conditional Access, security defaults, authorization policy) and
    # resource-plane config (Azure Resource Graph rows) can be carried IN the collection, so the
    # identity-config (IDG-*) and resource-config (ARG-*) rules run deterministically on a file /
    # the bundled demo, not only on a live Microsoft Graph / Resource Graph pull. None when
    # absent (a plain AzureHound dump), so the live path is unaffected.
    identity_config, resource_config = _config_from_ing(ing)
    return g, _assess(g, on_progress=on_progress, extra_tier0=extra_tier0,
                      identity_config=identity_config, resource_config=resource_config)


def _assess(g: Graph, *, on_progress=None, extra_tier0: "set[str] | None" = None,
            identity_config=None, resource_config=None) -> dict[str, Any]:
    if on_progress:
        n = len(extra_tier0 or ())
        on_progress("Re-deriving privilege-escalation edges (ownership, RBAC, managed identity, PIM eligibility)..."
                    + (f" +{n} user-selected Tier-0 asset(s)" if n else ""))
    derive(g, extra_tier0=extra_tier0)
    if on_progress:
        on_progress("Running deterministic safety-net rules...")
    result = run_rules(g)
    if on_progress:
        crit = sum(1 for f in result.findings if f.severity.value == "Critical")
        on_progress(f"Deterministic rules found {len(result.findings)} finding(s) ({crit} critical).")
    score: PostureScore = compute_score(result)
    analytics: Analytics = compute_analytics(g)
    attack_paths = compute_attack_paths(g)
    attack_graph = compute_attack_graph(g, analytics)
    from .completeness import assess_collection
    collection = assess_collection(g)
    return _to_dict(g, result, score, analytics, collection, attack_paths, attack_graph,
                    identity_config=identity_config, resource_config=resource_config)


def _to_dict(g, result, score, analytics, collection, attack_paths=None, attack_graph=None,
             identity_config=None, resource_config=None) -> dict[str, Any]:
    by_category: dict[str, int] = {}
    for f in result.findings:
        by_category[f.category.value] = by_category.get(f.category.value, 0) + 1
    finding_dicts = [
        {
            "source": "deterministic", "rule_id": f.rule_id, "title": f.title, "severity": f.severity.value,
            "category": f.category.value, "best_practice": f.best_practice,
            "entities": [asdict(e) for e in f.entities],
            "affected_count": f.count,
            "what": f.description,
            # Distinct from `what`: the knowledge base's "why" (falls back to the
            # description only when no dedicated rationale exists).
            "why_it_matters": detail_for(f.rule_id).get("why") or f.description,
            "attack_scenario": detail_for(f.rule_id).get("scenario", ""),
            "escalation_chain": [],
            "evidence": [],
            "remediation": f.remediation,
            "detection": detail_for(f.rule_id).get("detection", ""),
            "detail": detail_for(f.rule_id),
            "references": f.references, "frameworks": f.frameworks,
        } for f in result.findings
    ]
    # Stamp MITRE ATT&CK + Azure Threat Matrix (ATRM) on every finding for the CLI path too.
    from .coverage import enrich_frameworks
    for _f in finding_dicts:
        enrich_frameworks(_f)
    # Deterministic maximum-impact path for every finding. When the
    # AI pipeline runs it recomputes this over the merged finding set; this covers the
    # deterministic-only path (CLI, no API key) so the attack map is never empty.
    from .scoring import compute_max_impact_paths
    attack_map = compute_max_impact_paths(g, finding_dicts)
    # Config-plane findings carried IN the collection: identity-config (IDG-*, from CA /
    # security-defaults / authorization-policy records) and resource-config (ARG-*, from Azure
    # Resource Graph rows). Appended AFTER the attack map (they are config, not graph paths) but
    # folded into findings, severity counts, by-category, not_assessed and the score, so the CLI
    # and any file scan surface them deterministically, not only a live Azure pull.
    not_assessed = list(result.not_assessed)
    _added = False
    for _cfg, _runner in ((identity_config, "graph_rules"), (resource_config, "arg_rules")):
        if _cfg is None:
            continue
        if _runner == "graph_rules":
            from .graph_rules import run_graph_rules as _run
        else:
            from .arg_rules import run_arg_rules as _run
        _findings, _na = _run(_cfg)
        for _f in _findings:
            enrich_frameworks(_f)
            by_category[_f.get("category", "")] = by_category.get(_f.get("category", ""), 0) + 1
        finding_dicts.extend(_findings)
        not_assessed.extend(_na)
        _added = _added or bool(_findings)
    if _added:
        from .scoring import rescore_from_findings
        score = rescore_from_findings(finding_dicts)   # dict shape, same keys as asdict(score)
    _score_dict = score if isinstance(score, dict) else asdict(score)
    return {
        "tool_version": __version__,
        "tenant_id": g.tenant_id,
        "ingest_summary": g.ingest_summary,
        "ai_enabled": False,
        "ai_executive_summary": None,
        "score": _score_dict,
        "findings": finding_dicts,
        "attack_map": attack_map,
        "not_assessed": not_assessed,
        "coverage": {
            "assessed_kinds": sorted(result.assessed_kinds),
            "not_assessable_domains": [
                "MFA / authentication methods", "Conditional Access policies",
                "Sign-in / audit logs", "Network (NSG / exposure)",
                "Encryption-at-rest / data-plane", "Diagnostic logging",
            ],
        },
        "analytics": {
            "tier0": analytics.tier0,
            "maximum_impact_chain": analytics.max_impact,
            "choke_points": analytics.choke_points,
            "choke_fix_plan": (analytics.choke or {}).get("fix_plan", []),
            "choke_pairs_total": (analytics.choke or {}).get("pairs_total", 0),
            "choke_exact_min_cut": (analytics.choke or {}).get("exact_min_cut"),
            "exposure": analytics.exposure,
            "blast_radius_top": _blast_radius_top(g, analytics),
            "findings_by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
            "cross_subscription": analytics.cross_subscription,
        },
        "collection": collection,
        "attack_paths": (attack_paths or {}).get("paths", []),
        "attack_graph": attack_graph or {"nodes": [], "edges": []},
        "subscriptions": {
            n.id.split("/")[2]: n.name or n.id.split("/")[2]
            for n in g.nodes_of_kind(NodeKind.SUBSCRIPTION)
            if "/" in n.id and len(n.id.split("/")) > 2
        },
    }
