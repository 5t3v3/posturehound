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

__version__ = "2.0.0"


def assess_bytes(raw: bytes, *, source: str = "<upload>") -> dict[str, Any]:
    _, result = assess_bytes_with_graph(raw, source=source)
    return result


def assess_bytes_with_graph(raw: bytes, *, source: str = "<upload>",
                            on_progress=None) -> tuple[Graph, dict[str, Any]]:
    ing = ingest.parse_bytes(raw, source=source)
    g = build_graph(ing)
    return g, _assess(g, on_progress=on_progress)


def assess_file(path: str | Path) -> dict[str, Any]:
    ing = ingest.parse_file(path)
    return _assess(build_graph(ing))


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
    return g, _assess(g, on_progress=on_progress, extra_tier0=extra_tier0)


def _assess(g: Graph, *, on_progress=None, extra_tier0: "set[str] | None" = None) -> dict[str, Any]:
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
    return _to_dict(g, result, score, analytics, collection, attack_paths, attack_graph)


def _to_dict(g, result, score, analytics, collection, attack_paths=None, attack_graph=None) -> dict[str, Any]:
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
    return {
        "tool_version": __version__,
        "tenant_id": g.tenant_id,
        "ingest_summary": g.ingest_summary,
        "ai_enabled": False,
        "ai_executive_summary": None,
        "score": asdict(score),
        "findings": finding_dicts,
        "attack_map": attack_map,
        "not_assessed": result.not_assessed,
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
            "blast_radius_top": sorted(
                ({"id": k, "name": g.display(k), "reachable_privileged": v}
                 for k, v in analytics.blast_radius.items()),
                key=lambda x: -x["reachable_privileged"])[:15],
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
