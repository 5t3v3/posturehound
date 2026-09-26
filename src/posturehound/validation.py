"""Result-quality: calibration, a recall proxy, and a label-driven precision harness.

The findings pipeline is high-precision but its quality was, until now, only *claimed*.
This module makes quality measurable and honest:

  • calibrate()        - assign every finding an evidence-based quality tier and an
                         effective confidence.
  • recall_proxy()     - a differential-coverage signal: tier-0-reaching principals no
                         analytical finding explains, surfaced as possible blind spots.
  • stratified_sample()- a representative, deterministic sample to hand an analyst.
  • precision_metrics()- from analyst labels, precision overall and per tier/source,
                         each with a 95% Wilson confidence interval (never a bare ratio).

Everything here is pure and deterministic given its inputs; the only state is the
analyst's labels, persisted by store.validation_*.
"""
from __future__ import annotations

import collections
import hashlib
import math

from . import store

# Evidence tiers, strongest first. A finding's tier is derived from HOW it can be
# trusted, not from its severity:
#   verified_fact - a configuration fact read straight from Azure (e.g. "storage
#                   account has shared-key enabled"). No identity attack path; the
#                   deterministic rule IS the proof.
#   corroborated  - an identity attack path independently corroborated by graph analysis.
#   supported     - grounded and plausible, with partial or single-engine support.
#   lead          - a low-confidence, uncorroborated AI hypothesis for an analyst to run down.
QUALITY_TIERS = ("verified_fact", "corroborated", "supported", "lead")


def _has_path(f: dict) -> bool:
    return bool((f.get("max_impact_path") or {}).get("hops"))


def classify(f: dict) -> tuple[str, int, bool]:
    """Return (quality_tier, effective_confidence, needs_review) for one finding."""
    src = f.get("source")
    conf = f.get("confidence")
    conf = conf if isinstance(conf, int) else None
    has_path = _has_path(f)

    # A deterministic config finding with no attack path is a direct observation - the
    # highest-trust category.
    if src == "deterministic" and not has_path:
        return "verified_fact", 95, False
    # A deterministic escalation rule with a path is rule-grounded (not a guess).
    if src == "deterministic":
        return "supported", max(conf or 0, 75), False
    # AI hypothesis: confidence decides lead vs supported.
    if (conf or 0) >= 60:
        return "supported", conf or 60, False
    return "lead", conf or 45, True


def calibrate(findings: list[dict]) -> dict:
    """Annotate every finding in place with quality_tier / effective_confidence /
    needs_review.

    Returns the per-tier counts. Idempotent, so it is safe to run at serve time on top
    of whatever the pipeline stored."""
    counts: collections.Counter = collections.Counter()
    for f in findings:
        # Path-consolidation roll-ups are the attack-path view, not report findings - every
        # other function here excludes them, so the tier counts must too, or quality_tiers
        # sums to the raw array (401) and contradicts the 118-finding report it describes.
        if f.get("source") == "path_consolidation":
            continue
        tier, eff, needs = classify(f)
        f["quality_tier"] = tier
        f["effective_confidence"] = eff
        f["needs_review"] = needs
        counts[tier] += 1
    return {t: counts.get(t, 0) for t in QUALITY_TIERS}


def recall_proxy(result: dict) -> dict:
    """A differential-coverage signal for the otherwise-unmeasurable false-negative rate.

    Without a labelled ground-truth tenant, recall cannot be measured directly. This is an
    honest PROXY: every principal that reaches a Tier-0 asset in the computed attack map,
    for which NO analytical finding (rule or AI, excluding the auto-generated path roll-ups)
    names that principal, is a candidate blind spot - the escalation is real but nothing
    explains the misconfiguration behind it. It over-counts (the enabling issue may be filed
    against a group the principal belongs to), so it is a lead list, not a defect count."""
    findings = result.get("findings") or []
    named: set[str] = set()
    for f in findings:
        if f.get("source") == "path_consolidation":
            continue
        for e in f.get("entities") or []:
            eid = (e.get("id") if isinstance(e, dict) else e) or ""
            if eid:
                named.add(str(eid).lower())
    am = result.get("attack_map") or {}
    tier0_paths = [p for p in (am.get("paths") or []) if p.get("reaches_tier0")]
    traversal = {"MemberOf", "Owns"}
    unexplained: dict[str, str] = {}
    for p in tier0_paths:
        # Look at the ABUSE steps on the path - the hops where a principal exercises a
        # privilege (everything except plain MemberOf/Owns traversal). The escalation is
        # "explained" only if a finding actually names the principal doing the abusing; a
        # tenant-wide "any node appears somewhere" test is trivially always true and would
        # make this a meaningless all-clear. A path built purely from group membership has
        # no abuse step here and is covered by the group's own findings, so it is not a gap.
        abuse_sources = {
            str((h.get("from") or {}).get("id") or "").lower()
            for h in (p.get("hops") or [])
            if h.get("via") not in traversal and (h.get("from") or {}).get("id")
        }
        if abuse_sources and abuse_sources.isdisjoint(named):
            ent = p.get("entry") or {}
            eid = str(ent.get("id") or "").lower()
            unexplained.setdefault(eid, ent.get("name") or eid)
    return {
        "tier0_reaching_entries": len(tier0_paths),
        "unexplained_entry_count": len(unexplained),
        "unexplained_samples": list(unexplained.values())[:10],
        "note": "Proxy, not a measured recall. A tier-0 path is a candidate blind spot when "
                "NO finding names the principal exercising a privilege on it - the abused "
                "privilege was never flagged. Pure group-membership chains are excluded.",
    }


def stratified_sample(findings: list[dict], n: int, scan_id: str) -> list[str]:
    """A deterministic, tier-stratified sample of finding_keys for an analyst to label.

    Proportional across quality tiers so the labelled set represents the whole report, and
    seeded by the scan id so the same scan always yields the same sample (a stable worklist)."""
    import random

    pool = [f for f in findings if f.get("source") != "path_consolidation"]
    if not pool:
        return []
    n = max(1, min(n, len(pool)))
    rng = random.Random(int(hashlib.sha1((scan_id or "").encode()).hexdigest()[:12], 16))
    buckets: dict[str, list] = collections.defaultdict(list)
    for f in pool:
        buckets[f.get("quality_tier") or "lead"].append(f)
    total = len(pool)
    keys: list[str] = []
    for tier in QUALITY_TIERS:
        items = buckets.get(tier) or []
        if not items:
            continue
        take = min(len(items), max(1, round(n * len(items) / total)))
        rng.shuffle(items)
        keys.extend(store.finding_key(f) for f in items[:take])
    # Trim/pad to exactly n deterministically.
    if len(keys) > n:
        keys = keys[:n]
    elif len(keys) < n:
        seen = set(keys)
        extra = [store.finding_key(f) for f in pool if store.finding_key(f) not in seen]
        rng.shuffle(extra)
        keys.extend(extra[: n - len(keys)])
    return keys


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials. Honest small-sample bounds
    (a plain k/n over 12 labels is not a defensible precision figure)."""
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def _segment(items: list[tuple[str, dict]]) -> dict:
    tp = sum(1 for _, v in items if v.get("verdict") == "true_positive")
    fp = sum(1 for _, v in items if v.get("verdict") == "false_positive")
    n = tp + fp
    lo, hi = wilson_interval(tp, n)
    return {
        "labeled": n, "tp": tp, "fp": fp,
        "precision": round(tp / n, 3) if n else None,
        "ci95": [round(lo, 3), round(hi, 3)] if n else None,
    }


def precision_metrics(findings: list[dict], labels: dict) -> dict:
    """Measured precision from analyst labels - overall and per quality tier / source,
    each with a 95% Wilson interval. 'unsure' labels are counted but excluded from
    precision. Labels for findings not in this scan are ignored."""
    by_key = {store.finding_key(f): f for f in findings
              if f.get("source") != "path_consolidation"}
    decided = [(k, v) for k, v in labels.items()
               if k in by_key and v.get("verdict") in ("true_positive", "false_positive")]
    by_tier = {}
    for tier in QUALITY_TIERS:
        seg = [(k, v) for k, v in decided if by_key[k].get("quality_tier") == tier]
        if seg:
            by_tier[tier] = _segment(seg)
    by_source = {}
    for src in ("deterministic", "ai_generated", "ai_chain"):
        seg = [(k, v) for k, v in decided if by_key[k].get("source") == src]
        if seg:
            by_source[src] = _segment(seg)
    unsure = sum(1 for k, v in labels.items()
                 if k in by_key and v.get("verdict") == "unsure")
    overall = _segment(decided)
    return {
        "overall": overall,
        "by_tier": by_tier,
        "by_source": by_source,
        "unsure": unsure,
        "labelable_findings": len(by_key),
        "labeled": overall["labeled"] + unsure,
    }
