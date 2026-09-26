"""AI-generated findings, with the deterministic rule engine as a safety net.

Design: the AI is the analyst. It receives the deterministic fact pack
(facts.py) - never raw AzureHound files - and generates the findings: entry
points, misconfigurations, lateral movement, privilege escalation. Every
entity/edge it cites is validated against the fact pack (ai_findings.py); a
finding that references anything not in the tenant is rejected outright.

The deterministic rule engine (rules/library.py) still runs unconditionally and
is kept as a safety net: a small set of always-critical patterns (excessive
Global Admins, guest with Tier-0 role, disabled-but-privileged accounts, etc.)
that must never be silently missed even if the AI omits them. Its findings are
merged with the AI-generated ones, deduped where they overlap, and clearly
labelled by source so nothing is presented as AI-derived that wasn't.

Default model: Claude Sonnet (better reasoning for finding generation than
Haiku; configurable). The API key is read from Settings/per-request; it is
never logged, stored, or placed in output. If no key/SDK is present, AI
generation is skipped and the assessment falls back to the deterministic
findings only, with ai_enabled=False and a specific ai_error.
"""
from __future__ import annotations

import json
import os

from . import ai_findings, store
from .coverage import enrich_frameworks
from .facts import audit_fact_pack, build_fact_pack
from .model import EdgeType, Graph, NodeKind


class LLMClient:
    """Holds model slots: Sonnet (specialists), Opus (synthesizer + correlator), Sonnet/Haiku (skeptic)."""

    def __init__(self, sonnet_model: str = ai_findings.DEFAULT_SONNET_MODEL,
                 haiku_model: str = ai_findings.DEFAULT_HAIKU_MODEL,
                 opus_model: str = ai_findings.DEFAULT_OPUS_MODEL,
                 api_key: str | None = None) -> None:
        self.sonnet_model = sonnet_model
        self.haiku_model  = haiku_model
        self.opus_model   = opus_model
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")

    @property
    def available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import anthropic  # noqa: F401
            return True
        except ImportError:
            return False


def _det_to_unified(f: dict) -> dict:
    """Deterministic findings from the engine are already in the unified shape;
    this only guards against older/foreign dicts missing a field."""
    f = dict(f)
    f.setdefault("source", "deterministic")
    f.setdefault("escalation_chain", [])
    f.setdefault("evidence", [])
    return f


def _dedupe_key(f: dict) -> tuple:
    raw = f.get("entities") or []
    ids = tuple(sorted(
        (e.get("id", "") if isinstance(e, dict) else str(e)) for e in raw
    ))
    return (f.get("category", "").lower(), ids)


def _generate_executive_summary(findings: list[dict], score: dict,
                                 api_key: str,
                                 model: str) -> tuple[str | None, str | None]:
    """Generate a 3-5 sentence executive summary for non-technical stakeholders.

    Uses a single lightweight call after the full pipeline so it has the complete
    picture: confirmed findings and the severity breakdown.

    Returns (summary, error). The error is returned rather than swallowed so a
    missing executive summary is explainable instead of silently blank.
    """
    try:
        import anthropic  # noqa: F401 - availability probe
    except ImportError:
        return None, "the 'anthropic' package is not installed"
    try:
        grade = score.get("grade", "?")
        sc = score.get("score", 0)
        sev = score.get("severity_counts", {})
        # Exclude attack-path findings, exactly as the badges and the score do. Including
        # them let the model count 291 path findings as Criticals and open with "300
        # critical weaknesses" directly above a badge reading "9 critical" - the single
        # most visible contradiction the report could contain. Paths are summarised
        # separately below from their own count.
        scored = [f for f in findings if f.get("source") != "path_consolidation"]
        n_paths = len(findings) - len(scored)
        top = [f for f in scored if f.get("severity") in ("Critical", "High")][:4]
        top_titles = "; ".join(
            (f.get("title", "") or "")[:120].replace("\n", " ") for f in top
        )
        path_note = (f" Separately, graph analysis mapped {n_paths} escalation route(s) to "
                     f"high-privilege targets; these are reported in their own section and "
                     f"are NOT part of the finding counts above." if n_paths else "")
        prompt = (
            f"You are a senior security consultant writing a 3-5 sentence executive summary "
            f"for a board-level audience - no technical jargon, no bullet points, plain prose only.\n\n"
            f"Tenant posture grade: {grade} ({sc}/100).\n"
            f"THESE ARE THE ONLY FINDING COUNTS - use them verbatim and invent no others:\n"
            f"  Critical: {sev.get('Critical',0)}, High: {sev.get('High',0)}, "
            f"Medium: {sev.get('Medium',0)}, Low: {sev.get('Low',0)}.\n"
            f"Top issues: {top_titles or 'none'}.{path_note}\n\n"
            f"Write the executive summary now. State the overall risk level, name the most critical "
            f"exposures without technical detail, and close with one concrete recommended first step. "
            f"Cite ONLY the counts given above - any other number will contradict the report's own "
            f"figures. Do not use headers, bullets, or markdown. Plain paragraph only."
        )
        # Shared factory - a direct construction crashes on a stale SSL_CERT_FILE.
        client = ai_findings.build_client(api_key)
        # create_message, not client.messages.create: `temperature` is deprecated on the
        # Claude 5 models and sending it returns HTTP 400.
        msg = ai_findings.create_message(
            client,
            model=model,
            max_tokens=350,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        text = (msg.content[0].text if msg.content else "").strip()
        if not text:
            return None, "the model returned an empty response"
        return text, None
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


# Bump when a change to prompts, tool schemas or post-processing should invalidate
# every cached analysis (otherwise a repeat scan would replay pre-change output).
AI_ANALYSIS_VERSION = "2026-09-16.2"  # +severity rubric + per-domain reading guide (prompt tuning)

# Fields of GenerationResult that must round-trip through the cache for a replayed
# analysis to be indistinguishable from a fresh one.
_CACHED_GEN_FIELDS = (
    "findings", "rejected", "sonnet_raw_count", "sonnet_grounded_count",
    "stage_errors", "specialist_counts", "failed_specialists",
    "chain_findings_count", "skeptic_dropped", "non_assessable_dropped",
    "coverage_warnings", "chokepoints", "remediation_roadmap",
)


_COMPUTE_KINDS = {NodeKind.VM, NodeKind.VMSS, NodeKind.FUNCTION_APP,
                  NodeKind.LOGIC_APP, NodeKind.WEB_APP, NodeKind.AKS, NodeKind.AUTOMATION}
# Escalation primitives among PRINCIPALS - the attack surface. Edges to ephemeral compute
# (managed-identity theft on a specific VM) are excluded from the fingerprint: which VM
# instance currently hosts an identity is not a posture change.
_FINGERPRINT_EDGES = {
    EdgeType.CAN_ADD_SECRET, EdgeType.CAN_ADD_MEMBER, EdgeType.CAN_ADD_OWNER,
    EdgeType.CAN_GRANT_ROLE, EdgeType.CAN_GRANT_APP_ROLE, EdgeType.CAN_ESCALATE_RBAC,
    EdgeType.CAN_RESET_PASSWORD,
}


def _stabilize_entity(g: Graph, eid: str) -> str:
    """Map an ephemeral compute resource to the STABLE identity it carries, so a VM instance
    being replaced by an equivalent one (same managed identity, same privilege) is not seen as
    a change. A new host with a NEW identity still changes the fingerprint - as it should."""
    n = g.node(eid)
    if n is not None and n.kind in _COMPUTE_KINDS:
        mis = sorted(e.dst for e in g.out_edges(eid, EdgeType.HAS_MANAGED_IDENTITY))
        return "compute:" + (",".join(mis) if mis else n.kind.value)
    return eid


def _posture_fingerprint(g: Graph, det_findings: list[dict]) -> list:
    """A signature of the tenant's SECURITY POSTURE, stable across benign inventory churn.

    Built from the deterministic findings (rule id + the entities each is about, with ephemeral
    compute normalized to its managed identity) plus the Tier-0 set and the principal-plane
    escalation edges. The 110 deterministic rules comprehensively cover the attack surface, so
    if this signature is unchanged the security posture is unchanged - and the (non-deterministic)
    AI analysis can be replayed rather than re-rolled. A real change - a new privileged principal,
    a new dangerous grant, a new escalation path, a newly-exposed resource - moves a deterministic
    finding and so changes the signature, busting the cache. Only churn that no rule flags (an
    ephemeral VM, an unprivileged new account) is tolerated, which is exactly what makes two
    consecutive scans of an unchanged posture return the same result."""
    findings_sig = sorted(
        (
            (f.get("rule_id") or f.get("title") or ""),
            tuple(sorted(_stabilize_entity(g, e.get("id") if isinstance(e, dict) else e)
                         for e in (f.get("entities") or [])
                         if (e.get("id") if isinstance(e, dict) else e))),
        )
        for f in det_findings
    )
    tier0 = sorted(n.id for n in g.nodes() if "tier0" in n.tags)
    esc = sorted(
        (e.src, e.dst, e.type.value) for e in g.edges()
        if e.type in _FINGERPRINT_EDGES
    )
    return [findings_sig, tier0, esc]


def _analysis_cache_key(fact_pack, client: LLMClient, det_findings: list[dict],
                        g: Graph) -> str:
    """Hash the SECURITY POSTURE the analysis depends on - not the raw fact pack.

    Keying on the whole pack meant any incidental inventory drift (an ephemeral VM spinning up,
    a non-privileged account created) produced a different key, missed the cache, and re-rolled
    the non-deterministic model ensemble - so two consecutive scans of an UNCHANGED posture
    returned very different finding sets. Instead we key on a posture fingerprint: the
    deterministic findings (which comprehensively cover the attack surface) plus the Tier-0 set
    and principal-plane escalation edges, with ephemeral compute normalized to its identity.
    Same posture ⇒ same key ⇒ the stored analysis is replayed; a real posture change moves a
    deterministic finding and busts the key. This makes the tool's result stable run-to-run
    while still re-analysing whenever the security posture actually changes."""
    import hashlib

    payload = {
        "version": AI_ANALYSIS_VERSION,
        "models": [client.sonnet_model, client.opus_model, client.haiku_model],
        "posture": _posture_fingerprint(g, det_findings),
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:32]


def _gen_from_cache(cached: dict):
    gen = ai_findings.GenerationResult()
    for k in _CACHED_GEN_FIELDS:
        if k in cached:
            setattr(gen, k, cached[k])
    gen.sonnet_model = cached.get("sonnet_model", "")
    gen.opus_model = cached.get("opus_model", "")
    gen.haiku_model = cached.get("haiku_model", "")
    gen.det_rejected_keys = set(cached.get("det_rejected_keys") or [])
    return gen


def _gen_to_cache(gen) -> dict:
    out = {k: getattr(gen, k, None) for k in _CACHED_GEN_FIELDS}
    out["sonnet_model"] = gen.sonnet_model
    out["opus_model"] = gen.opus_model
    out["haiku_model"] = gen.haiku_model
    out["det_rejected_keys"] = sorted(getattr(gen, "det_rejected_keys", set()) or [])
    return out


# Prose fields whose exact wording should read identically across re-runs. Structural
# fields (severity, confidence, entities, category, attack_primitive, paths) are
# NEVER pinned - they must always reflect the current tenant, only the words are frozen.
_NARRATIVE_FIELDS = ("title", "summary", "what", "reasoning", "why_it_matters",
                     "attack_scenario", "remediation", "detection")


def _narrative_identity(f: dict) -> str:
    """Stable, wording-independent identity for a finding.

    Keyed on the facts that make it THIS finding - its rule (or specialist category)
    plus the exact set of entities it is about - never on its title or prose (which is
    what we are pinning). Same entities + same category ⇒ same identity ⇒ the same
    wording is reused; if the entity set changes, the identity changes and the finding
    is re-narrated afresh, so a materially different finding never inherits stale prose.
    """
    import hashlib
    ents = f.get("entities") or []
    ids = sorted(
        (e.get("id", "") if isinstance(e, dict) else str(e)) for e in ents
        if (e.get("id") if isinstance(e, dict) else e)
    )
    base = f.get("rule_id") or f.get("category") or ""
    if not ids and not base:
        return ""
    # Fold in the affected count: the pinned prose often cites a number ("297 members"),
    # which lives in the wording, not the entity-id set. If the count drifts (297 -> 290)
    # the identity must change so the finding RE-narrates instead of pinning a stale number
    # over current data. len(ids) is the fallback when affected_count is absent.
    cnt = f.get("affected_count")
    if not isinstance(cnt, int):
        cnt = len(ids)
    sig = f"{base}|{cnt}|{','.join(ids)}"
    return hashlib.sha1(sig.encode()).hexdigest()[:20]


def pin_narratives(findings: list[dict], *, reuse: bool = True,
                   on_progress=None) -> dict:
    """Make a finding's human-readable text reproducible across re-runs.

    The whole-analysis cache only replays on a byte-identical fact pack; a live
    re-collection drifts and re-samples the models, so the SAME finding reads
    differently each run. This second layer pins the prose per finding: the first
    time a finding is seen its wording is stored under its stable identity, and every
    later run overlays that stored wording, so recurring findings read identically.
    reuse=False (a 'Fresh AI analysis' request) re-samples AND re-pins to the new
    wording, so subsequent normal runs reproduce the fresh text. Best-effort.
    """
    pinned = stored = 0
    for f in findings:
        ident = _narrative_identity(f)
        if not ident:
            continue
        prev = store.narrative_get(ident) if reuse else None
        if prev:
            for k in _NARRATIVE_FIELDS:
                v = prev.get(k)
                if isinstance(v, str) and v.strip():
                    f[k] = v
            pinned += 1
        else:
            payload = {k: f[k] for k in _NARRATIVE_FIELDS
                       if isinstance(f.get(k), str) and f[k].strip()}
            if payload and store.narrative_put(ident, payload):
                stored += 1
    if on_progress and (pinned or stored):
        on_progress(f"Narrative pin: {pinned} finding(s) reuse their prior wording "
                    f"(reproducible), {stored} newly pinned.")
    return {"pinned": pinned, "stored": stored}


def _attach_attack_map(result: dict, findings: list[dict], g: Graph,
                       client: "LLMClient", *, on_progress=None, trace=None) -> None:
    """Give every attack a maximum-impact path and a path plot.

    1. scoring.compute_max_impact_paths walks the real escalation graph to attach the
       worst-case path to each finding (deterministic, grounded).
    2. The cartographer specialist narrates and names each path (AI, with a
       deterministic fallback so coverage is total).
    Best-effort: any failure leaves the deterministic paths intact and is surfaced,
    never raised."""
    from .scoring import compute_max_impact_paths
    try:
        amap = compute_max_impact_paths(g, findings)
    except Exception as e:  # pragma: no cover - defensive
        result["attack_map"] = {"paths": [], "count": 0, "tier0_count": 0,
                                "error": f"{type(e).__name__}: {e}"}
        return

    cart_client = None
    if client is not None and getattr(client, "available", False):
        try:
            cart_client = ai_findings.build_client(client.api_key)
        except Exception:
            cart_client = None
    # Narrate only the top few paths, on Haiku (naming + one-line summary of an ALREADY-computed
    # path is restatement, not reasoning - the deterministic fallback covers every other path).
    # Was Opus (priciest), then Sonnet; Haiku is quality-neutral here and ~3× cheaper than Sonnet.
    model = ai_findings.DEFAULT_NARRATION_MODEL
    try:
        enriched = ai_findings.run_attack_cartographer(
            cart_client, model, findings, on_progress=on_progress, trace=trace)
    except Exception as e:
        enriched = 0
        if on_progress:
            on_progress(f"Cartographer failed: {type(e).__name__}: {e}")

    result["attack_map"] = amap
    if on_progress:
        on_progress(
            f"Attack map: {amap['count']} maximum-impact path(s) "
            f"({amap['tier0_count']} reaching Tier-0); {enriched} narrated by the cartographer.")


def apply_ai_generation(result: dict, g: Graph, client: LLMClient, *,
                         on_progress=None,
                         reuse_analysis: bool = True, trace=None) -> dict:
    """Run the multi-specialist AI pipeline (17 Sonnet specialists -> Opus compound
    synthesizer -> Opus attack-chain correlator -> skeptic -> attack-map cartographer)
    over the fact pack, merge with the deterministic safety-net findings already in
    `result`, and return the updated result. Never raises for AI failures - those are
    captured as ai_error so the caller can surface them; the deterministic findings are
    always preserved."""
    det_unified = [_det_to_unified(f) for f in result["findings"]]
    # Stamp MITRE ATT&CK + Azure Threat Matrix (ATRM) on every deterministic finding (covers
    # the AI-unavailable / AI-failed early returns too; the AI findings are stamped post-merge).
    for _f in det_unified:
        enrich_frameworks(_f)
    result["deterministic_finding_count"] = len(det_unified)

    if not client.available:
        result["ai_enabled"] = False
        result["ai_error"] = ("AI generation was requested but the 'anthropic' package or an "
                              "API key is not available.")
        result["findings"] = det_unified
        return result

    try:
        if on_progress:
            on_progress("Extracting the deterministic fact pack for AI reasoning...")
        fact_pack = build_fact_pack(g)
        # Standing accuracy check: cross-validate the pack against the graph before the model
        # ever sees it. An accurate pack is silent; a fabricated entity, a phantom escalation
        # edge, or a drifted count is recorded on the result and surfaced loudly, so a
        # derivation regression is caught rather than narrated to the model as fact.
        try:
            _audit = audit_fact_pack(g, fact_pack)
            result["fact_pack_audit"] = {
                "ok": _audit["ok"],
                "counts_mismatch": len(_audit["counts_mismatch"]),
                "ungrounded_entities": len(_audit["ungrounded_entities"]),
                "phantom_escalation_edges": len(_audit["phantom_escalation_edges"]),
                "tier0_not_in_graph": len(_audit["tier0_not_in_graph"]),
            }
            if not _audit["ok"] and on_progress:
                _n = (result["fact_pack_audit"]["ungrounded_entities"]
                      + result["fact_pack_audit"]["phantom_escalation_edges"]
                      + result["fact_pack_audit"]["counts_mismatch"]
                      + result["fact_pack_audit"]["tier0_not_in_graph"])
                on_progress(f"[ACCURACY] fact-pack audit found {_n} integrity issue(s) - see "
                            f"result['fact_pack_audit']; the pack may misrepresent the graph.")
        except Exception:
            pass   # the audit is a safety net; it must never break a scan
        # Reproducibility: replay a stored analysis when the inputs are byte-identical.
        # The models reject temperature/top_p/top_k, so re-running the same collection
        # re-samples and yields a different finding set (63-73 on one real tenant). The
        # cache makes the TOOL deterministic even though the model is not.
        cache_key = _analysis_cache_key(fact_pack, client, det_unified, g)
        result["ai_analysis_key"] = cache_key
        cached = store.ai_cache_get(cache_key) if reuse_analysis else None
        if cached:
            gen = _gen_from_cache(cached)
            result["ai_analysis_reused"] = True
            if on_progress:
                on_progress(
                    "Reusing the stored AI analysis - this collection and model set were "
                    "already analysed, so the findings are identical to that run. "
                    "Re-scan with 'Fresh AI analysis' to re-query the models."
                )
        else:
            gen = ai_findings.generate_findings(fact_pack, client.api_key,
                                                sonnet_model=client.sonnet_model,
                                                opus_model=client.opus_model,
                                                haiku_model=client.haiku_model,
                                                on_progress=on_progress,
                                                det_findings=det_unified,
                                                # Lets every specialist distinguish "absent
                                                # from the tenant" from "never collected".
                                                collection=result.get("collection"),
                                                trace=trace)
            result["ai_analysis_reused"] = False
            if not store.ai_cache_put(cache_key, _gen_to_cache(gen)) and on_progress:
                # Never fail silently: a cache that quietly refuses to write means the
                # next identical scan re-samples and the results differ again.
                _why = (store.AI_CACHE_LAST_ERROR or ["unknown error"])[-1]
                on_progress(f"Warning: could not store the analysis for reuse ({_why}). "
                            f"A repeat scan of this collection will re-query the models "
                            f"and may return a different finding set.")
    except Exception as e:  # network / auth / model / parse errors at either stage
        result["ai_enabled"] = False
        result["ai_error"] = f"AI generation failed: {type(e).__name__}: {e}"
        result["findings"] = det_unified
        return result

    if on_progress:
        on_progress("Merging AI-generated findings with the deterministic safety net...")
    seen = {_dedupe_key(f) for f in gen.findings}
    det_rejected = getattr(gen, "det_rejected_keys", set())
    merged = list(gen.findings) + [
        f for f in det_unified
        if _dedupe_key(f) not in seen
        and (f.get("rule_id") or f.get("title") or "") not in det_rejected
    ]
    merged.sort(key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(f["severity"], 5))

    # Stamp ATT&CK + ATRM on the merged set - the AI findings (mitre_technique) get their
    # frameworks here, the deterministic ones are already tagged (idempotent).
    for _f in merged:
        enrich_frameworks(_f)
    result["findings"] = merged

    # Reproducible wording: overlay each finding's pinned prose (or pin it on first
    # sight) BEFORE the cartographer and executive summary read titles, so the whole
    # report downstream is worded identically on a re-scan of the same tenant.
    _pin = pin_narratives(merged, reuse=reuse_analysis, on_progress=on_progress)
    result["ai_narrative_pinned"] = _pin["pinned"]
    result["ai_narrative_stored"] = _pin["stored"]

    # Maximum-impact path plot - every attack gets its worst-case path
    # through the real escalation graph, and the cartographer narrates and names it.
    _attach_attack_map(result, merged, g, client, on_progress=on_progress, trace=trace)

    # Recompute severity counts from the merged list - pre-AI counts only covered
    # deterministic findings, so the filter bar would show wrong numbers.
    # Attack-path findings are EXCLUDED, matching scoring.rescore_from_findings and the
    # badges. Counting them here inflated Critical from 9 to 300, and because the
    # executive summary is generated from these counts it opened with "300 critical
    # findings" directly above a badge reading 9.
    if "score" in result:
        _scored = [f for f in merged if f.get("source") != "path_consolidation"]
        result["score"]["severity_counts"] = {
            s: sum(1 for f in _scored if f.get("severity") == s)
            for s in ("Critical", "High", "Medium", "Low", "Info")
        }
    result["ai_enabled"] = True
    result["ai_model"] = (f"{gen.sonnet_model} (specialists) \u2192 "
                          f"{gen.opus_model} (synthesizer+correlator) \u2192 "
                          f"{gen.haiku_model} (skeptic) \u2192 "
                          f"{ai_findings.DEFAULT_NARRATION_MODEL} (narration)")
    result["ai_sonnet_model"] = gen.sonnet_model
    result["ai_opus_model"]   = gen.opus_model
    result["ai_haiku_model"]  = gen.haiku_model
    result["ai_sonnet_raw_count"] = gen.sonnet_raw_count
    result["ai_sonnet_grounded_count"] = gen.sonnet_grounded_count
    result["ai_generated_count"] = sum(1 for f in gen.findings if f.get("source") == "ai_generated")
    result["ai_rejected_count"] = len(gen.rejected)
    result["ai_rejected"] = gen.rejected[:20]
    # Split the reject reasons so the report is accurate: "referencing entities not in this
    # tenant" is only true for grounding rejects. Malformed model output (no title / bad
    # severity) is a DIFFERENT failure and must not be reported as a hallucination signal.
    _ungrounded = sum(1 for r in gen.rejected
                      if isinstance(r, dict) and "entity id(s) unknown" in (r.get("reason") or ""))
    _malformed = len(gen.rejected) - _ungrounded
    result["ai_rejected_ungrounded"] = _ungrounded
    result["ai_rejected_malformed"] = _malformed
    result["ai_stage_errors"] = gen.stage_errors
    result["ai_specialist_counts"] = gen.specialist_counts
    result["ai_failed_specialists"] = gen.failed_specialists
    result["ai_skeptic_dropped"] = gen.skeptic_dropped
    result["ai_error"] = None
    result["chokepoints"]         = gen.chokepoints
    result["remediation_roadmap"] = gen.remediation_roadmap
    result["coverage_warnings"]   = gen.coverage_warnings

    # Generate executive summary last - it needs the fully merged finding list
    if on_progress:
        on_progress("Generating executive summary...")
    summary, summary_err = _generate_executive_summary(
        merged,
        result.get("score", {}),
        client.api_key,
        ai_findings.DEFAULT_NARRATION_MODEL,   # narration, not reasoning - Haiku is fine here
    )
    if summary:
        result["ai_executive_summary"] = summary
    elif summary_err:
        result["ai_stage_errors"] = list(result.get("ai_stage_errors") or []) + [
            f"Executive summary could not be generated: {summary_err}"
        ]
        if on_progress:
            on_progress(f"Executive summary failed: {summary_err}")

    return result
