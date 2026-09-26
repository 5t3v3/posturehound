"""Deterministic finding narration.

AI-narrated findings read specifically ("Aaron Drake, a disabled account, retains
Owner across 11 subscriptions…") because the model names the actual entities. A
deterministic finding historically showed only its rule-level description - the same
generic sentence for every instance - so it felt thin next to the AI version even
though the underlying evidence was every bit as concrete.

This module builds, WITHOUT an LLM, a specific per-finding summary and evidence list
from the finding's own entities and their evidence: counts, names, roles, scopes,
permissions, membership, credential counts, etc. It is deterministic, grounded (every
value comes from the collected graph), and idempotent. Applied to every non-AI finding
(deterministic safety-net rules plus the ARG and Microsoft Graph rules the service
principal collects), so a no-AI scan reads like a real report, not a rule dump.
"""
from __future__ import annotations

from collections import Counter

# Evidence keys worth surfacing, in priority order, with a human label and formatter.
# Kept generic so it works across every rule's evidence shape without per-rule code.
_LIST_KEYS = ("assignments", "permissions", "scopes", "delegated_scopes", "roles",
              "self_escalating_roles", "vaults", "tier0_via")
_COUNT_KEYS = {
    "member_count": "members", "credential_count": "credentials",
    "distinct_pushers": "principals can push", "key_vaults_reachable": "Key Vaults reachable",
    "permission_count": "dangerous permissions", "role_count": "roles",
    "total_global_admins": "Global Administrators", "tier0_principal_count": "Tier-0 principals",
    "guest_ratio": "guest ratio",
}
_SCALAR_KEYS = ("scope", "subscription", "consent", "role", "securityType",
                "softDeleteRetentionInDays", "enablePurgeProtection", "credentialKeyId")


def _kind(e: dict) -> str:
    return (e.get("kind") or "").replace("AZ", "") or "entity"


def _plural(kind: str, c: int) -> str:
    if c == 1:
        return kind
    if kind.endswith("y"):
        return kind[:-1] + "ies"      # ContainerRegistry -> ContainerRegistries
    if kind.endswith("s"):
        return kind
    return kind + "s"


def _fmt_val(v) -> str:
    if isinstance(v, list):
        head = ", ".join(str(x) for x in v[:4])
        return head + (f" (+{len(v) - 4} more)" if len(v) > 4 else "")
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


def evidence_lines(f: dict, cap: int = 20) -> list[str]:
    """One concrete line per affected entity: its name and the salient facts from its
    evidence - the per-instance detail a reviewer needs to act, with no LLM."""
    out: list[str] = []
    for e in (f.get("entities") or [])[:cap]:
        name = e.get("name") or e.get("id") or "?"
        ev = e.get("evidence") or {}
        note = str(ev.get("note") or "").strip()
        parts: list[str] = []
        for k in _LIST_KEYS:
            if ev.get(k):
                parts.append(_fmt_val(ev[k]))
        for k, label in _COUNT_KEYS.items():
            if isinstance(ev.get(k), (int, float)):
                parts.append(f"{ev[k]} {label}")
        for k in _SCALAR_KEYS:
            if ev.get(k) not in (None, "", [], {}):
                parts.append(f"{k}={_fmt_val(ev[k])}")
        detail = note or "; ".join(parts)
        out.append(f"{name} ({_kind(e)})" + (f" - {detail}" if detail else ""))
    n = f.get("affected_count") or len(f.get("entities") or [])
    if n > cap:
        out.append(f"… and {n - cap} more")
    return out


def finding_summary(f: dict) -> str:
    """A specific one-line summary naming the actual entities and the strongest concrete
    signal - the deterministic equivalent of the AI's per-finding prose."""
    ents = f.get("entities") or []
    n = f.get("affected_count") or len(ents)
    if not ents:
        return (f.get("what") or "").strip()

    kinds = Counter(_kind(e) for e in ents)
    kindstr = " / ".join(f"{c} {_plural(k, c)}" for k, c in kinds.most_common())
    names = [e.get("name") for e in ents if e.get("name")][:4]
    more = n - len(names)
    namestr = ", ".join(names) + (f" (+{more} more)" if more > 0 else "")

    # Strongest quantified signal across the entities (biggest membership / pusher /
    # credential / permission count) makes the scale of the exposure explicit. Skip the
    # weak/low-signal counts (role_count, guest ratio) and anything below 2.
    best_label, best_val = None, -1
    for e in ents:
        ev = e.get("evidence") or {}
        for k, label in _COUNT_KEYS.items():
            if k in ("role_count", "guest_ratio"):
                continue
            v = ev.get(k)
            if isinstance(v, (int, float)) and v > best_val:
                best_val, best_label = v, label
    highlight = ""
    if best_label and best_val >= 2:
        highlight = f" Up to {int(best_val)} {best_label} on a single entity."

    lead = f"{n} affected - {kindstr}: {namestr}." if n > 1 else f"{namestr} ({list(kinds)[0]})."

    # Cross-subscription span - the tenant-wide reach a per-subscription review misses.
    span = ""
    reach = f.get("subscription_reach_count") or 0
    subs = f.get("subscription_reach") or []
    if reach >= 2:
        shown = ", ".join(subs[:3]) + (f" (+{reach - 3} more)" if reach > 3 else "") if subs else ""
        span = f" Compromise spans {reach} subscription(s)" + (f": {shown}" if shown else "") + "."
    return (lead + highlight + span).strip()


def instantiated_scenario(f: dict) -> str:
    """The knowledge-base attack scenario (generic) prefixed with a concrete instantiation
    naming the worst affected entity and the reach it commands - so the scenario reads
    about THIS tenant's principals, not an abstract 'attacker'."""
    generic = str(f.get("attack_scenario") or (f.get("detail") or {}).get("scenario") or "").strip()
    ents = f.get("entities") or []
    if not ents:
        return generic
    top = ents[0]
    name = top.get("name") or "the affected principal"
    bits = []
    if f.get("max_impact_reaches_tier0") or (f.get("max_impact_path") or {}).get("reaches_tier0"):
        bits.append("reaching Tier-0")
    reach = f.get("subscription_reach_count") or 0
    if reach >= 2:
        bits.append(f"across {reach} subscriptions")
    tail = f" ({', '.join(bits)})" if bits else ""
    lead = f"Concretely: an attacker who compromises {name} ({_kind(top)}){tail} realises this."
    return f"{lead} {generic}".strip() if generic else lead


def enrich(f: dict) -> None:
    """Populate a non-AI finding in place with a concrete summary, evidence lines, and a
    distinct why-it-matters. Idempotent; never touches AI or attack-path findings."""
    if not isinstance(f, dict):
        return
    if f.get("source") in ("ai_generated", "ai_chain", "path_consolidation"):
        return
    detail = f.get("detail") or {}
    # A specific, entity-grounded summary (the card leads with this).
    if not (f.get("summary") or "").strip():
        f["summary"] = finding_summary(f)
    # Populate the finding-level evidence list if the rule left it empty.
    if not f.get("evidence"):
        lines = evidence_lines(f)
        if lines:
            f["evidence"] = lines
    # why_it_matters was historically a duplicate of `what` (the rule description). Prefer
    # the knowledge base's distinct "why" so the card does not repeat itself.
    why = str(detail.get("why") or "").strip()
    if why and (f.get("why_it_matters") or "").strip() == (f.get("what") or "").strip():
        f["why_it_matters"] = why
    # Concrete, instantiated attack scenario naming the worst entity + its reach.
    scen = instantiated_scenario(f)
    if scen:
        f["attack_scenario"] = scen
