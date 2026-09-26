"""Per-scan AI token usage + estimated cost accounting.

Every AI response's `usage` is recorded into a process-global, thread-safe meter that the
scan pipeline brackets (reset at scan start, snapshot before save). Token counts are EXACT
(reported by the API); the dollar figure is those counts times the editable rate table
below. Confirm the rates against current Anthropic pricing - only the cost is an estimate,
the token counts are real.

Concurrency note: the meter assumes one active scan at a time (scans run as background
jobs, normally sequential). Two truly-concurrent scans would share the meter; the recorded
totals would then combine - acceptable for a single-operator tool.
"""
from __future__ import annotations

import threading

# USD per 1,000,000 tokens. EDIT to match your current Anthropic pricing.
# cache_read = cached-input read rate; cache_write = cache-creation (write) rate.
PRICING: dict[str, dict[str, float]] = {
    "claude-opus-5":             {"in": 15.0, "out": 75.0, "cache_read": 1.50,  "cache_write": 18.75},
    "claude-sonnet-5":           {"in": 3.0,  "out": 15.0, "cache_read": 0.30,  "cache_write": 3.75},
    "claude-haiku-4-5":          {"in": 1.0,  "out": 5.0,  "cache_read": 0.10,  "cache_write": 1.25},
}
_DEFAULT_RATE = {"in": 3.0, "out": 15.0, "cache_read": 0.30, "cache_write": 3.75}


def _rate(model: str) -> dict[str, float]:
    m = model or ""
    for key, rate in PRICING.items():
        if m.startswith(key) or key.startswith(m):
            return rate
    return _DEFAULT_RATE


class _Meter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._on = False
        self._calls: list[dict] = []

    def reset(self) -> None:
        with self._lock:
            self._on = True
            self._calls = []

    def record(self, model: str, usage) -> None:
        """Record one response's usage (a no-op unless a scan bracket is active)."""
        if usage is None:
            return
        with self._lock:
            if not self._on:
                return
        try:
            row = {
                "model": model or "",
                "in": int(getattr(usage, "input_tokens", 0) or 0),
                "out": int(getattr(usage, "output_tokens", 0) or 0),
                "cache_read": int(getattr(usage, "cache_read_input_tokens", 0) or 0),
                "cache_write": int(getattr(usage, "cache_creation_input_tokens", 0) or 0),
            }
        except Exception:
            return
        with self._lock:
            self._calls.append(row)

    def snapshot(self) -> dict:
        """Summarise and stop recording (called once per scan, before save)."""
        with self._lock:
            calls = list(self._calls)
            self._on = False
        return summarize(calls)


meter = _Meter()


def summarize(calls: list[dict]) -> dict:
    """Aggregate raw per-call rows into per-model + total token counts and est. cost."""
    by_model: dict[str, dict] = {}
    total = {"calls": 0, "in": 0, "out": 0, "cache_read": 0, "cache_write": 0, "cost": 0.0}
    for c in calls:
        r = _rate(c["model"])
        cost = (c["in"] * r["in"] + c["out"] * r["out"]
                + c["cache_read"] * r["cache_read"] + c["cache_write"] * r["cache_write"]) / 1_000_000.0
        m = by_model.setdefault(c["model"], {"calls": 0, "in": 0, "out": 0,
                                             "cache_read": 0, "cache_write": 0, "cost": 0.0})
        for f in ("in", "out", "cache_read", "cache_write"):
            m[f] += c[f]
            total[f] += c[f]
        m["calls"] += 1
        m["cost"] = round(m["cost"] + cost, 6)
        total["calls"] += 1
        total["cost"] += cost
    total["cost"] = round(total["cost"], 6)
    return {
        "by_model": by_model,
        "total": total,
        "total_tokens": total["in"] + total["out"] + total["cache_read"] + total["cache_write"],
        "estimated_cost_usd": round(total["cost"], 4),
    }
