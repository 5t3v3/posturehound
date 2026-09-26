"""Verbose per-scan AI trace: a live, human-readable log of how the analysis unfolded -
every pipeline stage, the model's own reasoning, each candidate finding, and every
grounding / skeptic / coherence decision. Written to two files that grow in real time
(flushed after every entry, so `tail -f` shows a scan think out loud):

    ~/.posturehound/scan_traces/<id>.log     human-readable transcript (Claude-Code style)
    ~/.posturehound/scan_traces/<id>.jsonl   one JSON record per event, for tooling

Thread-safe: the 17 specialists run in parallel and all write through one TraceWriter.
Local only - a trace contains tenant specifics and never leaves the machine or the report.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .store import DATA_DIR

TRACE_DIR = DATA_DIR / "scan_traces"


def _clip(s, n=2000):
    # The trace is a COMPLETE, local, human-readable record of the run - it is deliberately
    # not truncated. `n` is retained only for call-site compatibility and is ignored: the full
    # model reasoning, every candidate's rationale, and each decision's detail are written
    # verbatim. This is write-only I/O built from responses the API has ALREADY returned; the
    # trace is never fed back into any prompt, so keeping it complete costs zero extra tokens.
    return "" if s is None else str(s)


class TraceWriter:
    def __init__(self, trace_id: str):
        self.id = trace_id
        self._lock = threading.Lock()
        self._t0 = time.time()
        self._log = None
        self._jsonl = None
        try:
            TRACE_DIR.mkdir(parents=True, exist_ok=True)
            self._log = open(TRACE_DIR / f"{trace_id}.log", "a", encoding="utf-8")
            self._jsonl = open(TRACE_DIR / f"{trace_id}.jsonl", "a", encoding="utf-8")
        except Exception:
            self._log = self._jsonl = None

    # ---- low level ---------------------------------------------------------
    def _emit(self, text: str, record: dict):
        if self._log is None:
            return
        with self._lock:
            try:
                self._log.write(text + "\n")
                self._log.flush()
                record["t"] = round(time.time() - self._t0, 3)
                self._jsonl.write(json.dumps(record, default=str) + "\n")
                self._jsonl.flush()
            except Exception:
                pass

    def _ts(self) -> str:
        d = time.time() - self._t0
        return f"[{int(d // 60):02d}:{d % 60:06.3f}]"

    # ---- public surface ----------------------------------------------------
    def section(self, title: str, **kv):
        bar = "─" * max(4, 66 - len(title))
        extra = ("  " + "  ".join(f"{k}={v}" for k, v in kv.items())) if kv else ""
        self._emit(f"\n{self._ts()} ══ {title} {bar}{extra}",
                   {"kind": "section", "title": title, **kv})

    def line(self, msg: str, indent: int = 1):
        self._emit(f"{self._ts()}{'  ' * indent}{msg}", {"kind": "line", "msg": msg})

    def kv(self, **kv):
        self._emit(f"{self._ts()}  " + "  ".join(f"{k}: {v}" for k, v in kv.items()),
                   {"kind": "kv", **kv})

    def model(self, stage: str, model: str, reasoning: str = "", tool_calls: int = 0,
              system_preview: str = ""):
        head = f"{self._ts()}  ◆ {stage} · model={model} · {tool_calls} tool call(s)"
        body = ""
        if reasoning.strip():
            body = "\n" + "\n".join("      │ " + ln for ln in _clip(reasoning).splitlines())
        self._emit(head + body,
                   {"kind": "model", "stage": stage, "model": model,
                    "tool_calls": tool_calls, "reasoning": _clip(reasoning),
                    "system_preview": _clip(system_preview, 300)})

    def candidate(self, stage: str, title: str, verdict: str, *, reason: str = "",
                  severity: str = "", confidence=None, reasoning: str = "", entities: int = 0):
        mark = {"kept": "✎", "recovered": "↺", "rejected": "✗", "dropped": "✗",
                "malformed": "✗", "downgraded": "▼"}.get(verdict, "·")
        meta = " ".join(x for x in (severity, f"conf {confidence}" if confidence is not None else "",
                                    f"{entities} ent" if entities else "") if x)
        tail = f" - {reason}" if reason else ""
        head = f"{self._ts()}    {mark} [{verdict.upper()}] \"{_clip(title, 120)}\"" \
               + (f"  ({meta})" if meta else "") + tail
        body = ""
        if reasoning.strip():
            body = "\n" + "\n".join("         " + ln for ln in _clip(reasoning, 600).splitlines())
        self._emit(head + body,
                   {"kind": "candidate", "stage": stage, "title": title, "verdict": verdict,
                    "reason": reason, "severity": severity, "confidence": confidence,
                    "entities": entities, "reasoning": _clip(reasoning, 600)})

    def close(self, scan_id: str | None = None):
        self._emit(f"\n{self._ts()} ══ TRACE COMPLETE"
                   + (f" · scan {scan_id}" if scan_id else ""),
                   {"kind": "close", "scan_id": scan_id})
        with self._lock:
            for fh in (self._log, self._jsonl):
                try:
                    fh and fh.close()
                except Exception:
                    pass
            self._log = self._jsonl = None
        # Link the trace to its scan id so it is findable by scan, not just by job.
        if scan_id and scan_id != self.id:
            for ext in (".log", ".jsonl"):
                try:
                    src, dst = TRACE_DIR / f"{self.id}{ext}", TRACE_DIR / f"{scan_id}{ext}"
                    if src.exists() and not dst.exists():
                        os.link(src, dst)
                except Exception:
                    pass


class _Noop:
    """A do-nothing tracer so callers can stay unconditional (`trace = trace or NOOP`)."""
    id = ""
    def section(self, *a, **k): pass
    def line(self, *a, **k): pass
    def kv(self, *a, **k): pass
    def model(self, *a, **k): pass
    def candidate(self, *a, **k): pass
    def close(self, *a, **k): pass


NOOP = _Noop()


def resolve(trace) -> "TraceWriter | _Noop":
    return trace if trace is not None else NOOP


def trace_path(trace_id: str, ext: str = ".log") -> Path:
    return TRACE_DIR / f"{trace_id}{ext}"
