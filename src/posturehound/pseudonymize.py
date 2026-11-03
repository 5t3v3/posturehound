"""AI pseudonymisation (PRD v2.1 Workstream E4).

The threat model promises that tenant identifiers are redacted before any data leaves the machine
for an LLM. This module makes that real: it builds a stable token map from the graph (display
names, UPNs/mail, object ids, app ids, tenant and subscription ids -> USER_001, SP_002, SUB_001,
...), redacts outbound prompt text, and restores the tokens in the model's output before the
grounding validator runs, so findings still reference real entities.

Deliberately KEPT UNREDACTED (they are not tenant secrets and the model needs them to reason):
role display names, Microsoft Graph permission names, and Microsoft well-known object/app ids and
role template GUIDs.

A single active pseudonymiser is held in a contextvar for the duration of a scan's AI pipeline, so
the message-send chokepoint can redact/restore without threading it through every call.
"""
from __future__ import annotations

import contextvars
import re

from .model import NodeKind

# Node kinds whose *names* are generic vocabulary, not tenant data (roles, synthetic objectives).
_KEEP_NAME_KINDS = {NodeKind.ROLE, NodeKind.TENANT_CONTROL, NodeKind.DATA_SINK,
                    NodeKind.SECURITY_CONTROLS, NodeKind.GRANTABLE_APP_ROLE}
# Microsoft well-known ids / names that must stay readable (first-party apps the model reasons about).
_WELL_KNOWN = {"00000003-0000-0000-c000-000000000000", "microsoft graph"}

_TOKEN_PREFIX = {
    NodeKind.USER: "USER", NodeKind.GROUP: "GROUP", NodeKind.SERVICE_PRINCIPAL: "SP",
    NodeKind.APP: "APP", NodeKind.SUBSCRIPTION: "SUB", NodeKind.MANAGEMENT_GROUP: "MG",
    NodeKind.KEY_VAULT: "KV", NodeKind.STORAGE: "STORAGE", NodeKind.VM: "VM",
    NodeKind.AKS: "AKS", NodeKind.CONTAINER_REGISTRY: "ACR", NodeKind.RESOURCE_GROUP: "RG",
}

_ACTIVE: "contextvars.ContextVar[Pseudonymizer | None]" = contextvars.ContextVar(
    "ph_pseudonymizer", default=None)


class Pseudonymizer:
    def __init__(self):
        self._fwd: dict[str, str] = {}     # real string -> token
        self._rev: dict[str, str] = {}     # token -> real string
        self._counters: dict[str, int] = {}

    def _token(self, kind_prefix: str) -> str:
        self._counters[kind_prefix] = self._counters.get(kind_prefix, 0) + 1
        return f"{kind_prefix}_{self._counters[kind_prefix]:03d}"

    def _map(self, real, token_prefix: str) -> None:
        s = str(real or "").strip()
        if len(s) < 3 or s.lower() in _WELL_KNOWN or s in self._fwd:
            return
        tok = self._token(token_prefix)
        self._fwd[s] = tok
        self._rev[tok] = s

    @classmethod
    def from_graph(cls, g) -> "Pseudonymizer":
        p = cls()
        if g is None:
            return p
        # Deterministic order so tokens are stable for the same tenant (reproducible caching).
        for n in sorted(g.nodes(), key=lambda x: str(x.id)):
            prefix = _TOKEN_PREFIX.get(n.kind)
            if prefix is None:
                continue
            props = n.props or {}
            # The id first (it is what findings reference), then the human identifiers.
            p._map(n.id, prefix)
            if n.kind not in _KEEP_NAME_KINDS:
                p._map(n.name, prefix)
            for f in ("userPrincipalName", "mail", "appId", "displayName"):
                if props.get(f):
                    p._map(props.get(f), prefix)
        if getattr(g, "tenant_id", None):
            p._map(g.tenant_id, "TENANT")
        return p

    # Apply longest-first so a value that is a substring of another is replaced correctly.
    def _ordered(self, mapping: dict) -> list:
        return sorted(mapping.items(), key=lambda kv: -len(kv[0]))

    def redact(self, text: str) -> str:
        if not text:
            return text
        for real, tok in self._ordered(self._fwd):
            if real in text:
                text = text.replace(real, tok)
        return text

    def restore(self, text: str) -> str:
        if not text:
            return text
        for tok, real in self._ordered(self._rev):
            if tok in text:
                text = text.replace(tok, real)
        return text

    @property
    def size(self) -> int:
        return len(self._fwd)


def enabled() -> bool:
    """Pseudonymisation is on by default; PH_AI_PSEUDONYMISE=0/false turns it off."""
    import os
    return str(os.getenv("PH_AI_PSEUDONYMISE", "1")).strip().lower() not in ("0", "false", "no", "off")


def activate(g) -> "object":
    """Install a scan-scoped pseudonymiser built from the graph; returns a reset token for
    deactivate(). No-op (returns None) when disabled."""
    if not enabled():
        return None
    return _ACTIVE.set(Pseudonymizer.from_graph(g))


def deactivate(token) -> None:
    if token is not None:
        try:
            _ACTIVE.reset(token)
        except Exception:
            _ACTIVE.set(None)


def active() -> "Pseudonymizer | None":
    return _ACTIVE.get()


def _redact_content(content, p: "Pseudonymizer"):
    if isinstance(content, str):
        return p.redact(content)
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                b = {**b, "text": p.redact(b["text"])}
            out.append(b)
        return out
    return content


def redact_messages_kwargs(kwargs: dict) -> dict:
    """Return a copy of anthropic messages kwargs with system + message text redacted. Pass-through
    when no pseudonymiser is active. This is the single outbound chokepoint."""
    p = active()
    if p is None or not p.size:
        return kwargs
    out = dict(kwargs)
    if isinstance(out.get("system"), str):
        out["system"] = p.redact(out["system"])
    elif isinstance(out.get("system"), list):
        out["system"] = _redact_content(out["system"], p)
    msgs = out.get("messages")
    if isinstance(msgs, list):
        out["messages"] = [{**m, "content": _redact_content(m.get("content"), p)}
                           if isinstance(m, dict) else m for m in msgs]
    return out


def restore_text(text: str) -> str:
    """Restore tokens -> real values in model output text, so findings reference real entities."""
    p = active()
    return p.restore(text) if (p is not None and p.size) else text


def restore_obj(obj):
    """Recursively restore tokens -> real values in a model output object (e.g. a tool_use input
    dict), so AI findings reference real entities before the grounding validator runs."""
    p = active()
    if p is None or not p.size:
        return obj
    if isinstance(obj, str):
        return p.restore(obj)
    if isinstance(obj, dict):
        return {k: restore_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [restore_obj(v) for v in obj]
    return obj
