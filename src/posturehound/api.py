"""PostureHound read-only web API.

Security posture of the app itself (the tool holds a tenant's privilege map):
  * READ-ONLY: the only input is a user-uploaded AzureHound file processed in
    memory. The API never reads server paths supplied by the user, never writes
    to disk, never fetches URLs (no SSRF), and never executes collection content.
  * Input validation: enforced max upload size; structure validated by the
    ingest layer; malformed input yields a clean 400, not a stack trace.
  * Security headers: strict CSP (no external origins), nosniff, frame-deny,
    referrer policy, permissions policy.
  * CORS: disabled by default (same-origin UI). Configure explicit origins via
    env if a separate frontend is used - never wildcard with credentials.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import re
import secrets
import threading
import time

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

# Claude model IDs follow the pattern (optional region prefix) + "claude-" + rest.
# Examples: claude-sonnet-5, claude-opus-5, us.claude-sonnet-5, claude-haiku-4-5-20251001
_MODEL_RE = re.compile(r"^(?:us\.|eu\.|ap\.)?claude-[a-z0-9][a-z0-9._-]{2,60}$")

from . import __version__, ai, auth as _authmod, ingest, jobs, store
from .engine import assess_many_with_graph
from .report import render_html
from .scoring import rescore_from_findings

_log = logging.getLogger("posturehound")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        import sys
        print(f"Warning: {name} is not a valid integer; using default {default}", file=sys.stderr)
        return default

MAX_UPLOAD_MB = _int_env("PH_MAX_UPLOAD_MB", 512)
MAX_TOTAL_MB = _int_env("PH_MAX_TOTAL_MB", max(MAX_UPLOAD_MB * 2, 1024))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_TOTAL_BYTES = MAX_TOTAL_MB * 1024 * 1024

# ── Authentication guard ─────────────────────────────────────────────────────
# A single global dependency runs before every route handler. Everything is protected
# except the SPA shell (no data), the health check, and the auth endpoints themselves;
# /static/* is a separate mount and is not covered by app dependencies.
AUTH_COOKIE = "ph_auth"
_PUBLIC_PATHS = frozenset({
    "/", "/health", "/favicon.ico",
    "/api/auth/login", "/api/auth/logout", "/api/auth/me",
})


def _current_user(request: Request) -> "str | None":
    """The authenticated username from the request's token cookie, or None."""
    token = request.cookies.get(AUTH_COOKIE)
    if not token:
        return None
    payload = _authmod.verify_token(token, store.jwt_secret())
    return payload.get("sub") if payload else None


def _auth_guard(request: Request) -> None:
    """Reject any request to a protected path without a valid token. Global dependency."""
    if not _authmod.enforcement_enabled():
        return
    path = request.url.path
    if path in _PUBLIC_PATHS or path.startswith("/static/"):
        return
    if _current_user(request) is None:
        raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")


app = FastAPI(title="PostureHound", version=__version__,
              docs_url=None, redoc_url=None, openapi_url=None,
              dependencies=[Depends(_auth_guard)])

# Self-hosted static assets (vendored Cytoscape.js for the attack-graph explorer).
# Served same-origin so the SPA can load them under a 'self' script-src.
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
_STATIC_DIR = _Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

_CSP = ("default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


@app.on_event("startup")
async def _startup():
    """Load .env and apply settings migrations."""
    # Load .env from project root (two levels up from this file: src/posturehound → project root).
    # override=False so an already-set ANTHROPIC_API_KEY in the shell environment wins.
    try:
        from dotenv import load_dotenv as _load_dotenv
        from pathlib import Path as _Path
        _env_file = _Path(__file__).parents[2] / ".env"
        if _env_file.exists():
            _load_dotenv(_env_file, override=False)
    except Exception:
        pass

    settings = store.get_settings()
    # Migrate haiku_model from old Haiku default to Sonnet if not explicitly customised.
    if settings.get("haiku_model") == "claude-haiku-4-5-20251001":
        store.save_settings({"haiku_model": "claude-sonnet-5"})

    # Seed the auth account (default admin) and the JWT secret on first boot, and warn loudly
    # while the default password is still in place.
    if _authmod.enforcement_enabled():
        try:
            store.bootstrap_auth()
            if store.auth_must_change():
                _log.warning("PostureHound is using the DEFAULT password for user '%s'. "
                             "Change it in Settings immediately.", store.get_auth_username())
        except Exception:
            _log.warning("auth bootstrap failed at startup", exc_info=True)

    # Warm the most-recent scan's attack graph in the background so the first Attack Graph
    # open after a (re)start is instant instead of a ~0.3s cold parse+build.
    try:
        scans = store.list_scans()
        if scans:
            latest = max(scans, key=lambda s: s.get("created_at") or "")
            _warm_graph_cache(latest["id"])
    except Exception:
        _log.warning("graph cache warm failed at startup", exc_info=True)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    # Let a route set its own CSP (e.g. the report needs a script nonce); only
    # apply the strict default when the route did not set one.
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Cache-Control"] = "no-store"
    return resp


async def _read_capped(upload: UploadFile) -> bytes:
    """Read an upload, enforcing the size cap without buffering unbounded data."""
    buf = bytearray()
    while chunk := await upload.read(1024 * 1024):
        buf.extend(chunk)
        if len(buf) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail=(
                f"A file exceeds the per-file size limit ({MAX_UPLOAD_MB} MB). "
                f"Raise it by starting the app with PH_MAX_UPLOAD_MB set higher "
                f"(e.g. PH_MAX_UPLOAD_MB=2048 ./start.sh)."))
    if not buf:
        raise HTTPException(status_code=400, detail="Empty upload.")
    return bytes(buf)


async def _collect(files: list[UploadFile] | None, file: UploadFile | None) -> list[tuple[bytes, str]]:
    """Read one or more uploads into (bytes, name) pairs.

    Accepts the multi-file field `files` and the legacy single `file` field, so an
    AzureHound split collection (ad.json + rm.json) can be uploaded together.
    """
    uploads = [u for u in (files or []) if u is not None]
    if file is not None:
        uploads.append(file)
    if not uploads:
        raise HTTPException(status_code=400, detail="No files provided.")
    total = 0
    blobs: list[tuple[bytes, str]] = []
    for up in uploads:
        raw = await _read_capped(up)
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise HTTPException(status_code=413, detail=(
                f"Combined upload exceeds the total size limit ({MAX_TOTAL_MB} MB). "
                f"Raise it with PH_MAX_TOTAL_MB."))
        blobs.append((raw, up.filename or "upload"))
    return blobs


@app.get("/health")
async def health():
    return {"status": "ok", "version": __version__}


# ── Authentication endpoints ──────────────────────────────────────────────────
# Simple in-memory login throttle (per username, per process): after too many failures
# the account is briefly locked to blunt brute force.
_LOGIN_FAILS: "dict[str, list[float]]" = {}
_LOGIN_MAX_FAILS = 5
_LOGIN_WINDOW_S = 60.0


def _login_locked(username: str) -> bool:
    now = time.time()
    fails = [t for t in _LOGIN_FAILS.get(username, []) if now - t < _LOGIN_WINDOW_S]
    _LOGIN_FAILS[username] = fails
    return len(fails) >= _LOGIN_MAX_FAILS


def _record_login_fail(username: str) -> None:
    _LOGIN_FAILS.setdefault(username, []).append(time.time())


def _set_auth_cookie(resp: Response, username: str, request: Request) -> None:
    token = _authmod.create_token(username, store.jwt_secret(), ttl_seconds=_authmod.ttl_seconds())
    resp.set_cookie(
        AUTH_COOKIE, token,
        max_age=_authmod.ttl_seconds(),
        httponly=True,                       # unreachable from JS - XSS can't steal it
        samesite="strict",                   # not sent cross-site - neutralises CSRF / rebinding
        secure=(request.url.scheme == "https"),
        path="/",
    )


@app.post("/api/auth/login")
async def api_auth_login(request: Request, username: str = Form(...), password: str = Form(...)):
    store.bootstrap_auth()
    username = (username or "").strip()
    if _login_locked(username):
        raise HTTPException(status_code=429, detail="Too many attempts. Wait a minute and try again.")
    if not store.verify_credentials(username, password):
        _record_login_fail(username)
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    _LOGIN_FAILS.pop(username, None)
    resp = JSONResponse({"ok": True, "username": username, "must_change": store.auth_must_change()})
    _set_auth_cookie(resp, username, request)
    return resp


@app.post("/api/auth/logout")
async def api_auth_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(AUTH_COOKIE, path="/")
    return resp


@app.get("/api/auth/me")
async def api_auth_me(request: Request):
    if not _authmod.enforcement_enabled():
        return {"authenticated": True, "username": store.get_auth_username(),
                "must_change": False, "enforced": False}
    user = _current_user(request)
    if not user:
        return {"authenticated": False}
    return {"authenticated": True, "username": user, "must_change": store.auth_must_change(),
            "enforced": True}


@app.post("/api/auth/password")
async def api_auth_password(request: Request, current_password: str = Form(...),
                            new_password: str = Form(...), new_username: str = Form("")):
    user = _current_user(request) or store.get_auth_username()
    if not store.verify_credentials(user, current_password):
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    if len(new_password or "") < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters.")
    final_user = (new_username or "").strip() or user
    store.set_credentials(final_user, new_password)
    resp = JSONResponse({"ok": True, "username": final_user})
    _set_auth_cookie(resp, final_user, request)   # re-issue (username may have changed)
    return resp


def _ai_coherence_gate(result: dict, g, key: str | None, *, on_progress=None, trace=None) -> None:
    """Final QA gate before the report: the model reviews each finding's attack path
    against the finding's own description and RESOLVES each divergence.
    A wrong-plane finding is re-anchored (path recomputed, summary refreshed); a
    right-primitive-but-divergent-route finding has its path summary
    realigned to the deterministic computed path. Either way the report ships a coherent
    path/description pair with no leftover discrepancy note. Best-effort - never
    blocks the scan."""
    key = (key or "").strip() or store.get_api_key()
    findings = result.get("findings") or []
    if not key or not findings:
        return
    settings = store.get_settings()
    # run_coherence_check -> _call_with_tools needs the RAW Anthropic client (client.messages),
    # NOT the LLMClient wrapper - the same client the specialists and cartographer use.
    try:
        client = ai.ai_findings.build_client(key)
    except Exception:
        return
    if client is None:
        return
    model = settings.get("sonnet_model") or ai.ai_findings.DEFAULT_HAIKU_MODEL
    try:
        outcome = ai.ai_findings.run_coherence_check(
            client, model, findings, on_progress=on_progress, trace=trace)
    except Exception:
        return
    corrected = outcome.get("corrected") or []
    realigned = outcome.get("realigned") or []
    result["ai_coherence"] = {
        "checked": outcome.get("checked", 0),
        "corrected": len(corrected),
        "realigned": len(realigned),
        "flagged": outcome.get("flagged", 0),
    }
    if not corrected and not realigned:
        return
    from .scoring import compute_max_impact_paths
    # A corrected attack_primitive changes the anchor, so the path must be recomputed
    # (idempotent for everything else) before its summary is refreshed.
    if corrected:
        compute_max_impact_paths(g, findings)
    for f in corrected:
        p = f.get("max_impact_path")
        if not p:
            continue
        f["max_impact_summary"] = ai.ai_findings._cartographer_fallback_summary(p)
    # Route-divergent findings keep their (unchanged) computed path; only the narration
    # was out of step, so realign the path summary to the actual path - no recompute,
    # no re-anchor. This turns a disclosed discrepancy into a coherent path narration.
    for f in realigned:
        p = f.get("max_impact_path")
        if p:
            f["max_impact_summary"] = ai.ai_findings._cartographer_fallback_summary(p)
        f.pop("coherence_note", None)


def _maybe_generate(result: dict, g, ai_on: bool, key: str | None, *,
                     on_progress=None,
                     reuse_analysis: bool = True, trace=None) -> dict:
    """Generate AI findings over the deterministic fact pack. The key (per-request
    or set in Settings) is held only in memory and never written to disk. Any
    failure is surfaced as `ai_error` so AI never silently does nothing, and the
    deterministic safety-net findings are always preserved."""
    if not ai_on:
        result["ai_enabled"] = False
        return result
    key = (key or "").strip() or store.get_api_key()
    if not key:
        result["ai_enabled"] = False
        result["ai_error"] = ("AI-generated findings were requested but no Anthropic API key is set. "
                              "Add one on the Settings page or in the scan form.")
        return result
    settings = store.get_settings()
    client = ai.LLMClient(api_key=key,
                          sonnet_model=settings["sonnet_model"],
                          opus_model=settings.get("opus_model", ai.ai_findings.DEFAULT_OPUS_MODEL),
                          haiku_model=settings.get("haiku_model", ai.ai_findings.DEFAULT_HAIKU_MODEL))
    return ai.apply_ai_generation(result, g, client, on_progress=on_progress,
                                  reuse_analysis=reuse_analysis, trace=trace)


def _attach_arg(result: dict, *, on_progress=None) -> None:
    """Collect Azure Resource Graph (v2 Track B) and merge its findings.

    Runs only when a Reader service principal is configured; otherwise records an
    honest coverage status so the network/database domains are never implied
    clean. Best-effort - a collection failure is captured in coverage, never
    raised into the scan.
    """
    from . import arg_rules, azure_arg
    cov = result.setdefault("coverage", {})
    try:
        creds = azure_arg.credentials_from_settings()
    except Exception:
        creds = None
    if creds is None:
        cov["arg_status"] = ("not collected - no Azure Resource Graph service principal "
                             "configured (network/database config not assessed)")
        return

    def _log(m):
        if on_progress:
            on_progress(m)

    _log("[ARG] Collecting Azure Resource Graph (network, databases, service config)…")
    try:
        arg = azure_arg.collect(creds, on_progress=on_progress)
    except Exception as e:  # never sink the scan
        cov["arg_status"] = f"collection failed: {type(e).__name__}: {e}"
        return
    if arg is None:
        cov["arg_status"] = "not collected"
        return
    findings, not_assessed = arg_rules.run_arg_rules(arg)
    result.setdefault("findings", []).extend(findings)
    result.setdefault("not_assessed", []).extend(not_assessed)
    cov["arg_status"] = (f"collected: {len(arg.subscription_ids)} subscription(s), "
                         f"{arg.total_rows()} resource row(s), {len(findings)} finding(s)"
                         + (f"; {len(arg.errors)} query error(s)" if arg.errors else ""))
    if arg.errors:
        cov["arg_errors"] = arg.errors
    # Clear the Network blind-spot ONLY if the network query actually returned -
    # if it errored, ARG-NET rules are not_assessed and the domain must stay listed.
    if "nsg_rules_any_inbound" in arg.rows or "public_ips" in arg.rows:
        nad = cov.get("not_assessable_domains") or []
        cov["not_assessable_domains"] = [d for d in nad if "Network" not in d]
    _log(f"[ARG] {len(findings)} finding(s) from Azure Resource Graph "
         f"across {len(arg.subscription_ids)} subscription(s).")


def _attach_graph(result: dict, *, on_progress=None) -> None:
    """Collect identity-plane config from Microsoft Graph (v2 Track B) and merge
    its findings. Gated on the same Reader SP; the SP additionally needs the Graph
    permission Policy.Read.All, otherwise Graph returns 403 and this records an
    honest 'not collected' status. Best-effort - never raised into a scan."""
    from . import azure_arg, azure_graph, graph_rules
    cov = result.setdefault("coverage", {})
    try:
        creds = azure_arg.credentials_from_settings()
    except Exception:
        creds = None
    if creds is None:
        cov["graph_status"] = "not collected - no service principal configured"
        return

    def _log(m):
        if on_progress:
            on_progress(m)

    _log("[Graph] Collecting identity config (Conditional Access, MFA, legacy auth)…")
    try:
        gr = azure_graph.collect(creds, on_progress=on_progress)
    except Exception as e:  # never sink the scan
        cov["graph_status"] = f"collection failed: {type(e).__name__}: {e}"
        return
    if gr is None:
        cov["graph_status"] = "not collected"
        return
    findings, not_assessed = graph_rules.run_graph_rules(gr)
    result.setdefault("findings", []).extend(findings)
    result.setdefault("not_assessed", []).extend(not_assessed)
    if gr.ok:
        cov["graph_status"] = (f"collected: {len(gr.ca_policies)} CA policy(ies), "
                               f"{len(findings)} identity finding(s)"
                               + (f"; {len(gr.errors)} error(s)" if gr.errors else ""))
        # Clear an identity blind-spot ONLY for the endpoint that actually returned.
        # A Conditional Access 403 with security-defaults OK must NOT clear
        # "Conditional Access" - its rules are not_assessed in that case.
        nad = cov.get("not_assessable_domains") or []
        if gr.collected.get("conditionalAccess"):
            nad = [d for d in nad if "MFA" not in d and "Conditional Access" not in d]
        elif gr.collected.get("securityDefaults"):
            nad = [d for d in nad if "MFA" not in d]   # security defaults inform MFA only
        cov["not_assessable_domains"] = nad
    else:
        cov["graph_status"] = ("not collected - Microsoft Graph unreachable or the SP lacks "
                               "Policy.Read.All" + (f" ({gr.errors[0]})" if gr.errors else ""))
    if gr.errors:
        cov["graph_errors"] = gr.errors


def _scan_health(result: dict, *, use_ai: bool) -> dict:
    """Post-scan sanity check so a SILENT failure never looks like 'few findings'.

    A crashed AI stage (ai_enabled=False), a whole finding-source coming back empty,
    or failed specialists are surfaced explicitly - both in
    the live log and on the saved scan (result['scan_health']) so the report can banner
    them. Warnings, never fatal: the scan still saves."""
    warnings: list[dict] = []

    def warn(level, msg):
        warnings.append({"level": level, "message": msg})

    findings = result.get("findings") or []
    ai_gen = sum(1 for f in findings if f.get("source") == "ai_generated")
    det = sum(1 for f in findings if f.get("source") == "deterministic")

    if use_ai:
        failed = result.get("ai_failed_specialists") or []
        stage_err = result.get("ai_stage_errors") or []

        def _label(x):
            return x.get("label") or x.get("key") if isinstance(x, dict) else str(x)

        def _first_reason():
            if stage_err:
                first = stage_err[0]
                return str(first.get("reason") if isinstance(first, dict) else first)[:160]
            return ""

        if not result.get("ai_enabled"):
            warn("critical", "AI analysis did NOT run - findings are deterministic-rules only. "
                             f"Cause: {result.get('ai_error') or 'unknown'}")
        elif ai_gen == 0 and (failed or stage_err):
            # The AI STAGE ran but every specialist errored (e.g. an APIConnectionError storm):
            # effectively NO AI analysis was produced. That is a FAILED scan, not a soft
            # "few findings" - the report is deterministic-only. Flag it critical and actionable.
            warn("critical",
                 f"AI analysis FAILED - {len(failed)} specialist(s) errored and 0 AI findings "
                 f"were produced, so this scan is DETERMINISTIC-ONLY (rules, no AI reasoning or "
                 f"attack narration). First error: {_first_reason() or 'unknown'}. This is "
                 f"usually a transient network/API problem - re-run the scan.")
        else:
            if ai_gen == 0:
                warn("warning", "AI ran but produced 0 findings - every specialist returned "
                                "nothing, which is unusual on a non-trivial tenant. Check "
                                "ai_stage_errors / ai_failed_specialists.")
            if failed:
                warn("warning", f"{len(failed)} AI specialist(s) failed to run: "
                                + ", ".join(_label(x) for x in failed[:8]))
            if stage_err:
                warn("warning", f"{len(stage_err)} AI stage error(s); first: " + _first_reason())

    if det == 0:
        warn("warning", "No deterministic rule findings - the always-on safety net fired "
                        "nothing. Verify the collection carries role assignments / RBAC.")

    status = ("critical" if any(w["level"] == "critical" for w in warnings)
              else "warning" if any(w["level"] == "warning" for w in warnings)
              else "ok")
    return {"status": status, "warnings": warnings}


def _refresh_scan_health(result: dict) -> dict:
    """Recompute scan_health from the CURRENT stored state.

    scan_health is captured once at scan time, but findings can be mutated after the
    scan saves (e.g. serve-time calibration). Deriving it at serve time from the stored
    result makes the health banner structurally incapable of going stale.

    The scan does not persist the caller's use_ai intent, so we reconstruct it: AI was
    requested if the scan enabled it or recorded an AI error (the crash case must still
    surface).
    """
    use_ai = bool(result.get("ai_enabled") or result.get("ai_error")
                  or result.get("ai_analysis_key") or result.get("ai_model"))
    return _scan_health(result, use_ai=use_ai)


def _run_scan_pipeline(job, blobs, names, *, use_ai, fresh_analysis, key, settings,
                       extra_tier0=None):
    """The scan pipeline shared by uploaded and live-collected scans: assessment +
    Track B (ARG/Graph) + AI + coherence gate + scoring + persistence. `blobs` is
    the collection to assess, whatever its source. `extra_tier0` is the optional set of
    user-selected Tier-0 asset ids for this scan (from the pre-assessment selection step)."""
    # ── Verbose AI trace: a live, tail-able transcript of how the analysis unfolds ──
    # Keyed on the job id (the scan id only exists after save); linked to the scan id at
    # the end. Every job.append progress line is mirrored into it, and the AI stages write
    # their model reasoning and per-candidate decisions directly.
    from . import trace as _tracemod
    trace = None
    try:
        if (settings.get("ai_trace_enabled", True)):
            trace = _tracemod.TraceWriter(job.id)
            trace.section("SCAN START", job=job.id, files=", ".join(names)[:120],
                          ai=use_ai, fresh=fresh_analysis)
    except Exception:
        trace = None
    _orig_append = job.append
    def _append(msg):
        _orig_append(msg)
        if trace is not None:
            try: trace.line(msg, indent=0)
            except Exception: pass
    job.append = _append   # mirror every progress line into the trace

    # ── PostureHound graph + deterministic rules ──────────────────────────
    try:
        g, result = assess_many_with_graph(blobs, on_progress=job.append,
                                           extra_tier0=set(extra_tier0 or ()))
    except ingest.IngestError as e:
        job.append(f"Invalid collection: {e}")
        job.finish(error=str(e))
        return

    # Azure Resource Graph + Microsoft Graph (v2 Track B) BEFORE the AI pipeline,
    # so their findings are in the deterministic set the AI reasons over and
    # counts - otherwise the AI executive summary (generated inside the pipeline
    # from severity_counts) would undercount while the rescored badges include
    # them. Runs only when a Reader SP is configured; best-effort.
    _attach_arg(result, on_progress=job.append)
    _attach_graph(result, on_progress=job.append)

    # ── AI pipeline ──────────────────────────────────────────────────────
    if job.cancelled:
        return
    if use_ai:
        from . import usage as _usage
        _usage.meter.reset()      # start counting tokens for this scan
    result = _maybe_generate(result, g, use_ai, key,
                             reuse_analysis=not fresh_analysis,
                             on_progress=job.append, trace=trace)

    # ── Final coherence gate: the AI reviews each finding against its OWN attack path
    #    before the report is written, and re-anchors any whose first move contradicts
    #    the description (path then recomputed for those). ─────────────────────────────
    if use_ai and not job.cancelled:
        _ai_coherence_gate(result, g, key, on_progress=job.append, trace=trace)

    # Rescore after all findings (deterministic + AI + ARG + Graph) are in.
    # The engine computed score from deterministic rules only; this replaces it
    # with the final score over the complete finding set.
    result["score"] = rescore_from_findings(result.get("findings", []))

    # Post-scan health check - a silent AI/coverage failure is surfaced
    # loudly here (log + result['scan_health']) instead of masquerading as "few findings".
    result["scan_health"] = _scan_health(result, use_ai=use_ai)
    for _w in result["scan_health"]["warnings"]:
        job.append(f"[HEALTH:{_w['level'].upper()}] {_w['message']}")
    if result["scan_health"]["status"] == "ok":
        job.append("[HEALTH] All checks passed.")

    if job.cancelled:
        return
    # AI token usage + estimated cost for this scan (exact tokens; cost = tokens × rates).
    if use_ai:
        from . import usage as _usage
        result["ai_usage"] = _usage.meter.snapshot()
        u = result["ai_usage"]
        job.append(f"AI usage: {u['total']['calls']} call(s), {u['total_tokens']:,} token(s), "
                   f"est. ${u['estimated_cost_usd']:.2f}.")
    result["_files"] = names
    if extra_tier0:
        result["user_tier0"] = sorted(set(extra_tier0))   # provenance: manual Tier-0 picks
    if trace is not None:
        result["ai_trace_id"] = job.id     # link the verbose trace to the saved scan
    job.append("Saving scan to history...")
    scan_id = store.save_scan(result, names)
    store.save_raw_blobs(scan_id, blobs)
    result["_scan_id"] = scan_id
    # Persist the attack graph from the already-derived in-memory graph (builds JSON + Kùzu),
    # so the explorer opens instantly and never rebuilds from raw. Best-effort: a graph failure
    # must not fail the scan.
    try:
        from .graph import persist_snapshot
        job.append("Building attack graph…")
        persist_snapshot(scan_id, g)
        _warm_graph_cache(scan_id)   # pre-build so opening the graph for this scan is instant
    except Exception:
        pass
    if trace is not None:
        try:
            trace.close(scan_id)           # finalise + hardlink <job>.log to <scan_id>.log
            # persist the scan-id-keyed trace id so the report/endpoint find it by scan id
            _r = store.get_scan(scan_id) or {}
            _r["ai_trace_id"] = scan_id
            store.update_scan(scan_id, _r)
        except Exception:
            pass
    final = result["score"]
    job.append(f"Posture score: grade {final['grade']} ({final['score']}/100) "
               f"- {len(result['findings'])} finding(s) total.")

    job.finish(scan_id=scan_id)


@app.post("/api/assess/start")
async def api_assess_start(files: list[UploadFile] | None = File(None),
                           file: UploadFile | None = File(None),
                           use_ai: bool = Form(False),
                           fresh_analysis: bool = Form(False),
                           anthropic_key: str | None = Form(None)):
    """Start a scan as a background job with real, live progress logging (each
    log line corresponds to an actual pipeline checkpoint - parsing, rule
    evaluation, the Sonnet call, the Opus review, scoring, persistence - not a
    client-side timer). Poll /api/jobs/{job_id} for the live log and result."""
    blobs = await _collect(files, file)
    names = [n for _, n in blobs]
    settings = store.get_settings()
    key = (anthropic_key or "").strip() or store.get_api_key()

    def work(job):
        job.append("Starting scan...")
        _run_scan_pipeline(job, blobs, names, use_ai=use_ai,
                           fresh_analysis=fresh_analysis, key=key, settings=settings)

    job = jobs.run_in_background(work)
    job.meta["files"] = names
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


@app.post("/api/assess/start-live")
async def api_assess_start_live(use_ai: bool = Form(False),
                                fresh_analysis: bool = Form(False),
                                anthropic_key: str | None = Form(None)):
    """Start a scan that COLLECTS the tenant live from the read-only service
    principal (no AzureHound upload). Collects the Entra directory graph via
    Microsoft Graph, wraps it in AzureHound's format, and runs the identical
    assessment pipeline. Requires the SP to hold Directory.Read.All."""
    from . import azure_dir, azure_arg
    if azure_arg.credentials_from_settings() is None:
        raise HTTPException(status_code=400, detail=(
            "No Azure service principal is configured. Add a Reader SP with "
            "Directory.Read.All in Settings before running a live collection."))
    settings = store.get_settings()
    key = (anthropic_key or "").strip() or store.get_api_key()

    def work(job):
        job.append("Starting live collection from the service principal…")
        collected = azure_dir.collect_live(on_progress=job.append)
        if collected is None:
            job.finish(error="No service principal configured for live collection.")
            return
        records, errors = collected
        for e in errors:
            job.append(f"[Live] Warning: {e}")
        if not records:
            job.finish(error="Live collection returned no data - check the SP has "
                             "Directory.Read.All (admin-consented) and Reader on the tenant.")
            return
        blobs = [(azure_dir.to_collection_bytes(records), "live-collection.json")]
        job.append(f"[Live] Collected {len(records)} record(s) (directory + Azure RBAC); assessing…")
        _run_scan_pipeline(job, blobs, ["live-collection.json"], use_ai=use_ai,
                           fresh_analysis=fresh_analysis, key=key, settings=settings)

    job = jobs.run_in_background(work)
    job.meta["files"] = ["live-directory.json"]
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


# ── Collect → (optional Tier-0 selection) → assess ──────────────────────────────
def _start_collect_job(blobs, names):
    """Shared collect job: build the browsable inventory, stash the blobs, return a
    collection_id the UI uses to drive the Tier-0 selection step."""
    from . import inventory
    def work(job):
        job.append(f"Building asset inventory from {len(blobs)} file(s) for Tier-0 selection…")
        inv = inventory.build_inventory(blobs)
        cid = store.save_pending_collection(blobs, inv)
        job.append(f"Inventory ready: {inv['total_assets']} asset(s) across "
                   f"{len(inv['categories'])} categor(y/ies); {len(inv['recommended'])} "
                   f"recommended Tier-0.")
        job.finish(collection_id=cid)
    job = jobs.run_in_background(work)
    job.meta["files"] = names
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


@app.post("/api/collect/start")
async def api_collect_start(files: list[UploadFile] | None = File(None),
                            file: UploadFile | None = File(None)):
    """Collect from an AzureHound upload WITHOUT assessing yet - builds the inventory
    for the optional Tier-0 selection step. Assess with /api/assess/from-collection."""
    blobs = await _collect(files, file)
    return _start_collect_job(blobs, [n for _, n in blobs])


@app.post("/api/collect/start-live")
async def api_collect_start_live():
    """Live-collect the tenant from the Reader SP WITHOUT assessing yet (single
    collection; assessment reuses the cached blobs, never re-collects)."""
    from . import azure_dir, azure_arg
    if azure_arg.credentials_from_settings() is None:
        raise HTTPException(status_code=400, detail=(
            "No Azure service principal is configured. Add a Reader SP with "
            "Directory.Read.All in Settings before running a live collection."))

    def work(job):
        from . import inventory
        job.append("Starting live collection from the service principal…")
        collected = azure_dir.collect_live(on_progress=job.append)
        if collected is None:
            job.finish(error="No service principal configured for live collection.")
            return
        records, errors = collected
        for e in errors:
            job.append(f"[Live] Warning: {e}")
        if not records:
            job.finish(error="Live collection returned no data - check the SP has "
                             "Directory.Read.All (admin-consented) and Reader on the tenant.")
            return
        blobs = [(azure_dir.to_collection_bytes(records), "live-collection.json")]
        job.append(f"[Live] Collected {len(records)} record(s); building inventory…")
        inv = inventory.build_inventory(blobs)
        cid = store.save_pending_collection(blobs, inv)
        job.append(f"Inventory ready: {inv['total_assets']} asset(s); "
                   f"{len(inv['recommended'])} recommended Tier-0.")
        job.finish(collection_id=cid)

    job = jobs.run_in_background(work)
    job.meta["files"] = ["live-directory.json"]
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


@app.post("/api/collect/from-scan")
async def api_collect_from_scan(scan_id: str = Form(...)):
    """Re-run from a previous scan's STORED collection - no re-collection from Azure.
    Reuses the raw blobs captured at that scan, so you can re-assess with different
    Tier-0 selections (or after engine changes) without hitting the tenant again."""
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    blobs = store.get_raw_blobs(scan_id)
    if not blobs:
        raise HTTPException(status_code=400,
                            detail="This scan has no stored collection to reuse (it predates raw-collection storage).")
    return _start_collect_job(blobs, [n for _, n in blobs])


@app.post("/api/assess/from-scan")
async def api_assess_from_scan(scan_id: str = Form(...), use_ai: bool = Form(False)):
    """One-click re-assessment of a previous scan's STORED collection. Deterministic by
    default (use_ai=False): no re-collection from Azure, no Tier-0 selection step, no AI -
    just re-run the current engine + rules over the captured raw blobs and save a new scan.
    This is the "re-scan stored collection (no AI)" action the History/Run UI exposes so a
    user can pick up rule/engine changes without the container shell or a live collection."""
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    blobs = store.get_raw_blobs(scan_id)
    if not blobs:
        raise HTTPException(status_code=400,
                            detail="This scan has no stored collection to reuse (it predates raw-collection storage).")
    names = [n for _, n in blobs]
    settings = store.get_settings()
    key = store.get_api_key() if use_ai else None

    def work(job):
        job.append(f"Re-assessing stored collection from scan {scan_id} "
                   f"(AI {'on' if use_ai else 'off'}, no re-collection)...")
        _run_scan_pipeline(job, blobs, names, use_ai=use_ai, fresh_analysis=False,
                           key=key, settings=settings)

    job = jobs.run_in_background(work)
    job.meta["files"] = names
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


@app.get("/api/collect/{cid}/inventory")
async def api_collect_inventory(cid: str):
    """Categories + recommended Tier-0 for a pending collection (assets paginated
    separately via /assets to keep this payload small)."""
    inv = store.get_pending_inventory(cid)
    if inv is None:
        raise HTTPException(status_code=404, detail="Collection not found or expired. Re-collect.")
    return JSONResponse({
        "categories": inv.get("categories", []),
        "recommended": inv.get("recommended", []),
        "total_assets": inv.get("total_assets", 0),
    })


@app.get("/api/collect/{cid}/assets")
async def api_collect_assets(cid: str, category: str, q: str = "",
                             page: int = 1, per_page: int = 20):
    """Search + paginate one category's assets (20 per page by default)."""
    from . import inventory
    inv = store.get_pending_inventory(cid)
    if inv is None:
        raise HTTPException(status_code=404, detail="Collection not found or expired. Re-collect.")
    return JSONResponse(inventory.paginate(inv, category, q=q, page=page, per_page=per_page))


@app.post("/api/assess/from-collection")
async def api_assess_from_collection(collection_id: str = Form(...),
                                     tier0_ids: str = Form(""),
                                     use_ai: bool = Form(False),
                                     fresh_analysis: bool = Form(False),
                                     anthropic_key: str | None = Form(None)):
    """Assess a previously collected tenant, optionally treating the given asset ids as
    Tier-0 for this scan. tier0_ids is a JSON array or comma-separated list of node ids."""
    blobs = store.get_pending_blobs(collection_id)
    if blobs is None:
        raise HTTPException(status_code=404, detail="Collection not found or expired. Re-collect.")
    import json as _json
    picks: list[str] = []
    raw = (tier0_ids or "").strip()
    if raw:
        try:
            parsed = _json.loads(raw)
            picks = [str(x) for x in parsed] if isinstance(parsed, list) else []
        except Exception:
            picks = [s.strip() for s in raw.split(",") if s.strip()]
    extra_tier0 = set(picks)
    names = [n for _, n in blobs]
    settings = store.get_settings()
    key = (anthropic_key or "").strip() or store.get_api_key()

    def work(job):
        if extra_tier0:
            job.append(f"Starting assessment with {len(extra_tier0)} user-selected Tier-0 asset(s)…")
        else:
            job.append("Starting assessment (no manual Tier-0 selection)…")
        _run_scan_pipeline(job, blobs, names, use_ai=use_ai, fresh_analysis=fresh_analysis,
                           key=key, settings=settings, extra_tier0=extra_tier0)
        store.delete_pending_collection(collection_id)   # consumed

    job = jobs.run_in_background(work)
    job.meta["files"] = names
    job.meta["started_at"] = int(time.time())
    return {"job_id": job.id}


@app.get("/api/jobs")
async def api_jobs_list():
    """Return all currently running (not-done) jobs."""
    return [
        {
            "id": j.id,
            "files": j.meta.get("files", []),
            "started_at": j.meta.get("started_at"),
            "last_message": j.log[-1]["message"] if j.log else "",
        }
        for j in jobs.list_running()
    ]


@app.post("/api/jobs/{job_id}/cancel")
async def api_job_cancel(job_id: str):
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    job.cancel()
    return {"cancelled": True}


@app.get("/api/jobs/{job_id}")
async def api_job_status(job_id: str, since: int = Query(0)):
    """Poll for job progress. `since` is the number of log lines already seen
    by the client, so repeated polls only return new lines."""
    job = jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found (it may have expired or the server restarted).")
    log_snapshot = job.log
    # Clamp `since` so an out-of-range value never silently returns empty
    # (client would interpret that as "no new messages" rather than "bad index").
    since_clamped = max(0, min(since, len(log_snapshot)))
    return {
        "done": job.done,
        "error": job.error,
        "scan_id": job.scan_id,
        "meta": job.meta,
        "log": log_snapshot[since_clamped:],
        "log_count": len(log_snapshot),
    }


def _read_trace(trace_id: str, ext: str, offset: int = 0) -> "tuple[str, int] | None":
    """Read a trace file from `offset` bytes to the end. Returns (new_text, new_offset)
    or None if the file does not exist. Used for both full fetch and live tailing."""
    from . import trace as _tracemod
    p = _tracemod.trace_path(trace_id, ext)
    if not p.exists():
        return None
    try:
        with open(p, "rb") as fh:
            fh.seek(max(0, offset))
            data = fh.read()
        return data.decode("utf-8", "replace"), (max(0, offset) + len(data))
    except Exception:
        return None


@app.get("/api/jobs/{job_id}/trace")
async def api_job_trace(job_id: str, offset: int = Query(0), format: str = Query("log")):
    """Live tail of an in-progress scan's verbose AI trace. `offset` is the byte position
    already seen; returns only new bytes plus the new offset, so a poll streams the file as
    the scan thinks out loud. Keyed on job id (the trace is written under the job id)."""
    if not all(c in "0123456789abcdef" for c in job_id) or not job_id:
        raise HTTPException(status_code=400, detail="Invalid job id.")
    ext = ".jsonl" if format == "jsonl" else ".log"
    got = _read_trace(job_id, ext, offset)
    if got is None:
        return {"exists": False, "text": "", "offset": offset}
    text, new_off = got
    job = jobs.get_job(job_id)
    return {"exists": True, "text": text, "offset": new_off,
            "done": bool(job.done) if job else True}


@app.get("/api/scans/{scan_id}/trace")
async def api_scan_trace(scan_id: str, format: str = Query("log")):
    """The full verbose AI trace for a saved scan (how the AI thought, per stage). Served as
    plain text (.log) or JSON-lines (.jsonl). Local artifact - contains tenant specifics, so
    it is never part of the shareable external report."""
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    tid = r.get("ai_trace_id") or scan_id
    ext = ".jsonl" if format == "jsonl" else ".log"
    got = _read_trace(tid, ext)
    if got is None and tid != scan_id:
        got = _read_trace(scan_id, ext)
    if got is None:
        raise HTTPException(status_code=404, detail="No AI trace was recorded for this scan.")
    media = "application/x-ndjson" if ext == ".jsonl" else "text/plain; charset=utf-8"
    return Response(content=got[0], media_type=media)


@app.get("/api/scans/{scan_id}/collection")
async def api_scan_collection(scan_id: str):
    """Download the raw collection that was assessed - the AzureHound-format {meta, data}
    JSON. For a LIVE-collected scan this is PostureHound's collector output (meta.type
    'azure', source 'posturehound-live'); for an UPLOADED scan it is the original file(s),
    verbatim. If a scan carried multiple files they are returned as a zip."""
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    blobs = store.get_raw_blobs(scan_id)
    if not blobs:
        raise HTTPException(status_code=404,
                            detail="No raw collection was stored for this scan (it may predate raw-blob storage).")
    if len(blobs) == 1:
        data, name = blobs[0]
        fn = name if name.lower().endswith(".json") else f"{name or 'collection'}.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-{fn}"'})
    import io as _io
    import zipfile as _zf
    buf = _io.BytesIO()
    with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as z:
        for i, (data, name) in enumerate(blobs):
            z.writestr(name or f"file{i}.json", data)
    return Response(content=buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-collection.zip"'})


# ---- attack graph -------------------------------------------------------
# Building an AttackGraph parses the snapshot JSON and constructs a networkx graph (~0.5s for
# large tenants). Every graph endpoint does this, so cache the built graph per scan, keyed on the
# snapshot file's mtime and the overlay (custom Tier-0) state so a re-scan or an analyst edit
# invalidates it. Bounded to the few most-recently-used scans.
_GRAPH_CACHE: "dict[str, tuple[tuple, object]]" = {}
_GRAPH_CACHE_MAX = 8


def _attack_graph_for(scan_id: str):
    """Load a scan's attack-graph snapshot (cached, else rebuilt from stored raw) and wrap
    it for querying. 404 if the scan or its raw collection is unavailable."""
    # Cheap existence check only - never a full load+finalize just to guard (this runs on
    # every graph request, including cache hits).
    if not store.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    from .graph import overlays, snapshot_for_scan
    from .graph.persist import snapshot_path
    from .graph.queries import AttackGraph

    overlay = overlays.load_overlay(scan_id)
    try:
        mtime = snapshot_path(scan_id).stat().st_mtime
    except OSError:
        mtime = None
    cache_key = (mtime, frozenset(overlay.tier0))
    if mtime is not None:
        hit = _GRAPH_CACHE.get(scan_id)
        if hit is not None and hit[0] == cache_key:
            return hit[1]

    snap = snapshot_for_scan(scan_id)
    if snap is None:
        raise HTTPException(status_code=404,
                            detail="No graph for this scan: no stored raw collection to rebuild from.")
    ag = AttackGraph(snap, overlay=overlay)
    # Re-stat: a cold cache just wrote the snapshot file, so its mtime now exists.
    try:
        mtime = snapshot_path(scan_id).stat().st_mtime
    except OSError:
        mtime = None
    if mtime is not None:
        if len(_GRAPH_CACHE) >= _GRAPH_CACHE_MAX and scan_id not in _GRAPH_CACHE:
            _GRAPH_CACHE.pop(next(iter(_GRAPH_CACHE)), None)
        _GRAPH_CACHE[scan_id] = ((mtime, frozenset(overlay.tier0)), ag)
    return ag


def _warm_graph_cache(scan_id: str) -> None:
    """Pre-build a scan's AttackGraph into the cache off the request path, so the first graph
    open is a cache hit instead of a ~0.3s cold parse+build. Best-effort, background, silent."""
    def _run():
        try:
            _attack_graph_for(scan_id)
        except Exception:
            pass
    threading.Thread(target=_run, name=f"warm-graph-{scan_id[:8]}", daemon=True).start()


@app.get("/api/scans/{scan_id}/graph/meta")
def api_graph_meta(scan_id: str):
    return JSONResponse(_attack_graph_for(scan_id).meta())


@app.get("/api/scans/{scan_id}/graph/overview")
def api_graph_overview(scan_id: str):
    """Every shortest attack path to Tier-0 - the default 'all paths we found' view."""
    ag = _attack_graph_for(scan_id)
    return JSONResponse(ag.to_elements(ag.overview()))


@app.get("/api/scans/{scan_id}/graph/node")
def api_graph_node(scan_id: str, id: str):
    """Full collected detail for one node (id passed as a query param - ids contain slashes),
    plus the findings that reference it."""
    ag = _attack_graph_for(scan_id)
    d = ag.node_detail(id)
    if d is None:
        raise HTTPException(status_code=404, detail="Node not found in this scan's graph.")
    scan = store.get_scan(scan_id) or {}
    related = []
    for f in (scan.get("findings") or []):
        if any((e or {}).get("id") == id for e in (f.get("entities") or [])):
            related.append({"title": f.get("title"), "severity": f.get("severity"),
                            "rule_id": f.get("rule_id"), "key": store.finding_key(f)})
            if len(related) >= 8:
                break
    d["related_findings"] = related
    return JSONResponse(d)


@app.get("/api/scans/{scan_id}/graph/presets")
def api_graph_presets(scan_id: str):
    """List the prebuilt queries offered in the explorer."""
    from .graph import queries as _q
    return JSONResponse({"presets": _q.PRESETS})


@app.get("/api/scans/{scan_id}/graph/preset")
def api_graph_preset(scan_id: str, name: str):
    ag = _attack_graph_for(scan_id)
    return JSONResponse(ag.to_elements(ag.run_preset(name)))


@app.get("/api/scans/{scan_id}/graph/paths-list")
def api_graph_paths_list(scan_id: str):
    """One row per principal that can reach Tier-0 (nearest target + hops) for the left-side list."""
    ag = _attack_graph_for(scan_id)
    return JSONResponse({"paths": ag.paths_list()})


@app.get("/api/scans/{scan_id}/graph/search")
def api_graph_search(scan_id: str, q: str = "", limit: int = 50):
    ag = _attack_graph_for(scan_id)
    hits = ag.search(q, limit=max(1, min(int(limit), 200)))
    return JSONResponse({"results": [
        {"id": n.id, "label": n.label, "kind": n.kind, "tier0": n.tier0,
         "critical": n.critical, "eligible": n.eligible} for n in hits]})


@app.get("/api/scans/{scan_id}/graph/expand")
def api_graph_expand(scan_id: str, node: str, direction: str = "both", limit: int = 200):
    ag = _attack_graph_for(scan_id)
    if direction not in ("in", "out", "both"):
        direction = "both"
    sg = ag.expand(node, direction=direction, limit=max(1, min(int(limit), 600)))
    return JSONResponse(ag.to_elements(sg))


@app.get("/api/scans/{scan_id}/graph/paths-to-tier0")
def api_graph_paths_to_tier0(scan_id: str, source: str, max_paths: int = 25,
                                   mode: str = "hops", via: str = ""):
    # No hop limit: escalation chains can be arbitrarily deep and truncating them hid real paths.
    # mode: "hops" (fewest steps) or "easiest" (lowest total traversal difficulty).
    # via (optional): comma-separated relationship types to restrict the paths to.
    ag = _attack_graph_for(scan_id)
    mode = "easiest" if mode == "easiest" else "hops"
    via_list = [x for x in (via or "").split(",") if x.strip()] or None
    sg = ag.paths_to_tier0(source, max_paths=max(1, min(int(max_paths), 100)), mode=mode, via=via_list)
    return JSONResponse(ag.to_elements(sg))


@app.get("/api/scans/{scan_id}/graph/path")
def api_graph_path(scan_id: str, source: str, target: str, mode: str = "hops", via: str = ""):
    ag = _attack_graph_for(scan_id)
    mode = "easiest" if mode == "easiest" else "hops"
    # `via` (optional): comma-separated relationship types to restrict the path to.
    via_list = [x for x in (via or "").split(",") if x.strip()] or None
    sg = ag.path(source, target, mode=mode, via=via_list)
    return JSONResponse(ag.to_elements(sg))


@app.get("/api/scans/{scan_id}/graph/reachable")
def api_graph_reachable(scan_id: str, source: str, cap: int = 600, via: str = ""):
    """Everything reachable FROM `source` (any node, not only Tier-0) as a forward DAG, optionally
    restricted to `via` relationship types - the explorer's 'From → all relationships' objective."""
    ag = _attack_graph_for(scan_id)
    via_list = [x for x in (via or "").split(",") if x.strip()] or None
    return JSONResponse(ag.to_elements(ag.reachable_from(source, via=via_list,
                                                         cap=max(20, min(int(cap), 1500)))))


@app.get("/api/scans/{scan_id}/graph/paths-to")
def api_graph_paths_to(scan_id: str, target: str, cap: int = 600):
    """Every principal that can reach `target`, with all tied shortest routes - used when the
    explorer has a 'To' but no 'From' (show everything leading to the selected item)."""
    ag = _attack_graph_for(scan_id)
    return JSONResponse(ag.to_elements(ag.paths_to(target, cap=max(20, min(int(cap), 1500)))))


@app.get("/api/scans/{scan_id}/graph/blast-radius")
def api_graph_blast_radius(scan_id: str, source: str, cap: int = 160):
    """Blast radius: everything `source` can reach downstream, ranked by impact/centrality -
    the damage that follows if this identity is compromised. `cap` bounds the RENDERED set (the
    highest-impact reachable nodes are kept); the message still reports the true total reached."""
    ag = _attack_graph_for(scan_id)
    return JSONResponse(ag.to_elements(ag.blast_radius(source, cap=max(20, min(int(cap), 600)))))


@app.get("/api/scans/{scan_id}/graph/all-relations")
def api_graph_all_relations(scan_id: str, source: str, cap: int = 300):
    """Every relationship reachable from `source` across ALL edge types (membership,
    ownership, roles, app-roles, managed identities, Key Vault access, containment, PIM
    eligibility, and derived abuse edges) - the node's full neighbourhood, direct relations
    first then everything transitively accessible. Opt-in (not a default view); `cap` bounds
    the rendered node set, nearest first."""
    ag = _attack_graph_for(scan_id)
    return JSONResponse(ag.to_elements(ag.all_relationships(source, cap=max(20, min(int(cap), 800)))))


@app.get("/api/scans/{scan_id}/graph/edge")
def api_graph_edge(scan_id: str, id: str):
    """Edge provenance: why this escalation exists, plus a best-effort link to findings that
    act on the source principal."""
    ag = _attack_graph_for(scan_id)
    d = ag.edge_detail(id)
    if d is None:
        raise HTTPException(status_code=404, detail="Edge not found in this scan's graph.")
    scan = store.get_scan(scan_id) or {}
    src = d["source"]["id"]
    related = []
    for f in (scan.get("findings") or []):
        if any((e or {}).get("id") == src for e in (f.get("entities") or [])):
            related.append({"title": f.get("title"), "severity": f.get("severity"),
                            "rule_id": f.get("rule_id"), "key": store.finding_key(f)})
            if len(related) >= 5:
                break
    d["related_findings"] = related
    return JSONResponse(d)


@app.post("/api/scans/{scan_id}/graph/cypher")
def api_graph_cypher(scan_id: str, query: str = Form(...)):
    """Run read-only Cypher against the scan's attack graph. Requires the Kùzu backend
    (available where its wheel installs, e.g. the 3.12 server; absent on some interpreters)."""
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    from .graph import kuzu_store, snapshot_for_scan
    if not kuzu_store.kuzu_available():
        raise HTTPException(status_code=501,
                            detail="The Cypher engine (Kùzu) is not installed on this server.")
    if not kuzu_store.is_read_only_cypher(query):
        raise HTTPException(status_code=400, detail="Only read-only Cypher is allowed.")
    snap = snapshot_for_scan(scan_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="No graph for this scan.")
    kg = kuzu_store.graph_for_cypher(snap, scan_id)
    try:
        return JSONResponse(kg.run_cypher(query))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query error: {e}")


@app.get("/api/scans/{scan_id}/graph/tier0")
def api_tier0_list(scan_id: str):
    """This scan's custom Tier-0 node ids (per-scan, seeded from its own run-time picks)."""
    return JSONResponse({"custom_tier0": store.get_custom_tier0(scan_id)})


@app.post("/api/scans/{scan_id}/graph/tier0")
def api_tier0_add(scan_id: str, id: str = Form(...)):
    return JSONResponse({"custom_tier0": store.add_custom_tier0(scan_id, id)})


@app.delete("/api/scans/{scan_id}/graph/tier0")
def api_tier0_remove(scan_id: str, id: str):
    return JSONResponse({"custom_tier0": store.remove_custom_tier0(scan_id, id)})


@app.post("/api/scans/{scan_id}/graph/tier0/clear")
def api_tier0_clear(scan_id: str):
    """Reset this scan's graph: drop every custom Tier-0 mark (built-in Tier-0 remains)."""
    return JSONResponse({"custom_tier0": store.clear_custom_tier0(scan_id)})


# ── Azure DevOps work-item integration (opt-in addon) ─────────────────────────
# ── Rule Library (catalog of every deterministic rule) ───────────────────────
def _rules_catalog() -> list[dict]:
    """Every deterministic rule across all three engines, normalised for the Rule Library view."""
    from .rules.base import REGISTRY as _GRAPH_REG
    from .rules import knowledge as _kn
    from . import arg_rules as _arg, graph_rules as _gr

    def _sev(s):
        return s.value if hasattr(s, "value") else str(s)

    def _cat(c):
        return c.value if hasattr(c, "value") else str(c)

    out: list[dict] = []
    for r in _GRAPH_REG:                       # AzureHound identity/authorization graph (AZ-*)
        out.append({
            "id": r.id, "title": r.title, "severity": _sev(r.severity), "category": _cat(r.category),
            "best_practice": r.best_practice, "frameworks": r.frameworks or {},
            "description": r.description, "remediation": r.remediation,
            "data_source": [k.value if hasattr(k, "value") else str(k) for k in (r.data_source or [])],
            "engine": "AzureHound graph", "knowledge": _kn.detail_for(r.id) or {}})
    for r in _arg.REGISTRY:                    # Azure Resource Graph (ARG-*)
        out.append({
            "id": r.id, "title": r.title, "severity": _sev(r.severity), "category": _cat(r.category),
            "best_practice": r.best_practice, "frameworks": r.frameworks or {},
            "description": r.description, "remediation": r.remediation,
            "data_source": [f"ARG: {r.query_key}"],
            "engine": "Azure Resource Graph", "knowledge": r.detail or {}})
    for r in getattr(_gr, "GRAPH_RULES_CATALOG", []):   # Microsoft Graph identity config (IDG-*)
        out.append({
            "id": r["id"], "title": r["title"], "severity": r["severity"], "category": r["category"],
            "best_practice": r.get("best_practice", False), "frameworks": r.get("frameworks", {}),
            "description": r.get("description", ""), "remediation": r.get("remediation", ""),
            "data_source": ["Microsoft Graph: Conditional Access / security defaults"],
            "engine": "Microsoft Graph", "knowledge": {}})
    out.sort(key=lambda x: x["id"])
    return out


@app.get("/api/rules")
async def api_rules_catalog():
    """Static catalog of every deterministic rule (all engines) for the Rule Library page."""
    rules = _rules_catalog()
    return JSONResponse({"count": len(rules), "rules": rules})


@app.get("/api/scans/{scan_id}/rules")
async def api_scan_rule_status(scan_id: str):
    """Per-rule outcome for one scan: fired (with count), not-assessed, or silent (assessed,
    no finding) - so a user can verify each rule behaved as expected against real data."""
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    from collections import Counter
    findings = r.get("findings") or []
    fired = Counter(f.get("rule_id") for f in findings if f.get("rule_id"))
    na = r.get("not_assessed") or []
    na_ids = sorted({x.get("rule_id") for x in na if isinstance(x, dict) and x.get("rule_id")})
    return JSONResponse({"fired": dict(fired), "not_assessed": na_ids})


@app.get("/api/integrations/ado")
async def api_ado_status():
    """Non-secret ADO integration status for the UI (gates the per-finding buttons)."""
    return JSONResponse(store.ado_status())


@app.post("/api/integrations/ado/test")
async def api_ado_test():
    from . import ado
    try:
        return JSONResponse(ado.test_connection(store.get_settings(), store.get_ado_pat() or ""))
    except ado.AdoError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/scans/{scan_id}/workitems")
async def api_ado_workitems(scan_id: str):
    """finding_key → created ADO work item {id, url, ...} for this scan."""
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return JSONResponse({"workitems": store.get_work_items(scan_id)})


@app.post("/api/scans/{scan_id}/findings/{finding_key}/workitem")
async def api_ado_create_workitem(scan_id: str, finding_key: str,
                                  assignee: str = Form(""),
                                  parent_epic: str = Form("")):
    """Create ONE Azure DevOps work item for a specific finding (explicit, per-finding action)."""
    from . import ado
    if not finding_key or len(finding_key) != 16 or not all(c in "0123456789abcdef" for c in finding_key):
        raise HTTPException(status_code=400, detail="Invalid finding_key format.")
    st = store.ado_status()
    if not st["enabled"]:
        raise HTTPException(status_code=400, detail="Azure DevOps integration is disabled in Settings.")
    if not st["configured"]:
        raise HTTPException(status_code=400,
                            detail="Azure DevOps is not configured (org URL, project, and PH_ADO_PAT).")
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    # idempotency: one work item per finding
    existing = store.get_work_items(scan_id).get(finding_key)
    if existing:
        return JSONResponse({"created": False, "workitem": existing,
                             "message": f"Work item #{existing.get('id')} already exists for this finding."})
    finding = next((f for f in (scan.get("findings") or [])
                    if store.finding_key(f) == finding_key), None)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in this scan.")
    cfg = store.get_settings()
    try:
        wi = ado.create_work_item(cfg, store.get_ado_pat() or "", finding,
                                  assignee=assignee or cfg.get("ado_default_assignee", ""),
                                  parent_epic=parent_epic or cfg.get("ado_default_parent_epic", ""))
    except ado.AdoError as e:
        raise HTTPException(status_code=400, detail=str(e))
    import time as _t
    wi["created_at"] = int(_t.time())
    store.record_work_item(scan_id, finding_key, wi)
    return JSONResponse({"created": True, "workitem": wi})


@app.get("/api/graph/saved-queries")
async def api_saved_queries_list():
    """User-saved attack-graph views (global across scans)."""
    return JSONResponse({"queries": store.get_saved_queries()})


@app.post("/api/graph/saved-queries")
async def api_saved_query_add(name: str = Form(...), view: str = Form(...)):
    import json as _json
    try:
        parsed = _json.loads(view)
        if not isinstance(parsed, dict):
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="view must be a JSON object.")
    try:
        return JSONResponse({"queries": store.add_saved_query(name, parsed)})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/graph/saved-queries")
async def api_saved_query_remove(name: str):
    return JSONResponse({"queries": store.remove_saved_query(name)})


# ---- scan history -------------------------------------------------------
@app.get("/api/scans")
async def api_scans_list():
    scans = store.list_scans()
    # Flag which scans still hold their raw collection, so the UI can offer a one-click
    # deterministic re-scan only for those (others predate raw-collection storage or were
    # imported without it).
    for s in scans:
        sid = s.get("id")
        if sid:
            s["has_collection"] = store.has_raw_collection(sid)
    return JSONResponse(scans)


@app.get("/api/scans/{scan_id}")
async def api_scan_get(scan_id: str):
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return JSONResponse(_with_statuses(r, scan_id))


@functools.lru_cache(maxsize=16)
def _load_subscription_names(scan_id: str) -> dict[str, str]:
    """Parse AZSubscription records from raw collection to build GUID→display-name map.

    Memoized: a scan's raw collection is immutable, so re-unzipping it on every findings/report
    load is wasted work. Callers treat the result as read-only. (Bounded LRU.)"""
    import io as _io
    import zipfile as _zf
    blobs = store.get_raw_blobs(scan_id)
    if not blobs:
        return {}
    sub_map: dict[str, str] = {}
    for data, name in blobs:
        try:
            if name.lower().endswith(".zip") or data[:2] == b"PK":
                with _zf.ZipFile(_io.BytesIO(data)) as z:
                    for fname in z.namelist():
                        if fname.endswith(".json"):
                            with z.open(fname) as f:
                                _extract_sub_names(json.loads(f.read()), sub_map)
            else:
                _extract_sub_names(json.loads(data), sub_map)
        except Exception:
            continue
    return sub_map


def _extract_sub_names(obj: object, out: dict[str, str]) -> None:
    items = obj.get("data", obj) if isinstance(obj, dict) else obj  # type: ignore[union-attr]
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict) or item.get("kind") != "AZSubscription":
            continue
        d = item.get("data") or {}
        guid = (d.get("subscriptionId") or "").lower().strip()
        name = (d.get("displayName") or "").strip()
        if guid and name:
            out[guid] = name


def _with_statuses(result: dict, scan_id: str) -> dict:
    """Attach persisted remediation status to each finding (New by default).

    Findings arrive already consolidated: store.get_scan runs report.finalize_findings at
    the single read chokepoint, so the interactive list matches the report by construction.
    """
    import re as _re
    statuses = store.get_finding_statuses(scan_id)
    result = dict(result)

    findings = result.get("findings", [])

    # Drop findings with no entities AND no meaningful description text.
    # These are incomplete AI outputs that were stored before the empty-finding filter was added.
    findings = [
        f for f in findings
        if f.get("entities")
        or (f.get("summary") or f.get("what") or f.get("why_it_matters") or "").strip()
    ]

    # Backfill role_in_finding for entities that predate the field or were left null by the AI.
    def _derive_role(e: dict, f: dict) -> str:
        if f.get("source") == "path_consolidation":
            return "Attack entry point"
        kind = (e.get("kind") or "").replace("AZ", "").strip()
        return f"Affected {kind.lower()}" if kind else "Affected entity"

    def _backfill_roles(f: dict) -> dict:
        ents = f.get("entities") or []
        if not ents or all(e.get("role_in_finding") for e in ents if isinstance(e, dict)):
            return f
        return {**f, "entities": [
            {**e, "role_in_finding": e.get("role_in_finding") or _derive_role(e, f)}
            if isinstance(e, dict) else e
            for e in ents
        ]}

    findings = [_backfill_roles(f) for f in findings]

    result["findings"] = [
        {**f, "_finding_key": store.finding_key(f), "status": statuses.get(store.finding_key(f), "New")}
        for f in findings
    ]

    # Enrich subscription GUID→name map from raw collection (authoritative display names).
    # Always merge raw names in - they override GUID-only fallbacks from engine.py on new scans.
    raw_sub_names = _load_subscription_names(scan_id)
    if raw_sub_names:
        existing = result.get("subscriptions") or {}
        result["subscriptions"] = {**existing, **raw_sub_names}
    elif "subscriptions" not in result:
        # No raw collection and no engine-generated map - stub GUIDs from ARM-path entity IDs.
        _guid_re = _re.compile(
            r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            _re.I)
        sub_map: dict[str, str] = {}
        for f in result.get("findings", []):
            for e in f.get("entities", []):
                if isinstance(e, dict):
                    m = _guid_re.search(e.get("id") or "")
                    if m:
                        guid = m.group(1).lower()
                        if guid not in sub_map:
                            sub_map[guid] = guid
        result["subscriptions"] = sub_map

    # Evidence-based quality tiers are DERIVED, so calibrate at serve time: every finding
    # gets a quality_tier / effective confidence. Also attach the tier summary + recall
    # proxy for the report/harness.
    try:
        from . import validation as _val
        served = result.get("findings") or []
        # Resolve any leftover coherence divergence uniformly at serve time: the pipeline
        # now realigns route-divergent findings, but scans taken before that change still
        # carry a disclosed note. Realign the path narration to the authoritative computed
        # path and drop the note so EVERY scan, old or new, renders coherently.
        for _f in served:
            if _f.get("coherence_note") and (_f.get("max_impact_path") or {}).get("hops"):
                _f["max_impact_summary"] = ai.ai_findings._cartographer_fallback_summary(_f["max_impact_path"])
                _f.pop("coherence_note", None)
        result["quality_tiers"] = _val.calibrate(served)
        result["recall_proxy"] = _val.recall_proxy(result)
        result["_validation"] = store.get_validation(scan_id)
        # Azure DevOps addon: non-secret status (gates the per-finding button) + already-created
        # work items (finding_key → {id, url}) so the report shows a link instead of the button.
        result["_ado"] = store.ado_status()
        result["_workitems"] = store.get_work_items(scan_id)
    except Exception:
        # Calibration is derived and best-effort, but a failure here silently drops quality
        # tiers / validation / ADO data from the served result - log it rather than hide it.
        _log.warning("serve-time calibration failed for scan %s", scan_id, exc_info=True)

    # Health banner is a DERIVED summary, not a snapshot: recompute it from the
    # findings we are about to serve so it can never contradict them. Falls back to
    # any stored value on error.
    try:
        result["scan_health"] = _refresh_scan_health(result)
    except Exception:
        _log.warning("scan-health refresh failed for scan %s", scan_id, exc_info=True)
    return result


@app.get("/api/scans/{scan_id}/findings/status")
async def api_get_statuses(scan_id: str):
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return store.get_finding_statuses(scan_id)


@app.post("/api/scans/{scan_id}/findings/{finding_key}/status")
async def api_set_status(scan_id: str, finding_key: str, status: str = Form(...)):
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    if status not in store.VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {store.VALID_STATUSES}")
    # finding_key must be the 16-char hex SHA-1 prefix produced by store.finding_key().
    # Validate before writing to prevent arbitrary key injection into the status JSON.
    if not finding_key or len(finding_key) != 16 or not all(c in "0123456789abcdef" for c in finding_key):
        raise HTTPException(status_code=400, detail="Invalid finding_key format.")
    return store.set_finding_status(scan_id, finding_key, status)


@app.get("/api/scans/{scan_id}/validation")
async def api_validation_get(scan_id: str):
    """The precision harness for a scan: the analyst's labels so far, the measured
    precision (overall + per quality tier / source, each with a 95% Wilson interval),
    a deterministic sample to label next, and the recall proxy. Everything needed to
    turn "we think it's accurate" into a number with a confidence bound."""
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    from . import validation as _val
    r = _with_statuses(r, scan_id)                 # calibrated tiers + finding keys
    findings = r.get("findings") or []
    labels = store.get_validation(scan_id)
    import os as _os
    n = 30
    try:
        n = max(1, min(200, int(_os.environ.get("PH_VALIDATION_SAMPLE", "30"))))
    except ValueError:
        pass
    return JSONResponse({
        "metrics": _val.precision_metrics(findings, labels),
        "quality_tiers": r.get("quality_tiers", {}),
        "recall_proxy": r.get("recall_proxy", {}),
        "sample": _val.stratified_sample(findings, n, scan_id),
        "labels": labels,
    })


@app.post("/api/scans/{scan_id}/validation/{finding_key}")
async def api_validation_label(scan_id: str, finding_key: str,
                               verdict: str = Form(...), note: str = Form(""),
                               by: str = Form("")):
    """Record one analyst verdict (true_positive / false_positive / unsure) on a finding,
    or clear it with verdict='clear'. Returns the freshly recomputed precision metrics."""
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if not finding_key or len(finding_key) != 16 or not all(c in "0123456789abcdef" for c in finding_key):
        raise HTTPException(status_code=400, detail="Invalid finding_key format.")
    v = None if verdict == "clear" else verdict
    if v is not None and v not in store.VALIDATION_VERDICTS:
        raise HTTPException(status_code=400,
                            detail=f"verdict must be one of {store.VALIDATION_VERDICTS} or 'clear'")
    labels = store.set_validation_label(scan_id, finding_key, v, note=note, by=by)
    from . import validation as _val
    findings = (_with_statuses(r, scan_id)).get("findings") or []
    return JSONResponse({"metrics": _val.precision_metrics(findings, labels), "labels": labels})


@app.get("/api/scans/{scan_id}/roadmap")
async def api_roadmap(scan_id: str):
    """Consolidated, prioritised remediation roadmap: every open finding sorted
    into Now / Next / Backlog, so the output is one actionable plan rather than
    N separate findings to individually triage."""
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    statuses = store.get_finding_statuses(scan_id)
    open_findings = [f for f in r.get("findings", [])
                     if f.get("source") != "path_consolidation"
                     and statuses.get(store.finding_key(f), "New") not in ("Resolved", "Risk Accepted")]

    def bucket(f: dict) -> str:
        if f["severity"] == "Critical":
            return "now"
        if f["severity"] == "High":
            return "next"
        return "backlog"

    roadmap = {"now": [], "next": [], "backlog": []}
    for f in sorted(open_findings, key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(f["severity"], 5)):
        roadmap[bucket(f)].append({
            "key": store.finding_key(f), "title": f["title"], "severity": f["severity"],
            "category": f.get("category"), "source": f.get("source"),
            "remediation": f.get("remediation", ""),
            "affected_count": len(f.get("entities", [])),
            "status": statuses.get(store.finding_key(f), "New"),
        })
    return roadmap


@app.delete("/api/scans/{scan_id}")
async def api_scan_delete(scan_id: str):
    result = store.delete_scan(scan_id)
    if not result["deleted"]:
        raise HTTPException(status_code=409 if "error" in result and "not found" not in result["error"].lower() else 404,
                            detail=result.get("error", "Scan not found."))
    return result


@app.get("/api/scans/{scan_id}/report", response_class=HTMLResponse)
async def api_scan_report(scan_id: str):
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    r = _with_statuses(r, scan_id)
    r["_scan_id"] = scan_id
    nonce = secrets.token_urlsafe(16)
    csp = (f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; "
           "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
    return HTMLResponse(render_html(r, nonce=nonce), headers={"Content-Security-Policy": csp})


# ---- settings (non-secret persisted; key held in memory) ----------------
def _safe_settings(s: dict) -> dict:
    """Strip secrets before returning settings to callers."""
    # Never return the ARG client secret; expose only whether one is set and
    # whether the whole SP is configured (via settings or PH_ARG_* env).
    import os as _os
    secret_set = bool(s.get("arg_client_secret") or _os.environ.get("PH_ARG_CLIENT_SECRET"))
    tenant = s.get("arg_tenant_id") or _os.environ.get("PH_ARG_TENANT_ID")
    client = s.get("arg_client_id") or _os.environ.get("PH_ARG_CLIENT_ID")
    s.pop("arg_client_secret", None)
    s["arg_secret_set"] = secret_set
    s["arg_configured"] = bool(tenant and client and secret_set)
    # Azure DevOps addon: PAT is env-only and never in settings; expose only its presence.
    s["ado_pat_present"] = bool(store.get_ado_pat())
    s["ado_configured"] = bool(s.get("ado_enabled") and s.get("ado_org_url")
                               and s.get("ado_project") and s["ado_pat_present"])
    return s


@app.get("/api/settings")
async def api_settings_get():
    s = store.get_settings()
    s["api_key_set"] = store.has_api_key()
    s["api_key_source"] = store.api_key_source()  # "env", "settings", or None
    # Non-secret auth status for the Account card (never the hash or JWT secret).
    s["auth_username"] = store.get_auth_username()
    s["auth_must_change"] = store.auth_must_change()
    return _safe_settings(s)


@app.post("/api/settings")
async def api_settings_set(ai_default: bool = Form(None),
                           min_severity: str | None = Form(None),
                           sonnet_model: str | None = Form(None),
                           opus_model: str | None = Form(None),
                           haiku_model: str | None = Form(None),
                           anthropic_key: str | None = Form(None),
                           clear_key: bool = Form(False),
                           arg_tenant_id: str | None = Form(None),
                           arg_client_id: str | None = Form(None),
                           arg_client_secret: str | None = Form(None),
                           arg_clear: bool = Form(False),
                           ado_enabled: bool = Form(None),
                           ado_org_url: str | None = Form(None),
                           ado_project: str | None = Form(None),
                           ado_area_path: str | None = Form(None),
                           ado_work_item_type: str | None = Form(None),
                           ado_tags: str | None = Form(None),
                           ado_default_assignee: str | None = Form(None),
                           ado_default_parent_epic: str | None = Form(None)):
    patch: dict = {}
    if ai_default is not None:
        patch["ai_default"] = ai_default
    if min_severity:
        if min_severity not in ("Critical", "High", "Medium", "Low", "Info"):
            raise HTTPException(status_code=400,
                                detail="min_severity must be one of Critical, High, Medium, Low, Info")
        patch["min_severity"] = min_severity
    if sonnet_model:
        if not _MODEL_RE.match(sonnet_model.strip()):
            raise HTTPException(status_code=400,
                                detail=f"Invalid sonnet_model name '{sonnet_model}'. "
                                       "Expected a Claude model ID, e.g. claude-sonnet-5.")
        patch["sonnet_model"] = sonnet_model.strip()
    if opus_model:
        if not _MODEL_RE.match(opus_model.strip()):
            raise HTTPException(status_code=400,
                                detail=f"Invalid opus_model name '{opus_model}'. "
                                       "Expected a Claude model ID, e.g. claude-opus-5.")
        patch["opus_model"] = opus_model.strip()
    if haiku_model:
        if not _MODEL_RE.match(haiku_model.strip()):
            raise HTTPException(status_code=400,
                                detail=f"Invalid haiku_model name '{haiku_model}'. "
                                       "Expected a Claude model ID, e.g. claude-sonnet-5.")
        patch["haiku_model"] = haiku_model.strip()
    # Azure Resource Graph / Microsoft Graph Reader service principal (v2 Track B).
    if arg_clear:
        patch["arg_tenant_id"] = ""
        patch["arg_client_id"] = ""
        patch["arg_client_secret"] = ""
    else:
        if arg_tenant_id is not None:
            patch["arg_tenant_id"] = arg_tenant_id.strip()
        if arg_client_id is not None:
            patch["arg_client_id"] = arg_client_id.strip()
        if arg_client_secret is not None and arg_client_secret.strip():
            patch["arg_client_secret"] = arg_client_secret.strip()
    # Azure DevOps work-item integration (all non-secret; PAT is env-only via PH_ADO_PAT).
    if ado_enabled is not None:
        patch["ado_enabled"] = ado_enabled
    if ado_org_url is not None:
        u = ado_org_url.strip()
        if u and not u.lower().startswith("https://"):
            raise HTTPException(status_code=400, detail="Azure DevOps org URL must be https://")
        patch["ado_org_url"] = u.rstrip("/")
    if ado_project is not None:
        patch["ado_project"] = ado_project.strip()
    if ado_area_path is not None:
        patch["ado_area_path"] = ado_area_path.strip()
    if ado_work_item_type is not None and ado_work_item_type.strip():
        patch["ado_work_item_type"] = ado_work_item_type.strip()
    if ado_tags is not None:
        patch["ado_tags"] = ado_tags.strip()
    if ado_default_assignee is not None:
        patch["ado_default_assignee"] = ado_default_assignee.strip()
    if ado_default_parent_epic is not None:
        ep = ado_default_parent_epic.strip()
        if ep and not ep.isdigit():
            raise HTTPException(status_code=400, detail="Parent Epic must be a numeric work-item id.")
        patch["ado_default_parent_epic"] = ep
    s = store.save_settings(patch)
    if clear_key:
        store.set_api_key(None)
    elif anthropic_key is not None and anthropic_key.strip():
        store.set_api_key(anthropic_key)
    s["api_key_set"] = store.has_api_key()
    s["api_key_source"] = store.api_key_source()
    return _safe_settings(s)


@app.post("/api/settings/test-connection")
async def api_test_connection(anthropic_key: str | None = Form(None),
                              sonnet_model: str | None = Form(None),
                              opus_model: str | None = Form(None),
                              haiku_model: str | None = Form(None)):
    """Make one minimal call per model to confirm the key works and each model is reachable."""
    key = (anthropic_key or "").strip() or store.get_api_key()
    if not key:
        raise HTTPException(status_code=400, detail="No API key provided or set in Settings.")
    try:
        import anthropic  # noqa: F401 - availability probe
    except ImportError:
        raise HTTPException(status_code=500, detail="The 'anthropic' package is not installed on the server.")
    for label, name in (("sonnet_model", sonnet_model), ("opus_model", opus_model), ("haiku_model", haiku_model)):
        if name is not None and not _MODEL_RE.match(name.strip()):
            raise HTTPException(status_code=400, detail=f"Invalid {label} name: {name!r}")
    settings = store.get_settings()
    _default_opus  = ai.ai_findings.DEFAULT_OPUS_MODEL
    _default_haiku = ai.ai_findings.DEFAULT_HAIKU_MODEL
    models = {
        "sonnet (specialists)": (sonnet_model.strip() if sonnet_model else settings["sonnet_model"]),
        "opus (synthesizer + correlator)": (opus_model.strip() if opus_model else settings.get("opus_model", _default_opus)),
        "haiku (skeptic)": (haiku_model.strip() if haiku_model else settings.get("haiku_model", _default_haiku)),
    }
    # Must go through the shared factory: a direct construction raises
    # FileNotFoundError when SSL_CERT_FILE points at a missing cert bundle, which
    # turned this endpoint into a blanket HTTP 500 with no usable message.
    client = ai.ai_findings.build_client(key)
    results = {}
    for role, model in models.items():
        try:
            # Route through create_message with the same parameters the pipeline uses.
            # A bare client.messages.create(...) call passed happily while every real
            # pipeline request failed with "`temperature` is deprecated for this model",
            # so this check must exercise the actual code path to mean anything.
            ai.ai_findings.create_message(
                client, model=model, max_tokens=8, temperature=0,
                messages=[{"role": "user", "content": "ping"}])
            results[role] = {"model": model, "ok": True}
        except Exception as e:
            results[role] = {"model": model, "ok": False, "error": f"{type(e).__name__}: {e}"}
    return results


@app.post("/api/settings/test-arg-connection")
async def api_test_arg_connection(arg_tenant_id: str | None = Form(None),
                                  arg_client_id: str | None = Form(None),
                                  arg_client_secret: str | None = Form(None)):
    """Validate the Azure Resource Graph Reader service principal (v2 Track B).

    Uses form-provided credentials if given, else the configured ones. Runs in a
    worker thread because the collector's httpx calls are synchronous.
    """
    from . import azure_arg, azure_graph, azure_dir
    creds = None
    if arg_tenant_id and arg_client_id and arg_client_secret:
        creds = azure_arg.ArgCredentials(arg_tenant_id.strip(), arg_client_id.strip(),
                                         arg_client_secret.strip())
    import anyio

    def _probe_all():
        # Three distinct grants, each checked separately so a missing one is caught
        # now, not as a silent 403 mid-scan:
        #   ARM Reader          -> Resource Graph (network/data config)
        #   Graph Policy.Read.All -> Conditional Access / security defaults
        #   Graph Directory.Read.All -> live directory collection (AzureHound-equivalent)
        arm = azure_arg.probe(creds)
        graph = azure_graph.probe(creds)
        directory = azure_dir.probe(creds)
        return {
            "ok": bool(arm.get("ok")),          # ARM Reader gates network/data findings
            "message": arm.get("message", ""),
            "subscriptions": arm.get("subscriptions", 0),
            "resource_graph": arm,
            "microsoft_graph": graph,
            "directory": directory,
        }
    return await anyio.to_thread.run_sync(_probe_all)


# Only identity PRINCIPALS anchor a finding's cross-scan identity. Resources (Key Vaults,
# storage accounts, VMs, …) are deliberately excluded: a rule-based finding "resolves" only
# when the rule stops firing, not when one resource in its affected list churns - and an
# ephemeral VM being replaced by an equivalent one, or one of 200 Key Vaults changing, is not
# a resolution. Keying on principals keeps the diff sensitive to WHO is over-privileged while
# ignoring which resources happen to be enumerated under a bulk finding.
_PRINCIPAL_COMPARE_KINDS = {"AZUser", "AZServicePrincipal", "AZGroup", "AZRole"}


def _finding_compare_id(f: dict):
    """A finding's identity for cross-scan comparison - deliberately independent of the AI's
    wording (its title/category are re-generated every run) and of resource-level churn. A
    deterministic finding is identified by its rule plus the identity PRINCIPALS it is about
    (so a resource-config rule matches on the rule alone and persists across resource churn,
    while a principal rule stays sensitive to a new over-privileged principal); an AI or
    attack-path finding by its principal subject set. Same underlying issue ⇒ same id across
    scans, so an UNCHANGED environment diffs clean instead of flipping findings resolved/new."""
    ents = [e for e in (f.get("entities") or []) if isinstance(e, dict)]
    subject = [e for e in ents if e.get("relation") == "subject"] or ents
    ids = tuple(sorted(
        e.get("id", "") for e in subject
        if e.get("id") and e.get("kind") in _PRINCIPAL_COMPARE_KINDS))
    if f.get("rule_id"):
        return ("rule", f["rule_id"], ids)
    return ("ai", ids)


@app.get("/api/scans/{scan_id_a}/compare/{scan_id_b}")
async def api_compare_scans(scan_id_a: str, scan_id_b: str):
    a, b = store.get_scan(scan_id_a), store.get_scan(scan_id_b)
    if not a or not b:
        raise HTTPException(status_code=404, detail="One or both scans not found.")

    def key_findings(res: dict) -> dict:
        out = {}
        for f in res.get("findings", []):
            out[_finding_compare_id(f)] = f
        return out

    fa, fb = key_findings(a), key_findings(b)
    resolved = [fa[k] for k in fa if k not in fb]
    new = [fb[k] for k in fb if k not in fa]
    persisting = [fb[k] for k in fb if k in fa]
    return {
        "a": {"id": scan_id_a, "grade": a["score"]["grade"], "score": a["score"]["score"],
              "created_at": a.get("_created_at"), "finding_count": len(fa)},
        "b": {"id": scan_id_b, "grade": b["score"]["grade"], "score": b["score"]["score"],
              "created_at": b.get("_created_at"), "finding_count": len(fb)},
        "resolved": [{"title": f["title"], "severity": f["severity"]} for f in resolved],
        "new": [{"title": f["title"], "severity": f["severity"]} for f in new],
        "persisting_count": len(persisting),
        "score_delta": b["score"]["score"] - a["score"]["score"],
    }


@app.get("/api/scans/{scan_id}/export.csv")
async def api_export_csv(scan_id: str):
    import csv
    import io as _io
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    buf = _io.StringIO()
    w = csv.writer(buf)
    w.writerow(["title", "severity", "category", "source", "confidence",
                "affected_entities", "what", "remediation"])
    def _csv_safe(v: str | None) -> str:
        s = str(v or "")
        if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
            s = "'" + s
        return s

    for f in r.get("findings", []):
        ents = "; ".join(e.get("name", "") for e in f.get("entities", []))
        w.writerow([_csv_safe(f.get("title")), _csv_safe(f.get("severity")),
                   _csv_safe(f.get("category")), _csv_safe(f.get("source", "")),
                   f.get("confidence", ""),
                   _csv_safe(ents), _csv_safe(f.get("what", "")), _csv_safe(f.get("remediation", ""))])
    return Response(content=buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="posturehound-{scan_id}.csv"'})


@app.get("/api/scans/{scan_id}/report.pdf")
async def api_scan_report_pdf(scan_id: str):
    """Render the shareable external assessment report as a PDF.

    This is the report handed to another team: no product name, no graph links,
    no URLs. If weasyprint (or a native library it needs) is unavailable, fall
    back to the print-ready HTML with a 503 hint so the caller can open it and
    print to PDF from the browser instead of failing outright.
    """
    from . import external_report
    r = store.get_scan(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="Scan not found.")
    fname = f"azure-identity-posture-{scan_id}.pdf"
    try:
        pdf = external_report.render_pdf(r)
    except external_report.PdfEngineUnavailable as e:
        # Serve the HTML so the user still gets the report; browser print → PDF.
        html = external_report.render_html(r)
        return HTMLResponse(
            html,
            headers={"X-PDF-Unavailable": "weasyprint not installed; showing printable HTML",
                     "X-PDF-Error": str(e)[:180]})
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="{fname}"'})


@app.get("/", response_class=HTMLResponse)
async def index():
    # Multi-page app shell (dashboard / scan / history / settings). One inline
    # script, allowed via a per-response nonce.
    from .webapp import render_spa
    nonce = secrets.token_urlsafe(16)
    # 'self' in script-src allows the vendored Cytoscape.js (same-origin /static/…);
    # the inline app script stays gated behind the per-response nonce.
    # frame-ancestors 'self' lets the server-rendered report embed the graph explorer in its
    # Attack Graph tab (same-origin) while still blocking cross-origin framing (clickjacking).
    csp = (f"default-src 'self'; script-src 'nonce-{nonce}' 'self'; style-src 'self' 'unsafe-inline'; "
           "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
    # The app shell carries all inline CSS/JS, so a cached copy silently pins an
    # old UI (stale graph styling, missing features). Never cache the shell - it's
    # tiny and regenerated per request anyway.
    headers = {
        "Content-Security-Policy": csp,
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    return HTMLResponse(render_spa(nonce), headers=headers)
