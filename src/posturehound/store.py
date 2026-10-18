"""Local persistence for the multi-page app.

Scan results are stored as JSON files under a data directory so the History and
Dashboard pages survive restarts. Non-secret settings (default AI toggle, minimum
severity) are persisted too. The Anthropic API key is deliberately NOT written to
disk, it is held in process memory for the server's lifetime, set from the
Settings page, so a plaintext key never lands on disk.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

DATA_DIR = Path(os.getenv("PH_DATA_DIR", str(Path.home() / ".posturehound")))
SCANS_DIR = DATA_DIR / "scans"
SETTINGS_FILE = DATA_DIR / "settings.json"

_DEFAULT_SETTINGS = {"ai_default": False, "min_severity": "Info",
                     "sonnet_model": "claude-sonnet-5",
                     "opus_model": "claude-opus-5",
                     "haiku_model": "claude-sonnet-5",
                     # Accuracy gate: AI findings below this (effective) confidence, and all
                     # 'lead'-tier AI findings, are shown under the separate "Leads" view instead
                     # of the main findings list. 0-100; deterministic findings are never gated.
                     "ai_lead_confidence": 50,
                     # Verbose per-scan AI trace (how each specialist thought), written live
                     # to ~/.posturehound/scan_traces/. On by default; a local artifact.
                     "ai_trace_enabled": True,
                     # Azure Resource Graph collector (v2 Track B), a read-only
                     # Reader/Security-Reader service principal. The secret prefers
                     # PH_ARG_CLIENT_SECRET so it need not be persisted here.
                     "arg_tenant_id": "", "arg_client_id": "", "arg_client_secret": "",
                     # Azure DevOps work-item integration (opt-in addon). All NON-secret;
                     # the PAT is env-only (PH_ADO_PAT) and is never persisted here.
                     "ado_enabled": False, "ado_org_url": "", "ado_project": "",
                     "ado_area_path": "", "ado_work_item_type": "Feature",
                     "ado_tags": "", "ado_default_assignee": "", "ado_default_parent_epic": ""}

# In-memory only; the Anthropic key is never persisted.
_api_key: str | None = None

# ---- .env / environment key helpers ----------------------------------------
# get_api_key() checks the environment first so a key in .env or the shell
# environment takes precedence without requiring the Settings page.

def _env_api_key() -> str | None:
    """Return the Anthropic key from the environment, if present."""
    return os.environ.get("ANTHROPIC_API_KEY") or None

# Serialises concurrent index reads/writes (single-process, multi-thread).
_INDEX_LOCK = threading.Lock()
_INDEX_FILE_NAME = "_index.json"

_SETTINGS_LOCK = threading.Lock()
_STATUS_LOCK = threading.Lock()


def _ensure() -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


# ---- AI analysis cache ----------------------------------------------------
# The Claude 5 models reject temperature/top_p/top_k, so there is no API-level way to
# make the analyst pipeline reproducible: the same collection scanned twice produced
# 63-73 findings. Caching the analysis against a hash of the EXACT model input makes
# the tool deterministic even though the model is not, a repeat scan of unchanged data
# returns byte-identical AI findings instead of re-sampling.
AI_CACHE_DIR = DATA_DIR / "ai_cache"


def ai_cache_get(key: str) -> dict | None:
    try:
        return json.loads((AI_CACHE_DIR / f"{key}.json").read_text())
    except Exception:
        return None


AI_CACHE_LAST_ERROR: list[str] = []


def ai_cache_put(key: str, payload: dict) -> bool:
    """Store an analysis. Returns False and records why on failure.

    `default=str` matters: the payload carries sets and dataclass-ish values, and a
    bare json.dump raised TypeError which the original except-clause swallowed, so the
    cache silently never wrote anything and reproducibility silently never happened.
    """
    try:
        AI_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(AI_CACHE_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, default=str)
            os.replace(tmp, AI_CACHE_DIR / f"{key}.json")
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except Exception as e:
        AI_CACHE_LAST_ERROR.append(f"{type(e).__name__}: {e}")
        return False


# ── Per-finding narrative pin (reproducible wording) ───────────────────────
# The whole-analysis cache (ai_cache_*) only replays when the fact pack is byte-
# identical. A live re-collection drifts (ephemeral AKS nodes, a new user), which
# misses that cache and re-samples the models, so the SAME finding reads differently
# run to run. The narrative pin is a second, finer layer keyed on a finding's stable
# identity (its entity set + category, never its wording): the first time a finding
# is seen its human-readable text is stored; every later run that produces the same
# finding overlays that stored text, so recurring findings read identically even when
# the surrounding scan changed. Structural fields (entities, severity, paths, BH) are
# never pinned, only the prose.
NARRATIVE_DIR = DATA_DIR / "narrative_cache"


def narrative_get(key: str) -> dict | None:
    try:
        return json.loads((NARRATIVE_DIR / f"{key}.json").read_text())
    except Exception:
        return None


def narrative_put(key: str, payload: dict) -> bool:
    """Pin a finding's narrative text under its stable identity. Best-effort."""
    try:
        NARRATIVE_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(NARRATIVE_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, default=str)
            os.replace(tmp, NARRATIVE_DIR / f"{key}.json")
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return True
    except Exception:
        return False


# ---- API key (memory only, with env-var fallback) -----------------------
def set_api_key(key: str | None) -> None:
    global _api_key
    _api_key = (key or "").strip() or None


def get_api_key() -> str | None:
    """Return the active API key: env var first, then in-memory (set via Settings)."""
    return _env_api_key() or _api_key


def has_api_key() -> bool:
    return bool(_env_api_key() or _api_key)


def api_key_source() -> str | None:
    """Return where the active key comes from: 'env', 'settings', or None."""
    if _env_api_key():
        return "env"
    if _api_key:
        return "settings"
    return None


# ---- settings (non-secret, persisted) ------------------------------------
def get_settings() -> dict[str, Any]:
    try:
        s = json.loads(SETTINGS_FILE.read_text())
    except Exception:
        s = {}
    return {**_DEFAULT_SETTINGS, **{k: v for k, v in s.items() if k in _DEFAULT_SETTINGS}}


def save_settings(patch: dict[str, Any]) -> dict[str, Any]:
    _ensure()
    with _SETTINGS_LOCK:
        s = get_settings()
        for k in _DEFAULT_SETTINGS:
            if k in patch:
                s[k] = patch[k]
        fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(s, f, indent=2)
            os.replace(tmp, SETTINGS_FILE)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return s


# ---- authentication account (single operator) ----------------------------
# The one account lives in auth.json (mode 0600): username, PBKDF2 password hash, the JWT
# signing secret, and a must_change flag set while the default password is still in place.
# The password hash and secret are NEVER returned by any API (see _safe_settings).
from . import auth as _auth  # noqa: E402  (auth.py has no store dependency, no cycle)

AUTH_FILE = DATA_DIR / "auth.json"
_AUTH_LOCK = threading.Lock()
_DEFAULT_ADMIN_USER = "admin"
_DEFAULT_ADMIN_PASSWORD = os.getenv("PH_ADMIN_PASSWORD", "").strip() or "posturehound"


def _load_auth() -> dict:
    try:
        return json.loads(AUTH_FILE.read_text())
    except Exception:
        return {}


def _save_auth(d: dict) -> None:
    _ensure()
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f, indent=2)
        os.replace(tmp, AUTH_FILE)
        try:
            os.chmod(AUTH_FILE, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ── RBAC: permission catalog + built-in roles ──────────────────────────────────
# A permission key gates one screen/feature. The SPA hides what a user's role lacks and the API
# refuses it. "*" (held only by Administrator) is every permission, including future ones.
PERMISSIONS: list[tuple[str, str]] = [
    ("dashboard",  "Dashboard"),
    ("findings",   "Findings & reports"),
    ("scan",       "Run scans & live collection"),
    ("history",    "Scan history & comparison"),
    ("graph",      "Attack graph explorer"),
    ("rules",      "Rule library"),
    ("compliance", "Compliance (CIS)"),
    ("traces",     "AI reasoning traces"),
    ("ado",        "Create Azure DevOps work items"),
    ("settings",   "Manage tool settings & integrations"),
    ("users",      "Manage users & roles"),
]
PERMISSION_KEYS: list[str] = [k for k, _ in PERMISSIONS]

# Built-in roles, seeded on first run and kept present. Administrator is immutable (always "*").
_DEFAULT_ROLES: dict[str, dict] = {
    "admin":   {"label": "Administrator", "permissions": ["*"], "builtin": True},
    "analyst": {"label": "Analyst",
                "permissions": ["dashboard", "findings", "scan", "history", "graph", "rules",
                                "compliance", "traces", "ado"], "builtin": True},
    "viewer":  {"label": "Viewer",
                "permissions": ["dashboard", "findings", "history", "compliance"], "builtin": True},
}


def permission_catalog() -> list[dict]:
    return [{"key": k, "label": lbl} for k, lbl in PERMISSIONS]


def _migrate_auth(d: dict) -> dict:
    """Bring an auth record up to the multi-user schema: fold a legacy single account into
    users{}, and ensure the built-in roles are present. Non-destructive to custom roles/users."""
    if "users" not in d:
        users: dict = {}
        if d.get("username") and d.get("password_hash"):   # legacy single-account record
            users[str(d["username"])] = {"password_hash": d["password_hash"], "role": "admin",
                                         "must_change": bool(d.get("must_change"))}
        d["users"] = users
    for k in ("username", "password_hash", "must_change"):
        d.pop(k, None)
    roles = d.setdefault("roles", {})
    for rk, rv in _DEFAULT_ROLES.items():
        if rk not in roles:
            roles[rk] = dict(rv)
    roles["admin"] = dict(_DEFAULT_ROLES["admin"])   # Administrator is always all-permissions
    return d


def bootstrap_auth() -> dict:
    """Ensure the auth store exists: migrate legacy records, seed the default admin user, the
    built-in roles, and the JWT secret on first run. Returns the record."""
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        if not d["users"]:
            d["users"][_DEFAULT_ADMIN_USER] = {
                "password_hash": _auth.hash_password(_DEFAULT_ADMIN_PASSWORD),
                "role": "admin", "must_change": True}
        if not d.get("jwt_secret") and not os.getenv("PH_JWT_SECRET"):
            d["jwt_secret"] = _auth.new_secret()
        _save_auth(d)
    return d


def jwt_secret() -> str:
    """The HS256 signing secret: PH_JWT_SECRET if set, else the persisted per-install secret."""
    env = os.getenv("PH_JWT_SECRET")
    if env:
        return env
    d = _load_auth()
    if d.get("jwt_secret"):
        return d["jwt_secret"]
    return bootstrap_auth()["jwt_secret"]


# ── Users ───────────────────────────────────────────────────────────────────────
def get_user(username: str) -> "dict | None":
    return (_load_auth().get("users") or {}).get(username or "")


def list_users() -> list[dict]:
    users = (_load_auth() or bootstrap_auth()).get("users") or {}
    return sorted(({"username": u, "role": v.get("role", "viewer"),
                    "must_change": bool(v.get("must_change")),
                    "created_at": v.get("created_at")} for u, v in users.items()),
                  key=lambda x: x["username"].lower())


def verify_credentials(username: str, password: str) -> "dict | None":
    """Return the user's public record ({username, role, must_change}) on success, else None."""
    u = get_user(username)
    if not u or not _auth.verify_password(password or "", u.get("password_hash") or ""):
        return None
    return {"username": username, "role": u.get("role", "viewer"),
            "must_change": bool(u.get("must_change"))}


def auth_must_change(username: str) -> bool:
    u = get_user(username)
    return bool(u and u.get("must_change"))


def _admin_count(users: dict) -> int:
    return sum(1 for v in users.values() if v.get("role") == "admin")


def create_user(username: str, password: str, role: str) -> None:
    username = (username or "").strip()
    if not username:
        raise ValueError("Username is required.")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        if username in d["users"]:
            raise ValueError(f"User '{username}' already exists.")
        if role not in d["roles"]:
            raise ValueError(f"Unknown role '{role}'.")
        import time as _t
        d["users"][username] = {"password_hash": _auth.hash_password(password),
                                "role": role, "must_change": False,
                                "created_at": int(_t.time())}
        _save_auth(d)


def delete_user(username: str) -> None:
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        u = d["users"].get(username)
        if not u:
            raise ValueError(f"User '{username}' not found.")
        if u.get("role") == "admin" and _admin_count(d["users"]) <= 1:
            raise ValueError("Cannot delete the last administrator.")
        del d["users"][username]
        _save_auth(d)


def set_user_role(username: str, role: str) -> None:
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        u = d["users"].get(username)
        if not u:
            raise ValueError(f"User '{username}' not found.")
        if role not in d["roles"]:
            raise ValueError(f"Unknown role '{role}'.")
        if u.get("role") == "admin" and role != "admin" and _admin_count(d["users"]) <= 1:
            raise ValueError("Cannot demote the last administrator.")
        u["role"] = role
        _save_auth(d)


def set_user_password(username: str, new_password: str, *, must_change: bool = False) -> None:
    """Set a user's password (admin reset, or self-service). Clears the default-password flag."""
    if not new_password or len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        u = d["users"].get(username)
        if not u:
            raise ValueError(f"User '{username}' not found.")
        u["password_hash"] = _auth.hash_password(new_password)
        u["must_change"] = bool(must_change)
        _save_auth(d)


# ── Roles ───────────────────────────────────────────────────────────────────────
def list_roles() -> dict:
    return (_load_auth() or bootstrap_auth()).get("roles") or {}


def _valid_perms(perms: list) -> list[str]:
    out, seen = [], set()
    for p in perms or []:
        p = str(p).strip()
        if p and p not in seen and (p == "*" or p in PERMISSION_KEYS):
            seen.add(p)
            out.append(p)
    return out


def save_role(name: str, label: str, permissions: list, *, create: bool) -> None:
    name = (name or "").strip().lower()
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError("Role name must be alphanumeric (dashes/underscores allowed).")
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        roles = d["roles"]
        existing = roles.get(name)
        if create and existing:
            raise ValueError(f"Role '{name}' already exists.")
        if not create and not existing:
            raise ValueError(f"Role '{name}' not found.")
        if existing and existing.get("builtin"):
            raise ValueError("Built-in roles cannot be edited.")
        roles[name] = {"label": (label or name).strip(),
                       "permissions": _valid_perms(permissions), "builtin": False}
        _save_auth(d)


def delete_role(name: str) -> None:
    with _AUTH_LOCK:
        d = _migrate_auth(_load_auth() or {})
        role = d["roles"].get(name)
        if not role:
            raise ValueError(f"Role '{name}' not found.")
        if role.get("builtin"):
            raise ValueError("Built-in roles cannot be deleted.")
        in_use = [u for u, v in d["users"].items() if v.get("role") == name]
        if in_use:
            raise ValueError(f"Role '{name}' is assigned to {len(in_use)} user(s); reassign them first.")
        del d["roles"][name]
        _save_auth(d)


def user_permissions(username: str) -> set:
    """The resolved permission set for a user (expands the Administrator '*' to every key)."""
    u = get_user(username)
    if not u:
        return set()
    perms = (list_roles().get(u.get("role", "")) or {}).get("permissions") or []
    if "*" in perms:
        return set(PERMISSION_KEYS)
    return {p for p in perms if p in PERMISSION_KEYS}


def has_permission(username: str, perm: str) -> bool:
    return perm in user_permissions(username)


# ---- custom Tier-0 (user-defined high-value targets, PER SCAN) ---
# Previously a single global list, which meant a Tier-0 mark made while viewing one scan
# bled into EVERY scan's graph (the "previous findings in the new graph" residue). It is now
# a {scan_id: [ids]} map; each scan's set is seeded from that scan's own run-time Tier-0 picks
# (result["user_tier0"]) the first time it is read, and edited independently thereafter.
CUSTOM_TIER0_FILE = DATA_DIR / "custom_tier0.json"
_TIER0_LOCK = threading.Lock()


def _load_tier0_map() -> dict[str, list[str]]:
    try:
        v = json.loads(CUSTOM_TIER0_FILE.read_text())
        if isinstance(v, dict):
            return {str(k): [str(x) for x in val] for k, val in v.items()}
        return {}                      # legacy global flat list → dropped (no longer applied)
    except Exception:
        return {}


def _save_tier0_map(m: dict[str, list[str]]) -> None:
    _ensure()
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({k: sorted(set(v)) for k, v in m.items()}, f, indent=2)
        os.replace(tmp, CUSTOM_TIER0_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@functools.lru_cache(maxsize=64)
def _seed_tier0_ids(scan_id: str) -> tuple[str, ...]:
    """A scan's run-time Tier-0 picks (result['user_tier0']). Memoized: the scan file is
    immutable once saved, and this otherwise re-parses a multi-MB scan JSON on every graph
    request (a scan with no manual mark is never in the tier0 map, so it re-seeds each time)."""
    p = SCANS_DIR / f"{_safe(scan_id)}.json"
    try:
        return tuple(str(x) for x in (json.loads(p.read_text()).get("user_tier0") or []))
    except Exception:
        return ()


def _seed_tier0(scan_id: str) -> set[str]:
    """Fresh mutable set of a scan's seed Tier-0 ids (safe for callers to mutate)."""
    return set(_seed_tier0_ids(scan_id))


def get_custom_tier0(scan_id: str) -> list[str]:
    """This scan's custom Tier-0 node ids (its own picks + any marks made on its graph)."""
    with _TIER0_LOCK:
        m = _load_tier0_map()
        ids = set(m[scan_id]) if scan_id in m else _seed_tier0(scan_id)
        return sorted(ids)


def add_custom_tier0(scan_id: str, node_id: str) -> list[str]:
    with _TIER0_LOCK:
        m = _load_tier0_map()
        ids = set(m[scan_id]) if scan_id in m else _seed_tier0(scan_id)
        ids.add(str(node_id))
        m[scan_id] = sorted(ids)
        _save_tier0_map(m)
        return m[scan_id]


def remove_custom_tier0(scan_id: str, node_id: str) -> list[str]:
    with _TIER0_LOCK:
        m = _load_tier0_map()
        ids = set(m[scan_id]) if scan_id in m else _seed_tier0(scan_id)
        ids.discard(str(node_id))
        m[scan_id] = sorted(ids)
        _save_tier0_map(m)
        return m[scan_id]


def clear_custom_tier0(scan_id: str) -> list[str]:
    """Drop every custom Tier-0 mark for a scan (including its seeded run-time picks), so the
    graph resets to the built-in Tier-0 set only."""
    with _TIER0_LOCK:
        m = _load_tier0_map()
        m[scan_id] = []
        _save_tier0_map(m)
        return []


# ── User-saved attack-graph queries ────────────────────────────────────────────
# A saved query is a small, serializable "view descriptor", {kind, source, target,
# preset, mode}, that the explorer can replay. Stored globally (like custom Tier-0)
# so a saved view is available across every scan of the tenant.
SAVED_QUERIES_FILE = DATA_DIR / "graph_saved_queries.json"
_SAVEDQ_LOCK = threading.Lock()
_MAX_SAVED_QUERIES = 100


def get_saved_queries() -> list[dict]:
    try:
        v = json.loads(SAVED_QUERIES_FILE.read_text())
        return [q for q in v if isinstance(q, dict) and q.get("name")] if isinstance(v, list) else []
    except Exception:
        return []


def _save_saved_queries(queries: list[dict]) -> list[dict]:
    _ensure()
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(queries, f, indent=2)
        os.replace(tmp, SAVED_QUERIES_FILE)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return queries


def add_saved_query(name: str, view: dict) -> list[dict]:
    name = str(name).strip()[:80]
    if not name:
        raise ValueError("name required")
    with _SAVEDQ_LOCK:
        queries = [q for q in get_saved_queries() if q.get("name") != name]   # replace by name
        queries.append({"name": name, "view": dict(view or {})})
        queries = queries[-_MAX_SAVED_QUERIES:]
        return _save_saved_queries(queries)


def remove_saved_query(name: str) -> list[dict]:
    with _SAVEDQ_LOCK:
        queries = [q for q in get_saved_queries() if q.get("name") != str(name)]
        return _save_saved_queries(queries)


# ---- scan history (persisted) --------------------------------------------
def _attack_path_display_count(result: dict) -> int:
    """Count attack paths the way the report's Attack Paths tab shows them.

    The raw stored findings hold one `path_consolidation` row per source group
    (291 on the test tenant), but the report runs `_synthesize_path_findings`
    then `_regroup_path_findings` before display, which merges same-group routes
    down to what the analyst actually sees (53). History used to count the raw
    291, so its "Attack Paths" column disagreed with every report. Apply the same
    two transforms here so the number matches. Best-effort: on any error fall
    back to the raw count rather than break the summary.
    """
    try:
        from . import report
        # Copy so the transform cannot mutate the caller's dict; finalize_findings is the
        # single shared consolidator (no-op when the scan was already finalized on write).
        staged = {**result, "findings": list(result.get("findings", []))}
        staged = report.finalize_findings(staged)
        return sum(1 for f in staged.get("findings", [])
                   if f.get("source") == "path_consolidation")
    except Exception:
        return sum(1 for f in result.get("findings", [])
                   if f.get("source") == "path_consolidation")


def _summary(result: dict, scan_id: str, files: list[str]) -> dict:
    from . import report as _report
    score = result.get("score", {})
    findings = result.get("findings", [])
    # Count severities the SAME way the interactive report's badges do: exclude attack-path rows and
    # AI "leads" (low-confidence / lead-tier AI findings shown under their own chip). Otherwise the
    # history table and dashboard tiles would show a higher Critical/High count than the report.
    _lead_thr = get_settings().get("ai_lead_confidence", 50)
    by_sev: dict[str, int] = {}
    for f in findings:
        if f.get("source") == "path_consolidation":
            continue  # counted separately; excluded from critical/high badges
        if _report.is_ai_lead(f, _lead_thr):
            continue  # leads sit under their own chip, not in the severity badges
        sev = f.get("severity") or "Info"
        by_sev[sev] = by_sev.get(sev, 0) + 1
    statuses = get_finding_statuses(scan_id)
    non_path_findings = [f for f in findings if f.get("source") != "path_consolidation"]
    non_path = len(non_path_findings)
    # Remediation progress is over the findings the user actually sees (non-path), so the fraction
    # and the percentage share one denominator.
    resolved = sum(1 for f in non_path_findings
                   if statuses.get(finding_key(f)) in ("Resolved", "Risk Accepted"))
    attack_paths = _attack_path_display_count(result)
    return {
        "id": scan_id,
        "created_at": result.get("_created_at"),
        "files": files,
        "tenant_id": result.get("tenant_id"),
        "grade": score.get("grade"),
        "score": score.get("score"),
        "findings": non_path,
        "attack_paths": attack_paths,
        "critical": by_sev.get("Critical", 0),
        "high": by_sev.get("High", 0),
        "ai_enabled": result.get("ai_enabled", False),
        "complete": result.get("collection", {}).get("complete", True),
        "resolved": resolved,
        "remediation_pct": round(100 * resolved / non_path) if non_path else 0,
    }


def _index_path() -> Path:
    return SCANS_DIR / _INDEX_FILE_NAME


def _read_index() -> list[dict]:
    """Read the lightweight index. Returns [] on any error (caller falls back to rebuild)."""
    p = _index_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text())
    except Exception:
        return []


def _write_index(entries: list[dict]) -> None:
    """Write the index atomically via a temp-file rename."""
    p = _index_path()
    try:
        fd, tmp = tempfile.mkstemp(dir=str(SCANS_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(entries, f)
            os.replace(tmp, p)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:
        pass  # index write failures are non-fatal; list_scans() will rebuild


def _rebuild_index() -> list[dict]:
    """Rebuild index by reading all scan files. Writes the new index to disk."""
    out: list[dict] = []
    for p in SCANS_DIR.glob("*.json"):
        if p.name == _INDEX_FILE_NAME:
            continue
        try:
            r = json.loads(p.read_text())
            out.append(_summary(r, p.stem, r.get("_files", r.get("ingest_summary", {}).get("files", []))))
        except Exception:
            continue
    out.sort(key=lambda s: s.get("created_at") or 0, reverse=True)
    _write_index(out)
    return out


def update_scan(scan_id: str, result: dict) -> bool:
    """Rewrite a stored scan in place, preserving its id and creation time.

    Used to patch a saved scan after the fact (e.g. linking the AI trace id). The
    index summary IS refreshed so History never disagrees with the report it links to.
    """
    p = SCANS_DIR / f"{scan_id}.json"
    if not p.exists():
        return False
    result = dict(result)
    result["_scan_id"] = scan_id
    fd, tmp = tempfile.mkstemp(dir=str(SCANS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(result, f, default=str)
        os.replace(tmp, p)
        try:
            files = result.get("_files") or result.get("ingest_summary", {}).get("files", [])
            entry = _summary(result, scan_id, files)
            entries = [e for e in _read_index() if e.get("id") != scan_id]
            entries.append(entry)
            entries.sort(key=lambda s: s.get("created_at") or 0, reverse=True)
            _write_index(entries)
        except Exception:
            pass  # index refresh is best-effort; list_scans() can rebuild
        return True
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def save_scan(result: dict, files: list[str]) -> str:
    _ensure()
    scan_id = uuid.uuid4().hex[:12]
    result = dict(result)
    # Consolidate attack-path findings ONCE, here at the write chokepoint, so the stored
    # scan is already canonical and every reader gets deduped findings for free (idempotent;
    # get_scan re-applies it only for scans written before this change).
    from . import report
    result = report.finalize_findings(result)
    result["_created_at"] = int(time.time())
    result["_scan_id"] = scan_id
    p = SCANS_DIR / f"{scan_id}.json"
    fd, tmp = tempfile.mkstemp(dir=str(SCANS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(result, f)
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Update index: prepend new summary so newest-first ordering is preserved.
    with _INDEX_LOCK:
        entries = _read_index()
        entry = _summary(result, scan_id, files)
        entries = [e for e in entries if e.get("id") != scan_id]  # dedupe on retry
        entries.insert(0, entry)
        _write_index(entries)
    return scan_id


def list_scans() -> list[dict]:
    _ensure()
    with _INDEX_LOCK:
        entries = _read_index()
        if not entries:
            # Index missing or empty, rebuild from full scan files on first call
            # or after data-dir recovery.
            scan_files = [p for p in SCANS_DIR.glob("*.json") if p.name != _INDEX_FILE_NAME]
            if scan_files:
                entries = _rebuild_index()
    return entries


def scan_exists(scan_id: str) -> bool:
    """Cheap existence check (no load/finalize) for guards that only need to 404."""
    return (SCANS_DIR / f"{_safe(scan_id)}.json").exists()


def get_scan(scan_id: str) -> dict | None:
    p = SCANS_DIR / f"{_safe(scan_id)}.json"
    if not p.exists():
        return None
    try:
        result = json.loads(p.read_text())
    except Exception:
        return None
    # Single read chokepoint: every consumer loads scans through here, so finalizing the
    # findings once means no reader can ever see the raw per-principal path rows. No-op for
    # scans saved after finalize moved to write time (they carry the marker).
    from . import report
    return report.finalize_findings(result)


def delete_scan(scan_id: str) -> dict:
    """Delete a scan and its remediation-status file. Never raises: OS-level
    failures (locked file, permissions - common on Windows if the JSON is open
    in another process) are caught and reported back rather than surfacing as
    an opaque 500 while the frontend shows a false 'Deleted' toast."""
    p = SCANS_DIR / f"{_safe(scan_id)}.json"
    if not p.exists():
        return {"deleted": False, "error": "Scan not found."}
    try:
        p.unlink()
    except OSError as e:
        return {"deleted": False, "error": f"Could not delete: {e}. "
                "The file may be open in another program or locked by the OS."}
    # Best-effort cleanup of associated files.
    try:
        sp = _status_file(scan_id)
        if sp.exists():
            sp.unlink()
    except OSError:
        pass
    delete_raw_blobs(scan_id)
    # Drop the cached attack-graph snapshot (and its Kùzu DB, which lives under the same
    # dir); otherwise each deleted scan orphans its snapshot dir on disk.
    try:
        from .graph.persist import delete_snapshot
        delete_snapshot(scan_id)
    except Exception:
        pass
    # Remove from index (best-effort; list_scans() rebuilds on next load if corrupt).
    with _INDEX_LOCK:
        entries = _read_index()
        updated = [e for e in entries if e.get("id") != scan_id]
        if len(updated) != len(entries):
            _write_index(updated)
    return {"deleted": True}


# ---- raw AzureHound blob storage (for BH CE re-ingestion) ---------------

RAW_DIR = DATA_DIR / "raw_collections"


def save_raw_blobs(scan_id: str, blobs: list[tuple[bytes, str]]) -> None:
    """Persist the raw AzureHound files so they can be re-uploaded to BH CE later."""
    d = RAW_DIR / _safe(scan_id)
    d.mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    for i, (data, name) in enumerate(blobs):
        base = Path(name).name or f"collection_{i}.json"
        candidate = base
        counter = 1
        while candidate in used:
            stem, suffix = Path(base).stem, Path(base).suffix
            candidate = f"{stem}_{counter}{suffix}"
            counter += 1
        used.add(candidate)
        (d / candidate).write_bytes(data)


def get_raw_blobs(scan_id: str) -> list[tuple[bytes, str]] | None:
    """Return stored raw blobs for a scan, or None if not available."""
    d = RAW_DIR / _safe(scan_id)
    if not d.exists():
        return None
    blobs = []
    for p in sorted(d.iterdir()):
        if p.is_file():
            blobs.append((p.read_bytes(), p.name))
    return blobs or None


def has_raw_collection(scan_id: str) -> bool:
    """True if a scan has stored raw blobs that can be re-assessed without re-collecting.
    Cheap existence check (no file reads) for listing which scans are re-scannable."""
    d = RAW_DIR / _safe(scan_id)
    return d.exists() and any(p.is_file() for p in d.iterdir())


def delete_raw_blobs(scan_id: str) -> None:
    """Remove stored raw blobs (called from delete_scan)."""
    import shutil
    d = RAW_DIR / _safe(scan_id)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


# ---- pending collections (collect → optional Tier-0 selection → assess) ----------
# A collection that has been gathered (live or uploaded) but not yet assessed, held
# between the collect phase and the assessment phase so the user can pick Tier-0 assets.
# Short-lived: cleaned up after assessment, and swept if older than the TTL.
PENDING_DIR = DATA_DIR / "pending_collections"
_PENDING_TTL_SECONDS = 6 * 3600


def _sweep_pending() -> None:
    """Drop pending collections older than the TTL (abandoned selections)."""
    import shutil
    if not PENDING_DIR.exists():
        return
    cutoff = time.time() - _PENDING_TTL_SECONDS
    for d in PENDING_DIR.iterdir():
        try:
            if d.is_dir() and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            continue


def save_pending_collection(blobs: list[tuple[bytes, str]], inventory: dict) -> str:
    """Persist collected blobs + a precomputed inventory; return a collection id."""
    _ensure()
    _sweep_pending()
    cid = uuid.uuid4().hex[:12]
    d = PENDING_DIR / _safe(cid)
    (d / "blobs").mkdir(parents=True, exist_ok=True)
    used: set[str] = set()
    for i, (data, name) in enumerate(blobs):
        base = Path(name).name or f"collection_{i}.json"
        candidate, counter = base, 1
        while candidate in used:
            stem, suffix = Path(base).stem, Path(base).suffix
            candidate = f"{stem}_{counter}{suffix}"
            counter += 1
        used.add(candidate)
        (d / "blobs" / candidate).write_bytes(data)
    (d / "inventory.json").write_text(json.dumps(inventory))
    return cid


def get_pending_blobs(cid: str) -> list[tuple[bytes, str]] | None:
    d = PENDING_DIR / _safe(cid) / "blobs"
    if not d.exists():
        return None
    blobs = [(p.read_bytes(), p.name) for p in sorted(d.iterdir()) if p.is_file()]
    return blobs or None


def get_pending_inventory(cid: str) -> dict | None:
    p = PENDING_DIR / _safe(cid) / "inventory.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def delete_pending_collection(cid: str) -> None:
    import shutil
    d = PENDING_DIR / _safe(cid)
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


# ---- finding status tracking (remediation workflow) ----------------------
# Lets the tool function as an ongoing loop rather than a one-shot report:
# mark a finding Acknowledged / In Progress / Resolved / Risk Accepted, and
# see remediation progress on the Dashboard and in the report.
VALID_STATUSES = ("New", "Acknowledged", "In Progress", "Resolved", "Risk Accepted")
_STATUS_DIR_NAME = "finding_status"


def finding_key(finding: dict) -> str:
    """Stable key for a finding within a scan: rule_id if deterministic,
    otherwise title + sorted entity ids (AI-generated findings have no rule_id)."""
    if finding.get("rule_id"):
        base = finding["rule_id"]
    elif finding.get("source") == "sp_group" and finding.get("sp_id"):
        # A service-principal group's title embeds its member count ("... N findings"), which shifts
        # as rules change, so a title-based key would change across re-scans and orphan its recorded
        # status / work item. Key on the stable service-principal id instead.
        base = f"sp_group|{finding['sp_id']}"
    else:
        entities = finding.get("entities") or []
        if not isinstance(entities, list):
            entities = []
        ids = ",".join(sorted(
            (e.get("id", "") if isinstance(e, dict) else str(e)) for e in entities
        ))
        base = f"{finding.get('title', '')}|{ids}"
    return hashlib.sha1(base.encode()).hexdigest()[:16]


# ---- Azure DevOps integration (PAT is env-only; config is non-secret settings) ----
def get_ado_pat() -> str | None:
    """The Azure DevOps Personal Access Token, env var ONLY (PH_ADO_PAT), never persisted."""
    v = (os.environ.get("PH_ADO_PAT") or "").strip()
    return v or None


def ado_status() -> dict:
    """Non-secret view of the ADO integration state for the UI: whether it is turned on and
    whether it is fully usable (enabled + org/project set + PAT present). Never exposes the PAT."""
    s = get_settings()
    has_pat = bool(get_ado_pat())
    configured = bool(s.get("ado_org_url") and s.get("ado_project") and has_pat)
    return {"enabled": bool(s.get("ado_enabled")), "pat_present": has_pat,
            "configured": configured, "org_url": s.get("ado_org_url", ""),
            "project": s.get("ado_project", ""), "area_path": s.get("ado_area_path", ""),
            "work_item_type": s.get("ado_work_item_type", "Feature"),
            "tags": s.get("ado_tags", ""), "default_assignee": s.get("ado_default_assignee", ""),
            "default_parent_epic": s.get("ado_default_parent_epic", "")}


_WORKITEMS_DIR_NAME = "workitems"
_WORKITEMS_LOCK = threading.Lock()


def _workitems_file(scan_id: str) -> Path:
    d = SCANS_DIR / _WORKITEMS_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{_safe(scan_id)}.json"


def get_work_items(scan_id: str) -> dict:
    """{finding_key: {id, url, type, assignee, parent_epic, created_at}}, created ADO tickets."""
    p = _workitems_file(scan_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def record_work_item(scan_id: str, key: str, info: dict) -> dict:
    with _WORKITEMS_LOCK:
        items = get_work_items(scan_id)
        items[key] = info
        _write_work_items(scan_id, items)
    return items


def delete_work_item(scan_id: str, key: str) -> dict | None:
    """Forget the local work-item record for a finding so a new ticket can be raised. Returns the
    removed record (or None if there was none). Does NOT touch Azure DevOps, the caller deletes the
    remote work item first."""
    with _WORKITEMS_LOCK:
        items = get_work_items(scan_id)
        removed = items.pop(key, None)
        if removed is not None:
            _write_work_items(scan_id, items)
    return removed


def _write_work_items(scan_id: str, items: dict) -> None:
    p = _workitems_file(scan_id)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(items, f, indent=2)
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _status_file(scan_id: str) -> Path:
    d = SCANS_DIR / _STATUS_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{_safe(scan_id)}.json"


def get_finding_statuses(scan_id: str) -> dict[str, str]:
    p = _status_file(scan_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def _refresh_index_remediation(scan_id: str) -> None:
    """Recompute the history-index entry's resolved / remediation_pct for one scan after a status
    change. The index snapshot is written at save time (when nothing is resolved yet), so without
    this the History page's remediation column stays frozen at 0 until a full index rebuild."""
    try:
        result = get_scan(scan_id)
        if not result:
            return
        statuses = get_finding_statuses(scan_id)
        non_path = [f for f in (result.get("findings") or [])
                    if f.get("source") != "path_consolidation"]
        resolved = sum(1 for f in non_path
                       if statuses.get(finding_key(f)) in ("Resolved", "Risk Accepted"))
        n = len(non_path)
        with _INDEX_LOCK:
            entries = _read_index()
            changed = False
            for e in entries:
                if e.get("id") == scan_id:
                    e["resolved"] = resolved
                    e["remediation_pct"] = round(100 * resolved / n) if n else 0
                    changed = True
                    break
            if changed:
                _write_index(entries)
    except Exception:
        pass  # best-effort; a full index rebuild corrects it


def set_finding_status(scan_id: str, key: str, status: str) -> dict[str, str]:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status!r}")
    with _STATUS_LOCK:
        statuses = get_finding_statuses(scan_id)
        statuses[key] = status
        p = _status_file(scan_id)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(statuses, f, indent=2)
            os.replace(tmp, p)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    _refresh_index_remediation(scan_id)   # keep the History remediation column current
    return statuses


# ── Validation labels (analyst ground-truth for the precision harness) ─────
VALIDATION_VERDICTS = ("true_positive", "false_positive", "unsure")
_VALIDATION_DIR_NAME = "validation"
_VALIDATION_LOCK = threading.Lock()


def _validation_file(scan_id: str) -> Path:
    d = SCANS_DIR / _VALIDATION_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{_safe(scan_id)}.json"


def get_validation(scan_id: str) -> dict:
    """Return {finding_key: {verdict, note, by, ts}} the analyst has recorded."""
    p = _validation_file(scan_id)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def set_validation_label(scan_id: str, key: str, verdict: str,
                         note: str = "", by: str = "") -> dict:
    """Record (or clear) one analyst verdict on a finding. verdict=None deletes it."""
    if verdict is not None and verdict not in VALIDATION_VERDICTS:
        raise ValueError(f"Invalid verdict: {verdict!r}")
    with _VALIDATION_LOCK:
        labels = get_validation(scan_id)
        if verdict is None:
            labels.pop(key, None)
        else:
            labels[key] = {"verdict": verdict, "note": (note or "")[:2000],
                           "by": (by or "")[:120], "ts": int(time.time())}
        p = _validation_file(scan_id)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(labels, f, indent=2)
            os.replace(tmp, p)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return labels


def _safe(scan_id: str) -> str:
    # ids are 12-char hex; strip anything else and cap length to prevent OS errors.
    return "".join(c for c in (scan_id or "") if c in "0123456789abcdef")[:12]
