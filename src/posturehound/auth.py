"""Authentication primitives: password hashing and HS256 JWTs (standard library only).

PostureHound holds a whole tenant's privilege map, so the web layer must authenticate.
This module is the crypto core; persistence of the account and the signing secret lives in
`store.py`, and the FastAPI wiring (cookie, guard, endpoints) lives in `api.py`.

JWT is implemented here rather than pulled in as a dependency, and the two classic JWT
weaknesses are closed explicitly:
  * algorithm confusion - the verifier PINS alg to "HS256" and rejects "none"/asymmetric,
    so a token cannot downgrade the check,
  * forgery - the signature is compared in constant time (hmac.compare_digest).
Only HS256 is ever produced or accepted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

# ── Password hashing (PBKDF2-HMAC-SHA256) ───────────────────────────────────
_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ITERS = 600_000          # OWASP 2023 guidance for PBKDF2-HMAC-SHA256
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Return an encoded PBKDF2 hash: pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>."""
    salt = secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ITERS}${_b64e(salt)}${_b64e(dk)}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of a candidate password against an encoded PBKDF2 hash."""
    try:
        algo, iters_s, salt_b64, hash_b64 = (encoded or "").split("$")
        if algo != _PBKDF2_ALGO:
            return False
        iters = int(iters_s)
        salt = _b64d(salt_b64)
        expected = _b64d(hash_b64)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return hmac.compare_digest(dk, expected)


# ── JWT (HS256 only) ─────────────────────────────────────────────────────────
_ALG = "HS256"
_HEADER = {"alg": _ALG, "typ": "JWT"}


def create_token(subject: str, secret: str, *, ttl_seconds: int) -> str:
    """Sign an HS256 access token for `subject` valid for `ttl_seconds`."""
    now = int(time.time())
    payload = {"sub": subject, "typ": "access", "iat": now, "exp": now + int(ttl_seconds)}
    signing_input = _b64e_json(_HEADER) + "." + _b64e_json(payload)
    sig = _sign(signing_input, secret)
    return signing_input + "." + sig


def verify_token(token: str, secret: str) -> "dict | None":
    """Return the payload if the token is a valid, unexpired HS256 access token, else None.

    Rejects any algorithm other than HS256 (no 'none'/RS256 confusion) and checks the
    signature in constant time before trusting any claim."""
    try:
        header_b64, payload_b64, sig = token.split(".")
    except (ValueError, AttributeError):
        return None
    signing_input = header_b64 + "." + payload_b64
    # Verify the signature FIRST, in constant time, before parsing/trusting claims.
    if not hmac.compare_digest(sig, _sign(signing_input, secret)):
        return None
    try:
        header = json.loads(_b64d(header_b64))
        payload = json.loads(_b64d(payload_b64))
    except Exception:
        return None
    # Pin the algorithm: never honour the token's own downgrade to none/asymmetric.
    if header.get("alg") != _ALG or header.get("typ") != "JWT":
        return None
    if payload.get("typ") != "access":
        return None
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or time.time() >= exp:
        return None
    return payload


# ── helpers ──────────────────────────────────────────────────────────────────
def new_secret() -> str:
    return secrets.token_urlsafe(48)


def ttl_seconds() -> int:
    try:
        hours = float(os.getenv("PH_AUTH_TTL_HOURS", "12"))
    except ValueError:
        hours = 12.0
    return int(max(0.1, hours) * 3600)


def enforcement_enabled() -> bool:
    """Auth is ON unless PH_AUTH_DISABLED is explicitly truthy (a documented test opt-out)."""
    return os.getenv("PH_AUTH_DISABLED", "").strip().lower() not in ("1", "true", "yes", "on")


def _sign(signing_input: str, secret: str) -> str:
    mac = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return _b64e(mac)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e_json(obj: dict) -> str:
    return _b64e(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
