# PRD - Authentication & Authorization for PostureHound

Status: implemented (V2)
Owner: PostureHound
Related: `docs/PRD.md`, the maturity assessment (tool-own-security gap)

## 1. Problem

PostureHound holds an entire Azure tenant's privilege map plus the status of live
secrets (Anthropic key, ARG service-principal secret, ADO PAT). Until now the web UI
had **no authentication**: the only control was binding to `127.0.0.1`. Any local
process - or a browser tricked into calling `localhost` (CSRF / DNS-rebinding) - could
read every finding, trigger scans, change settings, and create ADO work items.

For a tool whose whole job is finding identity-security weaknesses, running with no
front door is the biggest single maturity gap. This adds a first-class auth layer.

## 2. Goals

1. **Authentication** - the UI and API require a logged-in session. A default
   credential ships so the tool is usable on first boot; the operator changes it in
   Settings.
2. **Stateless authorization on every request** - after login, every request carries a
   **JWT** that is validated on the server before any handler runs. No valid token → 401.
3. **Credential management in Settings** - change username and password from the UI
   (current password required). A visible warning until the default password is changed.
4. **No regression** - the existing ~1380-test suite keeps passing; auth is exercised by
   dedicated tests.

## 3. Non-goals

- Multi-user / roles / RBAC. PostureHound is a single-operator local tool; there is one
  account. (The design leaves room to add users later - the token carries a `sub`.)
- OAuth / SSO / external IdP. Out of scope for a local tool.
- Password reset by email, MFA. Documented as possible future work.

## 4. Design

### 4.1 Credential storage
- A single account persisted in `~/.posturehound/auth.json`, mode `0600`:
  `{username, password_hash, jwt_secret, must_change, updated_at}`.
- **Password hashing**: PBKDF2-HMAC-SHA256, 600 000 iterations (OWASP 2023), 16-byte
  random per-password salt. Stored as `pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>`.
  Verification is constant-time (`hmac.compare_digest`).
- **Default credentials**: on first boot the account is seeded as
  `admin` / `posturehound` (the password can be overridden at first boot with
  `PH_ADMIN_PASSWORD`). `must_change=true` is set so the UI shows a persistent
  "change the default password" banner until the operator rotates it, and the server
  logs a warning on every boot while the default is unchanged.

### 4.2 Tokens (JWT)
- **Algorithm**: HS256 only. Implemented in the standard library (`hmac`/`hashlib`) to
  avoid a new dependency. The two classic JWT pitfalls are closed explicitly:
  - the verifier **pins** `alg` to `HS256` and rejects `none`/`RS*`/anything else
    (no algorithm confusion),
  - signature comparison is constant-time.
  `exp` and `iat` are checked; the token `typ` must be `access`.
- **Signing secret**: `PH_JWT_SECRET` if set (recommended for production); otherwise a
  48-byte random secret generated once and persisted in `auth.json`. Rotating the secret
  invalidates all existing sessions (acceptable).
- **TTL**: 12 hours by default, override with `PH_AUTH_TTL_HOURS`.
- **Delivery**: an **httpOnly**, **SameSite=Strict**, `Path=/` cookie named `ph_auth`.
  httpOnly keeps the token out of reach of any XSS; SameSite=Strict neutralizes CSRF and
  the DNS-rebinding POST class. `Secure` is set automatically when the request is HTTPS.

### 4.3 Enforcement
- A single global FastAPI dependency (`_auth_guard`) runs before every route handler.
- **Public paths** (no token required): `GET /` (the SPA shell - it has no data and then
  calls the auth API), `GET /health`, `POST /api/auth/login`, `GET /api/auth/me`,
  `POST /api/auth/logout`, and `/static/*` (a separate mount). Everything else - all
  `/api/*`, every scan/report/graph/settings route - requires a valid token.
- A missing/invalid/expired token yields `401`.
- **Login throttling**: after 5 failed attempts the account is locked for 60 seconds
  (in-memory, per process) to blunt brute force.

### 4.4 Endpoints
| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/auth/login` | public | username+password → set `ph_auth` cookie |
| POST | `/api/auth/logout` | public | clear the cookie |
| GET  | `/api/auth/me` | public | `{authenticated, username, must_change}` - the SPA uses it to choose login vs app |
| POST | `/api/auth/password` | required | change password (and optionally username); current password required; re-issues the cookie |

`GET /api/settings` additionally reports non-secret auth status
(`auth_username`, `auth_must_change`) so the UI can render the account card and the
default-password banner. The password hash and JWT secret are **never** returned by any
endpoint.

### 4.5 Frontend
- On boot the SPA calls `/api/auth/me`. Not authenticated → it renders a login screen and
  hides the nav; authenticated → normal app, plus a "Log out" control and (while
  `must_change`) a banner linking to Settings.
- Any API call that returns `401` drops the user back to the login screen.
- Settings gains an **Account** card: change username + new password, current password
  required.

### 4.6 Testing / compatibility
- Enforcement is disabled only when `PH_AUTH_DISABLED` is truthy. The test suite sets this
  in `conftest.py` so the existing endpoint tests are unaffected; `test_auth.py` clears it
  to exercise the real flow (login, protected 401/200, password change, tampered/expired/
  `alg=none` token rejection, default-password detection, logout).
- `PH_AUTH_DISABLED` defaults to **off**: production is authenticated by default and the
  flag is a documented test/opt-out only.

## 5. Security properties (summary)
- Passwords: never stored or logged in plaintext; PBKDF2-600k + per-password salt; constant-time verify.
- Tokens: HS256, algorithm pinned (no `none`/asymmetric confusion), constant-time signature check, expiry enforced, httpOnly + SameSite=Strict cookie.
- CSRF / DNS-rebinding: SameSite=Strict cookie is not sent on cross-site requests.
- Secrets at rest: `auth.json` is `0600`; the JWT secret prefers an env var.
- Brute force: per-account lockout after repeated failures.

## 6. Future work
- Multiple users + roles, MFA/TOTP, session revocation list, password-strength policy,
  and a first-run forced password change flow.
