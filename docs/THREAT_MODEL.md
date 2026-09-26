# PostureHound - Tool Threat Model

PostureHound processes an AzureHound collection, which is effectively a **map of every privilege relationship in a tenant**. A leaked or tampered collection - or a compromised instance of this tool - would hand an attacker a prioritised target list. The tool is therefore treated as holding sensitive data, even though it is read-only.

## Assets
- The uploaded AzureHound collection (directory objects, role assignments, ownership, credentials metadata).
- The derived assessment (Tier-0 set, attack paths, choke points) - a ready-made target list.

## Trust boundary
The only trusted input is the **user-uploaded file via the web app / CLI**. Everything in the collection is **untrusted data**, not instructions: it is parsed, never executed, and never used to drive network calls or filesystem access.

## Controls implemented (this build)

| Risk | Control |
|------|---------|
| SSRF / pivot via collection content | Tool never fetches URLs; no outbound calls from collection data |
| Path traversal / arbitrary file read | API accepts only multipart uploads; no server path is taken from the user; no endpoint reads arbitrary paths |
| Data exfiltration to disk | Processing is in-memory; the API writes nothing to disk (test-asserted) |
| Oversized upload / DoS | Streamed size cap (`PH_MAX_UPLOAD_MB`, default 50) → `413` |
| Malformed input → info leak | Clean `400` with a short message; no stack traces returned |
| XSS in HTML report / UI | All values HTML-escaped; strict CSP with `script-src 'none'`; no external scripts/CDNs |
| Clickjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| Cached sensitive output | `Cache-Control: no-store` |
| API surface enumeration | OpenAPI schema and `/docs` disabled |
| Cross-origin abuse | No wildcard CORS; same-origin by default |

## Controls to add when state/auth is introduced (planned phases)
- Authentication + RBAC on all endpoints; per-engagement isolation (task P2-003).
- Encryption-at-rest for any persisted collection/graph; hard-delete on engagement removal (P2-026).
- Audit logging of uploads, scans, queries, exports (P2-007).
- If the optional AI layer is enabled, an explicit opt-in gate before any tenant data leaves the environment, plus a redaction option, and audit of agent tool calls (P3-004). Use a local model for sensitive customer collections.

## Residual risk
Until authentication and persistence are added, deploy the tool only in a trusted, access-controlled environment (e.g. an analyst workstation or an internal network segment). Do not expose the current build to untrusted networks.
