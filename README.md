# PostureHound

**Read-only Azure / Entra identity attack-surface posture audit, driven by AzureHound collection data.**

> **New here?** Open the illustrated **[User Guide](docs/USER_GUIDE.html)** - setup through your first scan.
>
> Quick start (Docker):
> ```bash
> cp .env.example .env
> docker compose up -d --build      # then open http://127.0.0.1:31337
> # first sign-in: admin / posturehound  → change it in Settings
> ```

Local multi-page web app: **Dashboard**, **New scan**, **History** (stored locally), and **Settings**
(Anthropic API key held in server memory only, never written to disk). Start with `./setup.sh && ./start.sh`
and open `http://127.0.0.1:31013`.

The data layer is built against AzureHound v2's real output schema - the actual relationship kinds, the
per-resource RBAC assignment kinds (`AZSubscriptionRoleAssignment`, `AZKeyVaultRoleAssignment`, …),
GUID-referenced role definitions resolved via Azure's global built-in-role IDs, Graph app-role GUIDs, and
PIM-eligible (not just active) role assignments - so it parses genuine `azurehound` output, including
"shadow admin" paths that an active-roles-only view would miss entirely. Collect twice (a Microsoft Graph
token for the Entra plane and an Azure Management token for the resource plane, e.g. `ad.json` + `rm.json`)
and upload both together to merge.

PostureHound ingests an [AzureHound](https://github.com/SpecterOps/AzureHound) collection (its Azure
identity-graph JSON export) and evaluates the tenant's **identity security posture offline**: entry
points, misconfigurations, over-permissive service principals, lateral-movement opportunities, and
privilege-escalation chains to Tier-0.

> **Scope.** PostureHound assesses the **identity attack surface** visible in AzureHound data (directory
> roles, RBAC, app/SP permissions, ownership, group membership, Key Vault/storage access, managed identities,
> PIM eligibility). It is **not** a full CSPM. Controls AzureHound cannot see - MFA/authentication methods,
> Conditional Access, sign-in/audit logs, network exposure, encryption-at-rest - are reported as **not
> assessable**, never as a pass. See the Coverage panel in every report.

---

## How findings are produced

Two layers, working together:

1. **145 deterministic safety-net rules** across identity, apps/SPs, RBAC, groups, guests, Key Vault, storage,
   compute/managed-identity theft, PIM eligibility, Azure Resource Graph config, and tenant identity governance.
   These always run, so always-critical patterns can never be silently missed regardless of AI. Browse them on
   the in-app **Rules** page, or see [`docs/PRD.md`](docs/PRD.md).
2. **Two-agent AI generation** (opt-in, needs an Anthropic API key): a **Sonnet** analyst (L5) reasons
   broadly over a deterministic fact pack - not a fixed checklist - to generate candidate findings with full
   reasoning chains. An **Opus** principal architect (L8) reviews those candidates: keeps and deepens what
   holds up, re-grades severity where warranted, rejects what doesn't, and adds findings of its own by
   reasoning fresh over the same facts. Every claim from either agent is validated against the fact pack, so
   neither can fabricate an entity or relationship not actually in the tenant.

Findings from both layers are merged, deduped, and clearly tagged by source (✦ AI-generated vs. ⚙
deterministic) in the report.

## Remediation workflow

This isn't a one-shot report generator - findings can be tracked to closure:

- Mark any finding **New / Acknowledged / In Progress / Resolved / Risk Accepted**, persisted per scan.
- **Action Plan** tab: every open finding consolidated into one prioritised list (Now/Next/Backlog by
  severity), so remediation is one ordered plan instead of triaging findings individually.
- **Scan comparison**: diff two scans to see what got resolved and what's new.
- **Posture trend**: score-over-time sparkline on the Dashboard once you have more than one scan.

## Architecture

```
AzureHound JSON ─▶ ingest ─▶ normalize ─▶ derive ─▶ rules ─▶ score+analytics ─▶ report / API
                  (parse)    (graph)     (abuse     (catalog) (grade, max-impact,
                                          edges)               choke points)
```

The **deterministic engine is the single source of truth.** Scoring, reporting, the API, and any future AI layer read from it and may not assert facts it does not contain. Every derived edge carries its named primitive and evidence.

| Module | Responsibility |
|--------|----------------|
| `ingest.py` | Format detection (JSON / NDJSON / zip), streaming parse, resilient skip-and-count, `validate` |
| `normalize.py` | Map records into a typed `networkx` graph (nodes + raw relationship edges) |
| `derive.py` | Derive identity attack-path abuse edges (effective roles, AddSecret, app-role / RBAC escalation, KV reach) |
| `rules/` | Detection catalog + engine with data-source gating → "not assessed" |
| `scoring.py` | Posture score, blast-radius, maximum-impact chain, choke points |
| `report.py` | Self-contained, CSP-friendly HTML report |
| `api.py` | Hardened read-only FastAPI service |
| `cli.py` | `scan` / `validate` commands |

## Install

```bash
pip install -r requirements.txt          # networkx, orjson, fastapi, uvicorn, python-multipart
# dev: pytest, httpx
```

## Usage

**CLI**
```bash
python -m posturehound.cli scan collection.json                 # JSON to stdout
python -m posturehound.cli scan collection.json --format html --out report.html
python -m posturehound.cli scan collection.json --min-severity High
python -m posturehound.cli validate collection.json
```
The `scan` command exits non-zero (2) if any Critical finding exists - useful for CI gating.

**API**
```bash
uvicorn posturehound.api:app --port 8080
# GET  /            minimal uploader UI
# POST /api/assess  multipart file upload -> assessment JSON
# POST /api/report  multipart file upload -> HTML report
# POST /api/validate
# GET  /health
```

**Library**
```python
from posturehound import assess_file, assess_bytes
result = assess_file("collection.json")     # dict: score, findings, analytics, coverage
```

## Security posture of the tool itself

PostureHound holds a tenant's full privilege map, which is sensitive. The application is built read-only and defensively:

- **Read-only / in-memory.** The only input is a user-uploaded AzureHound file. The API never reads server paths supplied by the user, never writes to disk, never fetches URLs (no SSRF), and never executes collection content.
- **Input validation & limits.** Enforced max upload size (`PH_MAX_UPLOAD_MB`, default 50). Malformed input returns a clean `400`, never a stack trace.
- **Hardened responses.** Strict CSP (`script-src 'none'`), `nosniff`, frame-deny, `no-referrer`, `no-store`. The OpenAPI schema and interactive docs are disabled.
- **No wildcard CORS**; same-origin by default.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Data-model caveat

AzureHound's relationship representation varies by version. The loader field mappings in `normalize.py` are pragmatic and should be **validated against your AzureHound version** before relying on results - see [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) (open question OQ-1). The derivation and detection logic is version-independent; only the thin ingest adapter is version-sensitive.

## Tests

```bash
PYTHONPATH=src python -m pytest tests/ -q     # ingest, normalize, derive, rules, scoring, AI pipeline, graph engine
```
