![PostureHound](banner.svg)

# PostureHound

Read-only Azure / Entra identity attack-surface posture audit, driven by [AzureHound](https://github.com/SpecterOps/AzureHound) collection data.

---

## Installation

### Option 1 - Docker (recommended)

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Mac/Windows) or Docker Engine (Linux).

**1. Clone the repo**
```bash
git clone https://github.com/5t3v3/posturehound.git
cd posturehound
```

**2. Copy the example environment file**
```bash
cp .env.example .env
```

Edit `.env` if you want live Azure collection (fill in your Reader service-principal credentials) or AI findings (add your `ANTHROPIC_API_KEY`). Both are optional - you can upload an AzureHound file and get deterministic results without either.

**3. Start the container**
```bash
docker compose up -d --build
```

The first build takes 2-3 minutes. After that, subsequent starts are instant.

**4. Open the web UI**

Navigate to [http://127.0.0.1:31337](http://127.0.0.1:31337).

```bash
docker compose logs -f        # follow logs
docker compose down           # stop (data is preserved)
docker compose up -d          # restart without rebuilding
```

> **Data location.** Scans and settings are stored in `~/.posturehound` on your host machine, so they survive container rebuilds and `docker compose down`.

---

### Option 2 - Local Python

Requires Python 3.10+.

```bash
git clone https://github.com/5t3v3/posturehound.git
cd posturehound
pip install -r requirements.txt
uvicorn posturehound.api:app --port 31337
```

Or use the convenience scripts:
```bash
./setup.sh && ./start.sh
```

---

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
```

Open **http://127.0.0.1:31337** in your browser.
Default credentials: `admin` / `posturehound` - you are prompted to change the password on first sign-in.

---

## How to run a scan

1. **Collect** an AzureHound JSON export from your Azure tenant:
   ```bash
   azurehound list -t <tenant-id> -u <username> -p <password> -o collection.zip
   ```
   Or use live collection by setting the Reader SP credentials in `.env`.

2. **Upload** the collection file through the **New Scan** page in the web UI, or via the CLI:
   ```bash
   python -m posturehound.cli scan collection.json --format html --out report.html
   ```

3. **Review findings** on the report page. Findings are tagged by source (deterministic rule vs. AI-generated) and severity (Critical / High / Medium / Low / Informational).

---

## Findings engine

Two layers run on every scan:

**Deterministic rules (145 rules)**
Cover identity, apps/SPs, RBAC, groups, guests, Key Vault, storage, compute/managed-identity, PIM eligibility, Azure Resource Graph config, and tenant governance. Rules always run - critical patterns can never be silently missed regardless of AI availability. Browse them on the in-app **Rules** page or see [`docs/PRD.md`](docs/PRD.md).

**Two-agent AI generation** (opt-in, requires `ANTHROPIC_API_KEY`)
A **Sonnet** analyst reasons broadly over a deterministic fact pack to generate candidate findings with full reasoning chains. An **Opus** principal architect reviews those candidates, re-grades severity where warranted, rejects what does not hold up, and adds findings of its own. Every AI claim is validated against the fact pack - neither agent can fabricate an entity or relationship not present in the tenant data.

Findings from both layers are merged, deduplicated, and tagged by source (AI-generated vs. deterministic) in the report.

---

## Remediation workflow

Findings can be tracked to closure without leaving the tool:

- Set status per finding: **New / Acknowledged / In Progress / Resolved / Risk Accepted**
- **Action Plan** tab: every open finding in one prioritised list (Now / Next / Backlog by severity)
- **Scan comparison**: diff two scans to see what is resolved and what is new
- **Posture trend**: score-over-time sparkline on the Dashboard once you have more than one scan

---

## Architecture

```
AzureHound JSON -> ingest -> normalize -> derive -> rules -> score+analytics -> report / API
                  (parse)    (graph)     (abuse     (catalog) (grade, max-impact,
                                          edges)               choke points)
```

The deterministic engine is the single source of truth. Scoring, reporting, the API, and the AI layer all read from it and may not assert facts it does not contain.

| Module | Responsibility |
|--------|----------------|
| `ingest.py` | Format detection (JSON / NDJSON / zip), streaming parse, resilient skip-and-count |
| `normalize.py` | Map records into a typed `networkx` graph |
| `derive.py` | Derive abuse edges (effective roles, AddSecret, app-role / RBAC escalation, KV reach) |
| `rules/` | Detection catalog + engine with data-source gating |
| `scoring.py` | Posture score, blast-radius, maximum-impact chain, choke points |
| `report.py` | Self-contained CSP-friendly HTML report |
| `api.py` | Hardened read-only FastAPI service |
| `cli.py` | `scan` / `validate` commands |

---

## CLI reference

```bash
# Scan and print JSON
python -m posturehound.cli scan collection.json

# Produce an HTML report
python -m posturehound.cli scan collection.json --format html --out report.html

# Filter by minimum severity
python -m posturehound.cli scan collection.json --min-severity High

# Validate a collection file without scanning
python -m posturehound.cli validate collection.json
```

The `scan` command exits with code `2` if any Critical finding is present - useful for CI gating.

---

## API

```bash
uvicorn posturehound.api:app --port 8080

# GET  /            Minimal uploader UI
# POST /api/assess  Multipart file upload -> assessment JSON
# POST /api/report  Multipart file upload -> HTML report
# POST /api/validate
# GET  /health
```

---

## Library

```python
from posturehound import assess_file, assess_bytes

result = assess_file("collection.json")
# returns: { score, findings, analytics, coverage }
```

---

## Scope

PostureHound assesses the **identity attack surface** visible in AzureHound data: directory roles, RBAC, app/SP permissions, ownership, group membership, Key Vault/storage access, managed identities, and PIM eligibility.

It is **not** a full CSPM. Controls AzureHound cannot see - MFA/authentication methods, Conditional Access, sign-in/audit logs, network exposure, encryption-at-rest - are reported as **not assessable**, never as a pass. See the Coverage panel in every report.

---

## Security

PostureHound holds a tenant's full privilege map, which is sensitive. The application is built defensively:

- **Read-only / in-memory.** The API never reads server paths supplied by the user, never writes to disk, never fetches URLs, and never executes collection content.
- **Input validation.** Enforced max upload size (`PH_MAX_UPLOAD_MB`, default 50 MB). Malformed input returns a clean `400`.
- **Hardened responses.** Strict CSP (`script-src 'none'`), `nosniff`, frame-deny, `no-referrer`, `no-store`. OpenAPI docs are disabled.
- **No wildcard CORS.** Same-origin by default.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Data model caveat

AzureHound's relationship representation varies by version. The loader field mappings in `normalize.py` are pragmatic and should be **validated against your AzureHound version** before relying on results. See [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md).
