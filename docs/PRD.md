# PostureHound - Product Requirements Document

Version: 2.0.0
Status: current (supersedes the earlier root `PRD.md`)
Scope: this document catalogs **all existing features** of PostureHound as built.

---

## 1. Overview

PostureHound is a **read-only Azure identity-security posture scanner**. It ingests an
Azure identity/authorization graph - either an uploaded [AzureHound](https://github.com/BloodHoundAD/AzureHound)
collection or a live pull via a read-only service principal - and produces a graded posture
report: deterministic rule findings, an AI-analyzed finding set, and a native attack graph
that shows how a low-privileged principal can escalate to tenant-critical ("Tier-0") control.

It runs as a self-contained, single-tenant, local web application (Docker, bound to
`127.0.0.1`). It never modifies the tenant, never makes outbound calls except to the
Anthropic API (optional) and - in live-collection mode - Azure's read APIs.

### Design principles
- **Read-only & safe:** the only required input is a data file processed in memory; no writes
  to the tenant, no SSRF, no execution of collection content.
- **Deterministic first:** a rule engine produces the same findings byte-for-byte on the same
  input; the AI layer is additive and cached for reproducibility.
- **Grounded findings:** every finding maps to concrete objects and, where relevant, a real
  attack path in the graph - not a generic checklist item.
- **Framework-aligned:** findings carry MITRE ATT&CK, Azure Threat Matrix (ATRM), MS Threat
  Matrix, and CIS Azure references.

---

## 2. Users

- **Cloud security engineer / IAM admin** - runs scans, triages findings, tracks remediation.
- **Penetration tester / red teamer** - uses the attack graph to find and explain escalation paths.
- **Security lead / auditor** - reads the graded report, CIS best-practice coverage, and the shareable summary.

---

## 3. Data collection

Two interchangeable ways to get the graph in; both feed the same assessment pipeline.

1. **AzureHound upload.** Upload one or more collection files (`ad.json` + `rm.json`, or a
   `.zip`) via the UI or CLI. Multi-file split collections are merged. Per-file and total
   upload size caps (`PH_MAX_UPLOAD_MB` / `PH_MAX_TOTAL_MB`).
2. **Live collection (opt-in).** A read-only **Reader + Policy.Read.All** service principal
   lets PostureHound pull the identity graph via Microsoft Graph **and** resource/network/
   database/identity configuration via Azure Resource Graph - so a live scan sees exposure
   that AzureHound alone cannot (network firewalls, DB public access, Conditional Access / MFA
   config). Credentials are supplied via env (`PH_ARG_*`) or Settings; the secret is never
   returned by any API.

Raw collections are stored per scan so a scan can be **re-assessed** or its graph rebuilt
without re-collecting.

---

## 4. Assessment engine

### 4.1 Deterministic rule engine (145 rules)
The safety net: pure-Python rules that fire on collected facts, zero cost, zero hallucination.

- **108 identity-graph rules (`AZ-*`)** across: Applications & Service Principals (27),
  Privileged Identity (13), Azure RBAC (11), Key Vault (10), Groups & Membership (9),
  Storage & Data (9), Compute & Resource Abuse (6), Hygiene & Lifecycle (5), Guest &
  Cross-Tenant (3), Attack Path (3), Managed Identities & Resources (2), Best Practice (10).
- **33 Azure Resource Graph rules (`ARG-*`)** - network exposure, SQL/Cosmos/Postgres/MySQL/
  Redis config, AKS/ACR/App Service/Container Apps/Cognitive Services hardening, disks,
  Service Bus/Event Hub local auth, Defender tier.
- **4 identity-governance rules (`IDG-*`)** - tenant baseline: MFA enforcement, legacy-auth
  blocking, Conditional Access enforcement, baseline identity protection.
- Severity distribution (AZ): 10 Critical, 50 High, 32 Medium, 16 Low. **24 rules are
  CIS/best-practice** hardening checks (marked `best_practice`, kept at Low/Info by convention).
- **Property-gating:** rules that need a specific collected property emit `not_assessed`
  (rather than a false pass) when that property was not collected, so absence never reads as
  compliance.
- **Knowledge base:** each rule carries summary / why-it-matters / attack scenario /
  remediation / detection guidance and framework mappings.

### 4.2 AI analysis pipeline (optional, requires an Anthropic key)
Additive reasoning over the deterministic facts:

- **17 parallel domain specialists** (Sonnet) each analyze a focused slice of a shared
  "fact pack."
- **Cross-domain synthesizer** and **multi-step attack-chain correlator** (Opus) combine
  single-domain findings into compound, higher-severity chains.
- **Adversarial skeptic** vets Critical/High findings (confirm / downgrade / discard) with a
  written justification.
- **Coherence gate** re-anchors any finding whose attack path contradicts its description.
- **Cartographer** names attack paths; an **executive summary** stage narrates the posture.
- **Determinism via caching:** because the models reject temperature controls, the analysis
  is cached against a hash of the exact model input, so a repeat scan of unchanged data
  returns byte-identical AI findings.

### 4.3 Finding quality & validation
- **Quality tiers:** `verified_fact` (config read straight from Azure) → `corroborated` (an
  identity attack path corroborated by graph analysis) → `supported` → `lead` (low-confidence
  hypothesis).
- Serve-time **calibration** assigns each finding an effective confidence and a recall proxy.
- **Analyst validation labels** (true/false positive, unsure) persisted per finding.

### 4.4 Scoring
A 0–100 posture score and letter grade, weighted by severity, with hygiene/best-practice
findings counted but not penalizing the grade; methodology is recorded with the score.

---

## 5. Native attack graph

An in-house attack graph built directly from PostureHound's normalized model.

- **Backends:** networkx is the always-available source of truth and query engine; an
  embedded **Kùzu (Cypher)** backend is used for the ad-hoc query box when its wheel is
  available, with a transparent networkx fallback.
- **Escalation derivation:** ownership, RBAC at scope, managed-identity theft, PIM
  eligibility, group membership, Key Vault/storage data-plane access, container push, etc.,
  are derived into typed abuse edges. **Tier-0** is a curated high-impact target set.
- **Interactive explorer** (Attack Graph page):
  - All shortest paths to Tier-0 (overview), from-node trace to Tier-0 or to everything
    reachable, node→node path, paths-to a target, blast radius, all direct (1-hop)
    relationships, neighbor expansion.
  - **"Via" relationship filter** - constrain a path to chosen primitives (e.g.
    `CanGrantRole`, `CanStealManagedIdentity`).
  - **Ranking** by fewest hops or lowest total difficulty ("easiest").
  - **Custom Tier-0** targets marked per scan; **saved queries**; node/edge provenance
    panels with the findings that reference each node/edge.
  - Prebuilt preset queries (SPs→Tier-0, guests→Tier-0, disabled→Tier-0, dangerous app
    permissions, managed-identity abuse, Key Vault readers, storage-key access, etc.).
  - **Ad-hoc Cypher** query box (read-only verbs enforced) when Kùzu is available.
- **Per-finding path:** every finding carries its own max-impact path; "View in attack graph"
  plots that finding's actual entry→target path (a data-plane finding shows the path to its
  resource, an escalation finding the path to Tier-0).

---

## 6. Web application

Single-page app; pages:

- **Dashboard** - latest grade/score, finding counts, remediation progress, posture trend
  across scans; links to the full report and action plan.
- **New scan** - upload files or trigger a live collection; live job progress.
- **History** - all scans, grades, delete, and **scan-to-scan comparison** (resolved / new /
  persisting findings, score delta).
- **Attack Graph** - the interactive explorer (section 5).
- **Rules** - browse the full deterministic rule catalog (filter by category / severity /
  framework / type / engine) with per-scan behavior overlay (fired / silent / not-assessed).
- **AI Traces** - per-scan verbose trace of how each specialist/skeptic/correlator reasoned.
- **Settings** - see section 9.

### Reporting & export
- **Interactive HTML report** per scan (client-rendered, escalation-path visuals, framework
  pills, per-finding remediation).
- **PDF report** (WeasyPrint).
- **Shareable external report** - a leak-safe version for handing to another team (no internal
  tool names, no raw object ids/URLs).
- **CSV export** of findings.
- **Action plan / roadmap** view (prioritized remediation).

### Findings management
- Per-finding **status** (New / in-progress / Resolved / Risk Accepted) persisted per scan.
- Validation labels (section 4.3).

---

## 7. Azure DevOps integration (opt-in addon)

- Enabled and configured in Settings (org URL, project, work-item type - default **Feature**,
  area path, tags, default assignee, default parent **Epic**).
- Per-finding **"Create work item"** button (shown only when enabled and configured) that
  raises an ADO work item from the finding, optionally linked under a parent Epic and assigned
  to a free-text UPN/email; idempotent per finding.
- The **PAT is environment-only** (`PH_ADO_PAT`, Work Items: Read & Write); never written to
  disk or returned by any API. A connection test is available.

---

## 8. Authentication & authorization

(Full detail in `docs/PRD-auth.md`.)

- Single operator account; **default `admin` / `posturehound`** seeded on first boot (override
  with `PH_ADMIN_PASSWORD`), with a change-the-default banner and startup warning until rotated.
- **JWT (HS256)** validated on every request by a global guard; public paths are only the SPA
  shell, `/health`, the auth endpoints, and static assets.
- Password hashing PBKDF2-HMAC-SHA256 (600k iterations, per-password salt, constant-time
  verify); token delivered as an **httpOnly, SameSite=Strict** cookie (also closes CSRF /
  DNS-rebinding). Login throttled after repeated failures.
- Change username/password in Settings (current password required).

---

## 9. Settings & configuration

**Settings page:** Anthropic API key (memory-only unless in `.env`), minimum severity, the
Sonnet/Opus/skeptic model ids, AI connection test, Azure live-collection SP, Azure DevOps
integration, and the account/sign-in card.

**Environment variables:** `PH_DATA_DIR`, `ANTHROPIC_API_KEY`, `PH_ARG_TENANT_ID` /
`PH_ARG_CLIENT_ID` / `PH_ARG_CLIENT_SECRET`, `PH_ADO_PAT`, `PH_JWT_SECRET`,
`PH_AUTH_TTL_HOURS`, `PH_ADMIN_PASSWORD`, `PH_AUTH_DISABLED` (test/dev only),
`PH_MAX_UPLOAD_MB` / `PH_MAX_TOTAL_MB`, `PH_VALIDATION_SAMPLE`, `WORKERS`.

**Secrets policy:** the Anthropic key, ARG client secret, ADO PAT, and JWT secret are read
from the environment (or memory) and are **never** persisted to `settings.json` or returned by
any endpoint (only their presence is reported).

---

## 10. Command-line interface

- `posturehound scan <files…> [--format json|html] [--out FILE] [--min-severity …]` - assess a
  collection and emit findings (deterministic pipeline; AI when a key is present).
- `posturehound validate <files…>` - lint/parse a collection without assessing.
- Exit code reflects presence of Critical findings (CI-friendly).

---

## 11. Storage & data model

Everything lives under `PH_DATA_DIR` (default `~/.posturehound`): `scans/` (finalized
results + index), `raw_collections/` (immutable source, for re-assessment), `graphs/`
(per-scan snapshot + Kùzu db), `ai_cache/` and `narrative_cache/` (reproducibility),
`scan_traces/`, `settings.json`, `auth.json` (0600), `custom_tier0.json`,
`graph_saved_queries.json`. Findings are finalized/consolidated at a single read chokepoint so
the interactive list and the report always match.

---

## 12. Non-functional characteristics

- **Security of the tool itself:** read-only; localhost-only bind; strict CSP, `nosniff`,
  frame-deny, referrer/permissions policies, no-store; upload size caps; authenticated;
  secrets never persisted; the shareable report is leak-scrubbed.
- **Performance:** the built attack graph is cached per scan (invalidated by snapshot mtime +
  custom-Tier-0 state) and **warmed in the background** after a scan and on startup, so graph
  views open instantly; snapshots parse with orjson and slotted dataclasses; subscription-name
  and Tier-0-seed lookups are memoized; graph endpoints run off the event loop.
- **Determinism:** identical input → identical deterministic findings and (via caching)
  identical AI findings.
- **Reliability:** Docker `restart: unless-stopped`; best-effort error handling that never
  fails a scan on a non-critical sub-step; serve-time failures are logged, not swallowed.
- **Quality gate:** ~1,395 automated tests, including rule behavior, framework-coverage
  invariants, graph queries, the AI pipeline, ADO, auth, and performance-regression guards.

---

## 13. Deployment

- Docker Compose service on `127.0.0.1:31337`, `env_file: .env`, `PH_DATA_DIR=/data` mounted
  to `~/.posturehound`, single worker by default, auto-restart.
- Current tool version: **2.0.0**.

---

## 14. Out of scope / future work

- Multi-user accounts, roles/RBAC, SSO/OAuth, MFA/TOTP (auth is single-operator today).
- CI pipeline and packaging metadata (`pyproject.toml`) for the project itself.
- Scheduled/continuous collection and drift alerting.
- Additional cloud providers (PostureHound is Azure-only).
