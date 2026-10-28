> Publication review scope and independent gates: [candidate guide](docs/release/PUBLICATION_CANDIDATE.md).

# CyberQalqon AI

**Privacy-first SOC investigation platform designed around open-source security tooling.**

> M36 source consolidation candidate (M1–M35 preserved). This working tree is
> source-tested, not a production release. Evidence and independent gates:
> M36 validation (local-only historical reference: `docs/release/M36_VALIDATION.md`).

The consolidated platform includes CUSE normalization, bounded CQQL/FTS5 search,
shadow detections and finding history, cases and Investigation Workbench, and a
Go JSONL collector restricted to disposable synthetic Zeek/Suricata inputs.
Python 3.11, Go 1.27.0 and Node 24 are the development toolchains. See
source reconstruction (local-only historical reference: `docs/release/M36_BUILD_REPRODUCIBILITY.md`) for clean builds
and [the collector guide](collector/README.md) for its safety boundaries.

AI remains disabled; DET-001–DET-009 remain disabled/shadow-only. Historical
collection continuity is UNPROVEN. Performance acceptance, strict SAST disposition,
authenticated browser UAT, live telemetry and Git publication have separate gates.
No live activation follows from a source build or a passing test suite.

> v1.0 development line from the v0.9.1 baseline — deterministic SOC workflow; optional local
> advisory AI remains disabled | Built in Uzbekistan

---

## Project Vision

CyberQalqon AI enables Security Operations Center (SOC) analysts to investigate security incidents faster and more effectively using a locally hosted AI assistant that understands the Uzbek and Russian languages.

The platform ingests security events from Wazuh, normalizes and correlates them into incidents, maps them to the MITRE ATT&CK framework, scores investigation priority, and passes structured context to a local LLM that generates analyst-ready summaries and recommendations — all without sending data to external cloud services.

---

## Architecture

```
                   ┌──────────────────────────────────┐
                   │           Wazuh Manager           │
                   │  (Security Event Detection SIEM)  │
                   └──────────────┬───────────────────┘
                                  │ Raw Wazuh alert (JSON)
                                  ▼
                   ┌──────────────────────────────────┐
                   │ Durable CyberQalqon Sender        │
                   │ Queue · Retry · Dead Letter       │
                   └──────────────┬───────────────────┘
                                  │ Authenticated at-least-once delivery
                                  ▼
                   ┌──────────────────────────────────┐
                   │        Backend API (FastAPI)      │
                   │  Alert Ingestion · Normalization  │
                   │  Incidents · Auth · AI Boundary   │
                   └──────────┬───────────────────────┘
                              │           │
                              │           │  Incidents / Alerts
                              ▼           ▼
              ┌─────────────────────┐  ┌─────────────────────────┐
              │ Local Ollama        │  │   Frontend Dashboard     │
              │ bounded + validated │  │  Human decision boundary │
              │ advisory output     │  │  (Browser-based)         │
              └─────────────────────┘  └─────────────────────────┘
```

### Data Flow

```
Wazuh → durable sender → authenticated ingestion → normalization → SQLite → alerts/incidents → human session → explicit AI request → bounded context → local Ollama → validated advisory result → human decision
```

---

## Repository Structure

```
cyberqalqon-ai/
├── backend/          ← FastAPI API, migrations, and persistence
├── frontend/         ← React/Vite SOC application
├── collector/        ← Go synthetic JSONL collector, spool and checkpoint tests
├── ai/               ← Local AI operator documentation (implementation is backend-owned)
├── wazuh/            ← Wazuh delivery integration and rules
├── shared/           ← Shared JSON schemas and example fixtures
├── tests/            ← Integration and end-to-end tests
├── infra/            ← Docker/Compose infrastructure
├── docs/             ← Architecture, API, security documentation
├── scripts/          ← Developer tooling scripts
└── .github/          ← CI/CD workflows and PR templates
```

See [`docs/TEAM_RESPONSIBILITIES.md`](docs/TEAM_RESPONSIBILITIES.md) for current responsibility rules.

---

## Development Model

One lead development agent currently owns integration across the full repository. Work proceeds in
small dependency-ordered milestones on `dev/cyberqalqon`; `main` remains the stable PR target.
Shared contracts still require deliberate compatibility review before they change.

See [`docs/GIT_WORKFLOW.md`](docs/GIT_WORKFLOW.md) for the full branching strategy.

---

## Current MVP Status

### ✅ IMPLEMENTED

| Item                          | Details                                              |
|-------------------------------|------------------------------------------------------|
| Repository architecture       | Full directory skeleton with ownership boundaries    |
| Shared JSON schemas           | `normalized_alert.schema.json`, `ai_analysis.schema.json` |
| Example fixtures              | Alert example, 3 synthetic incidents                 |
| Backend health service        | `GET /health` → `{"status": "ok", "service": "cyberqalqon-backend"}` |
| Readiness endpoint            | DB/migration-aware `GET /readiness` without sensitive diagnostics |
| Wazuh alert ingestion         | Authenticated raw JSON ingestion with deterministic normalization |
| Reliable Wazuh delivery       | Enqueue-first sender, bounded SQLite retry spool, dead letters, CLI, and systemd/Wazuh entrypoints |
| SQLite persistence            | Raw + normalized retention and idempotent duplicate handling |
| SIEM event store              | Bounded Wazuh archive ingestion, schema-17 live compatibility, endpoint context, redaction, dedupe, hard-cap retention, indexes, FTS5, and saved searches; schema 18 remains approval-gated |
| SIEM investigation workspace  | Overview, Discover, hunting, linked evidence, hosts/sources, detection engineering, IOC intelligence, reports, and Administration |
| Detection engineering        | Consolidated Wazuh/M9 inventory, truthful MITRE coverage, local drafts, bounded dry-run, versions, audit, and deterministic quality analytics |
| Versioned migrations          | Transactional upgrades with legacy-row preservation and drift checks |
| Alert read APIs               | Typed list/detail responses, filtering, search, and cursor pagination |
| Incident management API       | Lifecycle, alert links, notes, assignment, audit, and cursor pagination |
| SOC case management API       | Explicit cases, collaboration, SHA-256 evidence manifests, safe playbooks, SLA, analytics, JSON/CSV/PDF reports |
| Incident correlation engine   | Deterministic scoped rules, atomic auto-linking, explainable metadata, and timeline UI |
| SOC frontend                  | Live dashboard, alert/incident investigation, durable case workflow, evidence, playbooks, and reporting |
| Analyst security boundary     | Argon2id accounts, server sessions, CSRF, roles, verified audit actors |
| Local AI analyst              | Ollama provider, bounded server context, structured validation, provenance, history, and safe UI; disabled by default and in the current lab |
| Deployment foundation         | Non-root images, HTTPS reverse proxy, same-origin UI/API, private services, persistent volumes; external acceptance gates remain |
| Backup and recovery           | Online verified SQLite backup, deliberate restore, safety copy, session invalidation |
| Backend test suite            | Ingestion, contracts, migrations, reads, validation, and security boundaries |
| Git workflow documentation    | Branch strategy, commit conventions, PR process      |
| Team responsibilities map     | Directory ownership clearly defined                  |
| Security baseline             | `.gitignore`, `.env.example`, no secrets committed   |
| Contributing guide            | Branch, commit, review, ownership rules              |

### Current operational acceptance

This repository is an engineering snapshot, not a claim of full production readiness. The
consolidated M1–M35 source and disposable-test evidence must be interpreted with these live gates:

- Historical archive continuity remains `UNPROVEN`; the legacy inode/rotated-generation mismatch
  is unresolved. Preserved unread data requires a separately approved reconciliation procedure.
- DET-001–DET-009 remain `DISABLED_BY_POLICY` / `SHADOW_ONLY`, `AI_ENABLED=false`, and historical
  replay is not active.
- Last reported live source schema was 17; M36 does not freshly attest the live database.
  Application startup targets 17 unless the existing schema-18 opt-in is explicitly enabled.
- Production batch ingestion is disabled; the approved path remains conservative single-event
  ingestion.
- M23 Operations live cold-query acceptance did not pass. M24 performance improvements pass
  disposable tests but have not been deployed or verified in the live runtime.
- Forward-ingestion approval and the current source generation/checkpoint must be revalidated
  before any activation or renewal; an expired approval must never be bypassed.
- Chrome/Edge browser UAT is `DEFERRED_BY_USER` and is not implied by component or build results.

Current source tests and independent release gates are in
`docs/release/M36_VALIDATION.md` (local-only historical reference: `docs/release/M36_VALIDATION.md`). Historical context is in
[`docs/siem/KNOWN_LIMITATIONS.md`](docs/siem/KNOWN_LIMITATIONS.md) and
`docs/siem/M24_VALIDATION.md` (local-only historical reference: `docs/siem/M24_VALIDATION.md`) for detailed evidence and constraints.

### 📋 PLANNED

| Component                         | Phase | Owner                    |
|-----------------------------------|-------|--------------------------|
| Real Wazuh staging verification   | 7     | Lead development agent   |
| MITRE catalog enrichment          | Future | Lead development agent  |
| Reproducible deployment stack     | 7     | Implemented; external acceptance pending |
| Full product deployment E2E       | 7     | Deterministic CI path implemented |

---

## Implemented Components and Deployment Boundaries

### Wazuh (Security Event Ingestion)
- Custom rules mapped to MITRE ATT&CK techniques
- Wazuh Integrator entrypoint commits raw JSON to a bounded sender spool before HTTP delivery
- Restartable retry worker provides exponential backoff, dead letters, status, and manual replay
- Deployment and operational procedures are in [`wazuh/docs/DEPLOYMENT.md`](wazuh/docs/DEPLOYMENT.md)

### Backend API
- Alert normalization, deduplication, versioned migrations, and query APIs
- Incident management with lifecycle states
- Human analyst sessions with enforced read/write/admin roles
- Investigation priority scoring (rule level + MITRE severity + context)
- Deterministic incident correlation and lifecycle management

### AI Engine (Privacy-First, Local Only)
- Ollama-only HTTP provider with a configurable operator-installed model
- Server-selected bounded context and explicit untrusted-telemetry separation
- Strict `ai-analysis-v1` validation, provenance, fingerprints, history, and staleness
- Graceful unavailable/error states with no fake or cloud fallback
- Advisory text only: no tools, commands, remediation, or incident mutation

### Frontend Dashboard
- Live operational totals backed by event, alert, incident, and source aggregation APIs
- Discover explorer with time presets, server filters, keyset pagination, and safe JSON evidence
- Host/source inventory, detection engineering, local IOC intelligence, and bounded report export
- Dedicated bounded threat hunting with saved queries and alert/incident evidence relationships
- Alert explorer with server-side filtering, pagination, detail, and MITRE context
- Incident lifecycle, alert links, notes, assignment, and audit history
- Backend-validated login/logout and role-aware mutation controls

---

## Security Principles

1. **Privacy by Design** — No security event data leaves the local network
2. **Local LLM Only** — AI inference runs on-premises
3. **No Secrets in Git** — `.env` is always git-ignored; only `.env.example` is committed
4. **Least Privilege** — Each module communicates through defined contracts only
5. **Audit Trail** — Incident state and validated AI analyses have separate provenance histories
6. **Advisory AI** — AI output never becomes identity, authorization, SOC state, or an executed action

---

## Development

### Prerequisites

- Python 3.11+
- Node.js 24+ (frontend CI/runtime baseline)
- Go 1.27.0 (synthetic collector builds and real TCP integration tests)
- Git 2.x

### Backend Quick Start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"cyberqalqon-backend"}
```

API docs: http://localhost:8000/docs

### Local Windows monitoring lab

The M10 Windows monitoring design, supported enrollment handoff, exact EventChannel filters,
built-in detection matrix, and safe test evidence are documented in:

- `docs/M10_WINDOWS_MONITORING_VALIDATION.md` (local-only historical reference: `docs/M10_WINDOWS_MONITORING_VALIDATION.md`)
- [`docs/windows/WINDOWS_AGENT_CONNECTIVITY.md`](docs/windows/WINDOWS_AGENT_CONNECTIVITY.md)
- [`docs/windows/WINDOWS_EVENT_COLLECTION.md`](docs/windows/WINDOWS_EVENT_COLLECTION.md)
- [`docs/windows/WINDOWS_DETECTION_COVERAGE.md`](docs/windows/WINDOWS_DETECTION_COVERAGE.md)
- [`docs/windows/WINDOWS_SAFE_TESTS.md`](docs/windows/WINDOWS_SAFE_TESTS.md)

### Production

The supported single-node production foundation uses Docker Compose, an
unprivileged TLS Nginx/React image, a non-root one-worker FastAPI image, a
persistent SQLite volume, protected runtime secrets, and optional private
Ollama. Start with:

- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- [`docs/BACKUP_RESTORE.md`](docs/BACKUP_RESTORE.md)
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md)

Do not deploy directly from `.env.production.example`; copy it to the ignored
`.env.production`, replace deployment values, supply trusted TLS material, and
complete the production checklist.

### Branch Setup

```bash
git clone https://github.com/timurbay4-ai/cyberqalqon-ai.git
cd cyberqalqon-ai
cp .env.example .env

git checkout dev/cyberqalqon
```

---

## Roadmap

The active v1.0 milestone plan and evidence checklist are:

- [`docs/roadmap/CYBERQALQON_V1_DEVELOPMENT_PLAN.md`](docs/roadmap/CYBERQALQON_V1_DEVELOPMENT_PLAN.md)
- [`docs/roadmap/CYBERQALQON_V1_CHECKLIST.md`](docs/roadmap/CYBERQALQON_V1_CHECKLIST.md)

| Phase | Milestone                                      | Target          |
|-------|------------------------------------------------|-----------------|
| 1–4   | SOC platform foundation ✅                     | Done            |
| 5     | Reliable Wazuh alert delivery ✅               | Done            |
| 6     | Secure bounded local Ollama analyst ✅          | Done            |
| 7     | Reproducible production deployment ✅          | Implemented; external gates remain |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch workflow, commit conventions, ownership rules, and the secrets policy.

For the v0.8 release-candidate evidence and operator handoff, see:

- [`docs/release/RELEASE_NOTES_V08.md`](docs/release/RELEASE_NOTES_V08.md)
- [`docs/release/RELEASE_GUIDE_V08.md`](docs/release/RELEASE_GUIDE_V08.md)
- [`docs/release/BROWSER_UAT_V08.md`](docs/release/BROWSER_UAT_V08.md)
- [`docs/release/GIT_STAGING_V08.md`](docs/release/GIT_STAGING_V08.md)
- [`docs/release/SIEM_V08_VALIDATION.md`](docs/release/SIEM_V08_VALIDATION.md)

---

*CyberQalqon AI — Built for privacy-conscious security teams.*
