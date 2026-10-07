# CyberQalqon AI

**Privacy-first AI-assisted SOC investigation platform designed around open-source security tooling.**

> Early MVP — Deterministic SOC workflow with a secure local advisory AI analyst | Built in Uzbekistan

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
| Wazuh alert ingestion         | Authenticated raw JSON ingestion with deterministic normalization |
| Reliable Wazuh delivery       | Enqueue-first sender, bounded SQLite retry spool, dead letters, CLI, and systemd/Wazuh entrypoints |
| SQLite persistence            | Raw + normalized retention and idempotent duplicate handling |
| Versioned migrations          | Transactional upgrades with legacy-row preservation and drift checks |
| Alert read APIs               | Typed list/detail responses, filtering, search, and cursor pagination |
| Incident management API       | Lifecycle, alert links, notes, assignment, audit, and cursor pagination |
| SOC frontend                  | Live dashboard, alert investigation, and incident workflow |
| Analyst security boundary     | Argon2id accounts, server sessions, CSRF, roles, verified audit actors |
| Local AI analyst              | Ollama provider, bounded server context, structured validation, provenance, history, and safe UI |
| Backend test suite            | Ingestion, contracts, migrations, reads, validation, and security boundaries |
| Git workflow documentation    | Branch strategy, commit conventions, PR process      |
| Team responsibilities map     | Directory ownership clearly defined                  |
| Security baseline             | `.gitignore`, `.env.example`, no secrets committed   |
| Contributing guide            | Branch, commit, review, ownership rules              |

### 📋 PLANNED

| Component                         | Phase | Owner                    |
|-----------------------------------|-------|--------------------------|
| Real Wazuh staging verification   | 7     | Lead development agent   |
| MITRE catalog enrichment          | Future | Lead development agent  |
| Reproducible deployment stack     | 7     | Lead development agent   |
| Full product deployment E2E       | 7     | Lead development agent   |

---

## Planned Components

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
- Live operational totals backed by alert and incident APIs
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
- Git 2.x

### Backend Quick Start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Health check:
```bash
curl http://localhost:8000/health
# {"status":"ok","service":"cyberqalqon-backend"}
```

API docs: http://localhost:8000/docs

### Branch Setup

```bash
git clone https://github.com/timurbay4-ai/cyberqalqon-ai.git
cd cyberqalqon-ai
cp .env.example .env

git checkout dev/cyberqalqon
```

---

## Roadmap

| Phase | Milestone                                      | Target          |
|-------|------------------------------------------------|-----------------|
| 1–4   | SOC platform foundation ✅                     | Done            |
| 5     | Reliable Wazuh alert delivery ✅               | Done            |
| 6     | Secure bounded local Ollama analyst ✅          | Done            |
| 7     | Reproducible production deployment            | Planned         |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch workflow, commit conventions, ownership rules, and the secrets policy.

---

*CyberQalqon AI — Built for privacy-conscious security teams.*
