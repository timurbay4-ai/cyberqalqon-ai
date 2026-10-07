# CyberQalqon AI

**Privacy-first AI-assisted SOC investigation platform designed around open-source security tooling.**

> Early MVP — Reliable Wazuh delivery, SOC ingestion, and deterministic incident workflow | Built in Uzbekistan

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
                   │  Incident Management · Scoring    │
                   └──────────┬───────────────────────┘
                              │           │
                 AIAnalysis   │           │  Incidents / Alerts
                              ▼           ▼
              ┌─────────────────────┐  ┌─────────────────────────┐
              │    AI Engine        │  │   Frontend Dashboard     │
              │  (Local LLM Only)   │  │  SOC Analyst Interface   │
              │  Uzbek · Russian    │  │  (Browser-based)         │
              └─────────────────────┘  └─────────────────────────┘
```

### Data Flow

```
Wazuh → durable sender → authenticated ingestion → normalization → SQLite → alert APIs → SOC workflow
```

---

## Repository Structure

```
cyberqalqon-ai/
├── backend/          ← FastAPI API, migrations, and persistence
├── frontend/         ← React/Vite SOC application
├── ai/               ← Local AI provider and safety boundary (deferred)
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
| Backend test suite            | Ingestion, contracts, migrations, reads, validation, and security boundaries |
| Git workflow documentation    | Branch strategy, commit conventions, PR process      |
| Team responsibilities map     | Directory ownership clearly defined                  |
| Security baseline             | `.gitignore`, `.env.example`, no secrets committed   |
| Contributing guide            | Branch, commit, review, ownership rules              |

### 📋 PLANNED

| Component                         | Phase | Owner                    |
|-----------------------------------|-------|--------------------------|
| Real Wazuh staging verification   | 6     | Lead development agent   |
| MITRE catalog enrichment          | 6     | Lead development agent   |
| Local Ollama analyst              | 6     | Lead development agent   |
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
- Runs entirely on local hardware — no external API calls
- Ollama-based LLM client (model TBD based on Uzbek/Russian capability)
- Structured JSON output validated against `ai_analysis.schema.json`
- Graceful fallback when LLM is unavailable or returns invalid output

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
5. **Audit Trail** — All incidents and AI analyses are stored with timestamps and context

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
| 6     | Wazuh staging, MITRE catalog, bounded local AI | Next            |
| 7     | Reproducible production deployment            | Planned         |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch workflow, commit conventions, ownership rules, and the secrets policy.

---

*CyberQalqon AI — Built for privacy-conscious security teams.*
