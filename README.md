# CyberQalqon AI

**Privacy-first AI-assisted SOC investigation platform designed around open-source security tooling.**

> Phase 1 — Repository Foundation | Built in Uzbekistan

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
                                  │ NormalizedAlert (JSON)
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
Wazuh → NormalizedAlert → Backend → Incident → AI Engine → AIAnalysis → Frontend
```

---

## Repository Structure

```
cyberqalqon-ai/
├── backend/          ← FastAPI backend API (Backend Developer)
├── frontend/         ← SOC dashboard (Frontend Developer)
├── ai/               ← Local LLM AI engine (AI Developer — deferred)
├── wazuh/            ← Wazuh integration & rules (Security Lead)
├── shared/           ← Shared JSON schemas and example fixtures
├── tests/            ← Integration and end-to-end tests
├── infra/            ← Docker/Compose infrastructure
├── docs/             ← Architecture, API, security documentation
├── scripts/          ← Developer tooling scripts
└── .github/          ← CI/CD workflows and PR templates
```

See [`docs/TEAM_RESPONSIBILITIES.md`](docs/TEAM_RESPONSIBILITIES.md) for full ownership boundaries.

---

## Team Development Model

Three developers (or coding agents) can work **simultaneously and independently**:

| Role                        | Branch           | Directory         |
|-----------------------------|------------------|-------------------|
| Backend Developer / Codex   | `dev-backend`    | `backend/`        |
| Frontend Developer          | `dev-frontend`   | `frontend/`       |
| AI Engine Developer         | `dev-ai`         | `ai/`             |
| Security / Integration Lead | `dev-backend`\*  | `wazuh/`, `tests/`|

\* Security Lead coordinates with the Backend Developer. Merges go through Pull Requests to `main`.

See [`docs/GIT_WORKFLOW.md`](docs/GIT_WORKFLOW.md) for the full branching strategy.

---

## Current MVP Status

### ✅ DONE (Phase 1)

| Item                          | Details                                              |
|-------------------------------|------------------------------------------------------|
| Repository architecture       | Full directory skeleton with ownership boundaries    |
| Shared JSON schemas           | `normalized_alert.schema.json`, `ai_analysis.schema.json` |
| Example fixtures              | Alert example, 3 synthetic incidents                 |
| Backend health service        | `GET /health` → `{"status": "ok", "service": "cyberqalqon-backend"}` |
| Git workflow documentation    | Branch strategy, commit conventions, PR process      |
| Team responsibilities map     | Directory ownership clearly defined                  |
| Security baseline             | `.gitignore`, `.env.example`, no secrets committed   |
| Contributing guide            | Branch, commit, review, ownership rules              |

### 🚧 IN PROGRESS

*(Nothing currently in progress — awaiting Phase 2 kickoff)*

### 📋 PLANNED

| Component                  | Phase | Owner                    |
|----------------------------|-------|--------------------------|
| Wazuh agent integration    | 2     | Security Lead            |
| Alert ingestion API        | 2     | Backend Developer        |
| PostgreSQL + SQLAlchemy    | 2     | Backend Developer        |
| Incident management API    | 2     | Backend Developer        |
| Priority scoring engine    | 2     | Backend Developer        |
| Frontend dashboard         | 2     | Frontend Developer       |
| Incident pages (UI)        | 2     | Frontend Developer       |
| Local LLM client (Ollama)  | 3     | AI Developer             |
| Prompt engineering         | 3     | AI Developer             |
| Uzbek/Russian summaries    | 3     | AI Developer             |
| MITRE ATT&CK enrichment    | 3     | Security Lead            |
| Docker Compose stack       | 3     | DevOps / Lead            |
| End-to-end tests           | 4     | All                      |

---

## Planned Components

### Wazuh (Security Event Ingestion)
- Custom rules mapped to MITRE ATT&CK techniques
- Integration script forwarding normalized events to the backend API

### Backend API
- Alert normalization and deduplication
- Incident management with lifecycle states
- Investigation priority scoring (rule level + MITRE severity + context)
- Adapter for receiving Wazuh integration webhook events

### AI Engine (Privacy-First, Local Only)
- Runs entirely on local hardware — no external API calls
- Ollama-based LLM client (model TBD based on Uzbek/Russian capability)
- Structured JSON output validated against `ai_analysis.schema.json`
- Graceful fallback when LLM is unavailable or returns invalid output

### Frontend Dashboard
- Incident list with priority sorting and filtering
- Incident detail view with AI analysis and MITRE ATT&CK context
- Alert explorer for raw event investigation

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
- Node.js 20+ (for frontend, when implemented)
- Git 2.x

### Backend Quick Start

```bash
cd backend
python -m venv .venv
source .venv/bin/activate    # Linux/macOS
.venv\Scripts\activate       # Windows

pip install -r requirements.txt
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
git clone https://github.com/<org>/cyberqalqon-ai.git
cd cyberqalqon-ai
cp .env.example .env

git checkout dev-backend    # Backend Developer
git checkout dev-frontend   # Frontend Developer
git checkout dev-ai         # AI Developer
```

---

## Roadmap

| Phase | Milestone                           | Target          |
|-------|-------------------------------------|-----------------|
| 1     | Repository foundation ✅            | Done            |
| 2     | Backend API + Wazuh integration     | TBD             |
| 3     | AI engine + Frontend dashboard      | TBD             |
| 4     | Integration tests + Polish          | TBD             |
| 5     | Production deployment               | TBD             |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch workflow, commit conventions, ownership rules, and the secrets policy.

---

*CyberQalqon AI — Built for privacy-conscious security teams.*
