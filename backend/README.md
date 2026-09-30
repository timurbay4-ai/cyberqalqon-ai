# Backend — CyberQalqon AI

**Owner:** Backend Developer / Codex Agent
**Stack:** Python · FastAPI · PostgreSQL (planned)

---

## Current State (Phase 1)

Phase 1 implements a single health-check endpoint only.
No business logic, authentication, or database is connected.

### Running the server

```bash
cd backend

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate          # Windows

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Available endpoints

| Method | Path      | Description             | Status      |
|--------|-----------|-------------------------|-------------|
| GET    | `/health` | Service health check    | ✅ Implemented |
| GET    | `/docs`   | Swagger UI              | ✅ Auto-generated |

---

## Planned (Phase 2+)

- `POST /api/v1/alerts/ingest` — Receive normalized alerts from Wazuh
- `GET /api/v1/incidents` — List incidents
- `GET /api/v1/incidents/{id}` — Incident detail
- `POST /api/v1/incidents/{id}/analyze` — Trigger AI analysis
- Database integration (PostgreSQL + SQLAlchemy)
- Authentication middleware

---

## Directory Structure

```
backend/
├── app/
│   ├── main.py          ← FastAPI application entry point
│   ├── api/routes/      ← Route handlers (future)
│   ├── core/            ← Config, security core (future)
│   ├── models/          ← ORM models (future)
│   ├── schemas/         ← Pydantic request/response schemas (future)
│   ├── services/        ← Business logic (future)
│   ├── detection/       ← Priority scoring engine (future)
│   ├── db/              ← Database session and migrations (future)
│   └── utils/           ← Shared utilities (future)
└── tests/               ← Unit tests (future)
```

---

## Shared Contracts

The backend must produce and consume alerts conforming to:
- `shared/schemas/normalized_alert.schema.json`
- `shared/schemas/ai_analysis.schema.json`
