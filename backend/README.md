# CyberQalqon AI Backend

The Phase 2 backend receives untrusted Wazuh JSON, normalizes and stores security evidence, assigns a deterministic Investigation Priority Score, and supports incident review. It does not perform AI analysis or automated response.

## Architecture

- FastAPI routes provide the versioned contract.
- Pydantic v2 validates API data and normalized fields.
- Services coordinate normalization, scoring, persistence, and review history.
- SQLAlchemy 2 repositories isolate database queries.
- SQLite is the MVP database; models and queries avoid SQLite-specific SQL where practical.
- `AIAnalyzer` is represented by a no-op implementation whose status is always `not_configured`.

## Setup and run

Python 3.11 or newer is required.

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Linux/macOS activation is `source .venv/bin/activate`. Interactive documentation is available at `http://127.0.0.1:8000/docs`.

Run tests:

```powershell
python -m pytest -q
```

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Environment label |
| `DATABASE_URL` | `sqlite:///./cyberqalqon.db` | SQLAlchemy database URL |
| `LOG_LEVEL` | `INFO` | Application log level |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed browser origins |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Maximum HTTP request body size |

The default SQLite file is `backend/cyberqalqon.db` when Uvicorn is started from `backend/`. No `.env` file is required. Environment variables can be supplied directly by the shell or deployment platform.

## API overview

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Process liveness |
| GET | `/ready` | Database readiness |
| POST | `/api/v1/ingest/wazuh` | Normalize and persist one raw Wazuh alert |
| GET | `/api/v1/incidents` | Paginated and filtered incidents |
| GET | `/api/v1/incidents/{id}` | Incident detail and evidence |
| POST | `/api/v1/incidents/{id}/review` | Append analyst review history |

See `docs/api/BACKEND_API.md` for the full contract.

## Investigation Priority Score

The score is deterministic and ranges from 0 to 100. It is not an attack probability, malicious probability, or AI confidence score.

```text
rule_component       = round(clamp(rule_level, 0, 15) / 15 * 70)
repetition_component = min(max(repetition_count - 1, 0) * 5, 20)
asset_component      = low: 0, normal: 3, high: 7, critical: 10
score                = clamp(rule_component + repetition_component + asset_component, 0, 100)
```

Asset importance defaults to `normal`. Phase 2 exact-delivery deduplication does not increase repetition count. Severity display categories are `low` (0–3), `medium` (4–7), `high` (8–11), and `critical` (12–15).

## Deduplication and AI status

If Wazuh supplies `id`, its hash is the idempotency key. Otherwise, a canonical hash of the complete raw JSON object is used. The first POST returns `201`; an exact retry returns `200`, the existing incident, and creates no new row.

Every incident exposes `ai_status: "not_configured"`. No model, local LLM, remote AI API, or synthetic AI result is used.

## Security baseline

The body is restricted to a JSON object and one MiB by default. Extracted strings and lists have bounds, SQL is parameterized through SQLAlchemy, raw evidence is stored as JSON but never executed, and ordinary API failures use sanitized error envelopes. Authentication and authorization are not part of Phase 2 and must be added before exposure outside a trusted network.
