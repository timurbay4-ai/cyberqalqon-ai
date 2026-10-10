# Backend — CyberQalqon AI

**Stack:** Python 3.11 · FastAPI · Pydantic · SQLite

## Implemented capabilities

- `GET /health`
- `GET /readiness` for DB/migration readiness without sensitive details
- `POST /api/v1/alerts/ingest` with an `X-API-Key` machine credential
- Deterministic Wazuh normalization and strict validation
- Idempotent persistence with alert-ID conflict detection
- Transactional, versioned SQLite migrations
- `GET /api/v1/alerts` with filtering and opaque cursor pagination
- `GET /api/v1/alerts/{alert_id}`
- Deterministic incident lifecycle, alert links, notes, assignment, and audit history
- Typed incident create/list/detail/status/link/note/assignment APIs
- Argon2id analyst credentials, opaque server-side sessions, CSRF protection, and enforced roles
- Operator-controlled first-administrator bootstrap with no default credentials
- Saved event searches, security audit, password change, and session revocation
- Bounded SIEM Overview, Discover, inventory, rule catalog, and filtered JSON/CSV reports
- Secure local Ollama analyst with bounded server-selected context, strict output validation,
  provenance/history, concurrency control, and stale detection

Automatic incident correlation remains intentionally out of scope. The AI path is advisory only and
cannot mutate incidents or execute tools. See [`../docs/AI_ANALYST.md`](../docs/AI_ANALYST.md).

## Run locally

From the repository root:

```powershell
Copy-Item .env.example .env
# Replace WAZUH_INGEST_API_KEY in .env with a strong random value.

Set-Location backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
pytest -q
python -m app.cli.bootstrap_analyst --username soc-admin --display-name "SOC Administrator"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The bootstrap command prompts twice without echoing the password. For controlled automation,
`--password-stdin` reads one line from standard input; never place a password in command arguments,
environment examples, or Git. Bootstrap succeeds only while the analyst table is empty.

API documentation is available at `http://127.0.0.1:8000/docs`.

## Alert reads

`GET /api/v1/alerts` supports:

| Parameter | Behavior |
|---|---|
| `rule_level` | Repeatable Wazuh level, 0–16; values use OR semantics |
| `agent` | Case-insensitive exact agent ID or name |
| `mitre_mapped` | Filter by presence or absence of upstream MITRE IDs |
| `mitre_id` | Exact validated ATT&CK technique ID |
| `start_time`, `end_time` | Inclusive ISO 8601 bounds with a UTC offset |
| `search` | Literal case-insensitive search across normalized alert fields |
| `limit` | Page size, 1–100; default 50 |
| `cursor` | Opaque keyset cursor returned by the previous page |

Results are ordered by normalized UTC occurrence time descending, then alert ID descending.
The response shape is:

```json
{
  "items": [],
  "page": {
    "limit": 50,
    "next_cursor": null,
    "total": 0
  }
}
```

Read endpoints require a valid human analyst session. The ingestion key is a separate machine-only
credential and is never accepted as a human session.

## Incident APIs

The incident contract is documented in [`../docs/api/INCIDENTS.md`](../docs/api/INCIDENTS.md).
Incident writes derive their audit actor from the authenticated backend principal. Public mutation
schemas contain no `actor` field. `VIEWER` can read; `ANALYST` and `ADMIN` can mutate incidents.

Incident list results use opaque keyset pagination and can be filtered by repeatable `status`,
repeatable `severity`, and case-insensitive exact `assigned_to`. Alert relationships store alert IDs
under foreign-key constraints; alert payloads are not duplicated. Post-ingest automatic correlation
is bounded, deterministic, and documented in
[`../docs/CORRELATION_ENGINE.md`](../docs/CORRELATION_ENGINE.md).

## SQLite migrations

Startup applies pending migrations from `app/db/migrations.py` in individual transactions and
records them in `schema_migrations` plus SQLite `user_version`.

- Migration 1 recognizes or creates the original ingestion table.
- Migration 2 preserves existing rows, normalizes stored occurrence timestamps to UTC, backfills
  deterministic query fields, and adds read indexes.
- Migration 3 adds incidents, alert links, append-only notes, lifecycle state, assignments, and
  ordered audit history without changing existing alert rows.
- Migration 4 adds analysts, digest-only server sessions, authentication indexes, and nullable
  stable analyst identifiers on existing note/history tables without rewriting prior audit text.
- Migration 5 adds append-only validated AI analysis provenance and indexed target history without
  rewriting alerts, incidents, authentication data, or incident audit history.
- Migration 6 adds lifecycle-safe automatic correlation metadata, unique automatic alert
  membership, and bounded candidate indexes without rewriting existing alerts or incidents.
- Migration 7 replaces the candidate index ordering with an agent/time/order layout selected by
  SQLite for bounded correlation lookups.
- Migration 8 adds the normalized security-event store, retention state, compound indexes, and FTS5.
- Migration 9 adds analyst-owned saved searches, bounded security audit, retention telemetry, and
  v0.2 exact-filter indexes without rewriting alerts, incidents, accounts, or event rows.
- Unknown future versions, inconsistent migration history, incompatible legacy schemas, or invalid
  stored normalized alerts stop startup. No database is dropped or silently rebuilt.

Back up a production database before deploying any migration, even though migrations are designed
to be non-destructive.

## Ingest the sanitized sample

```powershell
$headers = @{ 'X-API-Key' = '<the value from WAZUH_INGEST_API_KEY>' }
$body = Get-Content -Raw ..\wazuh\samples\authentication-failure.json
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/alerts/ingest `
  -Headers $headers `
  -ContentType 'application/json' `
  -Body $body
```

An initial request returns `201 Created`; an identical replay returns `200 OK` with
`"duplicate": true`.

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | File-backed SQLite URL; migrations currently reach schema v12 | `sqlite:///./backend/data/cyberqalqon.db` |
| `WAZUH_INGEST_API_KEY` | Shared secret for the ingest endpoint | unset; ingestion disabled |
| `MAX_INGEST_BYTES` | Maximum raw request size | `1048576` |
| `CORRELATION_ENABLED` | Run deterministic correlation after a new alert is stored | `true` |
| `CORRELATION_WINDOW_SECONDS` | Bounded evidence window | `900` |
| `CORRELATION_MAX_CANDIDATES` | Maximum candidate rows inspected per new alert | `200` |
| `CORRELATION_MAX_LINKS` | Maximum alert links in one correlation plan | `50` |
| `CORRELATION_RETRY_ATTEMPTS` | Retry count for SQLite busy failures | `1` |
| `CORS_ORIGINS` | Comma-separated explicit browser origins | Vite and legacy localhost origins |
| `ANALYST_SESSION_TTL_SECONDS` | Absolute server-side session lifetime | `28800` (8 hours) |
| `SESSION_COOKIE_SECURE` | Require HTTPS delivery for the analyst cookie | false in development; true otherwise |
| `LOGIN_MAX_FAILURES` | Failed passwords before temporary account lock | `5` |
| `LOGIN_LOCKOUT_SECONDS` | Temporary account lock duration | `900` |

All AI variables and defaults are documented in [`../docs/AI_ANALYST.md`](../docs/AI_ANALYST.md).

Production may provide the ingestion key through the mutually exclusive
`WAZUH_INGEST_API_KEY_FILE` setting. This is used by the Compose secret mount and
keeps the key out of image and environment metadata.

## Production backup and restore

Use `python -m app.cli.backup create --output-dir PATH` for a verified online
SQLite backup and `python -m app.cli.backup verify BACKUP` before retention or
restore. Restore is offline-only through `python -m app.cli.restore ...
--confirm-restore`; it preserves the current DB, migrates the restored snapshot,
and invalidates restored sessions. See
[`../docs/BACKUP_RESTORE.md`](../docs/BACKUP_RESTORE.md).

## Human authentication boundary

- `POST /api/v1/auth/login` establishes an HttpOnly, SameSite=Strict session cookie.
- `GET /api/v1/auth/session` validates the cookie and restores the current analyst plus CSRF token.
- `POST /api/v1/auth/logout` invalidates the server session.
- `ADMIN` may list, create, and update analysts under `/api/v1/auth/analysts`.
- Every analyst may change their password and revoke other sessions; the current session remains
  valid after password change while every other session is revoked.
- `ADMIN` may read the bounded security audit under `/api/v1/audit-events`.
- Every cookie-authenticated mutation requires both an allowed `Origin` and `X-CSRF-Token`.
- Session identifiers contain 256 bits of randomness; only SHA-256 digests are stored in SQLite.
- Active sessions are capped at ten per analyst; expired and excess rows are removed on login.
- Five consecutive invalid passwords lock the account for 15 minutes by default. Unknown usernames
  receive the same public error and execute a dummy Argon2id verification.

See [`../docs/api/AUTH.md`](../docs/api/AUTH.md) for the endpoint and role matrix.

All event fields are untrusted data. SQL inputs are parameterized, API errors avoid raw database
details, and only normalized fields—not raw event payloads—are returned by read endpoints.
