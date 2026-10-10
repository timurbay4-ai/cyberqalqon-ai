# Analyst Authentication API

Human authentication is independent from the Wazuh `X-API-Key` ingestion boundary.

## Roles

| Role | SOC reads | Incident mutations | Analyst administration |
|---|---:|---:|---:|
| `VIEWER` | yes | no | no |
| `ANALYST` | yes | yes | no |
| `ADMIN` | yes | yes | yes |

FastAPI enforces every permission. Frontend role checks only hide unavailable controls.

## Bootstrap

From `backend`, after configuring `DATABASE_URL`:

```powershell
.venv\Scripts\python.exe -m app.cli.bootstrap_analyst `
  --username soc-admin `
  --display-name "SOC Administrator"
```

The password is prompted without echo and stored only as an Argon2id hash. There is no default
account or password. The command refuses every attempt after the first analyst exists.

## Session endpoints

| Method | Path | Access |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Public credentials plus trusted `Origin` |
| `GET` | `/api/v1/auth/session` | Authenticated session |
| `POST` | `/api/v1/auth/logout` | Authenticated session plus CSRF |
| `GET` | `/api/v1/auth/sessions` | Current authenticated analyst |
| `POST` | `/api/v1/auth/sessions/revoke-others` | Current analyst plus CSRF |
| `PATCH` | `/api/v1/auth/password` | Current analyst plus CSRF and current password |
| `GET` | `/api/v1/auth/analysts` | `ADMIN` |
| `POST` | `/api/v1/auth/analysts` | `ADMIN` plus CSRF |
| `PATCH` | `/api/v1/auth/analysts/{analyst_id}` | `ADMIN` plus CSRF |

Login returns the current analyst and a per-session CSRF value while setting an opaque HttpOnly,
SameSite=Strict cookie. Only the cookie's SHA-256 digest is stored. Sessions expire server-side,
logout deletes the row, inactive accounts cannot resolve existing sessions, and active sessions are
capped at ten per analyst.

Password change verifies the current password, writes a new Argon2id hash, and revokes every other
session atomically. It does not reveal hashes and does not reset another account. Authentication
success/denial, logout, password changes, session revocation, and analyst administration emit
bounded security-audit events without credentials or session tokens.

State-changing requests require `X-CSRF-Token` and an exact allowed `Origin`. Production must use
HTTPS with `SESSION_COOKIE_SECURE=true`. Credentials and session identifiers must never appear in
URLs, logs, `VITE_*` variables, or browser storage.
