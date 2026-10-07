# CyberQalqon AI Frontend

React, TypeScript, and Vite SOC workspace connected to the authoritative FastAPI alert and incident
contracts.

## Capabilities

- Live backend health and honest unavailable/retry states
- Dashboard totals derived from real filtered API counts
- Alert list, detail, severity/agent/MITRE/time/search filters, and cursor pagination
- Incident list, detail, creation, lifecycle transitions, alert linking, notes, assignment, and audit
- Runtime response validation before backend JSON enters the component tree
- Responsive desktop and narrow-width analyst layouts
- Backend-validated login/logout/session restoration and role-aware incident controls
- Explicit local-AI alert/incident analysis with availability, loading/error, structured sections,
  history, provenance, truncation, and stale indicators

There is no demo adapter or silent fallback. If the backend is unavailable, the UI displays that
failure and never substitutes synthetic SOC records.

## Run locally

Start the backend at `http://localhost:8000`, bootstrap an analyst, then:

```powershell
Set-Location frontend
Copy-Item .env.example .env.local
npm ci
npm run typecheck
npm test
npm run dev
```

Open `http://localhost:5173`.

`VITE_API_BASE_URL` is the only frontend environment setting and defaults to
`http://localhost:8000`. It is a public browser destination, not a secret. Never put
`WAZUH_INGEST_API_KEY`, credentials, tokens, or private configuration in a `VITE_*` variable.

The backend default origin list explicitly includes `http://localhost:5173`. If Vite is deliberately
served from another host or port, configure that exact origin explicitly, for example:

```dotenv
CORS_ORIGINS=http://127.0.0.1:5173
```

Do not enable wildcard origins.

## Architecture

```text
Pages and components
        ↓
BackendApi interface
        ↓
HttpBackendApi (single fetch boundary)
        ↓
runtime contract parsers
        ↓
FastAPI /api/v1
```

Raw `fetch()` calls exist only in `src/api/client.ts`. Components receive the typed `BackendApi`
interface, keeping cookie credentials, CSRF headers, and 401 handling centralized. The detailed contract map
is in [docs/BACKEND_CONTRACT.md](docs/BACKEND_CONTRACT.md).

## Security boundary

- The browser never calls `POST /api/v1/alerts/ingest` and never receives its machine API key.
- Alert telemetry, incident fields, notes, actor names, and audit details are untrusted text.
- React text rendering is used throughout; `dangerouslySetInnerHTML` is prohibited.
- Unexpected response shapes fail closed with a contract error instead of entering the UI.
- The app shell is not mounted until `GET /api/v1/auth/session` validates the backend session.
- Session cookies are HttpOnly and are never stored in `localStorage` or exposed to React.
- The in-memory CSRF value is restored from the authenticated session endpoint and sent only on
  protected mutations.
- Incident audit actors come from backend principals; no actor-impersonation input exists.
- Frontend role checks are UX only. FastAPI remains the authorization boundary.
- The browser sends only target IDs and an optional bounded question to FastAPI; it never contacts
  Ollama, supplies authoritative telemetry, or receives provider credentials.
- AI/model output is attacker-influenced untrusted text and is never interpreted as HTML or a command.

## Current limitations

- Analyst account administration currently has an API/CLI boundary but no dedicated admin UI.
- Incident correlation remains explicit and analyst-directed.
- There is no automatic refresh or real-time event stream.
- No fake AI result is substituted when Ollama is disabled, unavailable, slow, or invalid.
