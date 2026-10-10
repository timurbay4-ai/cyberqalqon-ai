# CyberQalqon AI Frontend

React, TypeScript, and Vite SOC workspace connected to the authoritative FastAPI alert and incident
contracts.

## Capabilities

- Live backend health and honest unavailable/retry states
- Dashboard totals derived from real filtered API counts
- Alert list, detail, severity/agent/MITRE/time/search filters, and cursor pagination
- Incident list, detail, creation, lifecycle transitions, alert linking, notes, assignment, and audit
- Discover with category/outcome filters, keyset pagination, saved searches, and linked evidence
- Hosts, read-only detection rules, filtered reports, and account/session Administration
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

The frontend defaults to the current browser origin in development and production.
Vite proxies `/health`, `/readiness`, and `/api/v1/*` to
`CYBERQALQON_DEV_PROXY_TARGET` (`http://127.0.0.1:8000` by default). This keeps the
host-only `SameSite=Strict` analyst cookie on one site even if the UI is opened as
either `localhost` or `127.0.0.1`. `VITE_API_BASE_URL` remains an optional public
browser destination for deliberately cross-origin deployments, not a secret. Never put
`WAZUH_INGEST_API_KEY`, credentials, tokens, or private configuration in a `VITE_*` variable.

The backend default origin list explicitly includes `http://localhost:5173`. If Vite is deliberately
served from another host or port, configure that exact origin explicitly, for example:

```dotenv
CORS_ORIGINS=http://127.0.0.1:5173
```

Do not enable wildcard origins.

To override the local proxy target without changing application code:

```dotenv
VITE_API_BASE_URL=
CYBERQALQON_DEV_PROXY_TARGET=http://127.0.0.1:8000
```

The proxy setting is consumed only by Vite configuration and is not a browser
secret or production routing mechanism.

The production image is a multi-stage Node build plus unprivileged Nginx. Its
CSP permits only same-origin scripts/styles/connections and normal React text
rendering; no inline script, direct Ollama call, or runtime secret is required.
See [`../docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md).

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

- Deployed Wazuh rules remain read-only; local declarative drafts support validation and bounded
  historical testing but require a separate manual operator deployment. Reports remain JSON/CSV.
- Agent connectivity is not inferred from event freshness without a supported Wazuh API session.
- There is no automatic refresh or real-time event stream.
- No fake AI result is substituted when Ollama is disabled, unavailable, slow, or invalid.
