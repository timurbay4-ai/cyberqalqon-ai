# CyberQalqon SIEM v0.8 release guide

This guide is the release-candidate operator entry point. It complements the
detailed production deployment, backup/restore, operations, and local-lab
documents. Commands assume the repository root in PowerShell unless stated
otherwise.

## Supported demonstration profile

- Windows 11 host with PowerShell and WSL2.
- Python 3.11 virtual environment under `backend/.venv`.
- Node.js 24 and the locked npm dependency tree.
- Ubuntu 24.04 WSL Wazuh Manager and Kali WSL test agent.
- One local SQLite database at schema 14.
- `AI_ENABLED=false`; no Ollama or LLM is required.

Minimum practical local profile: four logical CPU cores, 8 GiB RAM, and 20 GiB
free disk. Recommended for a simultaneous browser, two WSL distributions,
manager, frontend build, and regression run: six or more logical cores, 16 GiB
RAM, and 30 GiB free disk. These are demonstration guidelines, not production
capacity claims.

## Install from a reviewed snapshot

```powershell
python -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
npm --prefix frontend ci
```

Copy `.env.example` to an untracked `.env` and change only local deployment
values. Keep secrets in ACL-restricted files referenced by `*_FILE`; do not paste
secret contents into documentation, screenshots, shell history, image layers, or
Git.

## Local startup

Terminal 1 - analyst API:

```powershell
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend `
  --host 127.0.0.1 --port 8000 --no-access-log
```

Terminal 2 - frontend:

```powershell
npm --prefix frontend run dev
```

Terminal 3 - WSL-only ingestion endpoint. Resolve the current Windows WSL
virtual-interface address every time; never reuse a historical address and never
bind this listener to a public/LAN interface.

```powershell
$wslGateway = Get-NetIPAddress -InterfaceAlias 'vEthernet (WSL (Hyper-V firewall))' `
  -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty IPAddress
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend `
  --host $wslGateway --port 18000 --no-access-log
```

Validate without generating attack traffic:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/readiness -UseBasicParsing
backend\.venv\Scripts\python.exe scripts\validate_local_lab.py `
  --output artifacts\lab-validation\latest-v08-passive.json
```

Expected result is `PASS: 9 checks`. Active Nmap/Gobuster/HTTP probes remain
opt-in and require separate authorization for the local loopback lab.

## Shutdown

Stop the three foreground development processes with `Ctrl+C`. Do not terminate
SQLite while a migration or backup is active. WSL services may be stopped through
their native service manager only when the demonstration is finished:

```powershell
wsl -d Ubuntu-24.04 -u root -- systemctl stop `
  cyberqalqon-event-shipper cyberqalqon-sender cyberqalqon-backend-relay `
  cyberqalqon-wazuh-manager-relay@1514 wazuh-manager
wsl -d kali-linux -u root -- systemctl stop `
  cyberqalqon-nftables-monitor cyberqalqon-wazuh-agent-relay wazuh-agent nginx
```

Stopping telemetry is optional for normal source work. Do not remove queues,
cursor state, enrollment data, or databases as part of shutdown.

## Environment reference

| Group | Variables | Rule |
| --- | --- | --- |
| Application | `APP_ENV`, `APP_DEBUG`, `DATABASE_URL` | Production rejects insecure cookies; relative DB paths resolve from repository root |
| Browser | `CORS_ORIGINS`, `SESSION_COOKIE_SECURE`, `ANALYST_SESSION_TTL_SECONDS`, `LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_SECONDS` | Exact origins only; no wildcard; Secure cookies required in production |
| Alert ingest | `WAZUH_INGEST_API_KEY` or `WAZUH_INGEST_API_KEY_FILE`, `MAX_INGEST_BYTES` | Direct and file forms are mutually exclusive |
| Event store | `MAX_EVENT_INGEST_BYTES`, `SECURITY_EVENT_RETENTION_DAYS`, `SECURITY_EVENT_MAX_RECORDS` | Bounded by validated configuration ranges |
| Wazuh inventory | `WAZUH_API_URL`, username/password file forms, CA bundle, timeout | HTTPS loopback only; unavailable rather than insecure when credentials/CA are absent |
| Correlation | `CORRELATION_ENABLED`, window, candidate/link limits, retry attempts | Deterministic, bounded, no background attack generation |
| AI | `AI_ENABLED` and `OLLAMA_*`, `AI_*` limits | Keep `AI_ENABLED=false` for this release candidate |
| Sender | `CYBERQALQON_URL`, ingest key, spool DB, timeout/backoff/queue/dead-letter limits | Configure in the protected sender environment, not browser config |
| Compose edge | exact origin, bind/HTTP/HTTPS ports, TLS paths, backup path, image tags, log limits | Secrets and TLS keys are mounted files, never image environment values |

`.env.example` and `.env.production.example` are the canonical complete
templates. They contain placeholders only.

## Backup and restore

Create and verify an online backup before every schema or release migration:

```powershell
Push-Location backend
.\.venv\Scripts\python.exe -m app.cli.backup create `
  --output-dir ..\backups --filename cyberqalqon-pre-release.db `
  --database-url sqlite:///./backend/data/cyberqalqon-local-lab.db
.\.venv\Scripts\python.exe -m app.cli.backup verify `
  ..\backups\cyberqalqon-pre-release.db
Pop-Location
```

Restore requires the backend to be stopped, an explicit confirmation flag, and
a preservation directory. Rehearse only against a disposable `tmp/` target. See
`docs/BACKUP_RESTORE.md` for production recovery and rollback decisions.

## Security assumptions

- TLS terminates at the production Nginx edge. HTTP redirects to HTTPS.
- The backend and SQLite volume remain on the private network.
- Analysts authenticate through server-side sessions; the browser stores no
  reusable password or bearer token.
- Mutations require exact Origin, session, CSRF, and permission checks.
- Wazuh ingestion uses a separate machine key with a bounded JSON body.
- The host protects `.env`, secrets, backups, TLS keys, and database files.
- Audit data is bounded application evidence, not an immutable compliance store.
- Case evidence digests detect application-record changes; they are not a legal
  forensic chain-of-custody certification.

## Release gates

Run from a clean process state, but do not clean or reset the Git worktree:

```powershell
backend\.venv\Scripts\python.exe -m pip check
backend\.venv\Scripts\python.exe -m compileall -q backend\app wazuh\cyberqalqon_sender scripts
backend\.venv\Scripts\python.exe -m pytest -q backend\tests
backend\.venv\Scripts\python.exe -m pytest -q tests\e2e
npm --prefix frontend run typecheck
npm --prefix frontend test
npm --prefix frontend run build
backend\.venv\Scripts\python.exe -m pytest -q wazuh\tests tests\deployment
git diff --check
```

Then complete `BROWSER_UAT_V08.md`. Do not approve release while a required gate
is FAIL or BLOCKED.

## Troubleshooting

| Symptom | Safe diagnostic | Recovery |
| --- | --- | --- |
| Frontend unavailable on `127.0.0.1` | `Get-NetTCPConnection -LocalPort 5173` | Start `npm --prefix frontend run dev`; config binds only IPv4 loopback |
| Login returns `untrusted_origin` | Compare the visible browser origin with `CORS_ORIGINS` | Add the exact intended loopback/HTTPS origin; never use `*` |
| In-app browser says backend unavailable | Test `/api/v1/auth/session` through the same frontend origin | Use normal Chrome/Edge; do not disable auth, CSRF, or browser controls |
| Shipper cursor stops | Compare archive size, cursor, timestamp and retry count | Start the WSL-interface backend listener; preserve the cursor and wait for catch-up |
| Relay unit active but ingest absent | Request `http://127.0.0.1:18000/health` from Ubuntu | Resolve and bind the current WSL gateway; rerun the passive validator |
| Sender last failure looks stale | Inspect queue, in-flight, dead-letter and later success | Treat durable current counters as authoritative; do not delete the spool |
| SQLite busy | Identify duplicate long writers; inspect WAL and process state | Stop unnecessary duplicate app processes gracefully; never delete WAL/SHM files |
| Wazuh API unavailable | Confirm credential/CA files are intentionally absent | Configure supported read-only credentials or keep authoritative agent state unknown |
| Windows agent unavailable | Inspect service state, configured manager and enrollment key | Follow supported elevated enrollment documentation; do not edit the client key manually |

## Related runbooks

- `docs/DEPLOYMENT.md`
- `docs/BACKUP_RESTORE.md`
- `docs/OPERATIONS.md`
- `docs/lab/OPERATIONAL_RECOVERY.md`
- `docs/siem/DEMO_RUNBOOK.md`
- `docs/siem/KNOWN_LIMITATIONS.md`
