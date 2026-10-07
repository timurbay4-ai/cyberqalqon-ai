# Production deployment

This runbook describes the supported single-node Docker Compose deployment. It
does not turn SQLite into a clustered database and does not expose Ollama or the
backend directly.

## Architecture and trust boundaries

```text
browser / Wazuh manager
          |
       TCP 443
          v
unprivileged Nginx + React (web) -- edge Docker network
          |
   private Docker network
          |
      FastAPI (backend, one process) ---- optional private Ollama
          |
 named SQLite data volume
          |
 protected host backup directory
```

Only `web` joins the edge network and publishes host ports: 80 redirects to
HTTPS and 443 terminates TLS. It also joins the internal private network to
proxy the API. `backend:8000` and `ollama:11434` remain attached only to that
private network and are never published. The Wazuh sender remains on the Wazuh
manager and delivers through the same public HTTPS origin as the browser.

One backend worker is intentional. SQLite is the single-node persistence layer,
and the M6 AI concurrency limiter is process-local. Adding Uvicorn workers would
multiply AI concurrency and complicate SQLite write behavior without providing
supported high availability.

## Host prerequisites and directories

- Docker Engine with the Compose plugin.
- A reviewed checkout of the intended release.
- A DNS name and a certificate/key valid for that name.
- Enough local storage for the database, backups, images, logs, and optional
  Ollama models.

Create protected runtime paths. Example for a dedicated Linux host:

```bash
install -d -m 0700 secrets
install -d -o 10001 -g 10001 -m 0700 backups
openssl rand -base64 48 > secrets/wazuh-ingest-api-key
chmod 0400 secrets/wazuh-ingest-api-key
cp /protected/pki/fullchain.pem secrets/tls.crt
cp /protected/pki/private-key.pem secrets/tls.key
chmod 0444 secrets/tls.crt
chmod 0400 secrets/tls.key
```

The containers run as UID/GID 10001 (backend) and 101 (web). Grant those IDs
read access to their respective mounted secret files with ownership or a narrow
filesystem ACL. Do not make a production private key world-readable. Compose
also requests mode `0400` for the ingestion secret.

Copy `.env.production.example` to the ignored `.env.production`, set mode 0600,
and replace every deployment value:

```bash
cp .env.production.example .env.production
chmod 0600 .env.production
```

Required decisions are:

- `CYBERQALQON_ORIGIN`: exact public HTTPS origin, with no trailing slash,
  for example `https://soc.example.org`;
- `WAZUH_INGEST_API_KEY_FILE`: protected file containing only the machine key;
- `TLS_CERT_PATH` and `TLS_KEY_PATH`: operator-managed PEM files;
- `BACKUP_DIR`: existing protected host directory;
- reviewed image/build metadata values.

The environment file contains paths and non-secret settings, not the key or
private key itself. Never put a password, session value, CSRF value, API key, or
TLS private key in a `VITE_*` build argument. React uses an empty production API
base URL and calls the same HTTPS origin.

## Render, build, and inspect

```bash
docker compose --env-file .env.production config --quiet
docker compose --env-file .env.production build backend web
docker image inspect cyberqalqon/backend:0.7.0 --format '{{.Config.User}}'
docker image inspect cyberqalqon/web:0.7.0 --format '{{.Config.User}}'
```

Expected image users are `10001:10001` and `101:101`. Review image history and
environment metadata before promotion:

```bash
docker history --no-trunc cyberqalqon/backend:0.7.0
docker history --no-trunc cyberqalqon/web:0.7.0
docker image inspect cyberqalqon/backend:0.7.0
docker image inspect cyberqalqon/web:0.7.0
```

No `.env`, database, backup, API key, analyst password, session token, private
key, model, or QA credential should appear. The build contexts have separate
strong `.dockerignore` files.

## Start and initialize

```bash
docker compose --env-file .env.production up -d backend web
docker compose --env-file .env.production ps
curl --fail https://soc.example.org/health
curl --fail https://soc.example.org/readiness
```

The backend creates the database directory, enables SQLite WAL, and applies
pending migrations before becoming ready. Unknown future migrations, schema
drift, or an unusable volume fail startup. The frontend can start independently;
temporary backend unavailability is shown honestly. Ollama is never a backend
startup dependency.

Create the first administrator explicitly. The password is read from the
terminal or stdin and never belongs in Compose:

```bash
docker compose --env-file .env.production exec backend \
  python -m app.cli.bootstrap_analyst \
  --username soc-admin --display-name 'SOC Administrator'
```

Bootstrap succeeds only when no analyst exists. There is no default or test
account. Production cookies are `Secure`, `HttpOnly`, `SameSite=Strict`, use
`Path=/`, and use the `__Host-` name. Login and CSRF trusted-origin checks must
match `CYBERQALQON_ORIGIN` exactly, including scheme and port.

## TLS, proxy, and browser behavior

Nginx accepts TLS 1.2/1.3 with operator-supplied material. Port 80 redirects to
HTTPS. Do not disable certificate verification for browsers or the Wazuh
sender. Prefer a system-trusted public/internal CA; otherwise install the
internal CA in client trust stores and configure the sender CA bundle.

The proxy provides HSTS on HTTPS, `nosniff`, deny framing plus CSP
`frame-ancestors`, a restrictive referrer policy, permissions policy, and a CSP
compatible with the generated React bundle. Vite hashed assets are immutable
for one year; `index.html` is not cached. Auth, alerts, incidents, AI, health,
and readiness are not proxy-cached. API request bodies are capped at 1 MiB to
match the production backend ingestion limit, fixed at 1 MiB in Compose. Change
both proxy and backend limits together in a reviewed release rather than only
overriding one side. AI routes get a 100-second proxy
bound while the backend/provider timeout remains authoritative.

Nginx replaces rather than appends the client-supplied forwarded-for value.
The backend does not use forwarded headers for authentication or authorization.
If another proxy is added, document its trusted hop explicitly instead of
blindly trusting arbitrary `X-Forwarded-*` input.

SPA fallback supports direct navigation and refresh. Verify `/`, `/alerts`, and
`/incidents`; the current UI uses internal page state, but these paths must
still serve the safe application shell rather than a proxy 404.

## Persistence, permissions, and logs

- `backend-data`: named volume containing `cyberqalqon.db` and transient WAL/SHM.
- `BACKUP_DIR`: protected host bind mount for explicit backups.
- `ollama-models`: optional model volume, not part of the application backup.
- Wazuh sender SQLite: separate storage on the Wazuh manager.

Application source and container root filesystems are read-only. Writable
surfaces are the named data volume, backup bind, and a bounded `/tmp` tmpfs.
Linux capabilities are dropped and `no-new-privileges` is enabled. The backend
logs operational messages to stdout/stderr and Uvicorn access logging is
disabled; Nginx access logs do not contain headers. Compose rotates JSON logs at
10 MiB × 5 files by default. Align the Docker daemon log policy as an additional
host safeguard.

SQLite requires local, reliable filesystem locking. Do not place its live files
on NFS/SMB, share the data volume between hosts, or claim active/active HA.

## Ollama choices

AI is disabled by default and is never on the core SOC readiness path.

For the optional private Compose service:

```bash
docker compose --env-file .env.production --profile ollama up -d ollama
docker compose --env-file .env.production exec ollama ollama pull APPROVED_MODEL_TAG
```

Then set `AI_ENABLED=true`, set that exact `OLLAMA_MODEL`, retain
`OLLAMA_BASE_URL=http://ollama:11434`,
`OLLAMA_ALLOW_PRIVATE_NETWORK=true`, and `OLLAMA_ALLOWED_HOSTS=ollama`; restart
only the backend. Models are never downloaded at build or startup and persist in
`ollama-models`.

For a host-managed Ollama, use `http://host.docker.internal:11434`, explicitly
set `OLLAMA_ALLOWED_HOSTS=host.docker.internal`, and retain the private-network
opt-in. Bind Ollama only where the Docker host can reach it and use host firewall
policy; never publish port 11434 to the LAN/Internet. Public URLs and unlisted
DNS names remain rejected.

An unavailable or loading model produces a bounded AI unavailable state. It
must not delay health, ingestion, alert/incident use, or authentication.

## Development versus production

Development remains unchanged: run Uvicorn with reload on localhost, Vite on
port 5173, and use `.env`/`frontend/.env.local`. Vite defaults to
`http://localhost:8000` only in development. Production uses the built assets,
same-origin requests, secure cookies, and exact HTTPS CORS/origin policy.

Do not use the self-signed bypass in `scripts/compose_smoke.py` outside an
isolated QA run. Production acceptance must use normal certificate validation.

See [BACKUP_RESTORE.md](BACKUP_RESTORE.md) and [OPERATIONS.md](OPERATIONS.md)
before promoting a release.
