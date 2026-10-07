# Operations and acceptance

Use this after reading [DEPLOYMENT.md](DEPLOYMENT.md) and
[BACKUP_RESTORE.md](BACKUP_RESTORE.md).

## Staging acceptance status

Observed on 2026-10-07 at Git commit `c087f7d`:

| Gate | Status | Evidence or next requirement |
|---|---|---|
| Local Docker | PENDING | Docker CLI 29.8.0 and Compose v5.5.1 are installed, but the local Docker Desktop Linux engine is unavailable. |
| CI Docker | PASS | Production image build, image/config inspection, and isolated HTTPS Compose smoke passed on `main`. |
| Local HTTPS | PENDING | The local stack was not started because the Docker engine is unavailable. |
| Trusted production TLS | PENDING | CI used synthetic self-signed QA TLS; an operator must supply and validate the trusted staging/production chain. |
| Real Ollama | PENDING | Ollama CLI 0.34.0 is installed, but the local daemon is unavailable; no model was downloaded. |
| Real Wazuh manager | PENDING | Only a local Wazuh agent was detected; no manager endpoint was available for acceptance. |
| Native browser | PENDING | Requires the local HTTPS stack before Chrome/Edge authenticated and responsive acceptance. |

Do not promote any `PENDING` external gate to `PASS` from deterministic tests
alone. Do not weaken TLS, origin, CSRF, cookie, or AI isolation controls to make
an acceptance environment work.

## Health, startup, and shutdown

- `GET /health`: liveness only; returns minimal service status and does not
  probe Ollama.
- `GET /readiness`: returns 200 only when SQLite is reachable and every known
  migration is applied; otherwise 503 with no filesystem/schema details.
- Web `/healthz`: internal container check on port 8080.
- Optional Ollama: its own healthcheck; never gates backend readiness.

Startup order is tolerant: web may start, backend initializes only its storage,
and Ollama may appear later. AI status can move from unavailable to available.
Uvicorn receives SIGTERM, allows a bounded 30-second graceful shutdown, and
AI provider calls remain bounded by configured timeouts. Use `docker compose
stop`, not process killing or live database copying.

## Network and firewall policy

- Allow approved analyst clients to TCP 443.
- Allow the Wazuh manager to TCP 443.
- Optionally allow TCP 80 only for redirect.
- Do not expose 8000, 11434, SQLite files, or the sender spool.
- Restrict SSH/host administration under operator policy.
- Review `docker compose config` and host firewall rules before promotion.

The stack does not modify the host firewall automatically.

## Disk and monitoring

Monitor growth of the backend DB/WAL, sender queue/dead letters, protected
backups, Docker images/layers, Ollama model volume, and rotated container logs.
Alert volume, incident notes/history, and AI analyses have no automatic
retention. Models are large and excluded from application backup. Establish
capacity thresholds and retention before production.

## Upgrade runbook

1. Record Git SHA, image IDs, health, disk, sender queue status, and AI status.
2. Create and verify a backend backup; preserve sender state separately if
   policy requires it.
3. Review release notes, `.env.production.example`, Compose diff, and image
   history. Never reuse an unreviewed mutable image.
4. Build/pull the reviewed release without deleting the old image.
5. Start the backend. Startup applies pending migrations before readiness.
6. Verify `/health`, `/readiness`, HTTPS/security headers, secure cookie,
   login/session refresh/logout, representative alert/incident reads and
   mutations, Wazuh synthetic ingestion, and AI status.
7. Decide whether to remain or roll back. Do not call an upgrade successful
   while readiness or acceptance is incomplete.

## Rollback runbook

SQLite downgrade is not automatic. Stop the backend, select the verified
pre-upgrade backup, restore it with the documented CLI, run the previous image,
and repeat health/browser/Wazuh checks. Restored sessions are invalidated. Keep
the failed database and logs under protected incident/change-management policy.

## Disaster recovery

1. Prepare a new trusted host and install Docker/Compose.
2. Restore the reviewed release checkout/images and protected environment,
   Wazuh key, and TLS material.
3. Create empty protected data/backup locations.
4. Start a one-off backend container and restore the verified database.
5. Start backend/web; verify migrations, liveness, readiness, TLS, and headers.
6. Log in again and inspect alerts, incidents, notes/audit, and AI history.
7. Reconnect the Wazuh sender and run a safe ingestion/retry acceptance.
8. Restore/reinstall Ollama models separately and verify AI status/quality.

## Wazuh staging acceptance

Real manager acceptance is environment-specific and must not be inferred from
the deterministic sender E2E.

1. Install the sender on the staging Wazuh manager.
2. Protect and configure the matching machine API key.
3. Configure the HTTPS CyberQalqon origin.
4. Configure the trusted CA through the system trust store or protected sender
   CA bundle; never disable verification.
5. Start the sender retry worker.
6. Register the custom Wazuh integration and validate manager configuration.
7. Generate a known safe test alert.
8. Verify the sender queue and delivery counters have no unexpected dead letter.
9. Confirm the backend receives the alert and an analyst can read it.
10. Stop the backend.
11. Generate a second safe alert.
12. Confirm durable queued state without payload/secret logging.
13. Restore the backend.
14. Confirm retry delivers and queue drains.
15. Search sender/backend/proxy logs for secret leakage.

Use the system CA store where possible. For internal PKI, set the sender's
protected CA bundle. Never disable TLS verification.

## Ollama acceptance

For the exact approved model and target hardware:

1. Confirm port 11434 is not public and the URL passes the explicit local/
   private allowlist.
2. Pull the model manually and record its exact tag/digest where available.
3. Verify status changes to `AVAILABLE` without restarting core SOC work.
4. Run alert and incident analyses in all required languages.
5. Include hostile telemetry that requests secrets, commands, role changes, or
   incident mutation. Confirm it remains quoted data.
6. Confirm no tools, automatic remediation, state mutation, or external provider
   is used; compare incident state before/after.
7. Stop Ollama and verify core auth/ingestion/reads/incidents remain healthy.

## Native browser acceptance

Use normal Chrome/Edge certificate validation and inspect the console/network
panel at desktop, tablet-ish, and narrow mobile-ish widths:

- login, reload/session restore, logout, and protected 401 after logout;
- cookie is Secure, HttpOnly, SameSite=Strict, Path=/, and not JS-readable;
- alerts/list/filter/detail/MITRE and direct refresh;
- incidents/list/create/status/note/assignment/audit and direct refresh;
- AI panel available/unavailable/history/stale behavior;
- no mixed content, CSP violation, unhandled error, horizontal clipping, or
  hidden critical control.

Record browser/version, release SHA, origin, result, console findings, and any
screen-size-specific issue. Do not weaken cookie, CSP, origin, CSRF, or TLS to
make automation pass.

## Production checklist

- [ ] Strong Wazuh key generated and protected.
- [ ] `.env.production` protected and contains no secret values.
- [ ] TLS chain/key configured and normal trust verification succeeds.
- [ ] HTTP redirects; HTTPS/HSTS and all security headers verified.
- [ ] Secure/HttpOnly/SameSite/Path cookie attributes verified.
- [ ] Exact production HTTPS CORS/origin configured.
- [ ] First administrator explicitly bootstrapped.
- [ ] No default/test/QA accounts or credentials remain.
- [ ] Backend volume persists across container recreation.
- [ ] Backup created, verified, protected, and transferred per policy.
- [ ] Isolated restore drill completed; restored sessions invalidated.
- [ ] Wazuh sender configured with TLS verification.
- [ ] Wazuh outage queue/retry test passed.
- [ ] Ollama private; approved model installed and tested.
- [ ] AI prompt-injection/advisory-only checks passed.
- [ ] Native-browser and responsive smoke passed without console errors.
- [ ] Logs/image history/files contain no secrets or QA artifacts.
- [ ] Published Docker ports and host firewall reviewed.
- [ ] Database/model/backup/log disk capacity monitored.
- [ ] Backup schedule/retention and rollback decision owner documented.

## Troubleshooting

| Symptom | Safe checks |
|---|---|
| Web health works, API 502/503 | `docker compose ps`, backend logs, `/readiness`, volume ownership, migration error |
| Backend restart loop | Production origin, secure cookie setting, readable secret file, writable data volume, schema compatibility |
| Login `untrusted_origin` | Browser origin must exactly equal `CYBERQALQON_ORIGIN` including HTTPS and port |
| Browser cookie absent | Valid HTTPS, Secure cookie, correct hostname/path; inspect `Set-Cookie` without copying token |
| Wazuh 401 | Backend/sender key match; secret file contains no accidental whitespace; rotate deliberately |
| Wazuh TLS error | Certificate hostname/chain and system/custom CA; never disable verification |
| AI misconfigured | Exact model plus allowed local/private endpoint; `ollama`/host name must be allowlisted |
| AI unavailable | Ollama health/model presence/network; core SOC should remain ready |
| Backup failure | Existing output name, directory ownership/free space, source readiness; never copy live files instead |
| Restore says busy | Backend or another SQLite user is still running; stop it rather than forcing file removal |
| Disk growth | Identify DB, sender, backup, image, log, or model owner before retention/deletion |

## Acceptance evidence matrix template

Use `PASS`, `FAIL`, `PENDING`, or `NOT APPLICABLE`; do not convert deterministic
fake integration into a real external pass.

| Feature | Automated | Real HTTP | Container | Real external |
|---|---|---|---|---|
| Authentication/CSRF/roles | backend + Compose smoke | local | CI when engine available | native browser pending until run |
| Alert ingestion/read | backend + sender E2E | local | Compose smoke | real Wazuh pending until run |
| Wazuh retry | sender E2E | local | not required | real manager outage pending |
| Incidents | backend + Compose smoke | local | Compose smoke | native browser pending |
| AI fake Ollama | deterministic E2E | local fake | backend image compatible | not a real model pass |
| AI real Ollama | no deterministic substitute | pending | optional service | exact model/hardware pending |
| Backup/restore | automated integration matrix | filesystem | backend image CLI | operator restore drill pending |
| TLS/headers | config + Compose smoke | self-signed QA | CI when engine available | trusted production TLS pending |
