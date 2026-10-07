# Backup and restore

The backend database is sensitive. It contains alert telemetry, analyst
password hashes, server-side sessions, incident notes/history, and persisted AI
analyses. Protect backups with restrictive permissions, operator-managed
encryption at rest, authenticated transfer, an explicit retention policy, and
verified destruction.

## Create and verify an online backup

The CLI uses SQLite's online backup API, so it captures a consistent snapshot
while WAL and controlled writes are active. It does not copy live `.db`, `-wal`,
or `-shm` files directly.

```bash
docker compose --env-file .env.production exec backend \
  python -m app.cli.backup create --output-dir /var/backups/cyberqalqon
```

Each operation creates a mode-0600 `.db` plus `.db.json` metadata. Metadata
contains UTC creation time, purpose, application version, Git/build identity,
schema/migration versions, filename, byte size, SHA-256, and integrity result.
It contains no path, password, API key, token, session, or database contents.

Verify before copying, retention, upgrade, and restore:

```bash
docker compose --env-file .env.production exec backend \
  python -m app.cli.backup verify \
  /var/backups/cyberqalqon/cyberqalqon-YYYYMMDDTHHMMSSZ-ID.db
```

Verification opens the DB read-only, runs SQLite `quick_check`, validates the
CyberQalqon migration history, recomputes SHA-256/size, and compares the sidecar.
An existing destination is never overwritten.

## Schedule backups on the host

Use host cron or a systemd timer; do not add a scheduler to FastAPI. Example
cron command (choose an operator-approved cadence and wrapper that records exit
status):

```cron
15 2 * * * cd /opt/cyberqalqon && docker compose --env-file .env.production exec -T backend python -m app.cli.backup create --output-dir /var/backups/cyberqalqon
```

Do not silently delete backups. Define retention (for example daily/weekly/
monthly tiers), verify the retained artifacts, monitor free space, and remove
only according to policy. Periodically restore to an isolated host; creation
alone is not proof of recoverability.

## Restore procedure

Restore is deliberately offline and never an API endpoint.

1. Verify the selected backup and metadata.
2. Record the current release/image and stop the backend. The web proxy may stay
   up and will report backend unavailability.
3. Run restore in a one-off container with the same data and backup mounts.
4. Start the backend; startup revalidates migrations and enables WAL.
5. Check readiness, log in again, inspect representative alerts/incidents/AI
   history, and perform Wazuh ingestion smoke.

```bash
docker compose --env-file .env.production stop backend
docker compose --env-file .env.production run --rm --no-deps backend \
  python -m app.cli.restore \
  /var/backups/cyberqalqon/SELECTED.db \
  --metadata /var/backups/cyberqalqon/SELECTED.db.json \
  --preserve-dir /var/backups/cyberqalqon \
  --confirm-restore
docker compose --env-file .env.production up -d backend
curl --fail https://soc.example.org/readiness
```

The command refuses a corrupt, tampered, non-CyberQalqon, future-schema, or busy
target. If a target exists, it first creates and verifies a uniquely named
`pre-restore` safety backup. It restores to a temporary sibling file, applies
pending migrations, checks foreign keys and integrity, invalidates every
restored analyst session, removes only the target's stale WAL/SHM sidecars, and
atomically replaces the database.

Session invalidation is intentional: disaster recovery must not resurrect old
browser sessions. Analysts log in again; accounts and password hashes remain.
There is no option to retain restored sessions.

## Rollback and older schemas

Validated backups from older known schema versions may be restored and are
migrated forward before replacement. A schema newer than the running image is
rejected. Migrations are not promised to be automatically reversible.

Release rollback therefore means:

1. a verified pre-upgrade database backup;
2. the previous reviewed image/code version;
3. backend stop;
4. restore the matching backup;
5. start the previous image and complete acceptance checks.

Do not run an older image against a database already upgraded by a newer image.

## Wazuh sender spool

The sender queue is a separate SQLite database on the Wazuh manager and is not
included in backend backups. It contains transient and dead-letter telemetry.
Prefer draining before maintenance. If policy requires a spool backup, stop the
worker or use a SQLite-aware online backup; never copy active DB/WAL/SHM files
casually. Do not merge the sender spool into the backend database.

## Automated coverage

The backend suite covers fresh and populated backups, a live WAL connection,
integrity/metadata verification, existing/invalid/unwritable destinations,
corruption/tampering, valid older-schema migration, safety preservation,
domain data including alert/incident/AI rows, and restored-session invalidation.
Production operators must still perform a periodic isolated restore drill.
