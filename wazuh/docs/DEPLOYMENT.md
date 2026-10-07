# Wazuh Sender Deployment and Operations

This guide installs the CyberQalqon sender on a Linux Wazuh manager. The implementation and local
HTTP E2E flow are verified; deployment against a real production Wazuh manager/version is not yet
verified. Confirm the custom Integrator arguments and configuration options against the
[current Wazuh external API integration documentation](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
and the
[`integration` reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
for the release being operated.

## Reliability and trust model

The Wazuh custom script commits each valid alert to a sender-specific SQLite database before the
HTTP attempt. A long-running worker retries transient failures. The application backend, not the
sender, owns normalization and business rules.

```text
alert file -> bounded JSON parse -> SQLite commit -> immediate authenticated POST
                                              |      |
                                              |      +-> 201/duplicate 200 -> complete
                                              |      +-> transient -> scheduled retry
                                              |      +-> terminal/409 -> dead letter
                                              +-> survives process/manager restart
```

The semantics are **at least once plus idempotent backend ingestion**. They are deliberately not
described as exactly once:

- A crash before the enqueue commit means the Wazuh invocation fails and no sender claim is made.
- A crash after enqueue leaves durable pending evidence.
- A crash before/during HTTP leaves a lease that becomes eligible again.
- If the backend commits and the sender loses the response, the replay receives the backend's
  idempotent duplicate response.
- A crash after success but before local deletion likewise produces a safe duplicate replay.
- Each claimed attempt is persisted before the HTTP call, so repeated crashes cannot reset the
  finite attempt budget.

## Prerequisites

- A Wazuh manager whose release supports custom integrations with JSON alert format.
- Python 3.11 or newer on the manager.
- Network reachability from the manager to the CyberQalqon backend.
- A trusted TLS certificate for the backend or an internal CA file.
- A strong machine ingestion key matching backend `WAZUH_INGEST_API_KEY`.
- Root access for installation; runtime is expected to use the Wazuh service account.

Do not put analyst cookies, CSRF tokens, usernames, or passwords in sender configuration. The
machine API key is a separate security domain and must never be exposed to the frontend.

## Recommended filesystem layout

| Path | Owner/mode | Content |
|---|---|---|
| `/opt/cyberqalqon-sender` | `root:wazuh`, `0750` | Python virtual environment/package |
| `/var/ossec/integrations/custom-cyberqalqon` | `root:wazuh`, `0750` | Wazuh entrypoint |
| `/etc/cyberqalqon/sender.env` | `root:wazuh`, `0640` | Worker configuration and machine key |
| `/var/lib/cyberqalqon-sender` | `wazuh:wazuh`, `0700` | Sender DB and SQLite WAL/SHM sidecars |
| `/var/lib/cyberqalqon-sender/sender.db` | runtime-created, `0600` | Queue, dead letters, counters |

The queue contains raw security telemetry and may contain credentials observed in monitored logs.
Protect it as sensitive evidence even though the sender never writes its own API key into the DB.
The systemd example sets `UMask=0077`; retain that setting so SQLite sidecars are restrictive too.

## Installation

From a trusted checkout or release artifact:

```bash
sudo install -d -o root -g wazuh -m 0750 /opt/cyberqalqon-sender
sudo python3.11 -m venv /opt/cyberqalqon-sender/.venv
sudo /opt/cyberqalqon-sender/.venv/bin/pip install ./wazuh

sudo install -o root -g wazuh -m 0750 \
  wazuh/integrations/custom-cyberqalqon \
  /var/ossec/integrations/custom-cyberqalqon

sudo install -d -o root -g wazuh -m 0750 /etc/cyberqalqon
sudo install -o root -g wazuh -m 0640 \
  wazuh/configs/cyberqalqon-sender.env.example \
  /etc/cyberqalqon/sender.env
sudo install -d -o wazuh -g wazuh -m 0700 /var/lib/cyberqalqon-sender
```

The committed entrypoint shebang intentionally targets
`/opt/cyberqalqon-sender/.venv/bin/python`. If a different installation root is required, update
the installed copy deliberately and keep its owner/mode restrictive.

Edit `/etc/cyberqalqon/sender.env` locally. It is not a shell script and should contain simple
`NAME=value` assignments. Never commit the installed file.

## Configuration reference

| Variable | Default | Constraints/purpose |
|---|---:|---|
| `CYBERQALQON_URL` | required | HTTPS origin only, no API path/query/credentials; trailing slash normalized |
| `CYBERQALQON_INGEST_API_KEY` | required | At least 16 non-control characters; redacted from repr/logs and never persisted |
| `CYBERQALQON_SENDER_DB` | platform default | Absolute sender-only SQLite path; Linux default `/var/lib/cyberqalqon-sender/sender.db` |
| `CYBERQALQON_CONNECT_TIMEOUT_SECONDS` | `5` | Positive, at most 120 |
| `CYBERQALQON_REQUEST_TIMEOUT_SECONDS` | `15` | Positive, at most 300 |
| `CYBERQALQON_MAX_ATTEMPTS` | `8` | 1–100; attempts persist across restart |
| `CYBERQALQON_BACKOFF_BASE_SECONDS` | `2` | Positive, at most 86400 |
| `CYBERQALQON_BACKOFF_MAX_SECONDS` | `300` | At least base, at most 86400 |
| `CYBERQALQON_BACKOFF_JITTER_RATIO` | `0.20` | 0–0.5 symmetric bounded jitter |
| `CYBERQALQON_MAX_PAYLOAD_BYTES` | `1048576` | 1024–104857600; keep aligned with backend `MAX_INGEST_BYTES` |
| `CYBERQALQON_QUEUE_MAX_ITEMS` | `10000` | 1–1000000 |
| `CYBERQALQON_QUEUE_MAX_BYTES` | `536870912` | Aggregate canonical payload-byte bound; must fit one maximum payload |
| `CYBERQALQON_DEAD_LETTER_MAX_ITEMS` | `1000` | 1–1000000 |
| `CYBERQALQON_DEAD_LETTER_MAX_BYTES` | `134217728` | Aggregate dead-letter payload bound; must fit one maximum payload |
| `CYBERQALQON_LEASE_SECONDS` | `60` | At least 10 and at least twice request timeout |
| `CYBERQALQON_WORKER_BATCH_SIZE` | `100` | Deterministic per-loop batch, 1–1000 |
| `CYBERQALQON_WORKER_POLL_SECONDS` | `5` | Idle wait, 0.05–300; prevents busy spin |
| `CYBERQALQON_SQLITE_BUSY_TIMEOUT_SECONDS` | `5` | Positive, at most 60 |
| `CYBERQALQON_CA_BUNDLE` | system trust | Optional existing absolute private-CA file; verification remains enabled |
| `CYBERQALQON_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `CYBERQALQON_ALLOW_INSECURE_HTTP` | `false` | Explicit development exception; works only for loopback hosts |

The HTTP client does not follow redirects and ignores ambient proxy variables, preventing the
machine key from being redirected or silently sent through an unexpected proxy. Use a direct
backend route and `CYBERQALQON_CA_BUNDLE` when an internal CA is required. There is no TLS
verification-disable option.

## Configure Wazuh Integrator

Copy the block from `configs/ossec-integration.xml.example` inside `<ossec_config>` in
`/var/ossec/etc/ossec.conf`. Replace both placeholders. The `<hook_url>` value is the backend
origin, such as `https://soc.internal.example`; do not append `/api/v1/alerts/ingest` because the
sender owns that exact path.

Wazuh custom integration names must start with `custom-`, and the script name must match. With
`<alert_format>json</alert_format>`, Wazuh invokes the script conceptually as:

```text
custom-cyberqalqon <alert-file> <api-key> <hook-url> [options]
```

The sender accepts only the first path as a regular input file. It never executes the file or
derives output paths from alert fields. The Wazuh-supplied key/URL override environment values for
that one invocation; the worker reads the same values from `/etc/cyberqalqon/sender.env`.

Validate the Wazuh configuration using the release's supported procedure, then restart the manager:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

The example Integrator timeout is longer than the sender request timeout. Because enqueue happens
first, even termination during an uncertain HTTP request leaves recoverable queue evidence.

## Install and run the retry worker

```bash
sudo install -o root -g root -m 0644 \
  wazuh/configs/cyberqalqon-sender.service \
  /etc/systemd/system/cyberqalqon-sender.service
sudo systemctl daemon-reload
sudo systemctl enable --now cyberqalqon-sender
sudo systemctl status cyberqalqon-sender
```

The process handles `SIGTERM`/`SIGINT`, completes its current synchronous database/HTTP operation,
and stops without deleting committed queue state. `Restart=on-failure` restarts unexpected exits.

## Retry and failure policy

The delay for attempt `n` is:

```text
min(max_delay, base_delay * 2^(n-1))
```

A symmetric multiplicative jitter is then applied and bounded by `max_delay`. A valid `Retry-After`
delta or HTTP date on `429` is honored when it asks for a longer wait, also capped at `max_delay`.
Invalid or negative values are ignored. Exponent growth is capped to prevent overflow.

Central classification:

| Outcome | Classification | Retry? |
|---|---|---|
| Valid `201 created` | `DELIVERED` | No |
| Valid `200 duplicate` | `DUPLICATE` | No; delivered-equivalent |
| `409` | `CONFLICT` | No; distinct from duplicate |
| `400`, `401`, `403`, `413`, `415`, `422` | `PERMANENT_FAILURE` | No |
| Other `3xx`/`4xx` | `PERMANENT_FAILURE`/protocol | No; redirects are not followed |
| `408`, `429`, any `5xx` | `TRANSIENT_FAILURE` | Yes |
| DNS/network/connect/read timeout | `TRANSIENT_FAILURE` | Yes |
| Unexpected/malformed `2xx` response | `TRANSIENT_FAILURE`/protocol | Yes, because commit is uncertain |

## SQLite spool and backpressure

The sender DB schema has three objects:

- `queue_items`: canonical payload, SHA-256 integrity digest, byte size, state, persisted attempt
  count, due time, expiring lease, safe failure fields, and optional replay link.
- `dead_letters`: retained payload and digest, terminal classification/category, HTTP status, bounded
  safe message, attempt/timestamps, and replay audit fields.
- `sender_stats`: constant-time byte/row accounting, counters, and last success/failure summary.

Pending-due and expired-lease selection are indexed; deterministic processing order is
`next_attempt_at`, then queue ID. Enqueue, count/byte accounting, completion, retry scheduling, and
dead-letter moves are transactional. SQLite uses a busy timeout, WAL, full synchronous durability,
and parameterized queries.

When the queue count or byte bound is reached, new enqueue is rejected with a non-zero integration
result and a structured high-severity error. Existing evidence is preserved. When dead-letter
capacity is exhausted, the terminal record remains in `queue_items` as `TERMINAL_BLOCKED`; it is
not retried and is not discarded. Increase capacity or export/resolve evidence deliberately before
accepting more load. Never remove the oldest security record merely to make room.

Disk sizing must include the DB, `sender.db-wal`, `sender.db-shm`, filesystem overhead, and retained
raw telemetry. Monitor free disk independently. Do not rotate or delete live SQLite files as logs.
Use SQLite-aware backup while the worker is stopped or the online backup API.

## Operator commands

Run commands with the same environment and service account as the worker:

```bash
sudo -u wazuh /bin/sh -c \
  '. /etc/cyberqalqon/sender.env; exec /opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender status --json'
```

Source only the root-managed protected environment file; never put the API key directly on an
interactive command line. Core commands after loading that environment:

```bash
cyberqalqon-sender status
cyberqalqon-sender status --json
cyberqalqon-sender drain --limit 100
cyberqalqon-sender dead-letter list --limit 50
cyberqalqon-sender dead-letter inspect 17
cyberqalqon-sender dead-letter inspect 17 --include-payload
cyberqalqon-sender dead-letter replay 17
cyberqalqon-sender dead-letter replay 17 --force
cyberqalqon-sender dead-letter reconcile --limit 100
```

`inspect` omits payload data unless explicitly requested. Payload output is untrusted and may be
sensitive. Replay keeps the original dead letter, increments its replay counter, links the new queue
ID, and records the latest replay result. Authentication, authorization, and configuration failures
refuse replay unless `--force` is supplied after the underlying condition is corrected.
After raising a dead-letter bound, `reconcile` transactionally moves retained `TERMINAL_BLOCKED`
records in deterministic order; it returns non-zero while any remain.

Persisted status includes delivered, duplicate, transient, retry, conflict, permanent, queue
rejection, and dead-letter-blocked counters; queue/dead-letter depth and payload bytes; oldest
pending age; and last success/failure. Counters survive process restart.

## Structured logs

Operational logs are one-line JSON with bounded fields such as `event`, `alert_id`, `queue_id`,
`attempt`, `classification`, `failure_category`, `http_status`, `duration_ms`, and
`next_retry_at`. Normal logs never contain full payloads or response bodies. Control characters,
ANSI escapes, and newlines in attacker-controlled strings are sanitized. Messages are truncated,
and the configured API key is redacted before logging or persistence.

Use the service journal:

```bash
sudo journalctl -u cyberqalqon-sender --since today
```

## Troubleshooting

| Symptom | Checks |
|---|---|
| `AUTHENTICATION` dead letters | Backend and sender keys match; backend restarted after secret change; no whitespace copied |
| `NETWORK`/timeouts | DNS, route/firewall, backend health, connect/request timeout values |
| TLS failure | Hostname matches certificate; CA installed or `CYBERQALQON_CA_BUNDLE` points to the right protected file |
| `VALIDATION` | Inspect safe metadata and, only in a protected terminal, the payload; backend schema is authoritative |
| `PAYLOAD_TOO_LARGE` | Align sender `CYBERQALQON_MAX_PAYLOAD_BYTES` with backend `MAX_INGEST_BYTES`; do not truncate |
| `CONFLICT` | Same explicit alert ID arrived with different raw content; investigate producer identity reuse |
| `TERMINAL_BLOCKED` | Dead-letter count/bytes are full; export/resolve evidence and adjust bounded capacity deliberately |
| Queue grows | Verify worker is active, then inspect recent failure category and backend health |
| Wazuh does not invoke script | Confirm custom name/script match, executable ownership/mode, JSON format, and release-specific manager logs |

## API key rotation

The backend currently supports one configured ingestion key. Rotation is a short coordinated
maintenance operation, not a zero-downtime dual-key operation:

1. Leave the worker running or stop it briefly; existing alerts remain durable.
2. Update backend `WAZUH_INGEST_API_KEY` and restart/reload the backend as its deployment requires.
3. Update `<api_key>` in Wazuh `ossec.conf` and `/etc/cyberqalqon/sender.env` without printing it.
4. Restart the Wazuh manager and sender worker.
5. Confirm `status`, submit a sanitized test event, then drain due items.

Requests during the mismatch become visible terminal authentication dead letters rather than
infinite retries. After the credentials match, replay those records deliberately with `--force`.
Queued transient failures remain queued throughout rotation.

## Upgrade

1. Check sender status and retain a SQLite-aware backup.
2. Stop `cyberqalqon-sender`; Wazuh invocations can continue enqueueing if the installed package is
   kept available, but a quiet maintenance window is simpler.
3. Upgrade the package in `/opt/cyberqalqon-sender/.venv` from the trusted release.
4. Reinstall the matching custom entrypoint and review config additions.
5. Run `cyberqalqon-sender status --json`, start the service, and drain a small batch.
6. Restart Wazuh only if its integration config or entrypoint changed.

The sender refuses a database schema newer than it understands. Do not downgrade across an
incompatible schema without restoring the matching DB backup.

## Uninstall or rollback

1. Stop and disable the worker.
2. Remove/comment the `custom-cyberqalqon` block and restart Wazuh manager.
3. Remove the installed integration script and application directory.
4. Retain `/var/lib/cyberqalqon-sender` and `/etc/cyberqalqon/sender.env` in protected backup until
   queued/dead-letter evidence has been reviewed and retention requirements are satisfied.

Do not delete the sender database during rollback merely to make the service appear healthy.
Restore the prior package and matching database backup if rollback must preserve active delivery.

## Verification scope

Verified by automation:

- Configuration validation and secret redaction.
- HTTP status/network/timeout classification and bounded response parsing.
- Queue bounds, UTF-8 byte accounting, transactional rollback, leases, restart persistence.
- Retry/backoff/jitter/`Retry-After`, exhaustion, dead-letter bounds, replay auditing.
- Attacker-controlled shell/traversal/HTML/SQL/prompt/Unicode/control strings remain data.
- Real localhost HTTP flow through FastAPI, including outage/restart/recovery, duplicate, conflict,
  analyst read, and authentication failure.

Not yet verified: installation and invocation on a real production Wazuh manager. Validate the
release-specific Integrator configuration and manager service account in staging before production.

## Production CyberQalqon endpoint acceptance

The sender targets the public CyberQalqon HTTPS origin; it never connects to the
private backend container. Prefer the system CA store. For internal PKI, install
the CA or set the protected `CYBERQALQON_CA_BUNDLE`; never set verification off.

Staging acceptance must install the sender and worker, configure the protected
key and HTTPS origin, enable the custom integration, generate a safe alert,
confirm enqueue/backend/analyst visibility, stop the backend, generate another
alert, confirm durable queueing, restore the backend, confirm retry delivery,
and inspect logs for secret leakage. The full numbered checklist is in
[`../../docs/OPERATIONS.md`](../../docs/OPERATIONS.md). Backend database backups
do not include the sender spool; use a separate SQLite-safe policy if that
transient/dead-letter evidence must be retained.
