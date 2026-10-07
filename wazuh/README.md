# CyberQalqon Wazuh Sender

The sender is the operational bridge from a Wazuh manager to CyberQalqon's existing machine-only
ingestion endpoint. It provides at-least-once delivery with a separate bounded SQLite spool; the
backend remains authoritative for validation, normalization, alert identity, idempotency, conflict
detection, and application persistence.

```text
Wazuh Integrator -> custom-cyberqalqon -> enqueue before HTTP -> backend ingest
                                              |
                                              +-> transient failure -> retry worker
                                              +-> terminal failure -> dead letter
```

The sender never authenticates as a human analyst. It sends only:

```http
POST /api/v1/alerts/ingest
Content-Type: application/json
X-API-Key: <machine ingestion key>
```

## Components

| Path | Purpose |
|---|---|
| `cyberqalqon_sender/` | Typed configuration, deterministic payload handling, HTTP policy, SQLite spool, retry worker, and CLI |
| `integrations/custom-cyberqalqon` | Wazuh Integrator-compatible executable entrypoint |
| `configs/ossec-integration.xml.example` | Sanitized Wazuh manager configuration block |
| `configs/cyberqalqon-sender.env.example` | Sender/worker environment template |
| `configs/cyberqalqon-sender.service` | Hardened systemd worker example |
| `docs/DEPLOYMENT.md` | Installation, operation, rotation, upgrade, rollback, and troubleshooting |
| `tests/` | Deterministic unit, failure, persistence, and security tests |

Wazuh calls the custom script with the alert JSON file path, API key, and hook URL as its first
three parameters. The script reads the path only as a regular data file, canonicalizes the JSON,
commits it to the spool, and then attempts immediate delivery. A separately restartable worker
drains due retries. No shell command is built from event content.

## Local development

Python 3.11 or newer is required.

```bash
cd wazuh
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
python -m compileall -q cyberqalqon_sender tests
```

For a loopback-only development backend, set the explicit unsafe exception:

```bash
export CYBERQALQON_URL=http://127.0.0.1:8000
export CYBERQALQON_ALLOW_INSECURE_HTTP=true
export CYBERQALQON_INGEST_API_KEY='replace-with-local-test-key'
export CYBERQALQON_SENDER_DB=/absolute/path/to/sender.db
cyberqalqon-sender submit samples/authentication-failure.json
cyberqalqon-sender status --json
cyberqalqon-sender drain
```

Plain HTTP to a non-loopback host is always rejected. HTTPS certificate verification cannot be
disabled; a private CA can be provided with `CYBERQALQON_CA_BUNDLE`.

## Delivery behavior

| Backend/network outcome | Sender result | Action |
|---|---|---|
| Contract-valid `201` | `DELIVERED` | Remove queue item |
| Contract-valid duplicate `200` | `DUPLICATE` | Remove queue item |
| `409` | `CONFLICT` | Dead-letter; never treated as duplicate |
| `400`, `401`, `403`, `413`, `415`, `422`, other unexpected `4xx`/redirect | `PERMANENT_FAILURE` | Dead-letter |
| `429`, `408`, `5xx`, network/DNS failure, connect/read timeout | `TRANSIENT_FAILURE` | Bounded retry, then dead-letter |
| Malformed or unexpected `2xx` response | `TRANSIENT_FAILURE` | Retry because backend commit is uncertain |

The worker uses a lease so a process crash cannot leave a permanent in-progress record. A crash
after the backend commits but before local completion can cause a replay; the backend's duplicate
response completes that replay safely. This is at-least-once delivery, not exactly-once delivery.

Queue and dead-letter count/byte limits reject new evidence or retain terminal evidence in a
`TERMINAL_BLOCKED` queue state. The sender never silently deletes the oldest alert to make room.

See [deployment and operations](docs/DEPLOYMENT.md) for the complete production procedure.
