# M9 Correlation Validation

_Validated 2026-10-08 on the authorized local CyberQalqon lab._

## Real historical evidence (read-only)

The dry-run inspected 12 supported historical alerts in
`backend/data/cyberqalqon-local-lab.db` with a 900-second window. It performed zero writes.

- `CORR-001`: `1791453257.771592` → `1791453359.776120` → `1791453533.777343`,
  same `agent:001|source:127.0.0.1`, compatible destination, 276.053 seconds.
- `CORR-004`: `1791453699.778702` followed by each of
  `1791453718.779372` and `1791453718.780650`, same agent and exact
  `/etc/cyberqalqon-lab/validation.conf` path, approximately 19.8 seconds.
- The alerts at 10:14 UTC were not proposed as `CORR-001`: enumeration and path probing occurred
  before the port-scan alert, so the required chronology did not match.

No historical incident was created. After migration, the live database retained 13 alerts and the
existing manual `Local Detection Lab Smoke` incident; automatic incident and link counts remained
zero.

Command:

```powershell
$env:PYTHONPATH='backend'
backend\.venv\Scripts\python.exe -m app.cli.correlate_alerts `
  --database-url sqlite:///./backend/data/cyberqalqon-local-lab.db `
  --limit 1000 --window-seconds 900
```

## Synthetic integration validation

The backend API/temp-database suite covers complete and partial chains, repeated enumeration, exact
FIM path matching, missing identity, different source/agent/target, IP normalization, loopback
scoping, delayed/out-of-order evidence, duplicate delivery, window boundary, unsupported high
severity alerts, manual and closed incident preservation, analyst assignment preservation, audit
events, transaction rollback, ingest failure isolation, and concurrent evaluation.

Latest results:

- Backend: 135 tests passed.
- Frontend: 51 tests passed, including correlation contract and chronological timeline rendering.
- Wazuh sender and deployment validation: 110 tests passed.
- TypeScript typecheck and Vite production build: passed.

## Performance

Windows/SQLite temp-database benchmark, 30 samples per path and 120 total alerts:

| Path | Median | p95 | Maximum |
|---|---:|---:|---:|
| Persist only | 21.152 ms | 24.835 ms | 25.260 ms |
| Persist + no-match correlation | 20.534 ms | 38.379 ms | 43.460 ms |
| Persist + automatic incident creation | 26.915 ms | 41.247 ms | 49.311 ms |

Peak Python allocation during 30 matched evaluations was approximately 121 KB. The 120-alert,
30-incident SQLite file was approximately 396 KB. Results are local measurements, not universal
service-level guarantees.

`EXPLAIN QUERY PLAN` selected:

```text
SEARCH alerts USING INDEX idx_alerts_correlation_candidates
  (agent_id=? AND occurred_at>? AND occurred_at<?)
```

The engine has no idle worker and therefore adds no recurring CPU work.

## Live pipeline and browser status

- Backend localhost readiness: HTTP 200.
- Backend WSL bridge readiness: HTTP 200.
- Passive local lab validator: 7/7 PASS.
- Kali Nginx, Wazuh agent, relay, and nftables monitor: active.
- Wazuh manager, sender, and manager/backend relays: active.
- Agent `001` (`cyberqalqon-test-web`): active.
- Sender queue and dead-letter count: zero.
- SQLite `quick_check`: `ok`.
- No new scan telemetry was generated.

The browser login shell rendered, but the Codex in-app browser reported the localhost backend as
unavailable even while both readiness endpoints returned HTTP 200 outside that browser. Therefore
authenticated real-browser timeline validation is **BLOCKED by the browser environment**. The
React timeline rendering and authentication regression tests passed; no credential was entered or
exposed during browser inspection.
