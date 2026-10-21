# M14 validation record

## Database rehearsal

Source: verified online backup
`backups/cyberqalqon-pre-m14-schema17-20261012T183339Z.db`.

- SHA-256: `22c0cc6fa6b7e28f55c386003e49da1ae7220c82d46286b19e1a434873b6f7d1`
- Bytes: 1,490,481,152
- Schema 17 to 18: 18 ms on the observed run
- Second application: 10 ms, idempotent
- `PRAGMA quick_check`: `ok`
- `PRAGMA foreign_key_check`: zero rows
- Preserved: 80,176 events, 40 alerts, three incidents, zero cases, one analyst
- Interrupted migration unit rehearsal: full schema-object rollback PASS

The live database was not migrated and remains schema 17.
An automated restart test confirmed the default migration gate leaves schema 17
unchanged, `/readiness` stays HTTP 200, and M14 storage APIs return bounded HTTP
503 `schema_approval_required` until the explicit opt-in is supplied.

## Disposable performance sample

`scripts/benchmark_m14.py` created and removed a schema-18 database with 10,000
synthetic events; all evaluation paths were bounded to 5,000 inputs.

| Operation | Result |
|---|---:|
| Single-rule median / max | 97.066 / 144.387 ms |
| Nine-rule median / max | 184.370 / 190.718 ms |
| Shadow median / max | 1,172.272 / 1,220.703 ms |
| Tuning median / max | 314.327 / 355.310 ms |
| Inventory median / max | 259.600 / 309.637 ms |
| SQLite bounded query median / max | 20.277 / 41.510 ms |
| State first persistence / restart replay | 657.560 / 518.742 ms |
| Four workers, 12 inventory reads | 5,615.602 ms wall |
| Shadow Python tracked peak | 16,686,096 bytes |
| DB growth after M14 runs | 34,447,360 to 42,065,920 bytes |

The second replay processed zero new events and identified 5,000 duplicates.
Alerts, incidents, and cases remained zero; quick check and FK check passed.
These are local synthetic observations, not an SLA.

## Safety and edge evidence

Automated coverage includes duplicate/out-of-order replay, host/account
isolation, stale config, invalid/oversized configuration, malicious identifier
input, future window, state-version mismatch, interrupted commit, SQLite busy,
VIEWER denial, CSRF/Origin through existing mutation dependencies, shadow
isolation, and M12 shadow investigation. Full suite counts belong to the final
milestone report after regression completes.

Final automated regression:

- Backend: 253/253 PASS.
- Frontend: 116/116 PASS.
- Wazuh sender/shipper/rule fixtures: 117/117 PASS.
- Deployment/validator contracts: 23/23 PASS.
- TypeScript and production build: PASS.
- Passive live validator: 7/9 checks PASS; overall FAIL because the WSL backend
  relay times out and the durable event-shipper cursor has backlog. Frontend,
  backend, Wazuh services, enrollment, sender queue, and database integrity PASS.
- Git diff whitespace check: PASS (line-ending conversion warnings only).

Browser UAT: **DEFERRED_BY_USER — NOT EXECUTED**. This is neither PASS nor a
product defect.
