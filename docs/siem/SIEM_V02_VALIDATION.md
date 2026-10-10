# SIEM v0.2 validation record

Validated on 2026-10-08 against the authorized local Windows/WSL lab. The checkout remained on
`main` at `b07fdd50dc3df71976bf9467f8ecb98e68045926`; no commit or push was created.

## Migration and data safety

- a verified online schema-v8 backup was created before deployment;
- a copy migrated from v8 to v9 with identical counts for alerts, incidents, incident links,
  incident history, events, analysts, and sessions;
- the live migration preserved the immediate pre-migration counts: 21 alerts, 2 incidents, 5
  incident links, 7 history entries, 2,340 events, 1 analyst, and 6 sessions;
- post-migration `PRAGMA quick_check` returned `ok`;
- the backup and its SHA-256 metadata are in the Git-ignored `backups/` directory.

## Automated and live evidence

| Gate | Result |
|---|---|
| Backend tests | 161 PASS |
| Frontend tests | 59 PASS |
| TypeScript | PASS |
| Frontend production build | PASS |
| Sender/shipper and deployment tests | 126 PASS |
| Active loopback validator | 13/13 PASS |
| SQLite integrity/schema | `ok`, version 9 |

The active validator generated new Wazuh alerts for rules `100101`, `100111`, and `100120` from
`cyberqalqon-test-web`. Its probe order runs the single sensitive-path event before correlation
bursts because Wazuh chooses one terminal child rule per event. All probes are hard-limited to a
literal loopback target. Repeat runs honor the deployed correlation rules' 60-second ignore window
before sending new probes, preventing cooldown state from being misreported as a detection failure.

The installed event shipper was backed up, replaced with the tested v2 counter implementation,
and restarted. Its durable cursor upgraded from v1 without losing device/inode/offset or accepted,
skipped, and rejected totals. The sender queue, pending, in-flight, terminal-blocked, and dead-letter
counts were zero at validation.

Browser automation remains an independent gate. A localhost-blocking browser environment is not
counted as a UI PASS; component/contract/build coverage remains PASS while browser E2E is BLOCKED.
