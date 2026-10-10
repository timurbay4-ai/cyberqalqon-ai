# Local operational recovery

## Backup and migration

Before a migration, create an online backup with `python -m app.cli.backup create`. Verify it with
the matching `verify` command. Rehearse restore only on a copy: initialize the copied database,
run `PRAGMA quick_check`, confirm its schema version, and compare alert/event/incident/analyst
counts. Never overwrite the live database during rehearsal.

If migration startup fails, stop the backend, preserve the failed database and logs, verify the
pre-migration backup again, and restore it only after the operator explicitly selects that backup.

## WSL gateway changes

The backend listener used by the Ubuntu relay must bind the current Windows WSL virtual-interface
address, not a historical address. From a normal PowerShell session:

```powershell
$wslGateway = (Get-NetIPAddress -InterfaceAlias 'vEthernet (WSL (Hyper-V firewall))' `
  -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty IPAddress)
backend\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend `
  --host $wslGateway --port 18000
wsl -d Ubuntu-24.04 -u root -- curl -fsS http://127.0.0.1:18000/health
```

This listener is limited to the WSL virtual interface. Do not bind it to a public/LAN interface.
If the Ubuntu `cyberqalqon-backend-relay` unit still targets an obsolete gateway, update it only in
an approved privileged maintenance window, run `systemctl daemon-reload`, and verify the exact
unit before restart.

## Sender and shipper

Read sender state with `cyberqalqon-sender status --json`. Queue depth and dead-letter count are
authoritative durable counters; an older `last_failure` does not override a later success. Compare
`event-shipper-state.json` offset with `archives.json` size. A fresh state timestamp, increasing
retry counter, and stationary cursor identify delivery blockage. After connectivity returns, the
same cursor must advance without deleting or rewinding state.

Run `scripts/capture_operational_health.py` before and after recovery. The second capture records a
deduplicated recovery transition. Then run the passive validator; active probes are never needed
for transport recovery.
