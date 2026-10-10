# Windows Wazuh Agent Connectivity

Validated on 2026-10-08 for the authorized local CyberQalqon lab.

## Discovered state

| Item | Observed value |
|---|---|
| Service | `WazuhSvc`, automatic, running as LocalSystem |
| Installation | `C:\Program Files (x86)\ossec-agent` |
| Configured manager | stale private address on `1514/tcp` (runtime value intentionally redacted) |
| Existing agent name | `AD_client_1` |
| Existing key | `client.keys` is empty; there is no enrolled identity to reuse |
| Manager | Wazuh 4.14.8 in Ubuntu 24.04 WSL2 |
| Manager address | Dynamic WSL address; discover it at execution time and do not hardcode it |
| Manager enrollment | port 1515 disabled in the manager configuration |
| Existing agents | `001` is `cyberqalqon-test-web`; it must not be replaced |

The interactive shell is medium-integrity and cannot write the protected agent configuration,
restart `WazuhSvc`, read Security events, or save an enrollment key. No UAC bypass, manual key
copy, duplicate manager record, or partial enrollment was attempted.

## Dynamic-IP-safe transport

`scripts/windows_wazuh_loopback_relay.py` listens only on `127.0.0.1:2514`. For each connection it
resolves Ubuntu's current RFC1918 WSL address and forwards bytes to manager port 1514. It does not
terminate Wazuh TLS, inspect telemetry, log credentials, or bind a LAN/public address.

```text
Windows Agent -> 127.0.0.1:2514 -> loopback relay
              -> current Ubuntu WSL RFC1918 address:1514 -> wazuh-remoted
```

The relay was tested from Windows through to an established `wazuh-remoted` TCP connection. It is
a normal user process, not a persistence mechanism; after a reboot it must be started again before
the agent. Creating an automatic-start task was deliberately avoided by the safe-test restrictions.

## Supported completion procedure

Use an elevated PowerShell session. Keep enrollment open only for the short local enrollment
window and never expose 1514/1515 on a public interface.

1. Back up `/var/ossec/etc/ossec.conf` on Ubuntu.
2. Temporarily enable Wazuh manager `authd` on 1515, validate the manager configuration, restart the
   manager, and confirm it is listening only through the intended WSL/private path.
3. Start a second temporary relay instance on `127.0.0.1:2515` targeting manager port 1515.
4. Run the supported installer from repository root:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\Install-WindowsWazuhMonitoring.ps1 `
     -ManagerAddress 127.0.0.1 -ManagerPort 2514 -EnrollmentPort 2515 `
     -AgentName "cyberqalqon-windows-$env:COMPUTERNAME" -Enroll
   ```

5. Confirm a new, distinct manager record (expected next free ID, not `001`) is active.
6. Disable manager enrollment again and stop the temporary 2515 relay. Leave TLS and agent
   authentication enabled.

The installer refuses a non-elevated shell and non-RFC1918/non-loopback manager address. It creates
an ACL-restricted backup under `C:\ProgramData\CyberQalqon\backups`, applies the narrow collection
configuration, runs Wazuh's `agent-auth.exe`, verifies a non-empty key, and restarts `WazuhSvc`.
No password or enrollment credential is embedded.

## Rollback

Restore the newest `ossec.conf` and `client.keys` from the installer-reported ProgramData backup,
then restart only `WazuhSvc`. Remove a newly enrolled Windows manager record only after confirming
its name and ID; never remove Agent `001`.
