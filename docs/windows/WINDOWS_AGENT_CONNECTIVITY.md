# Windows Wazuh Agent connectivity

Validated on 2026-10-11 for CyberQalqon v0.9.1.

## Live topology

```text
Windows Wazuh Agent 002
  -> 127.0.0.1:2514/tcp
  -> Windows WSL relay (`wslrelay.exe`)
  -> Kali `cyberqalqon-wazuh-agent-relay.service`
  -> /mnt/wsl/cyberqalqon-wazuh-1514.sock
  -> Ubuntu `cyberqalqon-wazuh-manager-relay@1514.service`
  -> 127.0.0.1:1514/tcp
  -> wazuh-remoted
```

No `netsh portproxy` rule, LAN listener, or public listener is used. The Windows
agent is configured only for the loopback endpoint, so WSL address changes do
not require an agent configuration change.

## Current state

| Item | Verified value |
| --- | --- |
| Service | `WazuhSvc`, Running, Automatic, LocalSystem |
| Installation | `C:\Program Files (x86)\ossec-agent` |
| Manager endpoint | `127.0.0.1:2514/tcp` |
| Manager identity | Agent `002`, `windows-agent-002` |
| Server state | Active; keepalive advancing |
| Agent version | Wazuh 4.7.5 |
| Manager version | Wazuh 4.14.8 |
| Application collection | Enabled and delivering |
| Control identity | Agent `001`, `cyberqalqon-test-web`, Active and unchanged |

The installed manager version is newer than the Windows agent. No agent upgrade
was needed for this local acceptance.

## Diagnostic procedure

Use read-only checks first:

```powershell
Get-Service -Name WazuhSvc
Test-NetConnection 127.0.0.1 -Port 2514 -InformationLevel Detailed
wsl.exe -d Ubuntu-24.04 -u root -- systemctl is-active wazuh-manager
wsl.exe -d Ubuntu-24.04 -u root -- /var/ossec/bin/agent_control -lc
```

Also require the CyberQalqon authenticated APIs to show Agent 002 with
`WAZUH_API` authority and `ONLINE`/`ENROLLED` state. Recent telemetry alone is
not proof that the agent is connected.

## Recovery

1. Confirm `WazuhSvc`, `cyberqalqon-wazuh-agent-relay.service`,
   `cyberqalqon-wazuh-manager-relay@1514.service`, and `wazuh-manager` are
   active.
2. Confirm only the loopback 2514 path is reachable from Windows. Do not expose
   1514, 1515, 2514, 2515, or 55000 to a LAN or public interface.
3. Restart only the failed relay component, then prove Agent 001 and Agent 002
   are both Active. Do not perform re-enrollment for a relay outage.
4. If protected Windows configuration is damaged, use the newest ACL-restricted
   backup under `C:\ProgramData\CyberQalqon\backups`; do not hand-edit or print
   `client.keys`.
5. If the manager record is absent, stop and use the supported Wazuh identity
   recovery workflow. Never create a duplicate or reuse/remove Agent 001.

## Rollback reference

The accepted Windows backup is:

`C:\ProgramData\CyberQalqon\backups\windows-agent002-v091-20261011T085215Z`

Restore it only in an approved maintenance window, restart only `WazuhSvc`, and
then verify service state, loopback transport, Agent 001, and Agent 002. Key
material and API credentials must remain out of Git, logs, screenshots, and
chat.
