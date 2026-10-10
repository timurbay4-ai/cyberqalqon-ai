# Windows Event Log Collection

The repository fragment `wazuh/configs/windows-eventchannels.xml` and the elevated installer use
exact Event ID filters. They do not collect the broad Application log, install Sysmon, or enable
new verbose audit policy.

| Channel | Provider requirement | Selected Event IDs |
|---|---|---|
| Security | Microsoft-Windows-Security-Auditing | 4624, 4625, 4720, 4726, 4732, 1102 |
| System | Service Control Manager | 7045 |
| Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell | 4104 |
| Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | 1116, 1117 |

At discovery time System, PowerShell Operational, and Defender Operational were enabled and
circular. Their record counts were 34,393, 2,139, and 13,684 respectively. Security-log metadata,
events, and `auditpol` require elevation and therefore could not be inspected. Script Block/Module
Logging policy was not enabled by this work; collection observes 4104 only when Windows already
emits it.

Read-only historical lookup confirmed the actual providers/channels on this host: System 7045 from
`Service Control Manager` (2026-10-08 05:34 +05), PowerShell 4104 from
`Microsoft-Windows-PowerShell` (2026-10-08 13:43 +05), and Defender 1116/1117 from
`Microsoft-Windows-Windows Defender` (2026-10-08 00:23 and 2026-10-07 23:40 +05). Event messages
were not printed or copied into artifacts.

The normalizer preserves the Wazuh alert timestamp, agent ID/name, Windows event ID, channel,
provider, computer name, target/subject username, and source IP/port when present. Wazuh's `-`
network sentinel is treated as missing data rather than an invalid IP address. All strings remain
untrusted display data.

The React alert detail renders a dedicated Windows section. Alert search indexes event ID, channel,
provider, and computer. Authentication, CSRF, RBAC, and ingest API-key validation are unchanged.

## Volume controls

- XPath filters admit only the listed IDs.
- Successful logon 4624 remains low severity under the built-in rules; it is not promoted by a
  custom rule.
- Repeated failed logons use Wazuh's existing correlation instead of a new worker or service.
- Event-channel sizes remain Windows-managed circular logs.
- Production tuning should measure 4624 volume after enrollment and may further restrict logon
  types if the host workload is noisy.
