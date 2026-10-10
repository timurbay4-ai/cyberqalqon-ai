# Windows Monitoring Safe Tests

## Tests completed

- Confirmed `WazuhSvc` is installed, automatic, and running.
- Confirmed Windows can reach the current Ubuntu WSL manager on TCP 1514.
- Read existing historical 7045, 4104, 1116, and 1117 metadata and confirmed their real provider
  and channel without printing event messages or generating new security activity.
- Started the loopback-only 2514 relay and observed an established connection at
  `wazuh-remoted`; no event payload was sent by the probe.
- Parsed the elevated installer without syntax errors and verified its refusal controls in tests.
- Validated exact provider/channel/Event ID fields in five inert fixtures:
  - `security-4625.json`
  - `security-4720.json`
  - `system-7045.json`
  - `powershell-4104.json`
  - `defender-1116.json`
- Normalized and ingested the synthetic 4625 Wazuh alert into a temporary authenticated API test
  database. It was searchable and did not join a Kali M9 incident.
- Rendered Windows event identity and hostile-looking strings safely in React component tests.

## Tests intentionally not run

- No administrator or real account was attacked.
- No disposable account was created because enrollment and Security-log access are blocked by the
  non-elevated shell.
- No brute force, log clearing, service installation, malware, Defender disablement, firewall
  disablement, or persistence mechanism was used.
- No live PowerShell test was claimed: the disconnected agent could not deliver it.
- No live Defender detection was generated.
- No standalone EventChannel `wazuh-logtest` PASS is claimed; Wazuh 4.14.8 cannot simulate its
  internal `windows_eventchannel` decoder from the JSON fixture without altering the live base rule.

## Post-enrollment checks

After an operator completes enrollment, perform one benign `Get-Process`, one intentionally invalid
logon against a disposable non-privileged local account, and ordinary login/logout. Record the
resulting manager and CyberQalqon alert IDs. Use the prepared fixtures—not real repeated logons—for
the eight-event `60204` correlation test. Do not clear logs or install a throwaway service merely to
obtain 1102/7045.
