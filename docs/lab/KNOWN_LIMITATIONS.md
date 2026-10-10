# Known Lab Limitations

## Telemetry gaps

- **Windows Agent enrollment — BLOCKED.** The installed agent has an empty key and a stale manager address. Manager enrollment is disabled and the current Windows shell is not elevated, so protected configuration, key creation, and service restart cannot be completed safely. A loopback dynamic-IP relay, elevated supported installer, exact collection configuration, and rollback documentation are ready. Manual key transfer was not attempted.
- **Windows live telemetry — BLOCKED.** System, PowerShell Operational, and Defender Operational channels are available, but the disconnected agent cannot deliver them. Security metadata and audit policy require elevation. Script Block and Module Logging policy was not enabled.
- **Windows EventChannel rule fixture limitation.** Wazuh 4.14.8 `wazuh-logtest` treats standalone EventChannel JSON as `json`, so the internal `windows_eventchannel` base rule cannot be runtime-tested without altering the installed base ruleset. The live ruleset was left untouched.
- **Sysmon — NOT_SUPPORTED.** Sysmon is not installed. It was not downloaded or installed automatically.
- **Linux process execution — NOT_SUPPORTED.** `auditd`/`auditctl` is absent on Kali. No heavyweight sensor was installed.
- **DNS and outbound-flow analytics — NOT_SUPPORTED.** No dedicated DNS, NetFlow, Zeek, or Suricata source is present. No external traffic was generated.
- **Real SSH authentication — BLOCKED.** SSH is inactive. Enabling password authentication would add unnecessary exposure, so validation is synthetic only.
- **Real web login telemetry — BLOCKED.** Kali Nginx serves a static `/login/` path, not an authentication service. The real CyberQalqon admin account was not attacked, and no disposable auth simulator was deployed in this pass.

## UI limitation

The Codex in-app browser loaded the frontend but blocked localhost `/api` requests with `ERR_BLOCKED_BY_CLIENT`. Therefore an authenticated visual dashboard check is blocked in that browser. Same-origin health and session endpoints were verified from the host, and backend/frontend automated tests passed. No authentication bypass or credential injection was attempted.

## Correlation and scope limitations

- Nmap telemetry covers only the explicit TCP ports in the nftables set and only Kali loopback. It is intentionally not general network IDS coverage.
- Rule `100111` has a 30-second threshold and a 60-second suppression interval. Slower reconnaissance is intentionally not escalated by this rule.
- Rule `100101` does not prove mathematical uniqueness of every requested path; Wazuh's `different_url` is pairwise correlation state.
- FIM realtime coverage added by this work is limited to `/etc/cyberqalqon-lab`. Existing broad `/etc` coverage remains periodic at 12 hours.
- WSL distributions share kernel journal events. The Ubuntu manager collector excludes kernel transport so Agent 001 owns network events; future topology changes should revalidate that filter.

## Operational notes

- Sender status retains its most recent historical failure after a later success. Queue `0`, dead letters `0`, and a newer `last_success` are the authoritative recovery signals.
- The full active JSON validation report is intentionally Git-ignored.
- A diagnostic command printed the former local ingest key during this run. That key was immediately rotated across the backend secret file, sender, and Wazuh integration; the replacement was never printed. The former value is invalid and must not be reused.
