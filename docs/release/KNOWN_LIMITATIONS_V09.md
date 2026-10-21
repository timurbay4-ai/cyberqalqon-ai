# CyberQalqon SIEM v0.9 known limitations

> Historical v0.9 snapshot. Current v0.9.1 gate status is recorded in
> `docs/release/RELEASE_GATE_V091.md`.

- **BLOCKED — live Wazuh API inventory.** The adapter is implemented and tested,
  but no approved least-privilege API credential and trusted CA are configured.
  Live agent rows therefore remain telemetry-observed with connection
  `UNKNOWN`.
- **BLOCKED — Windows enrollment and live telemetry.** `WazuhSvc` 4.7.5 is
  running, but the configured private manager endpoint is stale/unreachable,
  `client.keys` is empty, manager/auth relay port 1515 is unavailable, and the
  manager does not confirm the Windows test agent. No live Windows delivery is claimed.
- **PARTIAL — Windows logs.** Security/System/PowerShell/Defender contracts and
  fixtures are validated, but no live event can be accepted until enrollment is
  approved and completed. Sysmon is absent and was not installed.
- **PARTIAL — WSL relays.** Communication relay 2514 is healthy and resolves the
  current private WSL address per connection. Enrollment relay 2515 is absent by
  design. Relays are user processes rather than reboot-persistent services.
- **PARTIAL — scale.** Local SQLite, bounded caches, and 2,000 observed-identity
  aggregation are designed for this lightweight lab. No independent production
  load, HA, failover, or multi-manager acceptance test has been performed.
- **BLOCKED — authenticated browser UAT.** The Computer Use helper stopped at a
  mandatory URL-identification boundary before interaction. v0.9 did not bypass
  it, inject a session, create/reset an account, or expose a credential. The
  user-controlled checklist is `docs/release/BROWSER_UAT_V09.md`.
- **PARTIAL — enrollment maintenance workflow.** The manager has password-
  protected authd configured but disabled. Port 1515 must remain closed until an
  approved window. The current protected `agent-auth.exe` help cannot be
  inspected non-elevated, so the operator must review its supported password
  delivery mechanism before running the existing installer with `-Enroll`.

This milestone is not a declaration of enterprise production readiness.
