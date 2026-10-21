# Wazuh live acceptance — v0.9.1

Status: **PASS** on 2026-10-11 for the local read-only integration.

## Administrative rotation and TLS

The built-in Wazuh API `wazuh` administrator password was rotated through the
supported Wazuh security/RBAC implementation. The stored hash changed; the
separate `wazuh-wui` hash did not. Authentication with the replacement
credential returns HTTP 200.

A local lab CA and leaf certificate were installed for the API. The leaf is
valid for `localhost`, `127.0.0.1`, and `::1`; the observed connection negotiated
TLS 1.3 and hostname/IP verification passed with the explicitly trusted CA.
Wazuh API port 55000 remains loopback-only. TLS verification was never disabled.

Credential and trust files are Git-ignored and have protected Windows ACLs:

- `secrets/wazuh-api-admin.username`
- `secrets/wazuh-api-admin.password`
- `secrets/wazuh-api-reader.username`
- `secrets/wazuh-api-reader.password`
- `secrets/wazuh-api-ca.pem`

Retrieve values directly from those local files only when operationally
necessary. Do not copy them into chat, logs, issues, screenshots, or Git.

Security note: an unsuccessful pseudo-terminal rotation attempt echoed a
generated candidate into the local execution transcript before the hash was
changed. That candidate never became an active credential and was immediately
replaced in the protected local file. The active credential was set afterward
through the supported Wazuh user-update path. A scan of tracked/untracked source
and local logs found zero occurrences of the active admin or reader passwords.

## Least-privilege reader

The dedicated user `cyberqalqon-reader` is mapped to role
`cyberqalqon_reader`, has `allow_run_as=false`, and has only these policies:

- `agent:read` on the exact resources `agent:id:001` and `agent:id:002`;
- `manager:read` on manager resources required by the adapter.

It has no restart, upgrade, delete, group, configuration-write, RBAC-admin, or
manager-restart action. A probe of the user-list endpoint returned zero visible
items under policy filtering.

## Acceptance requests

| Request | Result |
| --- | --- |
| Reader authentication | HTTP 200 |
| `GET /agents` | HTTP 200; exactly Agents 001 and 002 |
| `GET /manager/info` | HTTP 200 |
| `GET /manager/status` | HTTP 200 |
| Effective user/role inspection | HTTP 200; expected reader role and policies |
| Backend `WazuhApiClient` | `available=true` |
| Manager version | `v4.14.8` |
| Agent 001 | `cyberqalqon-test-web`, active, Wazuh v4.14.8 |
| Agent 002 | `windows-agent-002`, active, Windows 11 Pro, Wazuh v4.7.5 |
| Repository integration | `AVAILABLE`, `CUSTOM_CA`, read-only, agent count 2 |

The current Wazuh 4.14 manager-info payload does not expose the name field the
adapter expects, so `manager_identity` is null. The adapter also interprets
some intentionally stopped optional manager daemons as a degraded detailed
manager-health value. These do not invalidate authenticated inventory or the
OS-service manager health, but remain presentation semantics to refine later.

## Recovery

Manager originals and private CA material remain in separate protected,
root-only backup directories whose exact runtime paths are excluded from
source control. Rollback must be a
separately approved maintenance action: restore the backed-up certificate/API
state, restore the prior RBAC database only if required, restart Wazuh Manager,
and prove loopback TLS/authentication and Agent 001 health before restoring
service. The Windows identity recovery backups also remain root-only; their
exact runtime paths are excluded from source control. Recovery must prove both
Agent 001 and Agent 002 health; Agent 001 must never be removed or replaced.
