# CyberQalqon Local Detection Lab Architecture

Validated on 2026-10-08. This document describes the discovered local lab, not a production deployment.

## Data flow

```text
Bounded loopback probes
  -> Kali Nginx / nftables / realtime FIM
  -> Kali Wazuh Agent (001: cyberqalqon-test-web)
  -> local WSL relay
  -> Ubuntu Wazuh Manager 4.14.8
  -> custom-cyberqalqon integration
  -> durable sender queue
  -> Windows loopback FastAPI backend
  -> SQLite
  -> React/Vite analyst UI

Windows Event Logs (prepared; live enrollment blocked)
  -> Windows Wazuh Agent
  -> 127.0.0.1:2514 dynamic-WSL relay
  -> Ubuntu Wazuh Manager
  -> existing delivery path
```

## Components

| Layer | Location | Validated state |
|---|---|---|
| Host | Windows 11 Pro, build 26300 | Frontend `127.0.0.1:5173`, backend `127.0.0.1:8000`, WSL relays loopback-bound |
| Web target | Kali WSL2 | Nginx active; only `127.0.0.1` was used for active tests |
| Endpoint telemetry | Kali WSL2 | Wazuh Agent `001`, journald, Nginx logs, realtime lab FIM |
| Network telemetry | Kali WSL2 | `nftables` accept-only rule, loopback source, 15 explicit TCP ports, rate limited |
| Analysis | Ubuntu 24.04 WSL2 | Wazuh Manager `4.14.8`; custom rules `100101`, `100110`-`100131` |
| Delivery | Ubuntu 24.04 WSL2 | Durable sender active; SQLite queue; dead-letter count zero |
| Application | Windows host | FastAPI, SQLite, React/TypeScript; authentication and CSRF protections unchanged |

The WSL address discovered during validation was dynamic. Its runtime value is
intentionally omitted and must never be hardcoded.

## Telemetry boundaries

- Network logging observes only TCP SYN packets entering Kali loopback from `127.0.0.1` for the explicit test port set.
- The nftables chain has `policy accept`; it does not drop or reject traffic and does not change a default firewall policy.
- WSL shares kernel journal events across distributions. The manager's local journald collector excludes `_TRANSPORT=kernel`; Kali Agent 001 remains the authoritative source for `CQ-NETSCAN` events. This prevents duplicate Agent 000 attribution.
- Nginx access and error logs are collected by Kali's Wazuh Agent.
- Realtime FIM is restricted to `/etc/cyberqalqon-lab`; broader existing periodic FIM remains unchanged.
- The Windows Wazuh Agent is not yet part of the active pipeline because it has no enrollment key
  and its protected configuration still contains a stale manager address. The running loopback-only
  relay resolves WSL address changes and was validated through to `wazuh-remoted`; elevated agent
  enrollment remains the missing step.

## Security boundaries

- All active probes target loopback. No public or unrelated private address was contacted.
- No packet-drop rule, password attack, real administrator account, malware, reverse shell, or destructive log-clearing test is used.
- Ingest authentication remains enabled. The currently valid ingest secret is stored in an existing Git-ignored, ACL-restricted local file and is not included in these documents.
- Analyst authentication, HttpOnly cookies, Origin checks, CSRF, RBAC, Argon2id hashing, and audit logging remain enabled.

## Installed lab artifacts

| Repository artifact | Runtime destination |
|---|---|
| `wazuh/configs/cyberqalqon-lab-network.nft` | Kali `/etc/nftables.d/cyberqalqon-lab-network.nft` |
| `wazuh/configs/cyberqalqon-nftables-monitor.service` | Kali `/etc/systemd/system/cyberqalqon-nftables-monitor.service` |
| `wazuh/configs/kali-fim-lab-directory.patch` | Applied to Kali `/var/ossec/etc/ossec.conf` |
| `wazuh/configs/manager-journald-no-kernel.patch` | Applied to Ubuntu `/var/ossec/etc/ossec.conf` |
| `wazuh/configs/manager-integration-rules.patch` | Applied to Ubuntu `/var/ossec/etc/ossec.conf` |
| `wazuh/rules/cyberqalqon_network_rules.xml` | Ubuntu `/var/ossec/etc/rules/` |
| `wazuh/rules/cyberqalqon_web_probe_rules.xml` | Ubuntu `/var/ossec/etc/rules/` |
| `wazuh/rules/cyberqalqon_fim_rules.xml` | Ubuntu `/var/ossec/etc/rules/` |

Numbered backups were created beside every modified WSL configuration before changes were applied.
