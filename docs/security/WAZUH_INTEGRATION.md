# Wazuh Integration Architecture — CyberQalqon AI

**Document:** `docs/security/WAZUH_INTEGRATION.md`
**Owner:** Security Integration Lead
**Branch:** dev-wazuh

---

## Executive Summary

CyberQalqon AI integrates with Wazuh, an open-source security platform, to
receive, forward, and AI-analyze security alerts. **Wazuh performs detection.**
CyberQalqon does not replace Wazuh; it augments analyst capability through
AI-assisted investigation, incident correlation, and multilingual summaries.

---

## Architecture Diagram

```
┌──────────────────────────────────────┐
│         Monitored Endpoints          │
│  Linux servers · Windows workstations│
│         · Docker containers          │
└───────────────┬──────────────────────┘
                │  Wazuh agent heartbeat, syslog,
                │  FIM events, syscall events
                ▼
┌──────────────────────────────────────┐
│           Wazuh Manager              │
│  ┌─────────────────────────────────┐ │
│  │   Rule Engine                   │ │
│  │   • Matches 3000+ built-in rules│ │
│  │   • Custom rules (wazuh/rules/) │ │
│  │   • MITRE ATT&CK mapping        │ │
│  └──────────────┬──────────────────┘ │
│                 │ alert JSON          │
│  ┌──────────────▼──────────────────┐ │
│  │   integratord daemon            │ │
│  │   • Filters by level/group      │ │
│  │   • Writes alert file           │ │
│  └──────────────┬──────────────────┘ │
└─────────────────│────────────────────┘
                  │ executes
                  ▼
┌──────────────────────────────────────┐
│  custom-cyberqalqon (shell wrapper)  │
│  cyberqalqon_sender.py               │
│  • Reads alert JSON (read-only)      │
│  • Validates it is a JSON object     │
│  • Posts original alert unchanged    │
│  • Configurable timeout              │
│  • 1 retry maximum                   │
│  • READ → FORWARD only               │
└───────────────┬──────────────────────┘
                │  HTTP POST application/json
                │  POST /api/v1/ingest/wazuh
                ▼
┌──────────────────────────────────────┐
│       CyberQalqon Backend            │
│  (being developed on dev-backend)    │
│  • Normalizes alert                  │
│  • Correlates incidents              │
│  • Scores investigation priority     │
│  • Invokes AI engine                 │
└──────────────────────────────────────┘
```

---

## Security Principles

### 1. Wazuh Is the Detection Authority

CyberQalqon does not perform its own intrusion detection. All:
- Event collection
- Rule matching
- MITRE ATT&CK mapping
- Alert generation

…are performed by Wazuh. CyberQalqon consumes the output.

### 2. Alert Data Is Untrusted

Every field of every Wazuh alert is treated as untrusted data:
- No alert field value is passed to `eval()` or `exec()`
- No alert field value is used to construct shell commands
- No alert field value is used to construct file paths
- Alert content is JSON-encoded and forwarded; nothing more

This includes deliberately adversarial content such as:
- Prompt-injection strings in `rule.description`
- Shell metacharacters in `full_log`
- Path traversal sequences in `data.*`

All such values are treated as plain JSON strings.

### 3. No Active Response

This integration does not:
- Block firewall rules
- Disable user accounts
- Kill processes
- Isolate network interfaces
- Execute any command derived from alert content

Active response is a future feature requiring explicit design review.

### 4. Secret Management

- API tokens are never committed to Git
- The `<api_key>` field in `ossec.conf` is passed to the sender as an argument
- Tokens are never written to log files
- The integration supports optional Bearer token authentication for future use

### 5. Network Failure Safety

If the CyberQalqon backend is unavailable:
- The sender returns exit code 2 after retries
- Wazuh's security processing continues unaffected
- No data is buffered indefinitely
- No destructive fallback occurs

---

## Data Flow Details

### What Is Forwarded

The sender forwards the **complete original Wazuh alert JSON object** to the
backend without modification. This preserves:

- `rule.mitre.id` — MITRE ATT&CK technique IDs mapped by Wazuh
- `rule.level` — Wazuh severity level (1-15)
- `rule.groups` — Rule group tags
- `agent.name`, `agent.id`, `agent.ip` — Source endpoint identity
- `full_log` — Original log line (untouched)
- `timestamp` — Event timestamp from Wazuh

### What Is NOT Modified

The sender does not:
- Normalize alert fields
- Add fields
- Remove fields
- Reclassify severity
- Override MITRE IDs

The backend (dev-backend) owns all normalization.

---

## MITRE ATT&CK Preservation

Wazuh maps events to MITRE ATT&CK techniques through its rule engine.
The `rule.mitre.id` array in the forwarded JSON is the authoritative source.

The CyberQalqon sender:
- Preserves `rule.mitre.id` exactly as received
- Does NOT guess, modify, or add MITRE technique IDs
- Does NOT use AI or heuristics to reclassify events

---

## Integration File Security

| File | Location (Wazuh Manager) | Permissions | Reason |
|---|---|---|---|
| `custom-cyberqalqon` | `/var/ossec/integrations/` | `750 root:wazuh` | Executable by integratord |
| `cyberqalqon_sender.py` | `/var/ossec/integrations/` | `640 root:wazuh` | Readable by wazuh, not world |
| Log file | `/var/ossec/logs/integrations/cyberqalqon.log` | `640 root:wazuh` | Sensitive metadata |

---

## Limitations (Phase 2)

| Limitation | Notes |
|---|---|
| No TLS verification config | Backend URL should use HTTPS in production |
| No alert replay buffer | Missed alerts during backend downtime are dropped |
| Single retry | 1 retry prevents alert storms; may miss transient failures |
| No rate limiting | High-volume alert environments may need tuning |
| No alert deduplication | Backend is responsible for deduplication |
| Real Wazuh runtime test deferred | System RAM insufficient for local Wazuh stack |

---

## Backend Contract

The backend agent (dev-backend) must provide:

```
POST /api/v1/ingest/wazuh
Content-Type: application/json

Request body: raw Wazuh alert JSON object

Expected responses:
  200 OK     — alert accepted
  201 Created — alert accepted and created
  400 Bad Request — malformed alert (will not be retried)
  5xx         — server error (will be retried once)

Optional future authentication:
  Authorization: Bearer <token>
```

See `wazuh/samples/` for example request bodies.

---

## References

- [Wazuh External API Integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [CyberQalqon Shared Schemas](../../shared/schemas/)
- [Wazuh Integration README](../../wazuh/README.md)