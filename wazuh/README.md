# Wazuh Integration — CyberQalqon AI

**Owner:** Security / Integration Lead
**Branch:** dev-wazuh
**Status:** Phase 2 — Integration implemented, runtime test deferred (resource constraints)

---

## Purpose

This directory contains the complete Wazuh integration for CyberQalqon AI.

Wazuh performs all security event detection, rule matching, and MITRE ATT&CK mapping.
CyberQalqon **does not replace Wazuh**. It consumes Wazuh alerts and provides
AI-assisted analysis, incident correlation, and an analyst-facing dashboard.

---

## Architecture

```
Wazuh Agent (endpoint)
        |  syslog / FIM / syscall events
        v
Wazuh Manager
        |  rule matching, MITRE mapping
        v
integratord daemon
        |  calls custom-cyberqalqon script for each alert >= level 7
        v
wazuh/integrations/custom-cyberqalqon   (shell wrapper)
        |
        v
wazuh/integrations/cyberqalqon_sender.py (Python sender)
        |  HTTP POST application/json
        v
CyberQalqon Backend: POST /api/v1/ingest/wazuh
        |  normalization, incident correlation, scoring
        v
AI Engine + Frontend Dashboard
```

The integration is **READ → FORWARD** only:
- No firewall changes
- No account modifications
- No process termination
- No active response in this phase

---

## Directory Structure

```
wazuh/
├── integrations/
│   ├── custom-cyberqalqon          Shell wrapper (Wazuh naming requirement)
│   ├── cyberqalqon_sender.py       Python alert sender
│   └── README.md                  This file
│
├── configs/
│   ├── ossec-cyberqalqon-snippet.xml   ossec.conf addition (NOT a replacement)
│   └── README.md
│
├── rules/
│   └── README.md                  (Custom rules — future phase)
│
├── decoders/
│   └── README.md                  (Custom decoders — future phase)
│
├── scripts/
│   ├── send_fixture.py             Manual fixture sender for testing
│   ├── health_check.py             Backend reachability check
│   └── validate_config.py          Static config validator
│
└── samples/
    ├── auth_failure.json            SSH brute-force pattern (level 10)
    ├── fim_change.json              File integrity modification (level 7)
    ├── privileged_group_change.json User added to sudo group (level 8)
    └── low_severity_event.json      Normal login event (level 3)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Wazuh Manager 4.x | Installed on a Linux server |
| Python 3.6+ | Bundled at `/var/ossec/framework/python/bin/python3` or system |
| CyberQalqon Backend | Running and reachable at configured URL |
| Network access | Wazuh Manager → CyberQalqon Backend on configured port |

---

## Integration Files

### `custom-cyberqalqon` (shell wrapper)

Wazuh integratord requires the integration script to be named `custom-*`.
This is a minimal shell wrapper that delegates to `cyberqalqon_sender.py`.

### `cyberqalqon_sender.py` (Python sender)

Production-quality sender. Responsibilities:
1. Read alert JSON from the file path provided by integratord (argv[1])
2. Validate it is a JSON object
3. POST the **original, unmodified** alert to `POST /api/v1/ingest/wazuh`
4. Handle timeouts, retries, and HTTP errors
5. Log useful metadata without logging secrets

**Security properties:**
- Alert field values are NEVER executed or evaluated
- No `eval`, `exec`, `shell=True`, or `os.system` anywhere
- Configurable timeouts prevent blocking Wazuh
- Optional Bearer token supported for future backend authentication

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CYBERQALQON_BACKEND_URL` | `http://127.0.0.1:8000/api/v1/ingest/wazuh` | Backend ingest URL |
| `CYBERQALQON_CONNECT_TIMEOUT` | `5` | TCP connect timeout (seconds) |
| `CYBERQALQON_READ_TIMEOUT` | `10` | HTTP read timeout (seconds) |
| `CYBERQALQON_MAX_RETRIES` | `1` | Maximum retries (0 = no retry) |
| `CYBERQALQON_RETRY_DELAY` | `2` | Delay between retries (seconds) |
| `CYBERQALQON_LOG_PATH` | `/var/ossec/logs/integrations/cyberqalqon.log` | Log file path |
| `CYBERQALQON_API_TOKEN` | (empty) | Bearer token (send_fixture.py only) |

---

## Deployment Instructions (Linux Wazuh Manager)

> **WARNING**: These steps modify a Wazuh installation. Read each step before executing.

### 1. Copy integration files

```bash
sudo cp wazuh/integrations/custom-cyberqalqon /var/ossec/integrations/
sudo cp wazuh/integrations/cyberqalqon_sender.py /var/ossec/integrations/
```

### 2. Set permissions

```bash
sudo chown root:wazuh /var/ossec/integrations/custom-cyberqalqon
sudo chown root:wazuh /var/ossec/integrations/cyberqalqon_sender.py
sudo chmod 750 /var/ossec/integrations/custom-cyberqalqon
sudo chmod 640 /var/ossec/integrations/cyberqalqon_sender.py
```

### 3. Add integration to ossec.conf

Open `/var/ossec/etc/ossec.conf` and add the `<integration>` block from
`wazuh/configs/ossec-cyberqalqon-snippet.xml` inside `<ossec_config>`.

Update `<hook_url>` to match your CyberQalqon backend address.

### 4. Validate configuration

```bash
sudo /var/ossec/bin/wazuh-logtest -t
# Should output: Configuration correctly loaded
```

### 5. Restart Wazuh manager

```bash
sudo systemctl restart wazuh-manager
```

### 6. Verify integration is running

```bash
sudo tail -f /var/ossec/logs/integrations/cyberqalqon.log
sudo tail -f /var/ossec/logs/ossec.log | grep integratord
```

---

## Test Mode (No Real Wazuh Required)

Run tests using the local mock HTTP server:

```bash
python tests/integration/test_wazuh_sender.py
```

Send a fixture manually:

```bash
python wazuh/scripts/send_fixture.py wazuh/samples/auth_failure.json \
  --url http://127.0.0.1:8000/api/v1/ingest/wazuh --verbose
```

Check backend health:

```bash
python wazuh/scripts/health_check.py --url http://127.0.0.1:8000
```

Validate configuration files statically:

```bash
python wazuh/scripts/validate_config.py
```

---

## Alert Level Filtering

The default configuration (`<level>7</level>`) forwards alerts with Wazuh
rule level ≥ 7 (medium and above). Adjust in `ossec-cyberqalqon-snippet.xml`.

| Level | Typical meaning |
|---|---|
| 3-6 | Low / informational |
| 7-9 | Medium (default threshold) |
| 10-12 | High |
| 13-15 | Critical |

---

## MITRE Preservation

The sender forwards the original Wazuh alert JSON without modification.
Wazuh's `rule.mitre.id` array is preserved exactly.

The sender **does not**:
- Guess MITRE techniques
- Replace or augment MITRE IDs
- Apply AI classification to events

---

## Retry Behavior

| Scenario | Behavior |
|---|---|
| HTTP 2xx | Success, exit 0 |
| HTTP 4xx | Fail immediately (non-retryable), exit 2 |
| HTTP 5xx | Retry up to MAX_RETRIES times, then exit 2 |
| Connection refused | Retry up to MAX_RETRIES times, then exit 2 |
| Timeout | Retry up to MAX_RETRIES times, then exit 2 |

Default: 1 retry with 2-second delay. Maximum total wait: ~17 seconds
(5s connect + 10s read + 2s delay = 17s worst case for one retry).

Wazuh security processing is NOT affected by CyberQalqon unavailability.

---

## Troubleshooting

### Integration not executing

```bash
# Check integratord is enabled in ossec.conf
grep -A5 "integration" /var/ossec/etc/ossec.conf
# Check integratord process
sudo ps aux | grep integratord
# Check ossec.log
sudo grep -i "integrat" /var/ossec/logs/ossec.log | tail -20
```

### Permission problem

```bash
# Verify permissions
ls -la /var/ossec/integrations/custom-cyberqalqon
ls -la /var/ossec/integrations/cyberqalqon_sender.py
# Should be: -rwxr-x--- root wazuh (custom-cyberqalqon)
#            -rw-r----- root wazuh (cyberqalqon_sender.py)
```

### Backend unreachable

```bash
python wazuh/scripts/health_check.py --url http://YOUR_BACKEND:8000
# From the Wazuh Manager server:
curl -sf http://YOUR_BACKEND:8000/health
```

### Incorrect URL

```bash
# Check the hook_url in ossec.conf
grep -A10 "custom-cyberqalqon" /var/ossec/etc/ossec.conf
```

### Wazuh config validation failure

```bash
sudo /var/ossec/bin/wazuh-logtest -t 2>&1 | grep -i error
```

### Invalid JSON from integration

```bash
sudo tail -50 /var/ossec/logs/integrations/cyberqalqon.log
```

---

## Rollback

To remove the CyberQalqon integration without affecting Wazuh:

1. Remove the `<integration>` block from `/var/ossec/etc/ossec.conf`
2. `sudo systemctl restart wazuh-manager`
3. Optionally remove: `/var/ossec/integrations/custom-cyberqalqon`
   and `/var/ossec/integrations/cyberqalqon_sender.py`

All other Wazuh configuration and data remain unchanged.

---

## Security Model

- Alert data is UNTRUSTED. No alert field is executed or evaluated.
- No credentials are stored in Git.
- The integration uses an optional Bearer token (future use).
- The integration is read-forward only; no host modifications occur.
- Wazuh is the source of truth for all security detection and MITRE mapping.

---

## Known Limitations

- Windows line endings in shell wrapper are stripped at deploy time (wrapper is Linux-only)
- Log rotation of `/var/ossec/logs/integrations/cyberqalqon.log` is not configured automatically
- Real Wazuh runtime test deferred (system RAM: 7.65 GB — insufficient for local Wazuh stack)
- Backend authentication (Bearer token) is wired but not enforced in MVP

---

## References

- [Wazuh External API Integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- Shared alert schema: `shared/schemas/normalized_alert.schema.json`
- Integration assumptions recorded in: `wazuh/integrations/README.md`