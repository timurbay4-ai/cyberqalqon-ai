# CyberQalqon AI — Wazuh Integration v2

**Branch:** `feature/wazuh-hardening-v1`  
**Base commit:** `b0973ef`  
**Date:** 2026-10-01  
**Engineer:** Antigravity Wazuh Integration Engineer

---

## 1. Actual Architecture

```
[Wazuh Manager integratord]
         |
         | (4 CLI args: alert_file, api_key, hook_url, full_alert_file)
         v
[custom-cyberqalqon]   ← Shell wrapper (/var/ossec/integrations/)
         |
         v
[cyberqalqon_sender.py v2]   ← Python sender
         |
         | HTTP POST JSON   Bearer <WAZUH_INGEST_TOKEN>
         v
[CyberQalqon Backend]  POST /api/v1/ingest/wazuh
         |
         v
[SQLite database]  ← raw_event preserved intact
```

**Development fixture testing path:**

```
[send_fixture.py]  (dev tool, not Wazuh integratord)
         |
         v
[CyberQalqon Backend]  POST /api/v1/ingest/wazuh
```

---

## 2. Event Delivery Sequence

1. Wazuh integratord detects an alert matching the configured `<level>` filter.
2. Writes the alert JSON to a temporary file.
3. Executes `custom-cyberqalqon <alert_file> <api_key> <hook_url> <alert_file>`.
4. Shell wrapper locates the Python interpreter and delegates to `cyberqalqon_sender.py`.
5. Sender reads the alert file using `utf-8-sig` encoding (handles UTF-8 BOM transparently).
6. Validates JSON structure (must be a dict, ≤ 2 MiB).
7. Serializes the original dict to UTF-8 JSON bytes (original data is not mutated).
8. POSTs to the configured `hook_url` with `Content-Type: application/json`.
9. If `api_key` argument is non-empty, adds `Authorization: Bearer <api_key>` header.
10. On success (HTTP 2xx) → exits 0.
11. On transient failure → retries with exponential backoff + full jitter.
12. On permanent failure (4xx, excluding 429) → exits 2 immediately (no retry).
13. After all retries exhausted → exits 2 (event is lost; no persistent buffer).

---

## 3. Authentication

| Token | Source | Scope |
|-------|--------|-------|
| `WAZUH_INGEST_TOKEN` | `ossec.conf <api_key>` field → argv[2] → `Bearer` header | Only `POST /api/v1/ingest/wazuh` |
| `API_ACCESS_TOKEN` | Backend environment only | Incident management APIs — NOT for Wazuh sender |

**Security guarantees:**
- Token values are **never** written to logs (only presence is logged: `token=present`).
- Tokens are **never** embedded in the frontend bundle.
- Wrong token → HTTP 401 → sender exits 2 immediately (no retry, no token brute-force amplification).

---

## 4. Configuration

### Environment Variables (Sender)

| Variable | Default | Description |
|----------|---------|-------------|
| `CYBERQALQON_BACKEND_URL` | `http://127.0.0.1:8000/api/v1/ingest/wazuh` | Ingest endpoint URL |
| `CYBERQALQON_CONNECT_TIMEOUT` | `5` | TCP connect timeout (seconds) |
| `CYBERQALQON_READ_TIMEOUT` | `15` | HTTP read timeout (seconds) |
| `CYBERQALQON_MAX_RETRIES` | `3` | Max retry attempts after initial failure |
| `CYBERQALQON_RETRY_BASE_DELAY` | `1.0` | Backoff base delay (seconds) |
| `CYBERQALQON_RETRY_MAX_DELAY` | `30.0` | Maximum backoff cap (seconds) |
| `CYBERQALQON_MAX_RETRY_AFTER` | `60.0` | Max seconds to honor `Retry-After` header |
| `CYBERQALQON_LOG_PATH` | `/var/ossec/logs/integrations/cyberqalqon.log` | Log file path |

### ossec.conf Integration Snippet

```xml
<!-- Add inside your existing <ossec_config> element -->
<integration>
  <name>custom-cyberqalqon</name>
  <hook_url>http://YOUR-BACKEND-HOST:8000/api/v1/ingest/wazuh</hook_url>
  <!-- Leave api_key empty if WAZUH_INGEST_TOKEN is not set on the backend -->
  <api_key>PLACEHOLDER-REPLACE-WITH-REAL-TOKEN-OR-LEAVE-EMPTY</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

> **WARNING:** Never commit real tokens to Git. The placeholder above is for documentation only.

---

## 5. Supported Retry Behavior

### v2 Policy (Implemented and Verified)

| Condition | Action |
|-----------|--------|
| `URLError` / `TimeoutError` / `OSError` | **Retry** with exponential backoff + full jitter |
| HTTP 5xx | **Retry** with exponential backoff + full jitter |
| HTTP 429 with `Retry-After` header | **Retry** after header value (bounded to `MAX_RETRY_AFTER_SECS`) |
| HTTP 429 without `Retry-After` | **Retry** with exponential backoff |
| HTTP 401 / 403 | **No retry** — exits 2 immediately |
| HTTP 400 / 422 | **No retry** — exits 2 immediately |
| Max retries exhausted | **Exits 2** — event is logged and lost |

### Backoff Formula

```
delay = random(0, min(MAX_RETRY_DELAY, BASE_DELAY × 2^attempt))
```

Full-jitter prevents thundering-herd when multiple Wazuh worker processes retry simultaneously.

### Delivery Guarantees

- **At-least-once** (with bounded retries): if retries succeed, the event is delivered.
- **Not exactly-once**: backend deduplication by `rule_id + agent_name + timestamp` prevents double-storage.
- **Not guaranteed if all retries fail**: events are logged but not buffered persistently.

---

## 6. Failure Handling

| Failure Scenario | Behavior |
|-----------------|----------|
| Backend offline | URLError → retry → eventual exit 2 + log |
| Connection timeout | TimeoutError → retry |
| Backend HTTP 500 | Retry |
| Backend HTTP 429 | Retry with Retry-After |
| Auth failure (401) | Immediate exit 2 (no retry) |
| Invalid payload (400) | Immediate exit 2 (no retry) |
| Alert file missing | Exit 1 (config error) |
| Alert file too large | Exit 1 (>2 MiB) |
| Invalid JSON | Exit 1 |
| Sender process killed | Event lost (no persistent buffer) |

---

## 7. Recovery

No persistent recovery mechanism is currently implemented. If the sender process is killed mid-retry, the event is lost. Future work (Phase 4+) could implement a local file-based queue with atomic operations.

See Section 15 (Remaining Limitations) for the implementation plan.

---

## 8. Logging

All log output goes to:
1. `stderr` (captured by Wazuh integratord and written to `/var/ossec/logs/integrations.log`)
2. The dedicated log file at `CYBERQALQON_LOG_PATH`

### Log Levels

| Level | Event |
|-------|-------|
| DEBUG | Startup parameters (file path, URL, token presence—not value) |
| INFO  | Successful delivery, retry scheduling |
| WARNING | Transient failures, retries |
| ERROR | Permanent failures, exhausted retries, file read errors |

### Safety

- Token values are **never** written to any log.
- Full alert content is **never** logged (only `rule_id`, `level`, `agent`, `timestamp`, `mitre_ids` are extracted safely).
- Log strings use `%`-style formatting — no f-string injection risk from untrusted alert data.

---

## 9. Test Commands

### Run all Wazuh unit tests (46 tests)

```powershell
cd C:\Users\user\Projects\cyberqalqon-wazuh-hardening
python -m pytest wazuh/tests/test_wazuh_integration.py -v
```

### Run M8 local integration E2E test (18 checks)

```powershell
# Requires backend running on port 8002
cd C:\Users\user\Documents\cyberqalqon-ai\backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8002

# In another shell:
cd C:\Users\user\Projects\cyberqalqon-wazuh-hardening
$env:PYTHONIOENCODING="utf-8"
python wazuh/tests/test_m8_e2e_integration.py
```

### Validate configuration files

```powershell
cd C:\Users\user\Projects\cyberqalqon-wazuh-hardening
python wazuh/scripts/validate_config.py
```

### Health check

```powershell
python wazuh/scripts/health_check.py --url http://127.0.0.1:8000
```

### Send a fixture manually (dev tool)

```powershell
python wazuh/scripts/send_fixture.py wazuh/samples/auth_failure.json --url http://127.0.0.1:8000/api/v1/ingest/wazuh --verbose
```

---

## 10. Verified Results

| Test Suite | Tests | Result |
|-----------|-------|--------|
| Unit tests (test_wazuh_integration.py) | 46 | **46 PASS** |
| M8 E2E integration (test_m8_e2e_integration.py) | 18 | **18 PASS** |
| validate_config.py snippet | 1 | **PASS** |
| validate_config.py sender | 1 | **PASS** |
| **Total** | **66** | **66 PASS** |

---

## 11. Known Limitations

1. **No persistent buffering**: If all retries fail, the event is lost. Wazuh itself provides some local buffering before calling the integration, but once the integration exits 2, the event is dropped.

2. **No exactly-once delivery**: At-least-once semantics only. Backend deduplication is the second line of defense.

3. **urllib timeout applies to full connection+read**: Python's `urllib` does not support separate connect/read timeouts natively. A future improvement using `httpx` or `requests` would allow finer control.

4. **Wazuh Manager not locally available**: All tests use synthetic fixtures. Live Wazuh Manager integration has not been tested against an authorized running manager.

5. **Single-process model**: The integration runs one process per alert (Wazuh's model). Concurrent retry for multiple simultaneous alerts is handled independently by OS process scheduling.

---

## 12. Local Demonstration Instructions

```powershell
# 1. Start the backend (auth disabled for local demo)
cd C:\Users\user\Documents\cyberqalqon-ai\backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Check backend health
python wazuh/scripts/health_check.py --url http://127.0.0.1:8000

# 3. Send sample fixtures
python wazuh/scripts/send_fixture.py wazuh/samples/auth_failure.json --verbose
python wazuh/scripts/send_fixture.py wazuh/samples/fim_change.json --verbose

# 4. Start frontend
cd C:\Users\user\Documents\cyberqalqon-ai\frontend
npm run dev

# 5. Open http://localhost:3000 — Dashboard shows real data
```

---

## 13. Future Backend Integration Requirements

For the AI Engine phase to work with this Wazuh integration:
- The `/api/v1/ingest/wazuh` contract must remain unchanged.
- `raw_event` field must continue to be preserved.
- `ai_status` field transition (`not_configured` → `pending` → `complete`) should be implemented in the backend normalization layer, not in the sender.
- The sender does not need to be modified for AI integration.
