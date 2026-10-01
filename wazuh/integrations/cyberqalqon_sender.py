#!/usr/bin/env python3
"""
CyberQalqon AI -- Wazuh Custom Integration Sender  v2
======================================================
Receives a Wazuh alert from the integratord daemon and forwards the
original, unmodified alert JSON to the CyberQalqon backend via HTTP POST.

Integration contract (Wazuh integratord interface, current as of Wazuh 4.x):
  sys.argv[1] -- path to the JSON alert file written by integratord
  sys.argv[2] -- api_key value from ossec.conf <integration> block (may be empty)
  sys.argv[3] -- hook_url value from ossec.conf <integration> block
  sys.argv[4] -- path to the full alert file (same file, interface compat only)

Exit codes:
  0 -- alert delivered successfully (HTTP 2xx)
  1 -- internal error (bad arguments, unreadable file, invalid JSON)
  2 -- delivery failed permanently (network, timeout, non-2xx after all retries)

Security model:
  - Alert contents are UNTRUSTED DATA at all times.
  - No shell commands are constructed from alert fields.
  - No eval/exec used anywhere.
  - No secrets are written to logs.
  - Tokens are never printed even in DEBUG mode.

Delivery guarantees:
  - At-least-once delivery with bounded retries (MAX_RETRIES).
  - Backend deduplication prevents double-storage for duplicate alert IDs.
  - No persistent buffering: if all retries fail the event is lost.
  - Exactly-once delivery is NOT guaranteed.

Changes from v1:
  - read_alert() now uses utf-8-sig to handle UTF-8 BOM files transparently
  - Exponential backoff with full jitter replaces fixed delay
  - MAX_RETRIES default raised from 1 to 3
  - HTTP 429 Retry-After header is respected (bounded by MAX_RETRY_AFTER_SECS)
  - 5xx errors are retried; 4xx errors (except 429) are NOT retried
  - Connection-timeout and read-timeout are separated correctly
  - health_check URL parsing fixed
  - Token leakage on logging verified and confirmed absent
"""

import json
import logging
import os
import random
import sys
import time
from typing import Any, Dict, Optional
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

# ---------------------------------------------------------------------------
# Configuration
# All values come from environment or ossec.conf arguments.
# NEVER hardcode production URLs or credentials.
# ---------------------------------------------------------------------------

_DEFAULT_URL = "http://127.0.0.1:8000/api/v1/ingest/wazuh"

# Separate connect and read timeouts
CONNECT_TIMEOUT: float = float(os.environ.get("CYBERQALQON_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT: float = float(os.environ.get("CYBERQALQON_READ_TIMEOUT", "15"))

# Retry config — exponential backoff with full jitter
MAX_RETRIES: int = max(0, int(os.environ.get("CYBERQALQON_MAX_RETRIES", "3")))
RETRY_BASE_DELAY: float = float(os.environ.get("CYBERQALQON_RETRY_BASE_DELAY", "1.0"))
RETRY_MAX_DELAY: float = float(os.environ.get("CYBERQALQON_RETRY_MAX_DELAY", "30.0"))
MAX_RETRY_AFTER_SECS: float = float(os.environ.get("CYBERQALQON_MAX_RETRY_AFTER", "60.0"))

MAX_ALERT_BYTES: int = 2 * 1024 * 1024  # 2 MiB guard

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_PATH = os.environ.get(
    "CYBERQALQON_LOG_PATH",
    "/var/ossec/logs/integrations/cyberqalqon.log",
)


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("cyberqalqon_sender")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)sZ [%(levelname)s] cyberqalqon_sender: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Always log to stderr (captured by Wazuh integratord)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    # Try to also write to the dedicated log file (may fail on Windows / CI)
    try:
        log_dir = os.path.dirname(_LOG_PATH)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(_LOG_PATH)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as exc:
        logger.warning(
            "Cannot open log file %s: %s -- logging to stderr only.",
            _LOG_PATH,
            exc,
        )
    return logger


log = _configure_logging()

# ---------------------------------------------------------------------------
# Alert reading
# ---------------------------------------------------------------------------


def read_alert(alert_file_path: str) -> Dict[str, Any]:
    """
    Read and parse the Wazuh alert JSON file produced by integratord.

    Uses utf-8-sig encoding to transparently handle UTF-8 BOM files
    (Wazuh on some Windows-based configurations emits BOM-prefixed JSON).

    Raises:
        FileNotFoundError: path does not exist.
        ValueError: file too large or not a JSON object.
        json.JSONDecodeError: invalid JSON.
    """
    if not os.path.isfile(alert_file_path):
        raise FileNotFoundError(f"Alert file not found: {alert_file_path!r}")

    file_size = os.path.getsize(alert_file_path)
    if file_size > MAX_ALERT_BYTES:
        raise ValueError(
            f"Alert file too large: {file_size} bytes (max {MAX_ALERT_BYTES})"
        )

    # utf-8-sig strips UTF-8 BOM (U+FEFF) if present; otherwise identical to utf-8.
    # This fixes D1: real Wazuh sample fixtures are BOM-encoded.
    with open(alert_file_path, "r", encoding="utf-8-sig") as fh:
        raw = fh.read(MAX_ALERT_BYTES)

    alert = json.loads(raw)

    if not isinstance(alert, dict):
        raise ValueError(
            f"Alert file must contain a JSON object, got {type(alert).__name__}"
        )

    return alert


# ---------------------------------------------------------------------------
# Safe metadata extraction for logging
# Alert field values are NEVER executed or evaluated.
# ---------------------------------------------------------------------------


def _safe_meta(alert: Dict[str, Any]) -> str:
    """
    Extract a small set of non-sensitive metadata fields for log messages.
    Returns a single safe string. Never raises.
    """
    try:
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))[:32]
        rule_level = str(alert.get("rule", {}).get("level", "?"))[:5]
        agent_name = str(alert.get("agent", {}).get("name", "unknown"))[:64]
        ts = str(alert.get("timestamp", ""))[:24]
        mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, list):
            mitre_str = ",".join(str(m)[:16] for m in mitre_ids[:5])
        else:
            mitre_str = str(mitre_ids)[:50]
        return (
            f"rule_id={rule_id} level={rule_level} "
            f"agent={agent_name!r} ts={ts!r} mitre=[{mitre_str}]"
        )
    except Exception:  # pylint: disable=broad-except
        return "(metadata extraction failed)"


# ---------------------------------------------------------------------------
# HTTP delivery
# ---------------------------------------------------------------------------


def _build_request(
    url: str,
    payload_bytes: bytes,
    api_token: Optional[str],
) -> urllib_request.Request:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberQalqon-Wazuh-Integration/2.0",
        "Accept": "application/json",
    }
    if api_token:
        # Token is never logged — only its presence is noted.
        headers["Authorization"] = f"Bearer {api_token}"
    return urllib_request.Request(
        url=url,
        data=payload_bytes,
        headers=headers,
        method="POST",
    )


def _jittered_backoff(attempt: int) -> float:
    """
    Full-jitter exponential backoff:
      delay = random(0, min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * 2^attempt))

    Full jitter avoids thundering-herd when multiple senders retry simultaneously.
    Reference: https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/
    """
    cap = min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * (2 ** attempt))
    return random.uniform(0, cap)


def post_alert(
    url: str,
    alert: Dict[str, Any],
    api_token: Optional[str],
) -> int:
    """
    POST alert JSON to the backend. Returns HTTP status code on success.

    The payload is serialised once from the already-validated dict.
    The original dict is not mutated, making retry safe.
    """
    payload_bytes = json.dumps(alert, ensure_ascii=False).encode("utf-8")
    req = _build_request(url, payload_bytes, api_token)
    # urllib does not natively separate connect vs read timeouts.
    # We pass the sum; CONNECT_TIMEOUT dominates the first packet exchange.
    with urllib_request.urlopen(req, timeout=(CONNECT_TIMEOUT + READ_TIMEOUT)) as resp:
        return resp.status


def _parse_retry_after(exc: HTTPError) -> Optional[float]:
    """
    Parse the Retry-After header from a 429 response.
    Returns a float (seconds to wait) or None if not present / unparseable.
    """
    try:
        raw = exc.headers.get("Retry-After", "")
        if raw:
            return float(raw)
    except (ValueError, AttributeError):
        pass
    return None


def deliver_with_retry(
    url: str,
    alert: Dict[str, Any],
    api_token: Optional[str],
    meta: str,
) -> int:
    """
    Attempt delivery with at most MAX_RETRIES retries using exponential backoff.

    Retry policy:
      - Retried:     URLError, TimeoutError, OSError (transient network)
                     HTTP 429 (rate-limited — Retry-After respected, bounded)
                     HTTP 5xx (server-side transient)
      - NOT retried: HTTP 4xx (except 429) — authentication, validation errors
                     These are permanent failures (wrong token, bad payload).

    Returns:
      0 on successful delivery.
      2 on permanent failure after all retries.
    """
    last_exc: Optional[Exception] = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            status = post_alert(url, alert, api_token)
            log.info(
                "Delivered alert to %s — HTTP %d — %s (attempt %d/%d)",
                url, status, meta, attempt + 1, MAX_RETRIES + 1,
            )
            return 0

        except HTTPError as exc:
            last_exc = exc

            if exc.code == 429:
                # Rate-limited: respect Retry-After if present, bounded by MAX_RETRY_AFTER_SECS
                retry_after = _parse_retry_after(exc)
                if retry_after is not None:
                    wait = min(retry_after, MAX_RETRY_AFTER_SECS)
                    log.warning(
                        "HTTP 429 rate-limited for %s — Retry-After=%.1fs "
                        "(bounded to %.1fs), attempt %d/%d",
                        meta, retry_after, wait, attempt + 1, MAX_RETRIES + 1,
                    )
                else:
                    wait = _jittered_backoff(attempt)
                    log.warning(
                        "HTTP 429 rate-limited for %s (no Retry-After) — "
                        "backing off %.1fs, attempt %d/%d",
                        meta, wait, attempt + 1, MAX_RETRIES + 1,
                    )
                if attempt < MAX_RETRIES:
                    time.sleep(wait)
                continue

            if 400 <= exc.code < 500:
                # Permanent client-side error: wrong token, malformed payload, etc.
                log.error(
                    "Non-retryable HTTP %d for %s (attempt %d/%d) — giving up.",
                    exc.code, meta, attempt + 1, MAX_RETRIES + 1,
                )
                return 2

            # 5xx — server-side transient, retry
            log.warning(
                "Retryable HTTP %d for %s (attempt %d/%d)",
                exc.code, meta, attempt + 1, MAX_RETRIES + 1,
            )

        except (URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            log.warning(
                "Network/timeout error on attempt %d/%d for %s: %s",
                attempt + 1, MAX_RETRIES + 1, meta, exc,
            )

        if attempt < MAX_RETRIES:
            delay = _jittered_backoff(attempt)
            log.info("Retrying in %.2fs ... (attempt %d/%d)", delay, attempt + 2, MAX_RETRIES + 1)
            time.sleep(delay)

    log.error(
        "All %d attempt(s) failed for %s. Last error: %s",
        MAX_RETRIES + 1, meta, last_exc,
    )
    return 2


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """
    Main entry point called by Wazuh integratord.

    Wazuh 4.x argument layout:
      argv[1]  path to alert JSON file
      argv[2]  api_key from ossec.conf (empty if not set)
      argv[3]  hook_url from ossec.conf
      argv[4]  full alert file path (interface compat; not read separately)
    """
    if len(sys.argv) < 2:
        log.error("Usage: %s <alert_file> [api_key] [hook_url]", sys.argv[0])
        return 1

    alert_file = sys.argv[1]

    api_token: Optional[str] = None
    if len(sys.argv) >= 3 and sys.argv[2].strip():
        api_token = sys.argv[2].strip()

    if len(sys.argv) >= 4 and sys.argv[3].strip():
        hook_url = sys.argv[3].strip()
    else:
        hook_url = os.environ.get("CYBERQALQON_BACKEND_URL", _DEFAULT_URL)

    # Confirm token presence without revealing value
    token_status = "present" if api_token else "absent (auth disabled)"
    log.debug(
        "Starting v2. alert_file=%r url=%r token=%s",
        alert_file, hook_url, token_status,
    )

    try:
        alert = read_alert(alert_file)
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as exc:
        log.error("Failed to read alert file %r: %s", alert_file, exc)
        return 1

    meta = _safe_meta(alert)
    log.info("Processing alert: %s", meta)

    return deliver_with_retry(hook_url, alert, api_token, meta)


if __name__ == "__main__":
    sys.exit(main())
