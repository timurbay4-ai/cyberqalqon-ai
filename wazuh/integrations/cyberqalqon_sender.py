#!/usr/bin/env python3
"""
CyberQalqon AI -- Wazuh Custom Integration Sender
==================================================
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
  2 -- delivery failed (network error, timeout, non-2xx response)

Security model:
  - Alert contents are UNTRUSTED DATA at all times.
  - No shell commands are constructed from alert fields.
  - No eval/exec used anywhere.
  - No secrets are written to logs.

Official reference:
  https://documentation.wazuh.com/current/user-manual/manager/
  integration-with-external-apis.html
"""

import json
import logging
import os
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

CONNECT_TIMEOUT: float = float(os.environ.get("CYBERQALQON_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT: float = float(os.environ.get("CYBERQALQON_READ_TIMEOUT", "10"))

MAX_RETRIES: int = int(os.environ.get("CYBERQALQON_MAX_RETRIES", "1"))
RETRY_DELAY: float = float(os.environ.get("CYBERQALQON_RETRY_DELAY", "2"))

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
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    try:
        log_dir = os.path.dirname(_LOG_PATH)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        fh = logging.FileHandler(_LOG_PATH)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError as exc:
        logger.warning("Cannot open log file %s: %s -- logging to stderr only.", _LOG_PATH, exc)
    return logger


log = _configure_logging()

# ---------------------------------------------------------------------------
# Alert reading
# ---------------------------------------------------------------------------


def read_alert(alert_file_path: str) -> Dict[str, Any]:
    """
    Read and parse the Wazuh alert JSON file produced by integratord.

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

    with open(alert_file_path, "r", encoding="utf-8") as fh:
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
    try:
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))
        rule_level = str(alert.get("rule", {}).get("level", "?"))
        agent_name = str(alert.get("agent", {}).get("name", "unknown"))
        ts = str(alert.get("timestamp", ""))[:24]
        mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
        if isinstance(mitre_ids, list):
            mitre_str = ",".join(str(m) for m in mitre_ids[:5])
        else:
            mitre_str = str(mitre_ids)[:50]
        return (
            f"rule_id={rule_id} level={rule_level} "
            f"agent={agent_name!r} ts={ts!r} mitre=[{mitre_str}]"
        )
    except Exception:
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
        "User-Agent": "CyberQalqon-Wazuh-Integration/1.0",
        "Accept": "application/json",
    }
    if api_token:
        # Token is not logged anywhere.
        headers["Authorization"] = f"Bearer {api_token}"
    return urllib_request.Request(
        url=url,
        data=payload_bytes,
        headers=headers,
        method="POST",
    )


def post_alert(
    url: str,
    alert: Dict[str, Any],
    api_token: Optional[str],
) -> int:
    """POST alert JSON. Returns HTTP status code on success."""
    payload_bytes = json.dumps(alert, ensure_ascii=False).encode("utf-8")
    req = _build_request(url, payload_bytes, api_token)
    with urllib_request.urlopen(req, timeout=(CONNECT_TIMEOUT + READ_TIMEOUT)) as resp:
        return resp.status


def deliver_with_retry(
    url: str,
    alert: Dict[str, Any],
    api_token: Optional[str],
    meta: str,
) -> int:
    """Attempt delivery with at most MAX_RETRIES retries. Returns 0 or 2."""
    last_exc: Optional[Exception] = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            status = post_alert(url, alert, api_token)
            log.info(
                "Delivered alert to %s -- HTTP %d -- %s (attempt %d)",
                url, status, meta, attempt + 1,
            )
            return 0
        except HTTPError as exc:
            log.warning(
                "Backend returned HTTP %d for %s (attempt %d/%d)",
                exc.code, meta, attempt + 1, MAX_RETRIES + 1,
            )
            last_exc = exc
            if 400 <= exc.code < 500:
                log.error("Non-retryable HTTP %d -- stopping. %s", exc.code, meta)
                return 2
        except (URLError, TimeoutError, OSError) as exc:
            log.warning(
                "Network error on attempt %d/%d for %s: %s",
                attempt + 1, MAX_RETRIES + 1, meta, exc,
            )
            last_exc = exc

        if attempt < MAX_RETRIES:
            log.info("Retrying in %.1fs ...", RETRY_DELAY)
            time.sleep(RETRY_DELAY)

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

    log.debug("Starting. alert_file=%r url=%r", alert_file, hook_url)

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
