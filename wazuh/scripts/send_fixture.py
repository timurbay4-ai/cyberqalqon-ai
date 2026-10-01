#!/usr/bin/env python3
"""
CyberQalqon AI -- Wazuh Fixture Sender
=======================================
Sends a sample Wazuh alert fixture to the CyberQalqon backend for
integration testing. This script is for DEVELOPMENT USE ONLY.

Usage:
  python send_fixture.py <fixture.json> --url http://127.0.0.1:8000/api/v1/ingest/wazuh
  python send_fixture.py wazuh/samples/auth_failure.json
  python send_fixture.py wazuh/samples/fim_change.json --timeout 15

Options:
  --url       Backend ingest URL (default: CYBERQALQON_BACKEND_URL env or localhost)
  --timeout   Request timeout in seconds (default: 15)
  --token     Bearer token (optional; prefer env CYBERQALQON_API_TOKEN)
  --verbose   Show full request/response details

Security:
  - No alert field values are executed.
  - Token is NOT printed in verbose mode.
"""

import argparse
import json
import os
import sys
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

_DEFAULT_URL = "http://127.0.0.1:8000/api/v1/ingest/wazuh"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a Wazuh alert fixture to the CyberQalqon backend."
    )
    parser.add_argument("fixture", help="Path to the JSON alert fixture file.")
    parser.add_argument(
        "--url",
        default=os.environ.get("CYBERQALQON_BACKEND_URL", _DEFAULT_URL),
        help="Backend ingest URL.",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="Request timeout (s).")
    parser.add_argument(
        "--token",
        default=os.environ.get("CYBERQALQON_API_TOKEN", ""),
        help="Optional Bearer token (prefer env CYBERQALQON_API_TOKEN).",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose output.")
    return parser.parse_args()


def load_fixture(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path!r}", file=sys.stderr)
        sys.exit(1)
    # utf-8-sig strips the UTF-8 BOM (U+FEFF) if present and is backward-compatible
    # with plain UTF-8 files.  The committed sample fixtures are BOM-encoded.
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        print(f"[ERROR] Fixture must be a JSON object, got {type(data).__name__}", file=sys.stderr)
        sys.exit(1)
    return data


def main() -> None:
    args = parse_args()
    alert = load_fixture(args.fixture)

    print(f"[INFO] Fixture:  {args.fixture}")
    print(f"[INFO] Target:   {args.url}")
    print(f"[INFO] Timeout:  {args.timeout}s")
    print(f"[INFO] Auth:     {'Bearer token present' if args.token else 'none'}")

    if args.verbose:
        rule_id = alert.get("rule", {}).get("id", "?")
        agent = alert.get("agent", {}).get("name", "?")
        level = alert.get("rule", {}).get("level", "?")
        mitre = alert.get("rule", {}).get("mitre", {}).get("id", [])
        print(f"[INFO] rule_id={rule_id} level={level} agent={agent!r} mitre={mitre}")

    payload = json.dumps(alert, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CyberQalqon-FixtureSender/1.0",
        "Accept": "application/json",
    }
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    req = urllib_request.Request(url=args.url, data=payload, headers=headers, method="POST")

    try:
        with urllib_request.urlopen(req, timeout=args.timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            print(f"[OK]   HTTP {resp.status} {resp.reason}")
            if args.verbose and body:
                print(f"[BODY] {body[:500]}")
    except HTTPError as exc:
        body = exc.read(1024).decode("utf-8", errors="replace")
        print(f"[FAIL] HTTP {exc.code} {exc.reason}: {body[:200]}", file=sys.stderr)
        sys.exit(2)
    except URLError as exc:
        print(f"[FAIL] Connection error: {exc.reason}", file=sys.stderr)
        sys.exit(2)
    except TimeoutError:
        print("[FAIL] Request timed out.", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
