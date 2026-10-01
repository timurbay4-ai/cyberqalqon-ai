#!/usr/bin/env python3
"""
CyberQalqon AI -- Backend Health Check
=======================================
Checks whether the CyberQalqon backend is reachable.

Usage:
  python health_check.py
  python health_check.py --url http://127.0.0.1:8000 --timeout 5

Output:
  OK           -- backend responded with HTTP 2xx
  UNREACHABLE  -- connection refused, DNS failure, or network error
  ERROR        -- backend responded with non-2xx status or unexpected error

Exit codes:
  0 -- OK
  1 -- UNREACHABLE or ERROR
"""

import argparse
import os
import sys
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

_DEFAULT_BASE = os.environ.get("CYBERQALQON_BACKEND_URL", "http://127.0.0.1:8000")
# Strip the ingest path if full URL was provided
_BASE = _DEFAULT_BASE.rstrip("/").rstrip("/api/v1/ingest/wazuh")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check CyberQalqon backend health.")
    parser.add_argument(
        "--url",
        default=_BASE,
        help="Base URL of the CyberQalqon backend (e.g. http://127.0.0.1:8000).",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds.")
    parser.add_argument("--path", default="/health", help="Health check path.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    base = args.url.rstrip("/")
    url = f"{base}{args.path}"

    try:
        req = urllib_request.Request(url=url, method="GET")
        with urllib_request.urlopen(req, timeout=args.timeout) as resp:
            if 200 <= resp.status < 300:
                print("OK")
                sys.exit(0)
            else:
                print(f"ERROR (HTTP {resp.status})")
                sys.exit(1)
    except HTTPError as exc:
        print(f"ERROR (HTTP {exc.code})")
        sys.exit(1)
    except URLError as exc:
        print(f"UNREACHABLE ({exc.reason})")
        sys.exit(1)
    except TimeoutError:
        print("UNREACHABLE (timeout)")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR ({exc})")
        sys.exit(1)


if __name__ == "__main__":
    main()
