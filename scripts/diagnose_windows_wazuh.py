"""Print a redacted, read-only Windows Wazuh Agent connectivity diagnosis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.windows_agent_diagnostics import collect_windows_diagnostic  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manager-distro", default="Ubuntu-24.04")
    args = parser.parse_args()
    result = collect_windows_diagnostic(manager_distro=args.manager_distro)
    print(json.dumps(result.redacted_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
