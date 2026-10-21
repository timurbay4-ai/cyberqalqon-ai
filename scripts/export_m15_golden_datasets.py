"""Export deterministic M15 fixtures for offline review without touching the live database."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.detection_quality import export_golden_datasets  # noqa: E402


DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "wazuh"
    / "fixtures"
    / "advanced-detection"
    / "m15-golden-v1.json"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(REPOSITORY_ROOT):
        raise SystemExit("output must stay within the repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(
        json.dumps(export_golden_datasets(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name == "posix":
        os.chmod(temporary, 0o600)
    os.replace(temporary, output)
    print(f"PASS: exported synthetic-only M15 fixtures to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
