"""Create and verify non-overwriting SQLite backups or restores."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.sqlite_backup import backup_sqlite_database, restore_sqlite_database  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("backup", "restore"):
        command = subparsers.add_parser(operation)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
    args = parser.parse_args()

    function = backup_sqlite_database if args.operation == "backup" else restore_sqlite_database
    result = function(args.source, args.destination)
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
