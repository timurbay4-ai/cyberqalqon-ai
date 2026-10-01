"""Verify a SQLite database before any Alembic adoption operation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.schema_verifier import create_read_only_sqlite_engine, verify_database_schema  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("database", type=Path, help="Existing SQLite database file")
    parser.add_argument(
        "--allow-alembic-version",
        action="store_true",
        help="Allow the Alembic version table when verifying an already managed copy",
    )
    args = parser.parse_args()

    engine = create_read_only_sqlite_engine(args.database)
    try:
        report = verify_database_schema(engine, allow_alembic_version=args.allow_alembic_version)
    finally:
        engine.dispose()
    print(json.dumps(report.to_dict(), indent=2))
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
