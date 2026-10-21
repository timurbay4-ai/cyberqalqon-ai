"""Rehearse schema 17 -> 18 on an explicit disposable database copy.

The source is opened read-only and never passed to the migration runner.  The
working copy must not already exist so an operator cannot accidentally overwrite
an evidence database.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.db.migrations import MIGRATIONS, apply_migrations  # noqa: E402


PRESERVED_TABLES = (
    "security_events",
    "alerts",
    "incidents",
    "soc_cases",
    "analysts",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _snapshot(path: Path, *, integrity: bool) -> dict[str, object]:
    uri = f"file:{path.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=30)) as connection:
        result: dict[str, object] = {
            "schema_version": int(connection.execute("PRAGMA user_version").fetchone()[0]),
            "migration_count": int(
                connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
            ),
            "foreign_key_errors": len(connection.execute("PRAGMA foreign_key_check").fetchall()),
            "counts": {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in PRESERVED_TABLES
            },
        }
        if integrity:
            result["quick_check"] = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--working-copy", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    working = args.working_copy.resolve()
    if source == working:
        raise SystemExit("source and working copy must differ")
    if not source.is_file():
        raise SystemExit("source backup does not exist")
    if working.exists():
        raise SystemExit("working copy already exists; refusing to overwrite it")
    if working.parent != (ROOT / "tmp").resolve():
        raise SystemExit("working copy must be an explicit direct child of repository tmp/")

    source_snapshot = _snapshot(source, integrity=False)
    if source_snapshot["schema_version"] != 17:
        raise SystemExit("M14 rehearsal requires a schema-17 source backup")
    working.parent.mkdir(parents=True, exist_ok=True)
    copy_started = time.perf_counter()
    shutil.copy2(source, working)
    copy_seconds = time.perf_counter() - copy_started

    migration_started = time.perf_counter()
    with closing(sqlite3.connect(working, timeout=60)) as connection, connection:
        first_versions = apply_migrations(connection)
    migration_seconds = time.perf_counter() - migration_started
    after_first = _snapshot(working, integrity=True)

    idempotency_started = time.perf_counter()
    with closing(sqlite3.connect(working, timeout=60)) as connection, connection:
        second_versions = apply_migrations(connection)
    idempotency_seconds = time.perf_counter() - idempotency_started
    after_second = _snapshot(working, integrity=False)

    result = {
        "source": str(source),
        "working_copy": str(working),
        "source_sha256": _sha256(source),
        "source_bytes": source.stat().st_size,
        "source_snapshot": source_snapshot,
        "copy_seconds": round(copy_seconds, 3),
        "migration_seconds": round(migration_seconds, 3),
        "idempotency_seconds": round(idempotency_seconds, 3),
        "first_versions": list(first_versions),
        "second_versions": list(second_versions),
        "after_first": after_first,
        "after_second": after_second,
        "latest_application_schema": len(MIGRATIONS),
        "preserved_counts": source_snapshot["counts"] == after_first["counts"],
        "idempotent": after_first == {**after_second, "quick_check": after_first["quick_check"]},
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if (
        result["preserved_counts"]
        and result["idempotent"]
        and after_first["foreign_key_errors"] == 0
        and after_first["quick_check"] == ["ok"]
        and after_first["schema_version"] == 18
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
