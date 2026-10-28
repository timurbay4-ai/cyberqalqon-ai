#!/usr/bin/env python3
"""Exercise rowid FTS migration safety only on disposable schema-17 copies."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import benchmark_m26_fts_candidate as prototype  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from benchmark_cqql import INSERT_SQL, synthetic_row  # noqa: E402


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(events: int) -> dict[str, Any]:
    base = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m27-fts-migration-") as raw:
        database = Path(raw) / "source.db"
        backup = Path(raw) / "source-pre-upgrade.backup.db"
        restored = Path(raw) / "restored.db"
        AlertRepository(f"sqlite:///{database.as_posix()}", migration_target_version=17).initialize()
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            for batch_start in range(0, events, 1_000):
                connection.executemany(
                    INSERT_SQL,
                    (
                        synthetic_row(index, base)
                        for index in range(batch_start, min(events, batch_start + 1_000))
                    ),
                )
                connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            evidence_before = prototype._evidence_digest(connection)  # noqa: SLF001
            schema_before = int(connection.execute("PRAGMA user_version").fetchone()[0])
            with closing(sqlite3.connect(backup)) as target:
                connection.backup(target)

            prototype._upgrade(connection)  # noqa: SLF001
            fts_rows_after_upgrade = int(
                connection.execute("SELECT COUNT(*) FROM security_events_fts_rowid_v2").fetchone()[0]
            )
            repeat_upgrade_rejected = False
            try:
                prototype._upgrade(connection)  # noqa: SLF001
            except sqlite3.OperationalError:
                repeat_upgrade_rejected = True
                connection.rollback()
            prototype_objects_after_repeat = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name='security_events_fts_rowid_v2' "
                    "OR name LIKE 'm26_fts_rowid_%'"
                ).fetchone()[0]
            )

            probe_index = events + 100
            probe = synthetic_row(probe_index, base)
            connection.execute(INSERT_SQL, probe)
            connection.commit()
            probe_event_id = str(probe[0])
            inserted_visible = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events_fts_rowid_v2 "
                    "WHERE security_events_fts_rowid_v2 MATCH 'synthetic' AND rowid=("
                    "SELECT rowid FROM security_events WHERE event_id=?)",
                    (probe_event_id,),
                ).fetchone()[0]
            ) == 1
            connection.execute(
                "UPDATE security_events SET search_text=search_text || ' m27updatemarker' "
                "WHERE event_id=?",
                (probe_event_id,),
            )
            connection.commit()
            update_visible = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events_fts_rowid_v2 "
                    "WHERE security_events_fts_rowid_v2 MATCH 'm27updatemarker'"
                ).fetchone()[0]
            ) == 1
            connection.execute("DELETE FROM security_events WHERE event_id=?", (probe_event_id,))
            connection.commit()
            delete_visible = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events_fts_rowid_v2 "
                    "WHERE security_events_fts_rowid_v2 MATCH 'm27updatemarker'"
                ).fetchone()[0]
            ) == 0

            failed_upgrade_rolled_back = False
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE; CREATE TABLE m27_failed_upgrade(value TEXT); "
                    "INSERT INTO m27_missing_table VALUES('fail'); COMMIT;"
                )
            except sqlite3.OperationalError:
                connection.rollback()
                failed_upgrade_rolled_back = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='m27_failed_upgrade'"
                ).fetchone() is None

            evidence_with_prototype = prototype._evidence_digest(connection)  # noqa: SLF001
            quick_with_prototype = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            prototype._downgrade(connection)  # noqa: SLF001
            evidence_after_downgrade = prototype._evidence_digest(connection)  # noqa: SLF001
            quick_after_downgrade = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            schema_after = int(connection.execute("PRAGMA user_version").fetchone()[0])
            prototype_objects_after_downgrade = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name='security_events_fts_rowid_v2' "
                    "OR name LIKE 'm26_fts_rowid_%'"
                ).fetchone()[0]
            )

        with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(restored)) as target:
            source.backup(target)
        with closing(sqlite3.connect(restored)) as connection:
            restored_count = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
            restored_evidence = prototype._evidence_digest(connection)  # noqa: SLF001
            restored_quick = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            restored_foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())

        report = {
            "scope": "DISPOSABLE_ONLY",
            "live_database_opened": False,
            "events": events,
            "schema_before": schema_before,
            "schema_after": schema_after,
            "fts_rows_after_upgrade": fts_rows_after_upgrade,
            "repeat_upgrade_rejected": repeat_upgrade_rejected,
            "prototype_objects_after_repeat": prototype_objects_after_repeat,
            "failed_upgrade_rolled_back": failed_upgrade_rolled_back,
            "insert_trigger": inserted_visible,
            "update_trigger": update_visible,
            "delete_trigger": delete_visible,
            "evidence_sha256_before": evidence_before,
            "evidence_sha256_with_prototype": evidence_with_prototype,
            "evidence_sha256_after_downgrade": evidence_after_downgrade,
            "backup_sha256": file_sha256(backup),
            "restored_event_count": restored_count,
            "restored_evidence_sha256": restored_evidence,
            "quick_check_with_prototype": quick_with_prototype,
            "quick_check_after_downgrade": quick_after_downgrade,
            "quick_check_restored": restored_quick,
            "foreign_key_violations": foreign_keys,
            "restored_foreign_key_violations": restored_foreign_keys,
            "prototype_objects_after_downgrade": prototype_objects_after_downgrade,
        }
        report["pass"] = all(
            (
                schema_before == schema_after == 17,
                fts_rows_after_upgrade == events,
                repeat_upgrade_rejected,
                prototype_objects_after_repeat == 4,
                failed_upgrade_rolled_back,
                inserted_visible,
                update_visible,
                delete_visible,
                evidence_before == evidence_with_prototype == evidence_after_downgrade,
                restored_count == events,
                restored_evidence == evidence_before,
                quick_with_prototype == quick_after_downgrade == restored_quick == "ok",
                foreign_keys == restored_foreign_keys == 0,
                prototype_objects_after_downgrade == 0,
            )
        )
        return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not 1_000 <= arguments.events <= 100_000:
        parser.error("events must be between 1000 and 100000")
    report = run(arguments.events)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
