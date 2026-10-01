from pathlib import Path

import pytest
from sqlalchemy import MetaData, create_engine, text

from app.db.base import Base
from app.db.schema_verifier import create_read_only_sqlite_engine, verify_database_schema
from app.db.sqlite_backup import backup_sqlite_database, inspect_sqlite_database, restore_sqlite_database
from app.models import incident, review  # noqa: F401


def create_model_database(path: Path) -> None:
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def test_schema_verifier_accepts_exact_non_ai_schema(tmp_path):
    database = tmp_path / "exact.db"
    create_model_database(database)
    engine = create_read_only_sqlite_engine(database)
    try:
        report = verify_database_schema(engine)
    finally:
        engine.dispose()
    assert report.valid
    assert report.issues == ()


def test_schema_verifier_rejects_index_drift(tmp_path):
    database = tmp_path / "drift.db"
    create_model_database(database)
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP INDEX ix_incidents_agent_name"))
    finally:
        engine.dispose()

    read_only_engine = create_read_only_sqlite_engine(database)
    try:
        report = verify_database_schema(read_only_engine)
    finally:
        read_only_engine.dispose()
    assert not report.valid
    assert any(issue.code == "index_mismatch" for issue in report.issues)


def test_schema_verifier_rejects_column_nullability_drift(tmp_path):
    database = tmp_path / "nullable-drift.db"
    drifted_metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        table.to_metadata(drifted_metadata)
    drifted_metadata.tables["reviews"].c.note.nullable = False
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        drifted_metadata.create_all(engine)
    finally:
        engine.dispose()

    read_only_engine = create_read_only_sqlite_engine(database)
    try:
        report = verify_database_schema(read_only_engine)
    finally:
        read_only_engine.dispose()
    assert not report.valid
    assert any(issue.code == "column_nullability_mismatch" for issue in report.issues)


def test_schema_verifier_rejects_unexpected_ai_table(tmp_path):
    database = tmp_path / "ai-drift.db"
    create_model_database(database)
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE incident_analyses (incident_id VARCHAR(36) PRIMARY KEY)"))
    finally:
        engine.dispose()

    read_only_engine = create_read_only_sqlite_engine(database)
    try:
        report = verify_database_schema(read_only_engine)
    finally:
        read_only_engine.dispose()
    assert not report.valid
    assert any(issue.code == "unexpected_ai_table" for issue in report.issues)


def test_backup_and_restore_preserve_schema_and_data_without_overwrite(tmp_path):
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    restored = tmp_path / "restored.db"
    create_model_database(source)
    engine = create_engine(f"sqlite:///{source.as_posix()}")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO incidents ("
                    "id, dedupe_key, created_at, updated_at, rule_metadata, mitre_ids, "
                    "mitre_tactics, mitre_techniques, raw_event, severity, priority_score, "
                    "repetition_count, asset_importance, ai_status, review_status"
                    ") VALUES ("
                    "'incident-1', 'dedupe-1', '2026-10-01', '2026-10-01', '{}', '[]', "
                    "'[]', '[]', '{\"sensitive\":\"not-printed\"}', 'low', 3, 1, "
                    "'normal', 'not_configured', 'needs_review')"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO reviews (id, incident_id, status, analyst, note, created_at) "
                    "VALUES ('review-1', 'incident-1', 'confirmed', 'tester', 'checked', '2026-10-01')"
                )
            )
    finally:
        engine.dispose()

    backup_result = backup_sqlite_database(source, backup)
    restore_result = restore_sqlite_database(backup, restored)
    source_snapshot = inspect_sqlite_database(source)
    restored_snapshot = inspect_sqlite_database(restored)

    assert backup_result.snapshot == source_snapshot
    assert restore_result.snapshot == source_snapshot
    assert restored_snapshot == source_snapshot
    assert restored_snapshot.row_counts == {"incidents": 1, "reviews": 1}
    with pytest.raises(FileExistsError):
        backup_sqlite_database(source, backup)
