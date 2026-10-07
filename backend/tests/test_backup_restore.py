from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.auth import AuthRepository
from app.db.backup import BackupError, create_backup, inspect_backup, restore_backup, verify_backup
from app.db.incidents import IncidentRepository
from app.db.migrations import MIGRATIONS
from app.schemas.auth import AnalystCreate, AnalystRole
from app.schemas.incidents import IncidentCreate, IncidentSeverity
from app.services.wazuh_normalizer import normalize_wazuh_alert, raw_event_fingerprint


PASSWORD = "Backup-Test-Password-77"


def _repository(path: Path) -> AlertRepository:
    repository = AlertRepository(f"sqlite:///{path.as_posix()}")
    repository.initialize()
    return repository


def _populate(path: Path, sample_alert: dict) -> dict[str, str]:
    repository = _repository(path)
    settings = Settings(database_url=f"sqlite:///{path.as_posix()}")
    auth = AuthRepository(path, settings)
    auth.bootstrap_first_admin(
        AnalystCreate(
            username="backup-admin",
            display_name="Backup Administrator",
            password=PASSWORD,
            role=AnalystRole.ADMIN,
        )
    )
    principal = auth.authenticate("backup-admin", PASSWORD)
    assert principal is not None
    auth.create_session(principal)
    alert = normalize_wazuh_alert(sample_alert)
    repository.ingest(alert, sample_alert, raw_event_fingerprint(sample_alert))
    incident = IncidentRepository(path).create(
        IncidentCreate(
            title="Backup preservation case",
            severity=IncidentSeverity.HIGH,
            alert_ids=[alert.alert_id],
        ),
        principal,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO ai_analyses (
                analysis_id, analysis_type, target_type, target_id,
                requested_by, requested_by_display, requested_at, completed_at,
                provider, model, model_digest, policy_version, schema_version,
                context_fingerprint, context_bytes, context_truncated,
                context_metadata_json, target_updated_at, result_json
            ) VALUES (?, 'ALERT_SUMMARY', 'alert', ?, ?, ?, ?, ?, 'ollama',
                      'fake-model', 'digest', 'cyberqalqon-ai-policy-v1',
                      'ai-analysis-v1', ?, 100, 0, ?, ?, ?)
            """,
            (
                "AI-BACKUP-1",
                alert.alert_id,
                principal.analyst_id,
                principal.audit_display,
                "2026-10-07T00:00:00+00:00",
                "2026-10-07T00:00:01+00:00",
                "a" * 64,
                json.dumps(
                    {
                        "context_bytes": 100,
                        "truncated": False,
                        "alerts_included": 1,
                        "alerts_available": 1,
                        "notes_included": 0,
                        "notes_available": 0,
                        "history_included": 0,
                        "history_available": 0,
                        "raw_event_included": True,
                        "truncation_reasons": [],
                    }
                ),
                "2026-10-07T00:00:00+00:00",
                json.dumps(
                    {
                        "summary": "Preserved analysis",
                        "assessment": "Test evidence",
                        "key_evidence": [],
                        "mitre_context": [],
                        "timeline_summary": None,
                        "hypotheses": [],
                        "investigation_steps": [],
                        "possible_false_positive_reasons": [],
                        "recommended_actions": [],
                        "containment_considerations": [],
                        "uncertainties": [],
                    }
                ),
            ),
        )
    return {"alert_id": alert.alert_id, "incident_id": incident.incident_id}


def test_fresh_database_backup_has_verified_non_secret_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.db"
    _repository(source)

    artifact = create_backup(source, tmp_path, filename="fresh.db")

    assert verify_backup(artifact.database_path, artifact.metadata_path).schema_version == len(MIGRATIONS)
    metadata = artifact.metadata_path.read_text(encoding="utf-8")
    assert '"integrity_check": "ok"' in metadata
    assert '"application_version": "0.7.0"' in metadata
    assert str(source) not in metadata
    assert "password" not in metadata.lower()
    assert "api_key" not in metadata.lower()


def test_online_backup_preserves_populated_wal_database(
    tmp_path: Path, sample_alert: dict
) -> None:
    source = tmp_path / "source.db"
    identifiers = _populate(source, sample_alert)
    writer = sqlite3.connect(source)
    writer.execute("PRAGMA journal_mode = WAL")
    writer.execute(
        "UPDATE incidents SET description = ? WHERE incident_id = ?",
        ("Committed while WAL is active", identifiers["incident_id"]),
    )
    writer.commit()
    try:
        artifact = create_backup(source, tmp_path, filename="online.db")
    finally:
        writer.close()

    with sqlite3.connect(artifact.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM ai_analyses").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM analyst_sessions").fetchone()[0] == 1
        assert connection.execute(
            "SELECT description FROM incidents WHERE incident_id = ?",
            (identifiers["incident_id"],),
        ).fetchone()[0] == "Committed while WAL is active"


def test_backup_refuses_existing_invalid_or_unwritable_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.db"
    _repository(source)
    (tmp_path / "exists.db").write_bytes(b"preserve")
    with pytest.raises(BackupError, match="already exists"):
        create_backup(source, tmp_path, filename="exists.db")
    with pytest.raises(BackupError, match="does not exist"):
        create_backup(source, tmp_path / "missing")

    original_open = os.open

    def denied(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777) -> int:
        if str(path).endswith("denied.db"):
            raise PermissionError("synthetic permission failure")
        return original_open(path, flags, mode)

    monkeypatch.setattr("app.db.backup.os.open", denied)
    with pytest.raises(BackupError, match="Unable to create SQLite backup"):
        create_backup(source, tmp_path, filename="denied.db")


def test_corrupt_or_tampered_backup_is_rejected(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(BackupError, match="readable SQLite"):
        inspect_backup(corrupt)

    source = tmp_path / "source.db"
    _repository(source)
    artifact = create_backup(source, tmp_path, filename="valid.db")
    metadata = json.loads(artifact.metadata_path.read_text(encoding="utf-8"))
    metadata["sha256"] = "0" * 64
    artifact.metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(BackupError, match="metadata does not match"):
        verify_backup(artifact.database_path, artifact.metadata_path)


def test_restore_rejects_backup_changed_after_verification(
    tmp_path: Path,
    sample_alert: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.db.backup as backup_module

    source = tmp_path / "source.db"
    identifiers = _populate(source, sample_alert)
    artifact = create_backup(source, tmp_path, filename="raced.db")
    target = tmp_path / "target.db"
    _repository(target)
    original_copy = backup_module._copy_database

    def mutate_then_copy(source_path: Path, destination_path: Path) -> None:
        with sqlite3.connect(source_path) as connection:
            connection.execute(
                "UPDATE incidents SET description = ? WHERE incident_id = ?",
                ("Changed after verification", identifiers["incident_id"]),
            )
        original_copy(source_path, destination_path)

    monkeypatch.setattr(backup_module, "_copy_database", mutate_then_copy)

    with pytest.raises(BackupError, match="changed during restore preparation"):
        restore_backup(artifact.database_path, artifact.metadata_path, target, tmp_path)

    with sqlite3.connect(target) as connection:
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_restore_preserves_existing_database_migrates_and_invalidates_sessions(
    tmp_path: Path, sample_alert: dict
) -> None:
    source = tmp_path / "source.db"
    identifiers = _populate(source, sample_alert)
    artifact = create_backup(source, tmp_path, filename="restore-source.db")
    target = tmp_path / "target.db"
    _repository(target)

    result = restore_backup(artifact.database_path, artifact.metadata_path, target, tmp_path)

    assert result.safety_backup is not None
    assert verify_backup(
        result.safety_backup.database_path, result.safety_backup.metadata_path
    ).schema_version == len(MIGRATIONS)
    assert result.invalidated_sessions == 1
    with sqlite3.connect(target) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
        assert connection.execute("SELECT COUNT(*) FROM analyst_sessions").fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_id = ?", (identifiers["alert_id"],)
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE incident_id = ?", (identifiers["incident_id"],)
        ).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM ai_analyses").fetchone()[0] == 1


def test_restore_of_valid_older_schema_runs_pending_migrations(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy.db"
    with sqlite3.connect(legacy) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        for migration in MIGRATIONS[:4]:
            migration.apply(connection)
            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, '2026-10-07T00:00:00+00:00')",
                (migration.version, migration.name),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")
    artifact = create_backup(legacy, tmp_path, filename="legacy-backup.db")
    target = tmp_path / "restored.db"

    result = restore_backup(artifact.database_path, artifact.metadata_path, target, tmp_path)

    assert result.schema_version == len(MIGRATIONS)
    with sqlite3.connect(target) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ai_analyses'"
        ).fetchone()[0] == 1


def test_failed_restore_validation_does_not_replace_target(tmp_path: Path) -> None:
    target = tmp_path / "target.db"
    _repository(target)
    original_hash = inspect_backup(target).sha256
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not sqlite")
    metadata = tmp_path / "corrupt.db.json"
    metadata.write_text("{}", encoding="utf-8")

    with pytest.raises(BackupError):
        restore_backup(corrupt, metadata, target, tmp_path)

    assert inspect_backup(target).sha256 == original_hash
