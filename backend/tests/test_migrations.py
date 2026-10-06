from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.db.alerts import AlertFilters, AlertRepository
from app.db.migrations import MIGRATIONS, MigrationError
from app.services.wazuh_normalizer import canonical_json, normalize_wazuh_alert, raw_event_fingerprint


LEGACY_SCHEMA = """
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_level INTEGER NOT NULL CHECK (rule_level BETWEEN 0 AND 16),
    normalized_json TEXT NOT NULL,
    raw_event_json TEXT NOT NULL,
    ingested_at TEXT NOT NULL
)
"""


def _repository(database_path: Path) -> AlertRepository:
    return AlertRepository(f"sqlite:///{database_path.as_posix()}")


def test_fresh_database_applies_every_migration(database_path: Path) -> None:
    repository = _repository(database_path)

    repository.initialize()

    with sqlite3.connect(database_path) as connection:
        versions = [row[0] for row in connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(alerts)")}
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert versions == [1, 2, 3, 4]
    assert user_version == 4
    assert {"agent_name", "has_mitre", "mitre_ids_text", "search_text"} <= columns
    with sqlite3.connect(database_path) as connection:
        incident_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'incident%'"
            )
        }
    assert {
        "incidents",
        "incident_alerts",
        "incident_notes",
        "incident_history",
    } <= incident_tables


def test_migrations_are_idempotent(database_path: Path) -> None:
    repository = _repository(database_path)

    repository.initialize()
    repository.initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 4


def test_milestone_three_database_upgrades_without_losing_incident_audit(
    database_path: Path,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for migration in MIGRATIONS[:3]:
            migration.apply(connection)
            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, ?, ?)",
                (migration.version, migration.name, "2026-10-06T00:00:00+00:00"),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")
        connection.execute(
            """
            INSERT INTO incidents VALUES (
                'INC-LEGACY', 'Existing case', '', 'HIGH', 'NEW', NULL,
                '2026-10-06T00:00:00+00:00', '2026-10-06T00:00:00+00:00'
            )
            """
        )
        connection.execute(
            "INSERT INTO incident_notes VALUES (?, ?, ?, ?, ?)",
            ("NOTE-LEGACY", "INC-LEGACY", "Preserve me", "legacy-analyst", "2026-10-06T00:01:00+00:00"),
        )
        connection.execute(
            """
            INSERT INTO incident_history (
                event_id, incident_id, event_type, actor, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("EVT-LEGACY", "INC-LEGACY", "CREATED", "legacy-analyst", "2026-10-06T00:00:00+00:00", "{}"),
        )
        connection.commit()

    _repository(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        incident = connection.execute(
            "SELECT title FROM incidents WHERE incident_id = 'INC-LEGACY'"
        ).fetchone()
        note = connection.execute(
            "SELECT body, author_id FROM incident_notes WHERE note_id = 'NOTE-LEGACY'"
        ).fetchone()
        history = connection.execute(
            "SELECT actor, actor_id, actor_display FROM incident_history WHERE event_id = 'EVT-LEGACY'"
        ).fetchone()
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert incident == ("Existing case",)
    assert note == ("Preserve me", None)
    assert history == ("legacy-analyst", None, "legacy-analyst")
    assert version == 4


def test_milestone_one_database_upgrades_without_losing_alerts(
    database_path: Path,
    sample_alert: dict,
) -> None:
    alert = normalize_wazuh_alert(sample_alert)
    normalized_json = canonical_json(alert.model_dump(mode="json", exclude_none=True))
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        for migration in MIGRATIONS[:2]:
            migration.apply(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.name, "2026-10-06T00:00:00+00:00"),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")
        connection.execute(
            """
            INSERT INTO alerts (
                alert_id, fingerprint, occurred_at, agent_id, agent_name,
                rule_id, rule_level, has_mitre, mitre_ids_text, search_text,
                normalized_json, raw_event_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                raw_event_fingerprint(sample_alert),
                alert.timestamp.astimezone(timezone.utc).isoformat(),
                alert.agent.id,
                alert.agent.name,
                alert.rule.id,
                alert.rule.level,
                bool(alert.mitre.ids),
                "|T1110|",
                "authentication",
                normalized_json,
                canonical_json(sample_alert),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    repository = _repository(database_path)
    repository.initialize()

    with sqlite3.connect(database_path) as connection:
        versions = [
            row[0]
            for row in connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )
        ]
        alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        incident_count = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert versions == [1, 2, 3, 4]
    assert user_version == 4
    assert alert_count == 1
    assert incident_count == 0
    assert repository.get(alert.alert_id) == alert


def test_legacy_ingestion_database_is_upgraded_without_losing_alerts(
    database_path: Path,
    sample_alert: dict,
) -> None:
    alert = normalize_wazuh_alert(sample_alert)
    normalized_json = canonical_json(alert.model_dump(mode="json", exclude_none=True))
    with sqlite3.connect(database_path) as connection:
        connection.execute(LEGACY_SCHEMA)
        connection.execute(
            """
            INSERT INTO alerts (
                alert_id, fingerprint, occurred_at, agent_id, rule_id, rule_level,
                normalized_json, raw_event_json, ingested_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_id,
                raw_event_fingerprint(sample_alert),
                alert.timestamp.isoformat(),
                alert.agent.id,
                alert.rule.id,
                alert.rule.level,
                normalized_json,
                canonical_json(sample_alert),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    repository = _repository(database_path)
    repository.initialize()

    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT occurred_at, agent_name, has_mitre, mitre_ids_text, search_text FROM alerts"
        ).fetchone()
        assert connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert row[0] == "2026-09-30T16:00:00.123000+00:00"
    assert row[1] == "demo-linux-host"
    assert row[2] == 1
    assert row[3] == "|T1110|"
    assert "multiple authentication failures" in row[4]
    assert repository.get(alert.alert_id) == alert
    assert repository.list(AlertFilters(search="authentication"), limit=10).total == 1


def test_incompatible_legacy_schema_fails_without_dropping_data(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO alerts (alert_id) VALUES ('preserve-me')")

    with pytest.raises(MigrationError, match="incompatible"):
        _repository(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT alert_id FROM alerts").fetchone()[0] == "preserve-me"


def test_unknown_future_migration_is_rejected(database_path: Path) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT)"
        )
        connection.execute(
            "INSERT INTO schema_migrations VALUES (99, 'future', '2026-10-06T00:00:00+00:00')"
        )
        connection.execute("PRAGMA user_version = 99")

    with pytest.raises(MigrationError, match="newer than this application"):
        _repository(database_path).initialize()


def test_user_version_mismatch_is_rejected(database_path: Path) -> None:
    repository = _repository(database_path)
    repository.initialize()
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA user_version = 1")

    with pytest.raises(MigrationError, match="disagrees with migration history"):
        repository.initialize()


def test_migration_name_drift_is_rejected(database_path: Path) -> None:
    repository = _repository(database_path)
    repository.initialize()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE schema_migrations SET name = 'changed-definition' WHERE version = 1"
        )

    with pytest.raises(MigrationError, match="name drift"):
        repository.initialize()
