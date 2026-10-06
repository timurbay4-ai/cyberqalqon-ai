"""Small, transactional, versioned SQLite migration runner."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from pydantic import ValidationError

from app.schemas.alerts import NormalizedAlert
from app.services.alert_index import alert_search_document, mitre_ids_document


class MigrationError(RuntimeError):
    """Raised when a database cannot be upgraded safely."""


MigrationOperation = Callable[[sqlite3.Connection], None]


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: MigrationOperation


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}


def _require_columns(
    connection: sqlite3.Connection,
    table: str,
    required: set[str],
) -> None:
    existing = _table_columns(connection, table)
    missing = sorted(required - existing)
    if missing:
        raise MigrationError(
            f"Existing '{table}' table is incompatible; missing columns: {', '.join(missing)}"
        )


def _migration_001_initial_alerts(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
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
    )
    _require_columns(
        connection,
        "alerts",
        {
            "alert_id",
            "fingerprint",
            "occurred_at",
            "agent_id",
            "rule_id",
            "rule_level",
            "normalized_json",
            "raw_event_json",
            "ingested_at",
        },
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_occurred_at ON alerts(occurred_at)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_level ON alerts(rule_level)")


def _migration_002_alert_read_indexes(connection: sqlite3.Connection) -> None:
    additions = {
        "agent_name": "TEXT NOT NULL DEFAULT ''",
        "has_mitre": "INTEGER NOT NULL DEFAULT 0 CHECK (has_mitre IN (0, 1))",
        "mitre_ids_text": "TEXT NOT NULL DEFAULT '|'",
        "search_text": "TEXT NOT NULL DEFAULT ''",
    }
    existing = _table_columns(connection, "alerts")
    for column, definition in additions.items():
        if column not in existing:
            connection.execute(f"ALTER TABLE alerts ADD COLUMN {column} {definition}")

    rows = connection.execute("SELECT alert_id, normalized_json FROM alerts").fetchall()
    for row in rows:
        alert_id = str(row[0])
        try:
            alert = NormalizedAlert.model_validate_json(row[1])
        except ValidationError as exc:
            raise MigrationError(
                f"Cannot migrate alert '{alert_id}': normalized JSON is invalid"
            ) from exc
        connection.execute(
            """
            UPDATE alerts
            SET occurred_at = ?, agent_name = ?, has_mitre = ?,
                mitre_ids_text = ?, search_text = ?
            WHERE alert_id = ?
            """,
            (
                alert.timestamp.astimezone(timezone.utc).isoformat(),
                alert.agent.name,
                bool(alert.mitre.ids),
                mitre_ids_document(alert),
                alert_search_document(alert),
                alert.alert_id,
            ),
        )

    _require_columns(connection, "alerts", set(additions))
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_occurred_id "
        "ON alerts(occurred_at DESC, alert_id DESC)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_agent_name ON alerts(agent_name COLLATE NOCASE)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_has_mitre ON alerts(has_mitre)")


def _migration_003_incident_foundation(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (
                severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            ),
            status TEXT NOT NULL CHECK (
                status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')
            ),
            assigned_to TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_alerts (
            incident_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY (incident_id, alert_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_notes (
            note_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            body TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            incident_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK (
                event_type IN (
                    'CREATED', 'STATUS_CHANGED', 'ALERT_LINKED',
                    'NOTE_ADDED', 'ASSIGNMENT_CHANGED'
                )
            ),
            actor TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        )
        """
    )

    _require_columns(
        connection,
        "incidents",
        {
            "incident_id",
            "title",
            "description",
            "severity",
            "status",
            "assigned_to",
            "created_at",
            "updated_at",
        },
    )
    _require_columns(
        connection,
        "incident_alerts",
        {"incident_id", "alert_id", "linked_at"},
    )
    _require_columns(
        connection,
        "incident_notes",
        {"note_id", "incident_id", "body", "author", "created_at"},
    )
    _require_columns(
        connection,
        "incident_history",
        {
            "history_id",
            "event_id",
            "incident_id",
            "event_type",
            "actor",
            "occurred_at",
            "details_json",
        },
    )

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_created_id "
        "ON incidents(created_at DESC, incident_id DESC)"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_assigned_to "
        "ON incidents(assigned_to COLLATE NOCASE)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts(alert_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_created "
        "ON incident_notes(incident_id, created_at, note_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_history_incident_order "
        "ON incident_history(incident_id, history_id)"
    )


def _migration_004_analyst_authentication(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analysts (
            analyst_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            username_normalized TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('ADMIN', 'ANALYST', 'VIEWER')),
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            failed_login_count INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
            locked_until TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_sessions (
            token_digest TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            csrf_token TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE
        )
        """
    )

    note_columns = _table_columns(connection, "incident_notes")
    if "author_id" not in note_columns:
        connection.execute(
            "ALTER TABLE incident_notes ADD COLUMN author_id TEXT "
            "REFERENCES analysts(analyst_id) ON DELETE RESTRICT"
        )
    history_columns = _table_columns(connection, "incident_history")
    if "actor_id" not in history_columns:
        connection.execute(
            "ALTER TABLE incident_history ADD COLUMN actor_id TEXT "
            "REFERENCES analysts(analyst_id) ON DELETE RESTRICT"
        )
    if "actor_display" not in history_columns:
        connection.execute("ALTER TABLE incident_history ADD COLUMN actor_display TEXT")
    connection.execute(
        "UPDATE incident_history SET actor_display = actor WHERE actor_display IS NULL"
    )

    _require_columns(
        connection,
        "analysts",
        {
            "analyst_id",
            "username",
            "username_normalized",
            "display_name",
            "role",
            "password_hash",
            "is_active",
            "failed_login_count",
            "locked_until",
            "created_at",
            "updated_at",
        },
    )
    _require_columns(
        connection,
        "analyst_sessions",
        {"token_digest", "analyst_id", "csrf_token", "created_at", "expires_at"},
    )
    _require_columns(connection, "incident_notes", {"author_id"})
    _require_columns(connection, "incident_history", {"actor_id", "actor_display"})
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_sessions_analyst "
        "ON analyst_sessions(analyst_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_sessions_expiry "
        "ON analyst_sessions(expires_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_notes_author_id "
        "ON incident_notes(author_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_history_actor_id "
        "ON incident_history(actor_id)"
    )


MIGRATIONS = (
    Migration(1, "initial_alerts", _migration_001_initial_alerts),
    Migration(2, "alert_read_indexes", _migration_002_alert_read_indexes),
    Migration(3, "incident_foundation", _migration_003_incident_foundation),
    Migration(4, "analyst_authentication", _migration_004_analyst_authentication),
)


def applied_migration_versions(connection: sqlite3.Connection) -> tuple[int, ...]:
    rows = connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    return tuple(int(row[0]) for row in rows)


def _validate_migration_history(connection: sqlite3.Connection) -> tuple[int, ...]:
    rows = connection.execute(
        "SELECT version, name FROM schema_migrations ORDER BY version"
    ).fetchall()
    applied = tuple(int(row[0]) for row in rows)
    known = {migration.version: migration.name for migration in MIGRATIONS}
    unknown = sorted(set(applied) - set(known))
    if unknown:
        raise MigrationError(
            "Database contains migration versions newer than this application: "
            + ", ".join(str(version) for version in unknown)
        )
    for row in rows:
        version = int(row[0])
        recorded_name = str(row[1])
        if recorded_name != known[version]:
            raise MigrationError(
                f"Migration {version} name drift: expected '{known[version]}', "
                f"found '{recorded_name}'"
            )
    return applied


def apply_migrations(connection: sqlite3.Connection) -> tuple[int, ...]:
    """Apply every pending migration transactionally without dropping user data."""

    versions = tuple(migration.version for migration in MIGRATIONS)
    if versions != tuple(range(1, len(MIGRATIONS) + 1)):
        raise MigrationError("Application migrations must be contiguous and start at version 1")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    connection.commit()

    applied = _validate_migration_history(connection)
    if applied and applied != tuple(range(1, max(applied) + 1)):
        raise MigrationError("Database migration history is not contiguous")

    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    current = max(applied, default=0)
    if user_version != current:
        raise MigrationError(
            f"SQLite user_version ({user_version}) disagrees with migration history ({current})"
        )

    for migration in MIGRATIONS:
        if migration.version in applied:
            continue
        try:
            connection.execute("BEGIN IMMEDIATE")
            migration.apply(connection)
            connection.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                (migration.version, migration.name, datetime.now(timezone.utc).isoformat()),
            )
            connection.execute(f"PRAGMA user_version = {migration.version}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    return applied_migration_versions(connection)
