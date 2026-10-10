"""Small, transactional, versioned SQLite migration runner."""

from __future__ import annotations

import hashlib
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


def _migration_005_ai_analysis_history(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ai_analyses (
            analysis_id TEXT PRIMARY KEY,
            analysis_type TEXT NOT NULL CHECK (
                analysis_type IN ('ALERT_SUMMARY', 'INCIDENT_SUMMARY', 'ANALYST_QUESTION')
            ),
            target_type TEXT NOT NULL CHECK (target_type IN ('alert', 'incident')),
            target_id TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_by_display TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            model_digest TEXT,
            policy_version TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            context_fingerprint TEXT NOT NULL,
            context_bytes INTEGER NOT NULL CHECK (context_bytes >= 0),
            context_truncated INTEGER NOT NULL CHECK (context_truncated IN (0, 1)),
            context_metadata_json TEXT NOT NULL,
            target_updated_at TEXT,
            result_json TEXT NOT NULL,
            FOREIGN KEY (requested_by) REFERENCES analysts(analyst_id) ON DELETE RESTRICT
        )
        """
    )
    _require_columns(
        connection,
        "ai_analyses",
        {
            "analysis_id", "analysis_type", "target_type", "target_id",
            "requested_by", "requested_by_display", "requested_at", "completed_at",
            "provider", "model", "model_digest", "policy_version", "schema_version",
            "context_fingerprint", "context_bytes", "context_truncated",
            "context_metadata_json", "target_updated_at", "result_json",
        },
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_analyses_target_history "
        "ON ai_analyses(target_type, target_id, completed_at DESC, analysis_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_analyses_requester "
        "ON ai_analyses(requested_by, completed_at DESC)"
    )


def _migration_006_incident_correlation(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_correlations (
            incident_id TEXT PRIMARY KEY,
            correlation_key TEXT NOT NULL UNIQUE,
            correlation_family TEXT NOT NULL,
            correlation_rule TEXT NOT NULL CHECK (
                correlation_rule IN ('CORR-001', 'CORR-002', 'CORR-003', 'CORR-004')
            ),
            classification TEXT NOT NULL,
            confidence TEXT NOT NULL CHECK (confidence IN ('EXACT_MATCH', 'STRONG_MATCH')),
            source_identity TEXT NOT NULL,
            target_identity TEXT NOT NULL,
            explanation TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            related_alert_count INTEGER NOT NULL CHECK (related_alert_count >= 2),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            auto_generated INTEGER NOT NULL DEFAULT 1 CHECK (auto_generated = 1),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS auto_correlation_alerts (
            alert_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            correlation_rule TEXT NOT NULL CHECK (
                correlation_rule IN ('CORR-001', 'CORR-002', 'CORR-003', 'CORR-004')
            ),
            linked_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incident_correlations(incident_id)
                ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT
        )
        """
    )
    _require_columns(
        connection,
        "incident_correlations",
        {
            "incident_id", "correlation_key", "correlation_family", "correlation_rule",
            "classification", "confidence", "source_identity", "target_identity",
            "explanation", "first_seen", "last_seen", "related_alert_count",
            "created_at", "updated_at", "auto_generated",
        },
    )
    _require_columns(
        connection,
        "auto_correlation_alerts",
        {"alert_id", "incident_id", "correlation_rule", "linked_at"},
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_correlation_candidates "
        "ON alerts(rule_id, occurred_at, agent_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_correlations_identity_window "
        "ON incident_correlations(correlation_family, source_identity, target_identity, last_seen)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_auto_correlation_alerts_incident "
        "ON auto_correlation_alerts(incident_id, linked_at, alert_id)"
    )


def _migration_007_correlation_candidate_index(connection: sqlite3.Connection) -> None:
    connection.execute("DROP INDEX IF EXISTS idx_alerts_correlation_candidates")
    connection.execute(
        "CREATE INDEX idx_alerts_correlation_candidates "
        "ON alerts(agent_id, occurred_at, alert_id, rule_id)"
    )


def _migration_008_security_event_store(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            event_id TEXT PRIMARY KEY,
            deduplication_id TEXT NOT NULL UNIQUE CHECK (length(deduplication_id) = 64),
            source_event_id TEXT,
            event_code TEXT,
            occurred_at TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            source_type TEXT NOT NULL CHECK (
                source_type IN (
                    'authentication', 'file_integrity', 'network', 'web',
                    'windows_event', 'wazuh_alert', 'wazuh_archive'
                )
            ),
            hostname TEXT,
            agent_id TEXT,
            agent_name TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
            destination_port INTEGER CHECK (
                destination_port IS NULL OR destination_port BETWEEN 1 AND 65535
            ),
            username TEXT,
            event_category TEXT,
            event_action TEXT,
            outcome TEXT,
            rule_id TEXT,
            severity INTEGER CHECK (severity IS NULL OR severity BETWEEN 0 AND 16),
            message TEXT NOT NULL,
            structured_json TEXT NOT NULL,
            raw_event_json TEXT NOT NULL,
            ingestion_source TEXT NOT NULL,
            related_alert_id TEXT,
            raw_size_bytes INTEGER NOT NULL CHECK (raw_size_bytes >= 2),
            search_text TEXT NOT NULL
        )
        """
    )
    _require_columns(
        connection,
        "security_events",
        {
            "event_id", "deduplication_id", "source_event_id", "event_code",
            "occurred_at", "ingested_at", "source_type", "hostname", "agent_id",
            "agent_name", "source_ip", "destination_ip", "source_port",
            "destination_port", "username", "event_category", "event_action",
            "outcome", "rule_id", "severity", "message", "structured_json",
            "raw_event_json", "ingestion_source", "related_alert_id",
            "raw_size_bytes", "search_text",
        },
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS security_event_store_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            last_retention_at TEXT
        )
        """
    )
    connection.execute(
        "INSERT OR IGNORE INTO security_event_store_state(singleton, last_retention_at) "
        "VALUES (1, NULL)"
    )

    rows = connection.execute(
        "SELECT alert_id, normalized_json, raw_event_json, ingested_at FROM alerts"
    ).fetchall()
    for row in rows:
        alert = NormalizedAlert.model_validate_json(row["normalized_json"])
        raw_canonical = str(row["raw_event_json"])
        fingerprint = hashlib.sha256(raw_canonical.encode("utf-8")).hexdigest()
        event_id = f"EVT-{fingerprint[:24].upper()}"
        normalized_json = str(row["normalized_json"])
        event_category = alert.rule.groups[0] if alert.rule.groups else None
        event_code = alert.windows.event_id if alert.windows else None
        hostname = alert.windows.computer if alert.windows and alert.windows.computer else alert.agent.name
        values = [
            event_id,
            str(row["alert_id"]),
            event_code,
            alert.timestamp.isoformat(),
            str(row["ingested_at"]),
            "wazuh_alert",
            hostname,
            alert.agent.id,
            alert.agent.name,
            str(alert.source.ip) if alert.source and alert.source.ip else None,
            str(alert.destination.ip) if alert.destination and alert.destination.ip else None,
            alert.source.port if alert.source else None,
            alert.destination.port if alert.destination else None,
            alert.user,
            event_category,
            alert.rule.id,
            alert.rule.level,
            alert.rule.description,
            "alert_backfill",
        ]
        search_text = " ".join(str(value) for value in values if value is not None).casefold()
        connection.execute(
            """
            INSERT OR IGNORE INTO security_events (
                event_id, deduplication_id, source_event_id, event_code,
                occurred_at, ingested_at, source_type, hostname, agent_id, agent_name,
                source_ip, destination_ip, source_port, destination_port, username,
                event_category, event_action, outcome, rule_id, severity, message,
                structured_json, raw_event_json, ingestion_source, related_alert_id,
                raw_size_bytes, search_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                fingerprint,
                str(row["alert_id"]),
                event_code,
                alert.timestamp.isoformat(),
                str(row["ingested_at"]),
                "wazuh_alert",
                hostname,
                alert.agent.id,
                alert.agent.name,
                str(alert.source.ip) if alert.source and alert.source.ip else None,
                str(alert.destination.ip) if alert.destination and alert.destination.ip else None,
                alert.source.port if alert.source else None,
                alert.destination.port if alert.destination else None,
                alert.user,
                event_category,
                alert.rule.id,
                alert.rule.level,
                alert.rule.description,
                normalized_json,
                normalized_json,
                "alert_backfill",
                str(row["alert_id"]),
                len(normalized_json.encode("utf-8")),
                search_text,
            ),
        )

    indexes = (
        "CREATE INDEX IF NOT EXISTS idx_security_events_occurred_id "
        "ON security_events(occurred_at DESC, event_id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_ingested "
        "ON security_events(ingested_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_source_type "
        "ON security_events(source_type, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_hostname "
        "ON security_events(hostname COLLATE NOCASE, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_agent "
        "ON security_events(agent_id, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_source_ip "
        "ON security_events(source_ip, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_destination_ip "
        "ON security_events(destination_ip, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_username "
        "ON security_events(username COLLATE NOCASE, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_event_code "
        "ON security_events(event_code, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_rule "
        "ON security_events(rule_id, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_severity "
        "ON security_events(severity, occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_security_events_related_alert "
        "ON security_events(related_alert_id)",
    )
    for statement in indexes:
        connection.execute(statement)

    try:
        connection.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS security_events_fts "
            "USING fts5(event_id UNINDEXED, search_text, tokenize='unicode61 remove_diacritics 2')"
        )
        connection.execute("DELETE FROM security_events_fts")
        connection.execute(
            "INSERT INTO security_events_fts(event_id, search_text) "
            "SELECT event_id, search_text FROM security_events"
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS security_events_fts_insert
            AFTER INSERT ON security_events BEGIN
                INSERT INTO security_events_fts(event_id, search_text)
                VALUES (new.event_id, new.search_text);
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS security_events_fts_delete
            AFTER DELETE ON security_events BEGIN
                DELETE FROM security_events_fts WHERE event_id = old.event_id;
            END
            """
        )
        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS security_events_fts_update
            AFTER UPDATE OF search_text ON security_events BEGIN
                DELETE FROM security_events_fts WHERE event_id = old.event_id;
                INSERT INTO security_events_fts(event_id, search_text)
                VALUES (new.event_id, new.search_text);
            END
            """
        )
    except sqlite3.OperationalError as exc:
        if "fts5" not in str(exc).casefold():
            raise


def _migration_009_siem_v02_operations(connection: sqlite3.Connection) -> None:
    """Add bounded analyst preferences, audit evidence, and measured search indexes."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_event_searches (
            saved_search_id TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            query_json TEXT NOT NULL CHECK (length(query_json) BETWEEN 2 AND 8192),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE,
            UNIQUE (analyst_id, name COLLATE NOCASE)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audit_events (
            audit_id TEXT PRIMARY KEY,
            action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
            actor_id TEXT,
            actor_display TEXT NOT NULL CHECK (length(actor_display) BETWEEN 1 AND 256),
            target_type TEXT NOT NULL CHECK (length(target_type) BETWEEN 1 AND 64),
            target_id TEXT,
            outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 8192),
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    _require_columns(
        connection,
        "saved_event_searches",
        {"saved_search_id", "analyst_id", "name", "query_json", "created_at", "updated_at"},
    )
    _require_columns(
        connection,
        "security_audit_events",
        {
            "audit_id", "action", "actor_id", "actor_display", "target_type",
            "target_id", "outcome", "occurred_at", "details_json",
        },
    )
    state_columns = _table_columns(connection, "security_event_store_state")
    if "last_deleted_count" not in state_columns:
        connection.execute(
            "ALTER TABLE security_event_store_state ADD COLUMN "
            "last_deleted_count INTEGER NOT NULL DEFAULT 0 CHECK (last_deleted_count >= 0)"
        )
    if "retained_records" not in state_columns:
        connection.execute(
            "ALTER TABLE security_event_store_state ADD COLUMN "
            "retained_records INTEGER NOT NULL DEFAULT 0 CHECK (retained_records >= 0)"
        )
    connection.execute(
        "UPDATE security_event_store_state SET retained_records = "
        "(SELECT COUNT(*) FROM security_events) WHERE singleton = 1"
    )

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_saved_event_searches_owner_order "
        "ON saved_event_searches(analyst_id, updated_at DESC, saved_search_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_audit_order "
        "ON security_audit_events(occurred_at DESC, audit_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_audit_actor_order "
        "ON security_audit_events(actor_id, occurred_at DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_audit_action_order "
        "ON security_audit_events(action, occurred_at DESC)"
    )

    # The v0.1 indexes omitted the event-id tiebreaker used by keyset pagination.
    # Rebuilding the bounded store indexes prevents temporary sort B-trees for
    # the common exact-match filters measured during the v0.2 audit.
    ordered_indexes = {
        "idx_security_events_source_type": "source_type, occurred_at DESC, event_id DESC",
        "idx_security_events_hostname": "hostname COLLATE NOCASE, occurred_at DESC, event_id DESC",
        "idx_security_events_agent": "agent_id, occurred_at DESC, event_id DESC",
        "idx_security_events_source_ip": "source_ip, occurred_at DESC, event_id DESC",
        "idx_security_events_destination_ip": "destination_ip, occurred_at DESC, event_id DESC",
        "idx_security_events_username": "username COLLATE NOCASE, occurred_at DESC, event_id DESC",
        "idx_security_events_event_code": "event_code, occurred_at DESC, event_id DESC",
        "idx_security_events_rule": "rule_id, occurred_at DESC, event_id DESC",
        "idx_security_events_severity": "severity, occurred_at DESC, event_id DESC",
        "idx_security_events_related_alert": "related_alert_id, occurred_at DESC, event_id DESC",
    }
    for name, columns in ordered_indexes.items():
        connection.execute(f"DROP INDEX IF EXISTS {name}")
        connection.execute(f"CREATE INDEX {name} ON security_events({columns})")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_events_category "
        "ON security_events(event_category COLLATE NOCASE, occurred_at DESC, event_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_security_events_outcome "
        "ON security_events(outcome COLLATE NOCASE, occurred_at DESC, event_id DESC)"
    )


def _migration_010_soc_alert_workflows(connection: sqlite3.Connection) -> None:
    """Add durable, auditable alert triage and per-analyst notifications."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_workflows (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK (
                status IN (
                    'NEW', 'ACKNOWLEDGED', 'IN_PROGRESS',
                    'RESOLVED', 'FALSE_POSITIVE'
                )
            ),
            assigned_to TEXT,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_activity_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_notes (
            note_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4096),
            author_id TEXT,
            author_display TEXT NOT NULL CHECK (length(author_display) BETWEEN 1 AND 256),
            created_at TEXT NOT NULL,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_history (
            history_id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            alert_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK (
                event_type IN ('STATUS_CHANGED', 'ASSIGNMENT_CHANGED', 'NOTE_ADDED')
            ),
            actor_id TEXT,
            actor_display TEXT NOT NULL CHECK (length(actor_display) BETWEEN 1 AND 256),
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 8192),
            version INTEGER NOT NULL CHECK (version >= 2),
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_notifications (
            notification_id TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            category TEXT NOT NULL CHECK (
                category IN (
                    'CRITICAL_ALERT', 'HIGH_ALERT',
                    'ALERT_ASSIGNED', 'INCIDENT_ASSIGNED'
                )
            ),
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
            preview TEXT NOT NULL CHECK (length(preview) BETWEEN 1 AND 320),
            target_type TEXT NOT NULL CHECK (target_type IN ('alert', 'incident')),
            target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
            event_key TEXT NOT NULL CHECK (length(event_key) BETWEEN 1 AND 512),
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE,
            UNIQUE (analyst_id, event_key)
        )
        """
    )

    _require_columns(
        connection,
        "alert_workflows",
        {
            "alert_id", "status", "assigned_to", "version", "created_at",
            "updated_at", "last_activity_at",
        },
    )
    _require_columns(
        connection,
        "alert_notes",
        {"note_id", "alert_id", "body", "author_id", "author_display", "created_at"},
    )
    _require_columns(
        connection,
        "alert_history",
        {
            "history_id", "event_id", "alert_id", "event_type", "actor_id",
            "actor_display", "occurred_at", "details_json", "version",
        },
    )
    _require_columns(
        connection,
        "analyst_notifications",
        {
            "notification_id", "analyst_id", "category", "title", "preview",
            "target_type", "target_id", "event_key", "created_at", "read_at",
        },
    )

    # Historical alerts receive only a neutral NEW workflow projection. No analyst
    # action, history entry, or notification is fabricated during backfill.
    connection.execute(
        """
        INSERT OR IGNORE INTO alert_workflows (
            alert_id, status, assigned_to, version,
            created_at, updated_at, last_activity_at
        )
        SELECT alert_id, 'NEW', NULL, 1, ingested_at, ingested_at, ingested_at
        FROM alerts
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_workflows_status_activity "
        "ON alert_workflows(status, last_activity_at DESC, alert_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_workflows_assignee_activity "
        "ON alert_workflows(assigned_to, last_activity_at DESC, alert_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_notes_alert_order "
        "ON alert_notes(alert_id, created_at, note_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_history_alert_order "
        "ON alert_history(alert_id, history_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_owner_order "
        "ON analyst_notifications(analyst_id, created_at DESC, notification_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_owner_unread "
        "ON analyst_notifications(analyst_id, read_at, created_at DESC)"
    )


def _migration_011_investigation_workspace(connection: sqlite3.Connection) -> None:
    """Add durable incident investigation state and isolated analyst preferences."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_checklist_items (
            checklist_item_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 1024),
            is_completed INTEGER NOT NULL DEFAULT 0 CHECK (is_completed IN (0, 1)),
            assigned_to TEXT,
            position INTEGER NOT NULL CHECK (position >= 0),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            created_by TEXT,
            updated_by TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (updated_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            UNIQUE (incident_id, position)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_evidence_pins (
            evidence_pin_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL CHECK (
                evidence_type IN ('EVENT', 'ALERT', 'INCIDENT_EVIDENCE')
            ),
            evidence_id TEXT NOT NULL CHECK (length(evidence_id) BETWEEN 1 AND 255),
            annotation TEXT NOT NULL DEFAULT '' CHECK (length(annotation) <= 4096),
            source_timestamp TEXT NOT NULL,
            pinned_by TEXT,
            pinned_by_display TEXT NOT NULL CHECK (length(pinned_by_display) BETWEEN 1 AND 256),
            pinned_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
            FOREIGN KEY (pinned_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            UNIQUE (incident_id, evidence_type, evidence_id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_investigation_activity (
            activity_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            activity_type TEXT NOT NULL CHECK (length(activity_type) BETWEEN 1 AND 64),
            entity_type TEXT NOT NULL CHECK (entity_type IN ('checklist', 'evidence')),
            entity_id TEXT NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 255),
            actor_id TEXT,
            actor_display TEXT NOT NULL CHECK (length(actor_display) BETWEEN 1 AND 256),
            action_at TEXT NOT NULL,
            source_timestamp TEXT,
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 8192),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_preferences (
            analyst_id TEXT PRIMARY KEY,
            dashboard_range TEXT NOT NULL DEFAULT '24h' CHECK (
                dashboard_range IN ('24h', '7d', '30d')
            ),
            discover_page_size INTEGER NOT NULL DEFAULT 25 CHECK (
                discover_page_size IN (25, 50, 100)
            ),
            alert_page_size INTEGER NOT NULL DEFAULT 25 CHECK (
                alert_page_size IN (25, 50, 100)
            ),
            incident_page_size INTEGER NOT NULL DEFAULT 25 CHECK (
                incident_page_size IN (25, 50, 100)
            ),
            table_density TEXT NOT NULL DEFAULT 'COMFORTABLE' CHECK (
                table_density IN ('COMFORTABLE', 'COMPACT')
            ),
            time_display TEXT NOT NULL DEFAULT 'LOCAL' CHECK (
                time_display IN ('LOCAL', 'UTC', 'RELATIVE')
            ),
            alert_default_sort TEXT NOT NULL DEFAULT 'time_desc' CHECK (
                alert_default_sort IN (
                    'time_desc', 'time_asc', 'severity_desc',
                    'severity_asc', 'activity_desc'
                )
            ),
            discover_columns_json TEXT NOT NULL DEFAULT
                '["time","source","host","identity","rule","event"]'
                CHECK (length(discover_columns_json) BETWEEN 2 AND 512),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            updated_at TEXT NOT NULL,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE
        )
        """
    )

    now = datetime.now(timezone.utc).isoformat()
    connection.execute(
        """
        INSERT OR IGNORE INTO analyst_preferences (analyst_id, updated_at)
        SELECT analyst_id, ? FROM analysts
        """,
        (now,),
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_checklist_incident_order "
        "ON incident_checklist_items(incident_id, position, checklist_item_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_incident_order "
        "ON incident_evidence_pins(incident_id, pinned_at DESC, evidence_pin_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_investigation_activity_order "
        "ON incident_investigation_activity(incident_id, action_at DESC, activity_id DESC)"
    )


def _migration_012_detection_engineering(connection: sqlite3.Connection) -> None:
    """Add local rule-draft, saved-hunt, and IOC metadata without changing detections."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_rule_drafts (
            draft_id TEXT PRIMARY KEY,
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
            description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 2048),
            severity INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 16),
            source_type TEXT NOT NULL CHECK (length(source_type) BETWEEN 1 AND 64),
            mitre_ids_json TEXT NOT NULL CHECK (length(mitre_ids_json) BETWEEN 2 AND 1024),
            conditions_json TEXT NOT NULL CHECK (length(conditions_json) BETWEEN 2 AND 8192),
            documentation TEXT NOT NULL DEFAULT '' CHECK (length(documentation) <= 8192),
            status TEXT NOT NULL CHECK (
                status IN ('DRAFT', 'VALIDATED', 'TESTED', 'READY_FOR_MANUAL_DEPLOYMENT')
            ),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            owner_analyst_id TEXT,
            owner_display TEXT NOT NULL CHECK (length(owner_display) BETWEEN 1 AND 256),
            last_tested_at TEXT,
            last_test_match_count INTEGER CHECK (
                last_test_match_count IS NULL OR last_test_match_count >= 0
            ),
            last_test_execution_ms REAL CHECK (
                last_test_execution_ms IS NULL OR last_test_execution_ms >= 0
            ),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (owner_analyst_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS detection_rule_versions (
            version_id TEXT PRIMARY KEY,
            draft_id TEXT NOT NULL,
            version_number INTEGER NOT NULL CHECK (version_number >= 1),
            snapshot_json TEXT NOT NULL CHECK (length(snapshot_json) BETWEEN 2 AND 16384),
            change_summary TEXT NOT NULL CHECK (length(change_summary) BETWEEN 1 AND 512),
            actor_id TEXT,
            actor_display TEXT NOT NULL CHECK (length(actor_display) BETWEEN 1 AND 256),
            created_at TEXT NOT NULL,
            FOREIGN KEY (draft_id) REFERENCES detection_rule_drafts(draft_id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            UNIQUE (draft_id, version_number)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS saved_hunts (
            saved_hunt_id TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
            query_json TEXT NOT NULL CHECK (length(query_json) BETWEEN 2 AND 4096),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc_indicators (
            indicator_id TEXT PRIMARY KEY,
            indicator_type TEXT NOT NULL CHECK (
                indicator_type IN ('IPV4', 'IPV6', 'DOMAIN', 'FILE_HASH')
            ),
            normalized_value TEXT NOT NULL CHECK (length(normalized_value) BETWEEN 1 AND 512),
            hash_algorithm TEXT CHECK (
                hash_algorithm IS NULL OR hash_algorithm IN ('MD5', 'SHA1', 'SHA256')
            ),
            source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 255),
            confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
            description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 2048),
            expires_at TEXT,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            created_by TEXT,
            updated_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (updated_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            UNIQUE (indicator_type, normalized_value)
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_detection_drafts_updated "
        "ON detection_rule_drafts(updated_at DESC, draft_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_detection_versions_draft "
        "ON detection_rule_versions(draft_id, version_number DESC)"
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_saved_hunts_owner_name "
        "ON saved_hunts(analyst_id, name COLLATE NOCASE)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_saved_hunts_owner_updated "
        "ON saved_hunts(analyst_id, updated_at DESC, saved_hunt_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ioc_active_type_value "
        "ON ioc_indicators(is_active, indicator_type, normalized_value)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ioc_expiration "
        "ON ioc_indicators(expires_at, indicator_id)"
    )


def _migration_013_operational_reliability(connection: sqlite3.Connection) -> None:
    """Persist bounded operational state transitions and per-analyst notices."""

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS operational_component_state (
            component_key TEXT PRIMARY KEY CHECK (length(component_key) BETWEEN 1 AND 128),
            component_kind TEXT NOT NULL CHECK (
                component_kind IN (
                    'manager', 'wazuh_api', 'sender', 'event_shipper',
                    'windows_agent', 'database'
                )
            ),
            state TEXT NOT NULL CHECK (
                state IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'UNKNOWN')
            ),
            authority TEXT NOT NULL CHECK (
                authority IN (
                    'WAZUH_API', 'OS_SERVICE_MANAGER', 'DURABLE_SENDER_STATE',
                    'DURABLE_SHIPPER_STATE', 'APPLICATION_DATABASE'
                )
            ),
            summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 320),
            metrics_json TEXT NOT NULL CHECK (length(metrics_json) BETWEEN 2 AND 16384),
            last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 512),
            observed_at TEXT NOT NULL,
            first_observed_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS operational_events (
            event_id TEXT PRIMARY KEY,
            component_key TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK (
                event_type IN ('ISSUE', 'RECOVERY', 'STATUS_CHANGE')
            ),
            severity TEXT NOT NULL CHECK (
                severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            ),
            previous_state TEXT CHECK (
                previous_state IS NULL OR
                previous_state IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'UNKNOWN')
            ),
            current_state TEXT NOT NULL CHECK (
                current_state IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'UNKNOWN')
            ),
            authority TEXT NOT NULL CHECK (
                authority IN (
                    'WAZUH_API', 'OS_SERVICE_MANAGER', 'DURABLE_SENDER_STATE',
                    'DURABLE_SHIPPER_STATE', 'APPLICATION_DATABASE'
                )
            ),
            summary TEXT NOT NULL CHECK (length(summary) BETWEEN 1 AND 320),
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 8192),
            deduplication_key TEXT NOT NULL UNIQUE CHECK (
                length(deduplication_key) BETWEEN 1 AND 256
            ),
            occurred_at TEXT NOT NULL,
            FOREIGN KEY (component_key) REFERENCES operational_component_state(component_key)
                ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_operational_events_order "
        "ON operational_events(occurred_at DESC, event_id DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_operational_events_component "
        "ON operational_events(component_key, occurred_at DESC)"
    )

    # Expand the existing per-analyst notification contract without fabricating
    # or dropping prior alert/incident notification history.
    connection.execute(
        """
        CREATE TABLE analyst_notifications_v13 (
            notification_id TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            category TEXT NOT NULL CHECK (
                category IN (
                    'CRITICAL_ALERT', 'HIGH_ALERT', 'ALERT_ASSIGNED',
                    'INCIDENT_ASSIGNED', 'OPERATIONAL_ISSUE',
                    'OPERATIONAL_RECOVERY'
                )
            ),
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
            preview TEXT NOT NULL CHECK (length(preview) BETWEEN 1 AND 320),
            target_type TEXT NOT NULL CHECK (
                target_type IN ('alert', 'incident', 'operational')
            ),
            target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
            event_key TEXT NOT NULL CHECK (length(event_key) BETWEEN 1 AND 512),
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE,
            UNIQUE (analyst_id, event_key)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO analyst_notifications_v13 (
            notification_id, analyst_id, category, title, preview,
            target_type, target_id, event_key, created_at, read_at
        )
        SELECT notification_id, analyst_id, category, title, preview,
               target_type, target_id, event_key, created_at, read_at
        FROM analyst_notifications
        """
    )
    connection.execute("DROP TABLE analyst_notifications")
    connection.execute("ALTER TABLE analyst_notifications_v13 RENAME TO analyst_notifications")
    connection.execute(
        "CREATE INDEX idx_notifications_owner_order "
        "ON analyst_notifications(analyst_id, created_at DESC, notification_id DESC)"
    )
    connection.execute(
        "CREATE INDEX idx_notifications_owner_unread "
        "ON analyst_notifications(analyst_id, read_at, created_at DESC)"
    )


def _migration_014_case_management(connection: sqlite3.Connection) -> None:
    """Add durable SOC cases, evidence custody, playbooks, SLA, and report history."""

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS soc_cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
            description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 8192),
            severity TEXT NOT NULL CHECK (
                severity IN ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            ),
            priority TEXT NOT NULL CHECK (priority IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            status TEXT NOT NULL CHECK (
                status IN ('OPEN', 'TRIAGING', 'INVESTIGATING', 'WAITING', 'RESOLVED', 'CLOSED')
            ),
            owner_id TEXT,
            source_type TEXT NOT NULL CHECK (source_type IN ('MANUAL', 'ALERT', 'INCIDENT')),
            source_id TEXT,
            resolution TEXT NOT NULL DEFAULT '' CHECK (length(resolution) <= 8192),
            closure_reason TEXT NOT NULL DEFAULT '' CHECK (length(closure_reason) <= 4096),
            created_by TEXT,
            created_by_display TEXT NOT NULL CHECK (length(created_by_display) BETWEEN 1 AND 256),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            first_response_at TEXT,
            resolved_at TEXT,
            closed_at TEXT,
            response_due_at TEXT NOT NULL,
            resolution_due_at TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            CHECK (
                (source_type = 'MANUAL' AND source_id IS NULL) OR
                (source_type IN ('ALERT', 'INCIDENT') AND source_id IS NOT NULL)
            ),
            FOREIGN KEY (owner_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (created_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_alerts (
            case_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            linked_by TEXT,
            linked_by_display TEXT NOT NULL,
            PRIMARY KEY (case_id, alert_id),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT,
            FOREIGN KEY (linked_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_incidents (
            case_id TEXT NOT NULL,
            incident_id TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            linked_by TEXT,
            linked_by_display TEXT NOT NULL,
            PRIMARY KEY (case_id, incident_id),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE RESTRICT,
            FOREIGN KEY (linked_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_events (
            case_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            linked_by TEXT,
            linked_by_display TEXT NOT NULL,
            PRIMARY KEY (case_id, event_id),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (event_id) REFERENCES security_events(event_id) ON DELETE RESTRICT,
            FOREIGN KEY (linked_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_comments (
            comment_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            comment_type TEXT NOT NULL CHECK (comment_type IN ('COMMENT', 'HANDOFF')),
            body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 4096),
            author_id TEXT,
            author_display TEXT NOT NULL,
            from_owner_id TEXT,
            to_owner_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (from_owner_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (to_owner_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_activity (
            activity_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            activity_type TEXT NOT NULL CHECK (length(activity_type) BETWEEN 1 AND 64),
            actor_id TEXT,
            actor_display TEXT NOT NULL,
            entity_type TEXT NOT NULL CHECK (length(entity_type) BETWEEN 1 AND 64),
            entity_id TEXT NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 255),
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 16384),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_evidence_refs (
            evidence_ref_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            reference_type TEXT NOT NULL CHECK (reference_type IN ('ALERT', 'EVENT', 'INCIDENT')),
            reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 255),
            source_label TEXT NOT NULL CHECK (length(source_label) BETWEEN 1 AND 320),
            source_timestamp TEXT NOT NULL,
            acquisition_method TEXT NOT NULL CHECK (acquisition_method = 'DATABASE_REFERENCE'),
            digest_algorithm TEXT NOT NULL CHECK (digest_algorithm = 'SHA-256'),
            digest TEXT NOT NULL CHECK (length(digest) = 64),
            integrity_status TEXT NOT NULL CHECK (
                integrity_status IN ('VERIFIED', 'MISMATCH', 'UNAVAILABLE')
            ),
            acquired_by TEXT,
            acquired_by_display TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            last_verified_at TEXT NOT NULL,
            annotation TEXT NOT NULL DEFAULT '' CHECK (length(annotation) <= 4096),
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            UNIQUE (case_id, reference_type, reference_id),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (acquired_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_custody_events (
            custody_event_id TEXT PRIMARY KEY,
            evidence_ref_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK (
                event_type IN ('ACQUIRED', 'VERIFIED', 'MISMATCH', 'UNAVAILABLE', 'ANNOTATED')
            ),
            actor_id TEXT,
            actor_display TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL CHECK (length(details_json) BETWEEN 2 AND 8192),
            FOREIGN KEY (evidence_ref_id) REFERENCES case_evidence_refs(evidence_ref_id)
                ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_playbooks (
            playbook_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            template_key TEXT NOT NULL CHECK (length(template_key) BETWEEN 1 AND 64),
            template_version INTEGER NOT NULL CHECK (template_version >= 1),
            name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 160),
            status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED')),
            created_by TEXT,
            created_by_display TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            UNIQUE (case_id, template_key, template_version),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_playbook_steps (
            step_id TEXT PRIMARY KEY,
            playbook_id TEXT NOT NULL,
            template_step_key TEXT NOT NULL,
            sequence INTEGER NOT NULL CHECK (sequence >= 0),
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
            description TEXT NOT NULL CHECK (length(description) BETWEEN 1 AND 1024),
            step_type TEXT NOT NULL CHECK (step_type IN ('ACTION', 'EVIDENCE', 'APPROVAL')),
            status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETED')),
            assigned_to TEXT,
            evidence_ref_id TEXT,
            completion_note TEXT NOT NULL DEFAULT '' CHECK (length(completion_note) <= 2048),
            completed_by TEXT,
            completed_by_display TEXT,
            completed_at TEXT,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
            UNIQUE (playbook_id, template_step_key),
            UNIQUE (playbook_id, sequence),
            FOREIGN KEY (playbook_id) REFERENCES case_playbooks(playbook_id) ON DELETE CASCADE,
            FOREIGN KEY (assigned_to) REFERENCES analysts(analyst_id) ON DELETE SET NULL,
            FOREIGN KEY (evidence_ref_id) REFERENCES case_evidence_refs(evidence_ref_id)
                ON DELETE SET NULL,
            FOREIGN KEY (completed_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS case_report_history (
            report_id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            format TEXT NOT NULL CHECK (format IN ('JSON', 'CSV', 'PDF')),
            generated_by TEXT,
            generated_by_display TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            redaction_profile TEXT NOT NULL CHECK (redaction_profile = 'CASE_REPORT_V1'),
            FOREIGN KEY (case_id) REFERENCES soc_cases(case_id) ON DELETE CASCADE,
            FOREIGN KEY (generated_by) REFERENCES analysts(analyst_id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_cases_status_updated
            ON soc_cases(status, updated_at DESC, case_id DESC);
        CREATE INDEX IF NOT EXISTS idx_cases_owner_updated
            ON soc_cases(owner_id, updated_at DESC, case_id DESC);
        CREATE INDEX IF NOT EXISTS idx_cases_priority_due
            ON soc_cases(priority, resolution_due_at, case_id);
        CREATE INDEX IF NOT EXISTS idx_cases_source
            ON soc_cases(source_type, source_id);
        CREATE INDEX IF NOT EXISTS idx_case_alerts_alert ON case_alerts(alert_id, case_id);
        CREATE INDEX IF NOT EXISTS idx_case_incidents_incident ON case_incidents(incident_id, case_id);
        CREATE INDEX IF NOT EXISTS idx_case_events_event ON case_events(event_id, case_id);
        CREATE INDEX IF NOT EXISTS idx_case_comments_order
            ON case_comments(case_id, created_at DESC, comment_id DESC);
        CREATE INDEX IF NOT EXISTS idx_case_activity_order
            ON case_activity(case_id, occurred_at DESC, activity_id DESC);
        CREATE INDEX IF NOT EXISTS idx_case_evidence_order
            ON case_evidence_refs(case_id, acquired_at DESC, evidence_ref_id DESC);
        CREATE INDEX IF NOT EXISTS idx_custody_evidence_order
            ON evidence_custody_events(evidence_ref_id, occurred_at, custody_event_id);
        CREATE INDEX IF NOT EXISTS idx_case_playbooks_case
            ON case_playbooks(case_id, created_at DESC, playbook_id DESC);
        CREATE INDEX IF NOT EXISTS idx_case_steps_order
            ON case_playbook_steps(playbook_id, sequence, step_id);
        CREATE INDEX IF NOT EXISTS idx_case_reports_order
            ON case_report_history(case_id, generated_at DESC, report_id DESC);
        """
    )

    # Extend the bounded notification contract while preserving every existing row.
    connection.execute(
        """
        CREATE TABLE analyst_notifications_v14 (
            notification_id TEXT PRIMARY KEY,
            analyst_id TEXT NOT NULL,
            category TEXT NOT NULL CHECK (
                category IN (
                    'CRITICAL_ALERT', 'HIGH_ALERT', 'ALERT_ASSIGNED',
                    'INCIDENT_ASSIGNED', 'OPERATIONAL_ISSUE',
                    'OPERATIONAL_RECOVERY', 'CASE_ASSIGNED',
                    'CASE_HANDOFF', 'CASE_SLA'
                )
            ),
            title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
            preview TEXT NOT NULL CHECK (length(preview) BETWEEN 1 AND 320),
            target_type TEXT NOT NULL CHECK (
                target_type IN ('alert', 'incident', 'operational', 'case')
            ),
            target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 255),
            event_key TEXT NOT NULL CHECK (length(event_key) BETWEEN 1 AND 512),
            created_at TEXT NOT NULL,
            read_at TEXT,
            FOREIGN KEY (analyst_id) REFERENCES analysts(analyst_id) ON DELETE CASCADE,
            UNIQUE (analyst_id, event_key)
        )
        """
    )
    connection.execute(
        """
        INSERT INTO analyst_notifications_v14 (
            notification_id, analyst_id, category, title, preview,
            target_type, target_id, event_key, created_at, read_at
        )
        SELECT notification_id, analyst_id, category, title, preview,
               target_type, target_id, event_key, created_at, read_at
        FROM analyst_notifications
        """
    )
    connection.execute("DROP TABLE analyst_notifications")
    connection.execute("ALTER TABLE analyst_notifications_v14 RENAME TO analyst_notifications")
    connection.execute(
        "CREATE INDEX idx_notifications_owner_order "
        "ON analyst_notifications(analyst_id, created_at DESC, notification_id DESC)"
    )
    connection.execute(
        "CREATE INDEX idx_notifications_owner_unread "
        "ON analyst_notifications(analyst_id, read_at, created_at DESC)"
    )


MIGRATIONS = (
    Migration(1, "initial_alerts", _migration_001_initial_alerts),
    Migration(2, "alert_read_indexes", _migration_002_alert_read_indexes),
    Migration(3, "incident_foundation", _migration_003_incident_foundation),
    Migration(4, "analyst_authentication", _migration_004_analyst_authentication),
    Migration(5, "ai_analysis_history", _migration_005_ai_analysis_history),
    Migration(6, "incident_correlation", _migration_006_incident_correlation),
    Migration(7, "correlation_candidate_index", _migration_007_correlation_candidate_index),
    Migration(8, "security_event_store", _migration_008_security_event_store),
    Migration(9, "siem_v02_operations", _migration_009_siem_v02_operations),
    Migration(10, "soc_alert_workflows", _migration_010_soc_alert_workflows),
    Migration(11, "incident_investigation_workspace", _migration_011_investigation_workspace),
    Migration(12, "detection_engineering_and_hunting", _migration_012_detection_engineering),
    Migration(13, "operational_reliability", _migration_013_operational_reliability),
    Migration(14, "soc_case_management", _migration_014_case_management),
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
