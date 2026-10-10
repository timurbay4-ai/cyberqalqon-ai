"""Per-analyst preference persistence with optimistic concurrency."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal
from app.schemas.preferences import (
    DEFAULT_DISCOVER_COLUMNS,
    AnalystPreferences,
    AnalystPreferencesUpdate,
)
from app.services.wazuh_normalizer import canonical_json


class PreferenceConflictError(RuntimeError):
    pass


class PreferenceRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _ensure(connection: sqlite3.Connection, analyst_id: str, now: str) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO analyst_preferences (analyst_id, updated_at) VALUES (?, ?)",
            (analyst_id, now),
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> AnalystPreferences:
        return AnalystPreferences(
            dashboard_range=row["dashboard_range"],
            discover_page_size=int(row["discover_page_size"]),
            alert_page_size=int(row["alert_page_size"]),
            incident_page_size=int(row["incident_page_size"]),
            table_density=row["table_density"],
            time_display=row["time_display"],
            alert_default_sort=row["alert_default_sort"],
            discover_columns=json.loads(row["discover_columns_json"]),
            version=int(row["version"]),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        actor: AnalystPrincipal,
        action: str,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, 'analyst_preferences', ?, 'SUCCESS', ?, '{}')
            """,
            (
                f"AUD-{uuid4().hex.upper()}", action, actor.analyst_id,
                actor.audit_display, actor.analyst_id, occurred_at,
            ),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN ("
            "SELECT audit_id FROM security_audit_events "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    def get(self, analyst_id: str) -> AnalystPreferences:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            self._ensure(connection, analyst_id, now)
            row = connection.execute(
                "SELECT * FROM analyst_preferences WHERE analyst_id = ?", (analyst_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("Unable to initialize analyst preferences")
        return self._from_row(row)

    def update(
        self, payload: AnalystPreferencesUpdate, actor: AnalystPrincipal
    ) -> AnalystPreferences:
        now = datetime.now(timezone.utc).isoformat()
        columns_json = canonical_json(payload.discover_columns)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._ensure(connection, actor.analyst_id, now)
            row = connection.execute(
                "SELECT version FROM analyst_preferences WHERE analyst_id = ?",
                (actor.analyst_id,),
            ).fetchone()
            if row is None or int(row["version"]) != payload.expected_version:
                current = int(row["version"]) if row is not None else 0
                raise PreferenceConflictError(
                    f"Expected version {payload.expected_version}; current version is {current}"
                )
            connection.execute(
                """
                UPDATE analyst_preferences SET
                    dashboard_range = ?, discover_page_size = ?, alert_page_size = ?,
                    incident_page_size = ?, table_density = ?, time_display = ?,
                    alert_default_sort = ?, discover_columns_json = ?,
                    version = version + 1, updated_at = ?
                WHERE analyst_id = ? AND version = ?
                """,
                (
                    payload.dashboard_range.value, payload.discover_page_size,
                    payload.alert_page_size, payload.incident_page_size,
                    payload.table_density.value, payload.time_display.value,
                    payload.alert_default_sort.value, columns_json, now,
                    actor.analyst_id, payload.expected_version,
                ),
            )
            self._audit(connection, actor, "ANALYST_PREFERENCES_UPDATED", now)
            updated = connection.execute(
                "SELECT * FROM analyst_preferences WHERE analyst_id = ?",
                (actor.analyst_id,),
            ).fetchone()
        if updated is None:
            raise RuntimeError("Preference update disappeared")
        return self._from_row(updated)

    def reset(self, expected_version: int, actor: AnalystPrincipal) -> AnalystPreferences:
        defaults = AnalystPreferencesUpdate(
            dashboard_range="24h",
            discover_page_size=25,
            alert_page_size=25,
            incident_page_size=25,
            table_density="COMFORTABLE",
            time_display="LOCAL",
            alert_default_sort="time_desc",
            discover_columns=list(DEFAULT_DISCOVER_COLUMNS),
            expected_version=expected_version,
        )
        result = self.update(defaults, actor)
        return result
