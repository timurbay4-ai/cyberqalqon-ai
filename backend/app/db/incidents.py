"""SQLite persistence for deterministic incident lifecycle management."""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.schemas.incidents import (
    IncidentCreate,
    IncidentDetail,
    IncidentEventType,
    IncidentHistoryEvent,
    IncidentNote,
    IncidentSeverity,
    IncidentStatus,
    IncidentSummary,
)
from app.schemas.auth import AnalystPrincipal
from app.services.wazuh_normalizer import canonical_json


class IncidentNotFoundError(LookupError):
    pass


class LinkedAlertNotFoundError(LookupError):
    pass


class DuplicateAlertLinkError(RuntimeError):
    pass


class InvalidIncidentTransitionError(RuntimeError):
    pass


class IncidentNoChangeError(RuntimeError):
    pass


class InvalidIncidentCursorError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IncidentFilters:
    statuses: tuple[IncidentStatus, ...] = ()
    severities: tuple[IncidentSeverity, ...] = ()
    assigned_to: str | None = None


@dataclass(frozen=True, slots=True)
class IncidentListResult:
    items: list[IncidentSummary]
    total: int
    next_cursor: str | None


ALLOWED_STATUS_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset(
        {IncidentStatus.TRIAGED, IncidentStatus.FALSE_POSITIVE}
    ),
    IncidentStatus.TRIAGED: frozenset(
        {
            IncidentStatus.INVESTIGATING,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.INVESTIGATING: frozenset(
        {
            IncidentStatus.TRIAGED,
            IncidentStatus.RESOLVED,
            IncidentStatus.FALSE_POSITIVE,
        }
    ),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.FALSE_POSITIVE: frozenset({IncidentStatus.TRIAGED}),
}


def _new_identifier(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex.upper()}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_cursor(created_at: str, incident_id: str) -> str:
    payload = canonical_json(
        {"created_at": created_at, "incident_id": incident_id, "v": 1}
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    if not cursor or len(cursor) > 2048:
        raise InvalidIncidentCursorError("cursor is malformed")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        payload: Any = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidIncidentCursorError("cursor is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"created_at", "incident_id", "v"}:
        raise InvalidIncidentCursorError("cursor is malformed")
    if payload["v"] != 1 or not isinstance(payload["incident_id"], str):
        raise InvalidIncidentCursorError("cursor is malformed")
    if not isinstance(payload["created_at"], str) or not payload["incident_id"]:
        raise InvalidIncidentCursorError("cursor is malformed")
    try:
        created_at = datetime.fromisoformat(payload["created_at"])
    except ValueError as exc:
        raise InvalidIncidentCursorError("cursor is malformed") from exc
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise InvalidIncidentCursorError("cursor is malformed")
    return created_at.astimezone(timezone.utc).isoformat(), payload["incident_id"]


def _summary_from_row(row: sqlite3.Row) -> IncidentSummary:
    return IncidentSummary(
        incident_id=row["incident_id"],
        title=row["title"],
        description=row["description"],
        severity=IncidentSeverity(row["severity"]),
        status=IncidentStatus(row["status"]),
        assigned_to=row["assigned_to"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        alert_count=int(row["alert_count"]),
    )


class IncidentRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _require_incident(
        connection: sqlite3.Connection,
        incident_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise IncidentNotFoundError(incident_id)
        return row

    @staticmethod
    def _require_alerts(connection: sqlite3.Connection, alert_ids: list[str]) -> None:
        if not alert_ids:
            return
        placeholders = ", ".join("?" for _ in alert_ids)
        rows = connection.execute(
            f"SELECT alert_id FROM alerts WHERE alert_id IN ({placeholders})",
            alert_ids,
        ).fetchall()
        found = {str(row["alert_id"]) for row in rows}
        for alert_id in alert_ids:
            if alert_id not in found:
                raise LinkedAlertNotFoundError(alert_id)

    @staticmethod
    def _append_history(
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        event_type: IncidentEventType,
        actor: AnalystPrincipal,
        occurred_at: datetime,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO incident_history (
                event_id, incident_id, event_type, actor, occurred_at, details_json,
                actor_id, actor_display
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _new_identifier("EVT"),
                incident_id,
                event_type.value,
                actor.audit_display,
                occurred_at.isoformat(),
                canonical_json(details),
                actor.analyst_id,
                actor.audit_display,
            ),
        )

    def create(self, request: IncidentCreate, actor: AnalystPrincipal) -> IncidentDetail:
        incident_id = _new_identifier("INC")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_alerts(connection, request.alert_ids)
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, description, severity, status,
                    assigned_to, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    request.title,
                    request.description,
                    request.severity.value,
                    IncidentStatus.NEW.value,
                    request.assigned_to,
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
            self._append_history(
                connection,
                incident_id=incident_id,
                event_type=IncidentEventType.CREATED,
                actor=actor,
                occurred_at=now,
                details={
                    "severity": request.severity.value,
                    "status": IncidentStatus.NEW.value,
                },
            )
            if request.assigned_to is not None:
                self._append_history(
                    connection,
                    incident_id=incident_id,
                    event_type=IncidentEventType.ASSIGNMENT_CHANGED,
                    actor=actor,
                    occurred_at=now,
                    details={"from": None, "to": request.assigned_to},
                )
            for alert_id in request.alert_ids:
                connection.execute(
                    "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) "
                    "VALUES (?, ?, ?)",
                    (incident_id, alert_id, now.isoformat()),
                )
                self._append_history(
                    connection,
                    incident_id=incident_id,
                    event_type=IncidentEventType.ALERT_LINKED,
                    actor=actor,
                    occurred_at=now,
                    details={"alert_id": alert_id},
                )
        detail = self.get(incident_id)
        if detail is None:  # Defensive: the transaction above committed the row.
            raise IncidentNotFoundError(incident_id)
        return detail

    def get(self, incident_id: str) -> IncidentDetail | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT i.*,
                       (SELECT COUNT(*) FROM incident_alerts ia
                        WHERE ia.incident_id = i.incident_id) AS alert_count
                FROM incidents i
                WHERE i.incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if row is None:
                return None
            alert_rows = connection.execute(
                """
                SELECT alert_id FROM incident_alerts
                WHERE incident_id = ?
                ORDER BY linked_at, alert_id
                """,
                (incident_id,),
            ).fetchall()
            note_rows = connection.execute(
                """
                SELECT note_id, body, author, author_id, created_at FROM incident_notes
                WHERE incident_id = ?
                ORDER BY created_at, note_id
                """,
                (incident_id,),
            ).fetchall()
            history_rows = connection.execute(
                """
                SELECT event_id, event_type, actor, actor_id, actor_display,
                       occurred_at, details_json
                FROM incident_history
                WHERE incident_id = ?
                ORDER BY history_id
                """,
                (incident_id,),
            ).fetchall()

        summary = _summary_from_row(row)
        return IncidentDetail(
            **summary.model_dump(),
            alert_ids=[str(alert_row["alert_id"]) for alert_row in alert_rows],
            notes=[
                IncidentNote(
                    note_id=note_row["note_id"],
                    body=note_row["body"],
                    author=note_row["author"],
                    author_id=note_row["author_id"],
                    created_at=datetime.fromisoformat(note_row["created_at"]),
                )
                for note_row in note_rows
            ],
            history=[
                IncidentHistoryEvent(
                    event_id=history_row["event_id"],
                    event_type=IncidentEventType(history_row["event_type"]),
                    actor=history_row["actor_display"] or history_row["actor"],
                    actor_id=history_row["actor_id"],
                    occurred_at=datetime.fromisoformat(history_row["occurred_at"]),
                    details=json.loads(history_row["details_json"]),
                )
                for history_row in history_rows
            ],
        )

    def list(
        self,
        filters: IncidentFilters,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> IncidentListResult:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")

        conditions: list[str] = []
        parameters: list[object] = []
        if filters.statuses:
            placeholders = ", ".join("?" for _ in filters.statuses)
            conditions.append(f"i.status IN ({placeholders})")
            parameters.extend(status.value for status in filters.statuses)
        if filters.severities:
            placeholders = ", ".join("?" for _ in filters.severities)
            conditions.append(f"i.severity IN ({placeholders})")
            parameters.extend(severity.value for severity in filters.severities)
        if filters.assigned_to:
            conditions.append("i.assigned_to = ? COLLATE NOCASE")
            parameters.append(filters.assigned_to)

        base_where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM incidents i" + base_where,
                    parameters,
                ).fetchone()[0]
            )

            page_conditions = list(conditions)
            page_parameters = list(parameters)
            if cursor:
                created_at, incident_id = _decode_cursor(cursor)
                page_conditions.append(
                    "(i.created_at < ? OR (i.created_at = ? AND i.incident_id < ?))"
                )
                page_parameters.extend((created_at, created_at, incident_id))
            page_where = f" WHERE {' AND '.join(page_conditions)}" if page_conditions else ""
            rows = connection.execute(
                """
                SELECT i.*,
                       (SELECT COUNT(*) FROM incident_alerts ia
                        WHERE ia.incident_id = i.incident_id) AS alert_count
                FROM incidents i
                """
                + page_where
                + " ORDER BY i.created_at DESC, i.incident_id DESC LIMIT ?",
                (*page_parameters, limit + 1),
            ).fetchall()

        has_more = len(rows) > limit
        visible_rows = rows[:limit]
        next_cursor = None
        if has_more and visible_rows:
            last = visible_rows[-1]
            next_cursor = _encode_cursor(last["created_at"], last["incident_id"])
        return IncidentListResult(
            items=[_summary_from_row(row) for row in visible_rows],
            total=total,
            next_cursor=next_cursor,
        )

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus,
        actor: AnalystPrincipal,
    ) -> IncidentDetail:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_incident(connection, incident_id)
            previous = IncidentStatus(row["status"])
            if status not in ALLOWED_STATUS_TRANSITIONS[previous]:
                raise InvalidIncidentTransitionError(
                    f"Incident status cannot transition from {previous.value} to {status.value}"
                )
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?",
                (status.value, now.isoformat(), incident_id),
            )
            self._append_history(
                connection,
                incident_id=incident_id,
                event_type=IncidentEventType.STATUS_CHANGED,
                actor=actor,
                occurred_at=now,
                details={"from": previous.value, "to": status.value},
            )
        detail = self.get(incident_id)
        if detail is None:
            raise IncidentNotFoundError(incident_id)
        return detail

    def link_alert(
        self,
        incident_id: str,
        alert_id: str,
        actor: AnalystPrincipal,
    ) -> IncidentDetail:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            self._require_alerts(connection, [alert_id])
            existing = connection.execute(
                "SELECT 1 FROM incident_alerts WHERE incident_id = ? AND alert_id = ?",
                (incident_id, alert_id),
            ).fetchone()
            if existing is not None:
                raise DuplicateAlertLinkError(alert_id)
            connection.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (?, ?, ?)",
                (incident_id, alert_id, now.isoformat()),
            )
            connection.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now.isoformat(), incident_id),
            )
            self._append_history(
                connection,
                incident_id=incident_id,
                event_type=IncidentEventType.ALERT_LINKED,
                actor=actor,
                occurred_at=now,
                details={"alert_id": alert_id},
            )
        detail = self.get(incident_id)
        if detail is None:
            raise IncidentNotFoundError(incident_id)
        return detail

    def add_note(
        self,
        incident_id: str,
        body: str,
        actor: AnalystPrincipal,
    ) -> IncidentNote:
        note_id = _new_identifier("NOTE")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            connection.execute(
                """
                INSERT INTO incident_notes (
                    note_id, incident_id, body, author, created_at, author_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    note_id,
                    incident_id,
                    body,
                    actor.audit_display,
                    now.isoformat(),
                    actor.analyst_id,
                ),
            )
            connection.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now.isoformat(), incident_id),
            )
            self._append_history(
                connection,
                incident_id=incident_id,
                event_type=IncidentEventType.NOTE_ADDED,
                actor=actor,
                occurred_at=now,
                details={"note_id": note_id},
            )
        return IncidentNote(
            note_id=note_id,
            body=body,
            author=actor.audit_display,
            author_id=actor.analyst_id,
            created_at=now,
        )

    def update_assignment(
        self,
        incident_id: str,
        assigned_to: str | None,
        actor: AnalystPrincipal,
    ) -> IncidentDetail:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_incident(connection, incident_id)
            previous = row["assigned_to"]
            if previous == assigned_to:
                raise IncidentNoChangeError("Incident assignment is unchanged")
            connection.execute(
                "UPDATE incidents SET assigned_to = ?, updated_at = ? WHERE incident_id = ?",
                (assigned_to, now.isoformat(), incident_id),
            )
            self._append_history(
                connection,
                incident_id=incident_id,
                event_type=IncidentEventType.ASSIGNMENT_CHANGED,
                actor=actor,
                occurred_at=now,
                details={"from": previous, "to": assigned_to},
            )
        detail = self.get(incident_id)
        if detail is None:
            raise IncidentNotFoundError(incident_id)
        return detail
