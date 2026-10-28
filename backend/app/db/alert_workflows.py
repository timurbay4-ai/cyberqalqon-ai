"""Durable alert triage with optimistic concurrency and atomic audit evidence."""

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

from app.schemas.alert_workflows import (
    AlertAssignee,
    AlertBulkAction,
    AlertBulkFailure,
    AlertBulkRequest,
    AlertBulkResponse,
    AlertWorkflowCounts,
    AlertWorkflowDetail,
    AlertWorkflowEventType,
    AlertWorkflowHistoryEvent,
    AlertWorkflowNote,
    AlertWorkflowSort,
    AlertWorkflowStatus,
    AlertWorkflowSummary,
)
from app.schemas.alerts import NormalizedAlert
from app.schemas.auth import AnalystPrincipal
from app.services.wazuh_normalizer import canonical_json


ACTIONABLE_STATUSES = (
    AlertWorkflowStatus.NEW,
    AlertWorkflowStatus.ACKNOWLEDGED,
    AlertWorkflowStatus.IN_PROGRESS,
)

ALLOWED_STATUS_TRANSITIONS: dict[AlertWorkflowStatus, frozenset[AlertWorkflowStatus]] = {
    AlertWorkflowStatus.NEW: frozenset(
        {AlertWorkflowStatus.ACKNOWLEDGED, AlertWorkflowStatus.FALSE_POSITIVE}
    ),
    AlertWorkflowStatus.ACKNOWLEDGED: frozenset(
        {
            AlertWorkflowStatus.IN_PROGRESS,
            AlertWorkflowStatus.RESOLVED,
            AlertWorkflowStatus.FALSE_POSITIVE,
        }
    ),
    AlertWorkflowStatus.IN_PROGRESS: frozenset(
        {AlertWorkflowStatus.RESOLVED, AlertWorkflowStatus.FALSE_POSITIVE}
    ),
    AlertWorkflowStatus.RESOLVED: frozenset(),
    AlertWorkflowStatus.FALSE_POSITIVE: frozenset(),
}


class AlertWorkflowNotFoundError(LookupError):
    pass


class AlertWorkflowConflictError(RuntimeError):
    pass


class InvalidAlertWorkflowTransitionError(RuntimeError):
    pass


class AlertWorkflowNoChangeError(RuntimeError):
    pass


class AlertAssigneeNotFoundError(LookupError):
    pass


class InvalidAlertWorkflowCursorError(ValueError):
    pass


class AlertBulkValidationError(RuntimeError):
    def __init__(self, failures: list[AlertBulkFailure]) -> None:
        super().__init__("Bulk alert operation was not applied")
        self.failures = failures


@dataclass(frozen=True, slots=True)
class AlertWorkflowFilters:
    rule_levels: tuple[int, ...] = ()
    rule_id: str | None = None
    agent: str | None = None
    mitre_mapped: bool | None = None
    mitre_id: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    search: str | None = None
    statuses: tuple[AlertWorkflowStatus, ...] = ()
    assigned_to: str | None = None
    unassigned: bool | None = None


@dataclass(frozen=True, slots=True)
class AlertWorkflowListResult:
    items: list[AlertWorkflowSummary]
    total: int
    next_cursor: str | None
    counts: AlertWorkflowCounts


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp filters must include a UTC offset")
    return value.astimezone(timezone.utc).isoformat()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _encode_cursor(offset: int) -> str:
    payload = canonical_json({"offset": offset, "v": 1})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> int:
    if not cursor or len(cursor) > 256:
        raise InvalidAlertWorkflowCursorError("cursor is malformed")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        payload: Any = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidAlertWorkflowCursorError("cursor is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"offset", "v"}
        or payload["v"] != 1
        or not isinstance(payload["offset"], int)
        or isinstance(payload["offset"], bool)
        or payload["offset"] < 0
    ):
        raise InvalidAlertWorkflowCursorError("cursor is malformed")
    return payload["offset"]


def _summary_from_row(row: sqlite3.Row) -> AlertWorkflowSummary:
    assignee = None
    if row["assigned_to"] is not None:
        assignee = AlertAssignee(
            analyst_id=row["assigned_to"],
            username=row["assignee_username"],
            display_name=row["assignee_display_name"],
        )
    return AlertWorkflowSummary(
        alert=NormalizedAlert.model_validate_json(row["normalized_json"]),
        status=AlertWorkflowStatus(row["status"]),
        assignee=assignee,
        version=int(row["version"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        last_activity_at=datetime.fromisoformat(row["last_activity_at"]),
        note_count=int(row["note_count"]),
    )


class AlertWorkflowRepository:
    def __init__(self, database_path: Path, *, notification_limit_per_analyst: int = 500) -> None:
        self.path = database_path
        self.notification_limit_per_analyst = notification_limit_per_analyst

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def list_active_assignees(self) -> list[AlertAssignee]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT analyst_id, username, display_name
                FROM analysts
                WHERE is_active = 1 AND role IN ('ADMIN', 'ANALYST')
                ORDER BY display_name COLLATE NOCASE, username_normalized
                """
            ).fetchall()
        return [
            AlertAssignee(
                analyst_id=row["analyst_id"],
                username=row["username"],
                display_name=row["display_name"],
            )
            for row in rows
        ]

    @staticmethod
    def _select_sql() -> str:
        return """
            SELECT a.normalized_json, a.rule_id, a.rule_level, a.agent_name,
                   w.alert_id, w.status, w.assigned_to, w.version,
                   w.created_at, w.updated_at, w.last_activity_at,
                   an.username AS assignee_username,
                   an.display_name AS assignee_display_name,
                   (SELECT COUNT(*) FROM alert_notes n WHERE n.alert_id = w.alert_id)
                       AS note_count
            FROM alert_workflows w
            JOIN alerts a ON a.alert_id = w.alert_id
            LEFT JOIN analysts an ON an.analyst_id = w.assigned_to
        """

    @staticmethod
    def _require_workflow(connection: sqlite3.Connection, alert_id: str) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT w.*, a.rule_id, a.rule_level, a.agent_name
            FROM alert_workflows w
            JOIN alerts a ON a.alert_id = w.alert_id
            WHERE w.alert_id = ?
            """,
            (alert_id,),
        ).fetchone()
        if row is None:
            raise AlertWorkflowNotFoundError(alert_id)
        return row

    @staticmethod
    def _require_assignee(connection: sqlite3.Connection, analyst_id: str | None) -> None:
        if analyst_id is None:
            return
        row = connection.execute(
            "SELECT 1 FROM analysts WHERE analyst_id = ? AND is_active = 1 "
            "AND role IN ('ADMIN', 'ANALYST')",
            (analyst_id,),
        ).fetchone()
        if row is None:
            raise AlertAssigneeNotFoundError(analyst_id)

    @staticmethod
    def _append_history(
        connection: sqlite3.Connection,
        *,
        alert_id: str,
        event_type: AlertWorkflowEventType,
        actor: AnalystPrincipal,
        occurred_at: datetime,
        details: dict[str, Any],
        version: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO alert_history (
                event_id, alert_id, event_type, actor_id, actor_display,
                occurred_at, details_json, version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"AHE-{uuid4().hex.upper()}",
                alert_id,
                event_type.value,
                actor.analyst_id,
                actor.audit_display,
                occurred_at.isoformat(),
                canonical_json(details),
                version,
            ),
        )
    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        alert_id: str,
        actor: AnalystPrincipal,
        occurred_at: datetime,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, 'alert', ?, 'SUCCESS', ?, ?)
            """,
            (
                f"AUD-{uuid4().hex.upper()}",
                action,
                actor.analyst_id,
                actor.audit_display,
                alert_id,
                occurred_at.isoformat(),
                canonical_json(details),
            ),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN ("
            "SELECT audit_id FROM security_audit_events "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    def _notify_assignment(
        self,
        connection: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        analyst_id: str | None,
        version: int,
        occurred_at: datetime,
    ) -> None:
        if analyst_id is None:
            return
        connection.execute(
            """
            INSERT OR IGNORE INTO analyst_notifications (
                notification_id, analyst_id, category, title, preview,
                target_type, target_id, event_key, created_at, read_at
            ) VALUES (?, ?, 'ALERT_ASSIGNED', ?, ?, 'alert', ?, ?, ?, NULL)
            """,
            (
                f"NTF-{uuid4().hex.upper()}",
                analyst_id,
                "Alert assigned to you",
                f"Rule {row['rule_id']} · level {row['rule_level']} · {row['agent_name']}",
                row["alert_id"],
                f"alert-assigned:{row['alert_id']}:{version}:{analyst_id}",
                occurred_at.isoformat(),
            ),
        )
        self._trim_notifications(connection, analyst_id)

    def _trim_notifications(self, connection: sqlite3.Connection, analyst_id: str) -> None:
        connection.execute(
            """
            DELETE FROM analyst_notifications
            WHERE analyst_id = ? AND notification_id IN (
                SELECT notification_id FROM analyst_notifications
                WHERE analyst_id = ?
                ORDER BY created_at DESC, notification_id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (analyst_id, analyst_id, self.notification_limit_per_analyst),
        )

    @staticmethod
    def _conditions(filters: AlertWorkflowFilters) -> tuple[list[str], list[object], list[str], list[object]]:
        alert_conditions: list[str] = []
        alert_parameters: list[object] = []
        if filters.rule_levels:
            placeholders = ", ".join("?" for _ in filters.rule_levels)
            alert_conditions.append(f"a.rule_level IN ({placeholders})")
            alert_parameters.extend(filters.rule_levels)
        if filters.rule_id:
            alert_conditions.append("a.rule_id = ? COLLATE NOCASE")
            alert_parameters.append(filters.rule_id)
        if filters.agent:
            alert_conditions.append(
                "(a.agent_id = ? COLLATE NOCASE OR a.agent_name = ? COLLATE NOCASE)"
            )
            alert_parameters.extend((filters.agent, filters.agent))
        if filters.mitre_mapped is not None:
            alert_conditions.append("a.has_mitre = ?")
            alert_parameters.append(filters.mitre_mapped)
        if filters.mitre_id:
            alert_conditions.append("instr(a.mitre_ids_text, ?) > 0")
            alert_parameters.append(f"|{filters.mitre_id}|")
        if filters.start_time:
            alert_conditions.append("a.occurred_at >= ?")
            alert_parameters.append(_utc_iso(filters.start_time))
        if filters.end_time:
            alert_conditions.append("a.occurred_at <= ?")
            alert_parameters.append(_utc_iso(filters.end_time))
        if filters.search:
            alert_conditions.append("a.search_text LIKE ? ESCAPE '\\'")
            alert_parameters.append(f"%{_escape_like(filters.search.casefold())}%")

        workflow_conditions: list[str] = []
        workflow_parameters: list[object] = []
        if filters.statuses:
            placeholders = ", ".join("?" for _ in filters.statuses)
            workflow_conditions.append(f"w.status IN ({placeholders})")
            workflow_parameters.extend(status.value for status in filters.statuses)
        if filters.assigned_to:
            workflow_conditions.append("w.assigned_to = ?")
            workflow_parameters.append(filters.assigned_to)
        if filters.unassigned is True:
            workflow_conditions.append("w.assigned_to IS NULL")
        elif filters.unassigned is False:
            workflow_conditions.append("w.assigned_to IS NOT NULL")
        return alert_conditions, alert_parameters, workflow_conditions, workflow_parameters

    def list(
        self,
        filters: AlertWorkflowFilters,
        *,
        limit: int,
        cursor: str | None = None,
        sort: AlertWorkflowSort = AlertWorkflowSort.TIME_DESC,
    ) -> AlertWorkflowListResult:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if any(level < 0 or level > 16 for level in filters.rule_levels):
            raise ValueError("rule levels must be between 0 and 16")
        offset = _decode_cursor(cursor) if cursor else 0
        alert_conditions, alert_params, workflow_conditions, workflow_params = self._conditions(filters)
        conditions = [*alert_conditions, *workflow_conditions]
        parameters = [*alert_params, *workflow_params]
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        alert_where = f" WHERE {' AND '.join(alert_conditions)}" if alert_conditions else ""
        order_by = {
            AlertWorkflowSort.TIME_DESC: "a.occurred_at DESC, a.alert_id DESC",
            AlertWorkflowSort.TIME_ASC: "a.occurred_at ASC, a.alert_id ASC",
            AlertWorkflowSort.SEVERITY_DESC: "a.rule_level DESC, a.occurred_at DESC, a.alert_id DESC",
            AlertWorkflowSort.SEVERITY_ASC: "a.rule_level ASC, a.occurred_at DESC, a.alert_id DESC",
            AlertWorkflowSort.ACTIVITY_DESC: "w.last_activity_at DESC, a.alert_id DESC",
        }[sort]

        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alert_workflows w JOIN alerts a ON a.alert_id = w.alert_id"
                    + where,
                    parameters,
                ).fetchone()[0]
            )
            rows = connection.execute(
                self._select_sql() + where + f" ORDER BY {order_by} LIMIT ? OFFSET ?",
                (*parameters, limit + 1, offset),
            ).fetchall()
            count_rows = connection.execute(
                """
                SELECT w.status, COUNT(*) AS count
                FROM alert_workflows w JOIN alerts a ON a.alert_id = w.alert_id
                """
                + alert_where
                + " GROUP BY w.status",
                alert_params,
            ).fetchall()
            unassigned = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alert_workflows w JOIN alerts a ON a.alert_id = w.alert_id"
                    + (alert_where + " AND w.assigned_to IS NULL" if alert_where else " WHERE w.assigned_to IS NULL"),
                    alert_params,
                ).fetchone()[0]
            )

        visible = rows[:limit]
        by_status = {status: 0 for status in AlertWorkflowStatus}
        for row in count_rows:
            by_status[AlertWorkflowStatus(row["status"])] = int(row["count"])
        actionable = sum(by_status[status] for status in ACTIONABLE_STATUSES)
        all_count = sum(by_status.values())
        return AlertWorkflowListResult(
            items=[_summary_from_row(row) for row in visible],
            total=total,
            next_cursor=_encode_cursor(offset + limit) if len(rows) > limit else None,
            counts=AlertWorkflowCounts(
                total=all_count,
                actionable=actionable,
                unassigned=unassigned,
                by_status=by_status,
            ),
        )

    def get(self, alert_id: str) -> AlertWorkflowDetail | None:
        with self._connect() as connection:
            row = connection.execute(
                self._select_sql() + " WHERE w.alert_id = ?",
                (alert_id,),
            ).fetchone()
            if row is None:
                return None
            note_rows = connection.execute(
                """
                SELECT note_id, body, author_id, author_display, created_at
                FROM alert_notes WHERE alert_id = ? ORDER BY created_at, note_id
                """,
                (alert_id,),
            ).fetchall()
            history_rows = connection.execute(
                """
                SELECT event_id, event_type, actor_id, actor_display,
                       occurred_at, details_json, version
                FROM alert_history WHERE alert_id = ? ORDER BY history_id
                """,
                (alert_id,),
            ).fetchall()
        summary = _summary_from_row(row)
        return AlertWorkflowDetail(
            **summary.model_dump(),
            notes=[
                AlertWorkflowNote(
                    note_id=note["note_id"],
                    body=note["body"],
                    author_id=note["author_id"],
                    author_display=note["author_display"],
                    created_at=datetime.fromisoformat(note["created_at"]),
                )
                for note in note_rows
            ],
            history=[
                AlertWorkflowHistoryEvent(
                    event_id=event["event_id"],
                    event_type=AlertWorkflowEventType(event["event_type"]),
                    actor_id=event["actor_id"],
                    actor_display=event["actor_display"],
                    occurred_at=datetime.fromisoformat(event["occurred_at"]),
                    details=json.loads(event["details_json"]),
                    version=int(event["version"]),
                )
                for event in history_rows
            ],
        )

    @staticmethod
    def _check_version(row: sqlite3.Row, expected_version: int) -> None:
        if int(row["version"]) != expected_version:
            raise AlertWorkflowConflictError(
                f"Alert workflow changed; expected version {expected_version}, "
                f"current version is {row['version']}"
            )

    def update_status(
        self,
        alert_id: str,
        status: AlertWorkflowStatus,
        expected_version: int,
        actor: AnalystPrincipal,
    ) -> AlertWorkflowDetail:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_workflow(connection, alert_id)
            self._check_version(row, expected_version)
            previous = AlertWorkflowStatus(row["status"])
            if status not in ALLOWED_STATUS_TRANSITIONS[previous]:
                raise InvalidAlertWorkflowTransitionError(
                    f"Alert status cannot transition from {previous.value} to {status.value}"
                )
            version = expected_version + 1
            changed = connection.execute(
                """
                UPDATE alert_workflows
                SET status = ?, version = ?, updated_at = ?, last_activity_at = ?
                WHERE alert_id = ? AND version = ?
                """,
                (status.value, version, now.isoformat(), now.isoformat(), alert_id, expected_version),
            ).rowcount
            if changed != 1:
                raise AlertWorkflowConflictError("Alert workflow was updated concurrently")
            details = {"from": previous.value, "to": status.value, "version": version}
            self._append_history(
                connection,
                alert_id=alert_id,
                event_type=AlertWorkflowEventType.STATUS_CHANGED,
                actor=actor,
                occurred_at=now,
                details=details,
                version=version,
            )
            self._append_audit(
                connection,
                action="ALERT_STATUS_CHANGED",
                alert_id=alert_id,
                actor=actor,
                occurred_at=now,
                details=details,
            )
        detail = self.get(alert_id)
        if detail is None:
            raise AlertWorkflowNotFoundError(alert_id)
        return detail

    def update_assignment(
        self,
        alert_id: str,
        assigned_to: str | None,
        expected_version: int,
        actor: AnalystPrincipal,
    ) -> AlertWorkflowDetail:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_workflow(connection, alert_id)
            self._check_version(row, expected_version)
            self._require_assignee(connection, assigned_to)
            previous = row["assigned_to"]
            if previous == assigned_to:
                raise AlertWorkflowNoChangeError("Alert assignment is unchanged")
            version = expected_version + 1
            changed = connection.execute(
                """
                UPDATE alert_workflows
                SET assigned_to = ?, version = ?, updated_at = ?, last_activity_at = ?
                WHERE alert_id = ? AND version = ?
                """,
                (assigned_to, version, now.isoformat(), now.isoformat(), alert_id, expected_version),
            ).rowcount
            if changed != 1:
                raise AlertWorkflowConflictError("Alert workflow was updated concurrently")
            details = {"from": previous, "to": assigned_to, "version": version}
            self._append_history(
                connection,
                alert_id=alert_id,
                event_type=AlertWorkflowEventType.ASSIGNMENT_CHANGED,
                actor=actor,
                occurred_at=now,
                details=details,
                version=version,
            )
            self._append_audit(
                connection,
                action="ALERT_ASSIGNMENT_CHANGED",
                alert_id=alert_id,
                actor=actor,
                occurred_at=now,
                details=details,
            )
            self._notify_assignment(
                connection,
                row=row,
                analyst_id=assigned_to,
                version=version,
                occurred_at=now,
            )
        detail = self.get(alert_id)
        if detail is None:
            raise AlertWorkflowNotFoundError(alert_id)
        return detail

    def add_note(
        self,
        alert_id: str,
        body: str,
        expected_version: int,
        actor: AnalystPrincipal,
    ) -> AlertWorkflowDetail:
        now = _utc_now()
        note_id = f"ANOTE-{uuid4().hex.upper()}"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_workflow(connection, alert_id)
            self._check_version(row, expected_version)
            version = expected_version + 1
            connection.execute(
                """
                INSERT INTO alert_notes (
                    note_id, alert_id, body, author_id, author_display, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (note_id, alert_id, body, actor.analyst_id, actor.audit_display, now.isoformat()),
            )
            changed = connection.execute(
                """
                UPDATE alert_workflows
                SET version = ?, updated_at = ?, last_activity_at = ?
                WHERE alert_id = ? AND version = ?
                """,
                (version, now.isoformat(), now.isoformat(), alert_id, expected_version),
            ).rowcount
            if changed != 1:
                raise AlertWorkflowConflictError("Alert workflow was updated concurrently")
            details = {"note_id": note_id, "version": version}
            self._append_history(
                connection,
                alert_id=alert_id,
                event_type=AlertWorkflowEventType.NOTE_ADDED,
                actor=actor,
                occurred_at=now,
                details=details,
                version=version,
            )
            self._append_audit(
                connection,
                action="ALERT_NOTE_ADDED",
                alert_id=alert_id,
                actor=actor,
                occurred_at=now,
                details=details,
            )
        detail = self.get(alert_id)
        if detail is None:
            raise AlertWorkflowNotFoundError(alert_id)
        return detail

    def bulk_update(self, request: AlertBulkRequest, actor: AnalystPrincipal) -> AlertBulkResponse:
        now = _utc_now()
        identifiers = [item.alert_id for item in request.items]
        versions = {item.alert_id: item.expected_version for item in request.items}
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            placeholders = ", ".join("?" for _ in identifiers)
            rows = connection.execute(
                f"""
                SELECT w.*, a.rule_id, a.rule_level, a.agent_name
                FROM alert_workflows w JOIN alerts a ON a.alert_id = w.alert_id
                WHERE w.alert_id IN ({placeholders})
                """,
                identifiers,
            ).fetchall()
            by_id = {str(row["alert_id"]): row for row in rows}
            failures: list[AlertBulkFailure] = []
            if request.action is AlertBulkAction.ASSIGN:
                try:
                    self._require_assignee(connection, request.assigned_to)
                except AlertAssigneeNotFoundError:
                    failures.extend(
                        AlertBulkFailure(
                            alert_id=alert_id,
                            code="assignee_not_found",
                            message="The selected active analyst does not exist",
                        )
                        for alert_id in identifiers
                    )
            if not failures:
                for alert_id in identifiers:
                    row = by_id.get(alert_id)
                    if row is None:
                        failures.append(
                            AlertBulkFailure(
                                alert_id=alert_id,
                                code="alert_not_found",
                                message="No alert workflow exists with this identifier",
                            )
                        )
                        continue
                    expected = versions[alert_id]
                    if int(row["version"]) != expected:
                        failures.append(
                            AlertBulkFailure(
                                alert_id=alert_id,
                                code="version_conflict",
                                message=f"Expected version {expected}; current version is {row['version']}",
                            )
                        )
                        continue
                    if request.action in {AlertBulkAction.ACKNOWLEDGE, AlertBulkAction.SET_STATUS}:
                        target = (
                            AlertWorkflowStatus.ACKNOWLEDGED
                            if request.action is AlertBulkAction.ACKNOWLEDGE
                            else request.status
                        )
                        if not (target is not None):
                            raise RuntimeError("Internal alert_workflows invariant failed")
                        previous = AlertWorkflowStatus(row["status"])
                        if target not in ALLOWED_STATUS_TRANSITIONS[previous]:
                            failures.append(
                                AlertBulkFailure(
                                    alert_id=alert_id,
                                    code="invalid_status_transition",
                                    message=f"Cannot transition from {previous.value} to {target.value}",
                                )
                            )
                    elif row["assigned_to"] == request.assigned_to:
                        failures.append(
                            AlertBulkFailure(
                                alert_id=alert_id,
                                code="assignment_unchanged",
                                message="Alert assignment is unchanged",
                            )
                        )
            if failures:
                raise AlertBulkValidationError(failures)

            for alert_id in identifiers:
                row = by_id[alert_id]
                expected = versions[alert_id]
                version = expected + 1
                if request.action in {AlertBulkAction.ACKNOWLEDGE, AlertBulkAction.SET_STATUS}:
                    target = (
                        AlertWorkflowStatus.ACKNOWLEDGED
                        if request.action is AlertBulkAction.ACKNOWLEDGE
                        else request.status
                    )
                    if not (target is not None):
                        raise RuntimeError("Internal alert_workflows invariant failed")
                    previous = AlertWorkflowStatus(row["status"])
                    connection.execute(
                        """
                        UPDATE alert_workflows
                        SET status = ?, version = ?, updated_at = ?, last_activity_at = ?
                        WHERE alert_id = ? AND version = ?
                        """,
                        (target.value, version, now.isoformat(), now.isoformat(), alert_id, expected),
                    )
                    details = {
                        "from": previous.value,
                        "to": target.value,
                        "version": version,
                        "bulk": True,
                    }
                    event_type = AlertWorkflowEventType.STATUS_CHANGED
                    audit_action = "ALERT_STATUS_CHANGED"
                else:
                    previous_assignment = row["assigned_to"]
                    connection.execute(
                        """
                        UPDATE alert_workflows
                        SET assigned_to = ?, version = ?, updated_at = ?, last_activity_at = ?
                        WHERE alert_id = ? AND version = ?
                        """,
                        (
                            request.assigned_to, version, now.isoformat(), now.isoformat(),
                            alert_id, expected,
                        ),
                    )
                    details = {
                        "from": previous_assignment,
                        "to": request.assigned_to,
                        "version": version,
                        "bulk": True,
                    }
                    event_type = AlertWorkflowEventType.ASSIGNMENT_CHANGED
                    audit_action = "ALERT_ASSIGNMENT_CHANGED"
                    self._notify_assignment(
                        connection,
                        row=row,
                        analyst_id=request.assigned_to,
                        version=version,
                        occurred_at=now,
                    )
                self._append_history(
                    connection,
                    alert_id=alert_id,
                    event_type=event_type,
                    actor=actor,
                    occurred_at=now,
                    details=details,
                    version=version,
                )
                self._append_audit(
                    connection,
                    action=audit_action,
                    alert_id=alert_id,
                    actor=actor,
                    occurred_at=now,
                    details=details,
                )

        updated = [self.get(alert_id) for alert_id in identifiers]
        return AlertBulkResponse(
            action=request.action,
            selected_count=len(identifiers),
            updated_count=len(identifiers),
            items=[item for item in updated if item is not None],
        )
