"""Transactional incident checklist, evidence pinning, and unified activity reads."""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal
from app.schemas.investigations import (
    ChecklistCreate,
    ChecklistItem,
    ChecklistReorder,
    ChecklistUpdate,
    EvidenceAnnotationUpdate,
    EvidencePin,
    EvidencePinCreate,
    EvidenceType,
    InvestigationActivity,
    InvestigationAnalyst,
    InvestigationTimelinePage,
    InvestigationWorkspace,
)
from app.services.wazuh_normalizer import canonical_json


class InvestigationNotFoundError(LookupError):
    pass


class InvestigationEvidenceNotFoundError(LookupError):
    pass


class InvestigationConflictError(RuntimeError):
    pass


class InvestigationDuplicateError(RuntimeError):
    pass


class InvestigationAssigneeNotFoundError(LookupError):
    pass


class InvestigationNoChangeError(RuntimeError):
    pass


class InvalidInvestigationCursorError(ValueError):
    pass


def _identifier(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex.upper()}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_cursor(offset: int) -> str:
    raw = canonical_json({"offset": offset, "v": 1}).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload: Any = json.loads(
            base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        )
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidInvestigationCursorError("cursor is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"offset", "v"}
        or payload["v"] != 1
        or not isinstance(payload["offset"], int)
        or isinstance(payload["offset"], bool)
        or payload["offset"] < 0
    ):
        raise InvalidInvestigationCursorError("cursor is malformed")
    return payload["offset"]


class InvestigationRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _require_incident(connection: sqlite3.Connection, incident_id: str) -> None:
        if connection.execute(
            "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone() is None:
            raise InvestigationNotFoundError(incident_id)

    @staticmethod
    def _require_assignee(
        connection: sqlite3.Connection, analyst_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT analyst_id, username, display_name FROM analysts
            WHERE analyst_id = ? AND is_active = 1 AND role IN ('ADMIN', 'ANALYST')
            """,
            (analyst_id,),
        ).fetchone()
        if row is None:
            raise InvestigationAssigneeNotFoundError(analyst_id)
        return row

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        actor: AnalystPrincipal,
        target_id: str,
        occurred_at: datetime,
        details: dict[str, object],
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, 'incident', ?, 'SUCCESS', ?, ?)
            """,
            (
                _identifier("AUD"), action, actor.analyst_id, actor.audit_display,
                target_id, occurred_at.isoformat(), canonical_json(details),
            ),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN ("
            "SELECT audit_id FROM security_audit_events "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    @staticmethod
    def _activity(
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        activity_type: str,
        entity_type: str,
        entity_id: str,
        actor: AnalystPrincipal,
        action_at: datetime,
        details: dict[str, object],
        source_timestamp: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO incident_investigation_activity (
                activity_id, incident_id, activity_type, entity_type, entity_id,
                actor_id, actor_display, action_at, source_timestamp, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _identifier("ACT"), incident_id, activity_type, entity_type, entity_id,
                actor.analyst_id, actor.audit_display, action_at.isoformat(),
                source_timestamp, canonical_json(details),
            ),
        )
        connection.execute(
            "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
            (action_at.isoformat(), incident_id),
        )

    @staticmethod
    def _checklist_from_row(row: sqlite3.Row) -> ChecklistItem:
        assignee = None
        if row["assigned_to"] is not None:
            assignee = InvestigationAnalyst(
                analyst_id=row["assigned_to"],
                username=row["assignee_username"],
                display_name=row["assignee_display"],
            )
        return ChecklistItem(
            checklist_item_id=row["checklist_item_id"],
            incident_id=row["incident_id"],
            body=row["body"],
            is_completed=bool(row["is_completed"]),
            assigned_to=assignee,
            position=int(row["position"]),
            version=int(row["version"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"] else None
            ),
            created_by_display=row["created_by_display"],
            updated_by_display=row["updated_by_display"],
        )

    @staticmethod
    def _evidence_from_row(row: sqlite3.Row) -> EvidencePin:
        return EvidencePin(
            evidence_pin_id=row["evidence_pin_id"],
            incident_id=row["incident_id"],
            evidence_type=EvidenceType(row["evidence_type"]),
            evidence_id=row["evidence_id"],
            annotation=row["annotation"],
            source_timestamp=datetime.fromisoformat(row["source_timestamp"]),
            pinned_by_display=row["pinned_by_display"],
            pinned_at=datetime.fromisoformat(row["pinned_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            version=int(row["version"]),
        )

    @staticmethod
    def _checklist_select() -> str:
        return """
            SELECT c.*, assignee.username AS assignee_username,
                   assignee.display_name AS assignee_display,
                   COALESCE(creator.display_name, 'Deleted analyst') AS created_by_display,
                   COALESCE(updater.display_name, 'Deleted analyst') AS updated_by_display
            FROM incident_checklist_items c
            LEFT JOIN analysts assignee ON assignee.analyst_id = c.assigned_to
            LEFT JOIN analysts creator ON creator.analyst_id = c.created_by
            LEFT JOIN analysts updater ON updater.analyst_id = c.updated_by
        """

    def _workspace(
        self, connection: sqlite3.Connection, incident_id: str
    ) -> InvestigationWorkspace:
        checklist_rows = connection.execute(
            self._checklist_select()
            + " WHERE c.incident_id = ? ORDER BY c.position, c.checklist_item_id",
            (incident_id,),
        ).fetchall()
        evidence_rows = connection.execute(
            "SELECT * FROM incident_evidence_pins WHERE incident_id = ? "
            "ORDER BY pinned_at DESC, evidence_pin_id DESC",
            (incident_id,),
        ).fetchall()
        checklist = [self._checklist_from_row(row) for row in checklist_rows]
        return InvestigationWorkspace(
            incident_id=incident_id,
            checklist_items=checklist,
            evidence_pins=[self._evidence_from_row(row) for row in evidence_rows],
            checklist_completed=sum(item.is_completed for item in checklist),
            checklist_total=len(checklist),
        )

    def get_workspace(self, incident_id: str) -> InvestigationWorkspace:
        with self._connect() as connection:
            self._require_incident(connection, incident_id)
            return self._workspace(connection, incident_id)

    def create_checklist_item(
        self, incident_id: str, payload: ChecklistCreate, actor: AnalystPrincipal
    ) -> InvestigationWorkspace:
        now = _now()
        item_id = _identifier("CHK")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            count = int(connection.execute(
                "SELECT COUNT(*) FROM incident_checklist_items WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()[0])
            if count >= 100:
                raise InvestigationConflictError("Checklist is limited to 100 items")
            if payload.assigned_to is not None:
                self._require_assignee(connection, payload.assigned_to)
            position = int(connection.execute(
                "SELECT COALESCE(MAX(position), -1) + 1 FROM incident_checklist_items "
                "WHERE incident_id = ?", (incident_id,),
            ).fetchone()[0])
            connection.execute(
                """
                INSERT INTO incident_checklist_items (
                    checklist_item_id, incident_id, body, is_completed, assigned_to,
                    position, version, created_at, updated_at, completed_at,
                    created_by, updated_by
                ) VALUES (?, ?, ?, 0, ?, ?, 1, ?, ?, NULL, ?, ?)
                """,
                (
                    item_id, incident_id, payload.body, payload.assigned_to, position,
                    now.isoformat(), now.isoformat(), actor.analyst_id, actor.analyst_id,
                ),
            )
            details = {"body": payload.body, "assigned_to": payload.assigned_to, "position": position}
            self._activity(
                connection, incident_id=incident_id, activity_type="CHECKLIST_CREATED",
                entity_type="checklist", entity_id=item_id, actor=actor,
                action_at=now, details=details,
            )
            self._audit(
                connection, action="INCIDENT_CHECKLIST_CREATED", actor=actor,
                target_id=incident_id, occurred_at=now,
                details={"checklist_item_id": item_id},
            )
            return self._workspace(connection, incident_id)

    def update_checklist_item(
        self,
        incident_id: str,
        item_id: str,
        payload: ChecklistUpdate,
        actor: AnalystPrincipal,
    ) -> InvestigationWorkspace:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            row = connection.execute(
                "SELECT * FROM incident_checklist_items "
                "WHERE incident_id = ? AND checklist_item_id = ?",
                (incident_id, item_id),
            ).fetchone()
            if row is None:
                raise InvestigationNotFoundError(item_id)
            if int(row["version"]) != payload.expected_version:
                raise InvestigationConflictError(
                    f"Expected version {payload.expected_version}; current version is {row['version']}"
                )
            fields = payload.model_fields_set
            body = payload.body if "body" in fields else str(row["body"])
            completed = payload.is_completed if "is_completed" in fields else bool(row["is_completed"])
            assigned_to = payload.assigned_to if "assigned_to" in fields else row["assigned_to"]
            if assigned_to is not None:
                self._require_assignee(connection, assigned_to)
            changes: dict[str, object] = {}
            if body != row["body"]:
                changes["body"] = {"from": row["body"], "to": body}
            if completed != bool(row["is_completed"]):
                changes["is_completed"] = {"from": bool(row["is_completed"]), "to": completed}
            if assigned_to != row["assigned_to"]:
                changes["assigned_to"] = {"from": row["assigned_to"], "to": assigned_to}
            if not changes:
                raise InvestigationNoChangeError("Checklist item is unchanged")
            completed_at = now.isoformat() if completed else None
            connection.execute(
                """
                UPDATE incident_checklist_items
                SET body = ?, is_completed = ?, assigned_to = ?, version = version + 1,
                    updated_at = ?, completed_at = ?, updated_by = ?
                WHERE incident_id = ? AND checklist_item_id = ? AND version = ?
                """,
                (
                    body, int(completed), assigned_to, now.isoformat(), completed_at,
                    actor.analyst_id, incident_id, item_id, payload.expected_version,
                ),
            )
            if "is_completed" in changes and len(changes) == 1:
                activity_type = "CHECKLIST_COMPLETED" if completed else "CHECKLIST_REOPENED"
            elif "assigned_to" in changes and len(changes) == 1:
                activity_type = "CHECKLIST_ASSIGNED"
            else:
                activity_type = "CHECKLIST_UPDATED"
            self._activity(
                connection, incident_id=incident_id, activity_type=activity_type,
                entity_type="checklist", entity_id=item_id, actor=actor,
                action_at=now, details={"changes": changes},
            )
            self._audit(
                connection, action=f"INCIDENT_{activity_type}", actor=actor,
                target_id=incident_id, occurred_at=now,
                details={"checklist_item_id": item_id, "changes": changes},
            )
            return self._workspace(connection, incident_id)

    def reorder_checklist(
        self, incident_id: str, payload: ChecklistReorder, actor: AnalystPrincipal
    ) -> InvestigationWorkspace:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            current = connection.execute(
                "SELECT checklist_item_id, version, position FROM incident_checklist_items "
                "WHERE incident_id = ? ORDER BY position, checklist_item_id",
                (incident_id,),
            ).fetchall()
            requested = {item.checklist_item_id: item.expected_version for item in payload.items}
            current_ids = {str(row["checklist_item_id"]) for row in current}
            if set(requested) != current_ids:
                raise InvestigationConflictError("Reorder must include every current checklist item")
            for row in current:
                if requested[str(row["checklist_item_id"])] != int(row["version"]):
                    raise InvestigationConflictError(
                        f"Checklist item {row['checklist_item_id']} has a newer version"
                    )
            current_order = [str(row["checklist_item_id"]) for row in current]
            next_order = [item.checklist_item_id for item in payload.items]
            if current_order == next_order:
                raise InvestigationNoChangeError("Checklist order is unchanged")
            connection.execute(
                "UPDATE incident_checklist_items SET position = position + 1000 "
                "WHERE incident_id = ?", (incident_id,),
            )
            for position, item in enumerate(payload.items):
                connection.execute(
                    """
                    UPDATE incident_checklist_items
                    SET position = ?, version = version + 1, updated_at = ?, updated_by = ?
                    WHERE incident_id = ? AND checklist_item_id = ?
                    """,
                    (position, now.isoformat(), actor.analyst_id, incident_id, item.checklist_item_id),
                )
            self._activity(
                connection, incident_id=incident_id, activity_type="CHECKLIST_REORDERED",
                entity_type="checklist", entity_id=incident_id, actor=actor,
                action_at=now, details={"order": next_order},
            )
            self._audit(
                connection, action="INCIDENT_CHECKLIST_REORDERED", actor=actor,
                target_id=incident_id, occurred_at=now, details={"order": next_order},
            )
            return self._workspace(connection, incident_id)

    @staticmethod
    def _evidence_timestamp(
        connection: sqlite3.Connection,
        incident_id: str,
        evidence_type: EvidenceType,
        evidence_id: str,
    ) -> str:
        if evidence_type is EvidenceType.EVENT:
            row = connection.execute(
                "SELECT occurred_at FROM security_events WHERE event_id = ?", (evidence_id,)
            ).fetchone()
        elif evidence_type is EvidenceType.ALERT:
            row = connection.execute(
                "SELECT occurred_at FROM alerts WHERE alert_id = ?", (evidence_id,)
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT a.occurred_at FROM incident_alerts ia
                JOIN alerts a ON a.alert_id = ia.alert_id
                WHERE ia.incident_id = ? AND ia.alert_id = ?
                """,
                (incident_id, evidence_id),
            ).fetchone()
        if row is None:
            raise InvestigationEvidenceNotFoundError(evidence_id)
        return str(row["occurred_at"])

    def pin_evidence(
        self, incident_id: str, payload: EvidencePinCreate, actor: AnalystPrincipal
    ) -> InvestigationWorkspace:
        now = _now()
        pin_id = _identifier("PIN")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            count = int(connection.execute(
                "SELECT COUNT(*) FROM incident_evidence_pins WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()[0])
            if count >= 100:
                raise InvestigationConflictError("Pinned evidence is limited to 100 items")
            source_timestamp = self._evidence_timestamp(
                connection, incident_id, payload.evidence_type, payload.evidence_id
            )
            try:
                connection.execute(
                    """
                    INSERT INTO incident_evidence_pins (
                        evidence_pin_id, incident_id, evidence_type, evidence_id,
                        annotation, source_timestamp, pinned_by, pinned_by_display,
                        pinned_at, updated_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                    """,
                    (
                        pin_id, incident_id, payload.evidence_type.value, payload.evidence_id,
                        payload.annotation, source_timestamp, actor.analyst_id,
                        actor.audit_display, now.isoformat(), now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise InvestigationDuplicateError("Evidence is already pinned") from exc
            details = {
                "evidence_type": payload.evidence_type.value,
                "evidence_id": payload.evidence_id,
                "annotation": payload.annotation,
            }
            self._activity(
                connection, incident_id=incident_id, activity_type="EVIDENCE_PINNED",
                entity_type="evidence", entity_id=pin_id, actor=actor,
                action_at=now, source_timestamp=source_timestamp, details=details,
            )
            self._audit(
                connection, action="INCIDENT_EVIDENCE_PINNED", actor=actor,
                target_id=incident_id, occurred_at=now,
                details={"evidence_pin_id": pin_id, **details},
            )
            return self._workspace(connection, incident_id)

    def annotate_evidence(
        self,
        incident_id: str,
        pin_id: str,
        payload: EvidenceAnnotationUpdate,
        actor: AnalystPrincipal,
    ) -> InvestigationWorkspace:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            row = connection.execute(
                "SELECT * FROM incident_evidence_pins "
                "WHERE incident_id = ? AND evidence_pin_id = ?",
                (incident_id, pin_id),
            ).fetchone()
            if row is None:
                raise InvestigationNotFoundError(pin_id)
            if int(row["version"]) != payload.expected_version:
                raise InvestigationConflictError(
                    f"Expected version {payload.expected_version}; current version is {row['version']}"
                )
            if row["annotation"] == payload.annotation:
                raise InvestigationNoChangeError("Evidence annotation is unchanged")
            connection.execute(
                "UPDATE incident_evidence_pins SET annotation = ?, updated_at = ?, "
                "version = version + 1 WHERE evidence_pin_id = ? AND version = ?",
                (payload.annotation, now.isoformat(), pin_id, payload.expected_version),
            )
            details = {"from": row["annotation"], "to": payload.annotation}
            self._activity(
                connection, incident_id=incident_id, activity_type="EVIDENCE_ANNOTATED",
                entity_type="evidence", entity_id=pin_id, actor=actor,
                action_at=now, source_timestamp=row["source_timestamp"], details=details,
            )
            self._audit(
                connection, action="INCIDENT_EVIDENCE_ANNOTATED", actor=actor,
                target_id=incident_id, occurred_at=now,
                details={"evidence_pin_id": pin_id},
            )
            return self._workspace(connection, incident_id)

    def unpin_evidence(
        self, incident_id: str, pin_id: str, expected_version: int, actor: AnalystPrincipal
    ) -> InvestigationWorkspace:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            row = connection.execute(
                "SELECT * FROM incident_evidence_pins "
                "WHERE incident_id = ? AND evidence_pin_id = ?",
                (incident_id, pin_id),
            ).fetchone()
            if row is None:
                raise InvestigationNotFoundError(pin_id)
            if int(row["version"]) != expected_version:
                raise InvestigationConflictError(
                    f"Expected version {expected_version}; current version is {row['version']}"
                )
            details = {"evidence_type": row["evidence_type"], "evidence_id": row["evidence_id"]}
            connection.execute(
                "DELETE FROM incident_evidence_pins WHERE evidence_pin_id = ? AND version = ?",
                (pin_id, expected_version),
            )
            self._activity(
                connection, incident_id=incident_id, activity_type="EVIDENCE_UNPINNED",
                entity_type="evidence", entity_id=pin_id, actor=actor,
                action_at=now, source_timestamp=row["source_timestamp"], details=details,
            )
            self._audit(
                connection, action="INCIDENT_EVIDENCE_UNPINNED", actor=actor,
                target_id=incident_id, occurred_at=now,
                details={"evidence_pin_id": pin_id, **details},
            )
            return self._workspace(connection, incident_id)

    def timeline(
        self, incident_id: str, *, limit: int = 50, cursor: str | None = None
    ) -> InvestigationTimelinePage:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        offset = _decode_cursor(cursor) if cursor else 0
        with self._connect() as connection:
            self._require_incident(connection, incident_id)
            total = int(connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM incident_history WHERE incident_id = ?) +
                    (SELECT COUNT(*) FROM incident_investigation_activity WHERE incident_id = ?)
                """,
                (incident_id, incident_id),
            ).fetchone()[0])
            rows = connection.execute(
                """
                SELECT activity_id, activity_type, entity_type, entity_id,
                       actor_display, action_at, source_timestamp, details_json
                FROM (
                    SELECT event_id AS activity_id, event_type AS activity_type,
                           'incident' AS entity_type, incident_id AS entity_id,
                           actor AS actor_display, occurred_at AS action_at,
                           CASE WHEN event_type = 'ALERT_LINKED' THEN (
                               SELECT a.occurred_at FROM alerts a
                               WHERE a.alert_id = json_extract(incident_history.details_json, '$.alert_id')
                           ) ELSE NULL END AS source_timestamp,
                           details_json
                    FROM incident_history WHERE incident_id = ?
                    UNION ALL
                    SELECT activity_id, activity_type, entity_type, entity_id,
                           actor_display, action_at, source_timestamp, details_json
                    FROM incident_investigation_activity WHERE incident_id = ?
                )
                ORDER BY action_at DESC, activity_id DESC LIMIT ? OFFSET ?
                """,
                (incident_id, incident_id, limit + 1, offset),
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return InvestigationTimelinePage(
            items=[
                InvestigationActivity(
                    activity_id=row["activity_id"],
                    activity_type=row["activity_type"],
                    entity_type=row["entity_type"],
                    entity_id=row["entity_id"],
                    actor_display=row["actor_display"],
                    action_at=datetime.fromisoformat(row["action_at"]),
                    source_timestamp=(
                        datetime.fromisoformat(row["source_timestamp"])
                        if row["source_timestamp"] else None
                    ),
                    details=json.loads(row["details_json"]),
                )
                for row in rows
            ],
            limit=limit,
            next_cursor=_encode_cursor(offset + limit) if has_more else None,
            total=total,
        )
