"""Append-only, bounded security audit evidence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from app.schemas.audit import SecurityAuditEvent
from app.services.wazuh_normalizer import canonical_json


AuditOutcome = Literal["SUCCESS", "DENIED", "FAILURE"]


class AuditRepository:
    def __init__(self, database_path: Path, *, max_records: int = 10_000) -> None:
        self.path = database_path
        self.max_records = max_records

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def append(
        self,
        *,
        action: str,
        actor_id: str | None,
        actor_display: str,
        target_type: str,
        target_id: str | None = None,
        outcome: AuditOutcome = "SUCCESS",
        details: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> SecurityAuditEvent:
        now = (occurred_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        event = SecurityAuditEvent(
            audit_id=f"AUD-{uuid4().hex.upper()}",
            action=action,
            actor_id=actor_id,
            actor_display=actor_display,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            occurred_at=now,
            details=details or {},
        )
        details_json = canonical_json(event.details)
        if len(details_json.encode("utf-8")) > 8192:
            raise ValueError("audit details exceed 8192 bytes")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO security_audit_events (
                    audit_id, action, actor_id, actor_display, target_type,
                    target_id, outcome, occurred_at, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.audit_id, event.action, event.actor_id, event.actor_display,
                    event.target_type, event.target_id, event.outcome,
                    event.occurred_at.isoformat(), details_json,
                ),
            )
            connection.execute(
                "DELETE FROM security_audit_events WHERE audit_id IN ("
                "SELECT audit_id FROM security_audit_events "
                "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET ?)",
                (self.max_records,),
            )
        return event

    def list(
        self,
        *,
        limit: int = 100,
        action: str | None = None,
        actor_id: str | None = None,
        target_type: str | None = None,
        outcome: AuditOutcome | None = None,
        search: str | None = None,
    ) -> list[SecurityAuditEvent]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        conditions: list[str] = []
        parameters: list[object] = []
        if action:
            conditions.append("action = ?")
            parameters.append(action)
        if actor_id:
            conditions.append("actor_id = ?")
            parameters.append(actor_id)
        if target_type:
            conditions.append("target_type = ?")
            parameters.append(target_type)
        if outcome:
            conditions.append("outcome = ?")
            parameters.append(outcome)
        if search:
            escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append(
                "(action LIKE ? ESCAPE '\\' OR actor_display LIKE ? ESCAPE '\\' "
                "OR COALESCE(target_id, '') LIKE ? ESCAPE '\\')"
            )
            pattern = f"%{escaped}%"
            parameters.extend((pattern, pattern, pattern))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_audit_events" + where
                + " ORDER BY occurred_at DESC, audit_id DESC LIMIT ?",
                (*parameters, limit),
            ).fetchall()
        return [
            SecurityAuditEvent(
                audit_id=row["audit_id"], action=row["action"], actor_id=row["actor_id"],
                actor_display=row["actor_display"], target_type=row["target_type"],
                target_id=row["target_id"], outcome=row["outcome"],
                occurred_at=datetime.fromisoformat(row["occurred_at"]),
                details=json.loads(row["details_json"]),
            )
            for row in rows
        ]
