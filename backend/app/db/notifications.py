"""Bounded, per-analyst notification reads and read-state mutations."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal
from app.schemas.notifications import AnalystNotification, NotificationCategory
from app.services.wazuh_normalizer import canonical_json


class NotificationNotFoundError(LookupError):
    pass


class NotificationRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _from_row(row: sqlite3.Row) -> AnalystNotification:
        return AnalystNotification(
            notification_id=row["notification_id"],
            category=NotificationCategory(row["category"]),
            title=row["title"],
            preview=row["preview"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            read_at=datetime.fromisoformat(row["read_at"]) if row["read_at"] else None,
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        actor: AnalystPrincipal,
        target_id: str | None,
        occurred_at: datetime,
        details: dict[str, object],
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, 'notification', ?, 'SUCCESS', ?, ?)
            """,
            (
                f"AUD-{uuid4().hex.upper()}", action, actor.analyst_id,
                actor.audit_display, target_id, occurred_at.isoformat(),
                canonical_json(details),
            ),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN ("
            "SELECT audit_id FROM security_audit_events "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    def list(
        self,
        analyst_id: str,
        *,
        limit: int = 25,
        unread_only: bool = False,
    ) -> tuple[list[AnalystNotification], int]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        with self._connect() as connection:
            unread_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM analyst_notifications "
                    "WHERE analyst_id = ? AND read_at IS NULL",
                    (analyst_id,),
                ).fetchone()[0]
            )
            where = "analyst_id = ?" + (" AND read_at IS NULL" if unread_only else "")
            rows = connection.execute(
                "SELECT * FROM analyst_notifications WHERE " + where
                + " ORDER BY created_at DESC, notification_id DESC LIMIT ?",
                (analyst_id, limit),
            ).fetchall()
        return [self._from_row(row) for row in rows], unread_count

    def mark_read(self, notification_id: str, actor: AnalystPrincipal) -> AnalystNotification:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM analyst_notifications "
                "WHERE notification_id = ? AND analyst_id = ?",
                (notification_id, actor.analyst_id),
            ).fetchone()
            if row is None:
                raise NotificationNotFoundError(notification_id)
            if row["read_at"] is None:
                connection.execute(
                    "UPDATE analyst_notifications SET read_at = ? "
                    "WHERE notification_id = ? AND analyst_id = ? AND read_at IS NULL",
                    (now.isoformat(), notification_id, actor.analyst_id),
                )
                self._audit(
                    connection,
                    action="NOTIFICATION_MARKED_READ",
                    actor=actor,
                    target_id=notification_id,
                    occurred_at=now,
                    details={"category": row["category"]},
                )
        with self._connect() as connection:
            updated = connection.execute(
                "SELECT * FROM analyst_notifications "
                "WHERE notification_id = ? AND analyst_id = ?",
                (notification_id, actor.analyst_id),
            ).fetchone()
        if updated is None:
            raise NotificationNotFoundError(notification_id)
        return self._from_row(updated)

    def mark_all_read(self, actor: AnalystPrincipal) -> int:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE analyst_notifications SET read_at = ? "
                "WHERE analyst_id = ? AND read_at IS NULL",
                (now.isoformat(), actor.analyst_id),
            ).rowcount
            if updated:
                self._audit(
                    connection,
                    action="NOTIFICATIONS_MARKED_READ",
                    actor=actor,
                    target_id=None,
                    occurred_at=now,
                    details={"updated_count": updated},
                )
        return updated
