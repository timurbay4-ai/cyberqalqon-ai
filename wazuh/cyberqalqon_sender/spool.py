"""Durable bounded SQLite spool, counters, leases, and dead letters."""

from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .logging import safe_text
from .models import (
    AlertPayload,
    DeliveryClassification,
    FailureCategory,
    QueueItem,
    StatusSnapshot,
)


SCHEMA_VERSION = 1
PENDING = "PENDING"
IN_FLIGHT = "IN_FLIGHT"
TERMINAL_BLOCKED = "TERMINAL_BLOCKED"


class SpoolError(RuntimeError):
    """Base error for sender persistence failures."""


class QueueCapacityError(SpoolError):
    """New evidence cannot fit without violating a configured bound."""


class ReplayRefusedError(SpoolError):
    """Manual replay requires a more explicit operator decision."""


@dataclass(frozen=True, slots=True)
class SpoolLimits:
    queue_max_items: int
    queue_max_bytes: int
    dead_letter_max_items: int
    dead_letter_max_bytes: int
    busy_timeout_seconds: float


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE sender_stats (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        queue_count INTEGER NOT NULL DEFAULT 0 CHECK (queue_count >= 0),
        queue_bytes INTEGER NOT NULL DEFAULT 0 CHECK (queue_bytes >= 0),
        dead_letter_count INTEGER NOT NULL DEFAULT 0 CHECK (dead_letter_count >= 0),
        dead_letter_bytes INTEGER NOT NULL DEFAULT 0 CHECK (dead_letter_bytes >= 0),
        delivered_count INTEGER NOT NULL DEFAULT 0 CHECK (delivered_count >= 0),
        duplicate_count INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_count >= 0),
        transient_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (transient_failure_count >= 0),
        retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
        conflict_count INTEGER NOT NULL DEFAULT 0 CHECK (conflict_count >= 0),
        permanent_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (permanent_failure_count >= 0),
        queue_rejected_count INTEGER NOT NULL DEFAULT 0 CHECK (queue_rejected_count >= 0),
        dead_letter_blocked_count INTEGER NOT NULL DEFAULT 0 CHECK (dead_letter_blocked_count >= 0),
        last_success_at REAL,
        last_failure_at REAL,
        last_failure_category TEXT,
        last_safe_error TEXT
    ) STRICT
    """,
    "INSERT INTO sender_stats(singleton) VALUES (1)",
    """
    CREATE TABLE queue_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
        state TEXT NOT NULL CHECK (state IN ('PENDING', 'IN_FLIGHT', 'TERMINAL_BLOCKED')),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
        next_attempt_at REAL NOT NULL,
        lease_token TEXT,
        lease_until REAL,
        created_at REAL NOT NULL,
        updated_at REAL NOT NULL,
        last_failure_category TEXT,
        last_safe_error TEXT,
        last_http_status INTEGER,
        replay_of_dead_letter_id INTEGER
    ) STRICT
    """,
    """
    CREATE INDEX queue_due_idx
    ON queue_items(state, next_attempt_at, id)
    """,
    """
    CREATE INDEX queue_oldest_idx
    ON queue_items(state, created_at)
    """,
    """
    CREATE INDEX queue_lease_idx
    ON queue_items(state, lease_until, next_attempt_at, id)
    """,
    """
    CREATE TABLE dead_letters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_queue_id INTEGER NOT NULL,
        alert_id TEXT,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
        classification TEXT NOT NULL,
        failure_category TEXT NOT NULL,
        http_status INTEGER,
        safe_message TEXT NOT NULL,
        attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
        first_seen_at REAL NOT NULL,
        failed_at REAL NOT NULL,
        replay_count INTEGER NOT NULL DEFAULT 0 CHECK (replay_count >= 0),
        last_replay_at REAL,
        last_replay_queue_id INTEGER,
        last_replay_result TEXT
    ) STRICT
    """,
    """
    CREATE INDEX dead_letters_failed_idx
    ON dead_letters(failed_at DESC, id DESC)
    """,
)


class SQLiteSpool:
    def __init__(self, database_path: Path, limits: SpoolLimits) -> None:
        self.database_path = database_path
        self.limits = limits

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self.limits.busy_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(
            f"PRAGMA busy_timeout = {int(self.limits.busy_timeout_seconds * 1000)}"
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        parent = self.database_path.parent
        parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        existed = self.database_path.exists()
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL").fetchone()
            connection.execute("PRAGMA synchronous = FULL")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise SpoolError(
                    f"sender database schema {version} is newer than supported {SCHEMA_VERSION}"
                )
            if version == 0:
                connection.execute("BEGIN EXCLUSIVE")
                try:
                    for statement in SCHEMA_STATEMENTS:
                        connection.execute(statement)
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
        except sqlite3.DatabaseError as exc:
            raise SpoolError("sender database initialization failed") from exc
        finally:
            connection.close()
        if os.name == "posix" and (not existed or self.database_path.exists()):
            os.chmod(self.database_path, 0o600)

    @staticmethod
    def _capacity_message(kind: str, count_limit: int, byte_limit: int) -> str:
        return (
            f"{kind} capacity exhausted (item limit {count_limit}, "
            f"payload-byte limit {byte_limit})"
        )

    def _queue_has_capacity(self, stats: sqlite3.Row, payload_bytes: int) -> bool:
        return (
            int(stats["queue_count"]) < self.limits.queue_max_items
            and int(stats["queue_bytes"]) + payload_bytes <= self.limits.queue_max_bytes
        )

    def enqueue(
        self,
        payload: AlertPayload,
        *,
        now: float,
        replay_of_dead_letter_id: int | None = None,
    ) -> int:
        rejected = False
        queue_id: int | None = None
        with self._transaction() as connection:
            stats = connection.execute(
                "SELECT * FROM sender_stats WHERE singleton = 1"
            ).fetchone()
            if stats is None:
                raise SpoolError("sender statistics row is missing")
            if not self._queue_has_capacity(stats, payload.payload_bytes):
                rejected = True
                message = self._capacity_message(
                    "queue",
                    self.limits.queue_max_items,
                    self.limits.queue_max_bytes,
                )
                connection.execute(
                    """
                    UPDATE sender_stats
                    SET queue_rejected_count = queue_rejected_count + 1,
                        last_failure_at = ?,
                        last_failure_category = ?,
                        last_safe_error = ?
                    WHERE singleton = 1
                    """,
                    (now, FailureCategory.QUEUE_CAPACITY.value, message),
                )
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO queue_items(
                        alert_id, payload_json, payload_sha256, payload_bytes,
                        state, attempt_count, next_attempt_at, created_at, updated_at,
                        replay_of_dead_letter_id
                    ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?)
                    """,
                    (
                        payload.alert_id,
                        payload.canonical_json,
                        payload.payload_sha256,
                        payload.payload_bytes,
                        now,
                        now,
                        now,
                        replay_of_dead_letter_id,
                    ),
                )
                queue_id = int(cursor.lastrowid)
                connection.execute(
                    """
                    UPDATE sender_stats
                    SET queue_count = queue_count + 1,
                        queue_bytes = queue_bytes + ?
                    WHERE singleton = 1
                    """,
                    (payload.payload_bytes,),
                )
        if rejected:
            raise QueueCapacityError(
                self._capacity_message(
                    "queue",
                    self.limits.queue_max_items,
                    self.limits.queue_max_bytes,
                )
            )
        if queue_id is None:
            raise SpoolError("enqueue did not create a queue record")
        return queue_id

    @staticmethod
    def _queue_item(row: sqlite3.Row, *, deliver_allowed: bool) -> QueueItem:
        return QueueItem(
            id=int(row["id"]),
            alert_id=row["alert_id"],
            payload_json=row["payload_json"],
            payload_sha256=row["payload_sha256"],
            payload_bytes=int(row["payload_bytes"]),
            state=row["state"],
            attempt_count=int(row["attempt_count"]),
            next_attempt_at=float(row["next_attempt_at"]),
            lease_token=row["lease_token"],
            lease_until=float(row["lease_until"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            replay_of_dead_letter_id=row["replay_of_dead_letter_id"],
            deliver_allowed=deliver_allowed,
        )

    def _claim(
        self,
        *,
        now: float,
        lease_seconds: float,
        max_attempts: int,
        queue_id: int | None,
    ) -> QueueItem | None:
        with self._transaction() as connection:
            parameters: list[Any] = [PENDING, now, IN_FLIGHT, now]
            id_clause = ""
            if queue_id is not None:
                id_clause = "AND id = ?"
                parameters.append(queue_id)
            row = connection.execute(
                f"""
                SELECT * FROM queue_items
                WHERE (
                    (state = ? AND next_attempt_at <= ?)
                    OR (state = ? AND lease_until <= ?)
                )
                {id_clause}
                ORDER BY next_attempt_at ASC, id ASC
                LIMIT 1
                """,
                parameters,
            ).fetchone()
            if row is None:
                return None
            deliver_allowed = int(row["attempt_count"]) < max_attempts
            lease_token = uuid.uuid4().hex
            attempt_increment = 1 if deliver_allowed else 0
            connection.execute(
                """
                UPDATE queue_items
                SET state = 'IN_FLIGHT',
                    attempt_count = attempt_count + ?,
                    lease_token = ?,
                    lease_until = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (attempt_increment, lease_token, now + lease_seconds, now, int(row["id"])),
            )
            claimed = connection.execute(
                "SELECT * FROM queue_items WHERE id = ?", (int(row["id"]),)
            ).fetchone()
            if claimed is None:
                raise SpoolError("claimed queue record disappeared")
            return self._queue_item(claimed, deliver_allowed=deliver_allowed)

    def claim_due(
        self,
        *,
        now: float,
        lease_seconds: float,
        max_attempts: int,
    ) -> QueueItem | None:
        return self._claim(
            now=now,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            queue_id=None,
        )

    def claim_by_id(
        self,
        queue_id: int,
        *,
        now: float,
        lease_seconds: float,
        max_attempts: int,
    ) -> QueueItem | None:
        return self._claim(
            now=now,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
            queue_id=queue_id,
        )

    @staticmethod
    def _leased_row(
        connection: sqlite3.Connection,
        queue_id: int,
        lease_token: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT * FROM queue_items
            WHERE id = ? AND state = 'IN_FLIGHT' AND lease_token = ?
            """,
            (queue_id, lease_token),
        ).fetchone()
        if row is None:
            raise SpoolError("queue lease is stale or missing")
        return row

    @staticmethod
    def _record_replay_result(
        connection: sqlite3.Connection,
        replay_id: int | None,
        result: str,
        now: float,
    ) -> None:
        if replay_id is not None:
            connection.execute(
                """
                UPDATE dead_letters
                SET last_replay_result = ?, last_replay_at = ?
                WHERE id = ?
                """,
                (result, now, replay_id),
            )

    def finish_success(
        self,
        item: QueueItem,
        classification: DeliveryClassification,
        *,
        now: float,
    ) -> None:
        if classification not in {
            DeliveryClassification.DELIVERED,
            DeliveryClassification.DUPLICATE,
        }:
            raise ValueError("finish_success requires a delivered-equivalent result")
        counter = "delivered_count" if classification == DeliveryClassification.DELIVERED else "duplicate_count"
        with self._transaction() as connection:
            row = self._leased_row(connection, item.id, item.lease_token)
            connection.execute("DELETE FROM queue_items WHERE id = ?", (item.id,))
            connection.execute(
                f"""
                UPDATE sender_stats
                SET queue_count = queue_count - 1,
                    queue_bytes = queue_bytes - ?,
                    {counter} = {counter} + 1,
                    last_success_at = ?
                WHERE singleton = 1
                """,
                (int(row["payload_bytes"]), now),
            )
            self._record_replay_result(
                connection,
                row["replay_of_dead_letter_id"],
                classification.value,
                now,
            )

    def _move_to_dead_letter(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        classification: DeliveryClassification,
        category: FailureCategory,
        safe_message: str,
        http_status: int | None,
        now: float,
    ) -> tuple[int | None, bool]:
        stats = connection.execute(
            "SELECT * FROM sender_stats WHERE singleton = 1"
        ).fetchone()
        if stats is None:
            raise SpoolError("sender statistics row is missing")
        payload_bytes = int(row["payload_bytes"])
        has_capacity = (
            int(stats["dead_letter_count"]) < self.limits.dead_letter_max_items
            and int(stats["dead_letter_bytes"]) + payload_bytes
            <= self.limits.dead_letter_max_bytes
        )
        bounded_message = safe_text(safe_message)
        if not has_capacity:
            connection.execute(
                """
                UPDATE queue_items
                SET state = 'TERMINAL_BLOCKED',
                    lease_token = NULL,
                    lease_until = NULL,
                    updated_at = ?,
                    last_failure_category = ?,
                    last_safe_error = ?,
                    last_http_status = ?
                WHERE id = ?
                """,
                (now, category.value, bounded_message, http_status, int(row["id"])),
            )
            connection.execute(
                """
                UPDATE sender_stats
                SET dead_letter_blocked_count = dead_letter_blocked_count + 1
                WHERE singleton = 1
                """
            )
            return None, True

        cursor = connection.execute(
            """
            INSERT INTO dead_letters(
                source_queue_id, alert_id, payload_json, payload_sha256,
                payload_bytes, classification, failure_category, http_status,
                safe_message, attempt_count, first_seen_at, failed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(row["id"]),
                row["alert_id"],
                row["payload_json"],
                row["payload_sha256"],
                payload_bytes,
                classification.value,
                category.value,
                http_status,
                bounded_message,
                int(row["attempt_count"]),
                float(row["created_at"]),
                now,
            ),
        )
        dead_letter_id = int(cursor.lastrowid)
        connection.execute("DELETE FROM queue_items WHERE id = ?", (int(row["id"]),))
        connection.execute(
            """
            UPDATE sender_stats
            SET queue_count = queue_count - 1,
                queue_bytes = queue_bytes - ?,
                dead_letter_count = dead_letter_count + 1,
                dead_letter_bytes = dead_letter_bytes + ?
            WHERE singleton = 1
            """,
            (payload_bytes, payload_bytes),
        )
        return dead_letter_id, False

    def finish_terminal(
        self,
        item: QueueItem,
        *,
        classification: DeliveryClassification,
        category: FailureCategory,
        safe_message: str,
        http_status: int | None,
        now: float,
    ) -> tuple[int | None, bool]:
        if classification not in {
            DeliveryClassification.PERMANENT_FAILURE,
            DeliveryClassification.CONFLICT,
            DeliveryClassification.TRANSIENT_FAILURE,
        }:
            raise ValueError("finish_terminal requires a failure result")
        with self._transaction() as connection:
            row = self._leased_row(connection, item.id, item.lease_token)
            dead_letter_id, blocked = self._move_to_dead_letter(
                connection,
                row,
                classification=classification,
                category=category,
                safe_message=safe_message,
                http_status=http_status,
                now=now,
            )
            if classification == DeliveryClassification.CONFLICT:
                counter_sql = "conflict_count = conflict_count + 1"
            elif classification == DeliveryClassification.TRANSIENT_FAILURE:
                counter_sql = "transient_failure_count = transient_failure_count + 1"
            else:
                counter_sql = "permanent_failure_count = permanent_failure_count + 1"
            connection.execute(
                f"""
                UPDATE sender_stats
                SET {counter_sql},
                    last_failure_at = ?,
                    last_failure_category = ?,
                    last_safe_error = ?
                WHERE singleton = 1
                """,
                (now, category.value, safe_text(safe_message)),
            )
            self._record_replay_result(
                connection,
                row["replay_of_dead_letter_id"],
                classification.value,
                now,
            )
            return dead_letter_id, blocked

    def finish_transient(
        self,
        item: QueueItem,
        *,
        category: FailureCategory,
        safe_message: str,
        http_status: int | None,
        next_attempt_at: float,
        max_attempts: int,
        now: float,
    ) -> tuple[int | None, bool, float | None]:
        with self._transaction() as connection:
            row = self._leased_row(connection, item.id, item.lease_token)
            connection.execute(
                """
                UPDATE sender_stats
                SET transient_failure_count = transient_failure_count + 1,
                    last_failure_at = ?,
                    last_failure_category = ?,
                    last_safe_error = ?
                WHERE singleton = 1
                """,
                (now, category.value, safe_text(safe_message)),
            )
            if int(row["attempt_count"]) >= max_attempts:
                exhausted_message = safe_text(f"retry attempts exhausted: {safe_message}")
                dead_letter_id, blocked = self._move_to_dead_letter(
                    connection,
                    row,
                    classification=DeliveryClassification.TRANSIENT_FAILURE,
                    category=FailureCategory.RETRY_EXHAUSTED,
                    safe_message=exhausted_message,
                    http_status=http_status,
                    now=now,
                )
                self._record_replay_result(
                    connection,
                    row["replay_of_dead_letter_id"],
                    DeliveryClassification.TRANSIENT_FAILURE.value,
                    now,
                )
                return dead_letter_id, blocked, None

            connection.execute(
                """
                UPDATE queue_items
                SET state = 'PENDING',
                    next_attempt_at = ?,
                    lease_token = NULL,
                    lease_until = NULL,
                    updated_at = ?,
                    last_failure_category = ?,
                    last_safe_error = ?,
                    last_http_status = ?
                WHERE id = ?
                """,
                (
                    next_attempt_at,
                    now,
                    category.value,
                    safe_text(safe_message),
                    http_status,
                    item.id,
                ),
            )
            connection.execute(
                """
                UPDATE sender_stats
                SET retry_count = retry_count + 1
                WHERE singleton = 1
                """
            )
            self._record_replay_result(
                connection,
                row["replay_of_dead_letter_id"],
                DeliveryClassification.TRANSIENT_FAILURE.value,
                now,
            )
            return None, False, next_attempt_at

    def status(self) -> StatusSnapshot:
        connection = self._connect()
        try:
            stats = connection.execute(
                "SELECT * FROM sender_stats WHERE singleton = 1"
            ).fetchone()
            if stats is None:
                raise SpoolError("sender statistics row is missing")
            states = {
                row["state"]: int(row["count"])
                for row in connection.execute(
                    "SELECT state, COUNT(*) AS count FROM queue_items GROUP BY state"
                ).fetchall()
            }
            oldest = connection.execute(
                """
                SELECT MIN(created_at) AS oldest
                FROM queue_items
                WHERE state IN ('PENDING', 'IN_FLIGHT')
                """
            ).fetchone()["oldest"]
            return StatusSnapshot(
                queue_depth=int(stats["queue_count"]),
                queue_bytes=int(stats["queue_bytes"]),
                pending_count=states.get(PENDING, 0),
                in_flight_count=states.get(IN_FLIGHT, 0),
                terminal_blocked_count=states.get(TERMINAL_BLOCKED, 0),
                dead_letter_count=int(stats["dead_letter_count"]),
                dead_letter_bytes=int(stats["dead_letter_bytes"]),
                delivered_count=int(stats["delivered_count"]),
                duplicate_count=int(stats["duplicate_count"]),
                transient_failure_count=int(stats["transient_failure_count"]),
                retry_count=int(stats["retry_count"]),
                conflict_count=int(stats["conflict_count"]),
                permanent_failure_count=int(stats["permanent_failure_count"]),
                queue_rejected_count=int(stats["queue_rejected_count"]),
                dead_letter_blocked_count=int(stats["dead_letter_blocked_count"]),
                last_success_at=stats["last_success_at"],
                last_failure_at=stats["last_failure_at"],
                last_failure_category=stats["last_failure_category"],
                last_safe_error=stats["last_safe_error"],
                oldest_pending_at=oldest,
            )
        finally:
            connection.close()

    def list_dead_letters(self, *, limit: int = 50) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(limit, 1_000))
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT id, source_queue_id, alert_id, payload_sha256, payload_bytes,
                       classification, failure_category, http_status, safe_message,
                       attempt_count, first_seen_at, failed_at, replay_count,
                       last_replay_at, last_replay_queue_id, last_replay_result
                FROM dead_letters
                ORDER BY failed_at DESC, id DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def get_dead_letter(
        self,
        dead_letter_id: int,
        *,
        include_payload: bool = False,
    ) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM dead_letters WHERE id = ?", (dead_letter_id,)
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            if not include_payload:
                result.pop("payload_json", None)
            return result
        finally:
            connection.close()

    def replay_dead_letter(
        self,
        dead_letter_id: int,
        *,
        now: float,
        force: bool = False,
    ) -> int:
        rejected = False
        queue_id: int | None = None
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM dead_letters WHERE id = ?", (dead_letter_id,)
            ).fetchone()
            if row is None:
                raise SpoolError("dead-letter record does not exist")
            if row["failure_category"] in {
                FailureCategory.AUTHENTICATION.value,
                FailureCategory.AUTHORIZATION.value,
                FailureCategory.CONFIGURATION.value,
            } and not force:
                raise ReplayRefusedError(
                    "authentication/configuration dead letters require --force after correction"
                )
            stats = connection.execute(
                "SELECT * FROM sender_stats WHERE singleton = 1"
            ).fetchone()
            if stats is None:
                raise SpoolError("sender statistics row is missing")
            payload_bytes = int(row["payload_bytes"])
            if not self._queue_has_capacity(stats, payload_bytes):
                rejected = True
                message = self._capacity_message(
                    "queue",
                    self.limits.queue_max_items,
                    self.limits.queue_max_bytes,
                )
                connection.execute(
                    """
                    UPDATE sender_stats
                    SET queue_rejected_count = queue_rejected_count + 1,
                        last_failure_at = ?,
                        last_failure_category = ?,
                        last_safe_error = ?
                    WHERE singleton = 1
                    """,
                    (now, FailureCategory.QUEUE_CAPACITY.value, message),
                )
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO queue_items(
                        alert_id, payload_json, payload_sha256, payload_bytes,
                        state, attempt_count, next_attempt_at, created_at, updated_at,
                        replay_of_dead_letter_id
                    ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, ?, ?)
                    """,
                    (
                        row["alert_id"],
                        row["payload_json"],
                        row["payload_sha256"],
                        payload_bytes,
                        now,
                        now,
                        now,
                        dead_letter_id,
                    ),
                )
                queue_id = int(cursor.lastrowid)
                connection.execute(
                    """
                    UPDATE sender_stats
                    SET queue_count = queue_count + 1,
                        queue_bytes = queue_bytes + ?
                    WHERE singleton = 1
                    """,
                    (payload_bytes,),
                )
                connection.execute(
                    """
                    UPDATE dead_letters
                    SET replay_count = replay_count + 1,
                        last_replay_at = ?,
                        last_replay_queue_id = ?,
                        last_replay_result = 'QUEUED'
                    WHERE id = ?
                    """,
                    (now, queue_id, dead_letter_id),
                )
        if rejected:
            raise QueueCapacityError(
                self._capacity_message(
                    "queue",
                    self.limits.queue_max_items,
                    self.limits.queue_max_bytes,
                )
            )
        if queue_id is None:
            raise SpoolError("dead-letter replay did not create a queue record")
        return queue_id

    def reconcile_terminal_blocked(
        self,
        *,
        now: float,
        limit: int = 100,
    ) -> dict[str, int]:
        """Move retained terminal records after an operator raises dead-letter capacity."""

        moved = 0
        bounded_limit = max(1, min(limit, 1_000))
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM queue_items
                WHERE state = 'TERMINAL_BLOCKED'
                ORDER BY updated_at ASC, id ASC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()
            for row in rows:
                stats = connection.execute(
                    "SELECT * FROM sender_stats WHERE singleton = 1"
                ).fetchone()
                if stats is None:
                    raise SpoolError("sender statistics row is missing")
                payload_bytes = int(row["payload_bytes"])
                if not (
                    int(stats["dead_letter_count"]) < self.limits.dead_letter_max_items
                    and int(stats["dead_letter_bytes"]) + payload_bytes
                    <= self.limits.dead_letter_max_bytes
                ):
                    break
                category = FailureCategory(row["last_failure_category"])
                if category == FailureCategory.CONFLICT:
                    classification = DeliveryClassification.CONFLICT
                elif category == FailureCategory.RETRY_EXHAUSTED:
                    classification = DeliveryClassification.TRANSIENT_FAILURE
                else:
                    classification = DeliveryClassification.PERMANENT_FAILURE
                dead_id, blocked = self._move_to_dead_letter(
                    connection,
                    row,
                    classification=classification,
                    category=category,
                    safe_message=row["last_safe_error"] or "terminal failure",
                    http_status=row["last_http_status"],
                    now=now,
                )
                if blocked or dead_id is None:
                    break
                moved += 1
        remaining = self.status().terminal_blocked_count
        return {"moved": moved, "remaining": remaining}

    def queue_record(self, queue_id: int) -> dict[str, Any] | None:
        """Return one record for diagnostics and deterministic tests, never configuration."""

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM queue_items WHERE id = ?", (queue_id,)
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            connection.close()
