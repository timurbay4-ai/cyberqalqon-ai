"""Read-only, deadline-bound SQLite execution for compiled CQQL queries."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from app.db.events import EventRepository
from app.schemas.cqql import CQQLGroupResult, CQQLNamedBucket, CQQLTimeBucket
from app.schemas.events import SecurityEventSummary
from app.services.cqql import CompiledCQQL, FIELD_CATALOG
from app.db.analytics_index_proposal import available as analytics_cover_available
from app.db.analytics_index_proposal import COVER_COLUMNS, INDEX_NAME


CQQL_QUERY_DEADLINE_SECONDS = 1.5
CQQL_QUERY_DEADLINE_MS = int(CQQL_QUERY_DEADLINE_SECONDS * 1_000)
CQQL_MAX_CONCURRENT_QUERIES = 4


class InvalidCQQLCursorError(ValueError):
    pass


class CQQLQueryTimeoutError(RuntimeError):
    pass


class CQQLQueryBusyError(RuntimeError):
    pass


class CQQLQueryCancelledError(RuntimeError):
    pass


class CQQLExecutionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CQQLSearchResult:
    items: list[SecurityEventSummary]
    next_cursor: str | None
    truncated: bool
    execution_ms: float
    data_freshness: datetime | None


@dataclass(frozen=True, slots=True)
class CQQLAnalyticsResult:
    groups: list[CQQLGroupResult]
    time_series: list[CQQLTimeBucket]
    matching_events: int
    execution_ms: float


@dataclass(frozen=True, slots=True)
class CQQLExportResult:
    items: list[SecurityEventSummary]
    truncated: bool
    execution_ms: float


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc).isoformat()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _cursor_binding(
    compiled: CompiledCQQL,
    start_time: datetime,
    end_time: datetime,
    sort: str,
) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "end": _utc_iso(end_time),
                "query": compiled.fingerprint,
                "sort": sort,
                "start": _utc_iso(start_time),
                "v": 1,
            }
        ).encode("utf-8")
    ).hexdigest()


def _encode_cursor(row: sqlite3.Row, binding: str, sort: str) -> str:
    payload = {
        "binding": binding,
        "event_id": str(row["event_id"]),
        "occurred_at": str(row["occurred_at"]),
        "sort": sort,
        "v": 1,
    }
    payload["checksum"] = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    return base64.urlsafe_b64encode(_canonical(payload).encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str, binding: str, sort: str) -> tuple[str, str]:
    if not cursor or len(cursor) > 2_048:
        raise InvalidCQQLCursorError("CQQL cursor is malformed")
    try:
        decoded = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True
        )
        payload = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCQQLCursorError("CQQL cursor is malformed") from exc
    expected_keys = {"binding", "checksum", "event_id", "occurred_at", "sort", "v"}
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise InvalidCQQLCursorError("CQQL cursor is malformed")
    checksum = payload.pop("checksum", None)
    expected_checksum = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    if not isinstance(checksum, str) or not hmac.compare_digest(checksum, expected_checksum):
        raise InvalidCQQLCursorError("CQQL cursor checksum is invalid")
    if payload.get("v") != 1 or payload.get("binding") != binding or payload.get("sort") != sort:
        raise InvalidCQQLCursorError("CQQL cursor does not match this query")
    event_id = payload.get("event_id")
    occurred_at = payload.get("occurred_at")
    if not isinstance(event_id, str) or not event_id or not isinstance(occurred_at, str):
        raise InvalidCQQLCursorError("CQQL cursor is malformed")
    try:
        parsed = datetime.fromisoformat(occurred_at)
    except ValueError as exc:
        raise InvalidCQQLCursorError("CQQL cursor is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidCQQLCursorError("CQQL cursor is malformed")
    return _utc_iso(parsed), event_id


GROUP_COLUMNS: dict[str, str] = {
    "event.provider": "e.event_provider",
    "host.name": "e.hostname",
    "source.ip": "e.source_ip",
    "event.severity": "e.severity",
    "event.code": "e.event_code",
    "event.category": "e.event_category",
    "event.source_type": "e.source_type",
    "event.outcome": "e.outcome",
    "rule.id": "e.rule_id",
}


class CQQLSearchRepository:
    """Executes validated CQQL without sharing cancellation state with writers."""

    def __init__(self, database_path: Path, *, fts_strategy: Literal['legacy','m32_rowid']='legacy') -> None:
        if fts_strategy not in {'legacy','m32_rowid'}:
            raise ValueError('unsupported FTS strategy')
        self.path = database_path
        self.fts_strategy = fts_strategy
        self._slots = threading.BoundedSemaphore(CQQL_MAX_CONCURRENT_QUERIES)

    def _predicate(self, connection: sqlite3.Connection, compiled: CompiledCQQL) -> str:
        if self.fts_strategy == 'm32_rowid' and compiled.uses_fts:
            from app.db.fts_rowid import verify, rewrite
            try:
                verify(connection)
                return rewrite(compiled)
            except sqlite3.OperationalError as exc:
                if any(reason in str(exc).casefold() for reason in ('interrupt','locked','busy')):
                    raise
                raise CQQLExecutionError('Experimental FTS index is unavailable or inconsistent') from exc
            except (ValueError, sqlite3.Error) as exc:
                raise CQQLExecutionError('Experimental FTS index is unavailable or inconsistent') from exc
        return compiled.sql

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            f"{self.path.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=1,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 1000")
        return connection

    @staticmethod
    def _install_deadline(
        connection: sqlite3.Connection,
        deadline: float,
        cancel_event: threading.Event | None = None,
    ) -> None:
        connection.set_progress_handler(
            lambda: 1
            if time.perf_counter() >= deadline
            or (cancel_event is not None and cancel_event.is_set())
            else 0,
            1_000,
        )

    @staticmethod
    def _translate_sqlite(
        error: sqlite3.OperationalError,
        cancel_event: threading.Event | None = None,
    ) -> RuntimeError:
        message = str(error).casefold()
        if "interrupted" in message:
            if cancel_event is not None and cancel_event.is_set():
                return CQQLQueryCancelledError("CQQL query was cancelled by the client")
            return CQQLQueryTimeoutError("CQQL query exceeded its execution deadline")
        if "locked" in message or "busy" in message:
            return CQQLQueryBusyError("CQQL storage is temporarily busy")
        return CQQLExecutionError("CQQL query could not be executed")

    @staticmethod
    def _require_fts(connection: sqlite3.Connection, compiled: CompiledCQQL) -> None:
        if compiled.uses_fts and connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='security_events_fts'"
        ).fetchone() is None:
            raise CQQLExecutionError("CQQL full-text index is unavailable")

    def _acquire_slot(self, cancel_event: threading.Event | None) -> None:
        queue_deadline = time.perf_counter() + 0.05
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise CQQLQueryCancelledError("CQQL query was cancelled before execution")
            remaining = queue_deadline - time.perf_counter()
            if remaining <= 0:
                raise CQQLQueryBusyError("CQQL concurrent query limit reached")
            if self._slots.acquire(timeout=min(remaining, 0.01)):
                return

    def _candidate_from(self, compiled: CompiledCQQL) -> str:
        source = "security_events e"
        # Only a single positive text comparison takes the hybrid path. Its IN
        # subquery materializes the COMPLETE integer set once; never correlated
        # MATCH-per-row, never an inner candidate LIMIT or a density guess.
        from app.db.fts_rowid import LEGACY
        hybrid = self.fts_strategy == 'm32_rowid' and compiled.sql == '(' + LEGACY + ')'
        if hybrid or compiled.planner_strategy in {"TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"}:
            source += " INDEXED BY idx_security_events_occurred_id"
        return source

    def search(
        self,
        compiled: CompiledCQQL,
        *,
        start_time: datetime,
        end_time: datetime,
        sort: Literal["newest", "oldest"],
        limit: int,
        cursor: str | None,
        cancel_event: threading.Event | None = None,
    ) -> CQQLSearchResult:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        self._acquire_slot(cancel_event)
        started = time.perf_counter()
        deadline = started + CQQL_QUERY_DEADLINE_SECONDS
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._install_deadline(connection, deadline, cancel_event)
            self._require_fts(connection, compiled)
            binding = _cursor_binding(compiled, start_time, end_time, sort)
            conditions = ["e.occurred_at BETWEEN ? AND ?", self._predicate(connection, compiled)]
            parameters: list[object] = [
                _utc_iso(start_time),
                _utc_iso(end_time),
                *compiled.parameters,
            ]
            if cursor:
                occurred_at, event_id = _decode_cursor(cursor, binding, sort)
                operator = "<" if sort == "newest" else ">"
                conditions.append(f"(e.occurred_at, e.event_id) {operator} (?, ?)")
                parameters.extend((occurred_at, event_id))
            direction = "DESC" if sort == "newest" else "ASC"
            # Sort/limit narrow, index-covered identities BEFORE fetching JSON
            # evidence and joining alerts. Keep the complete compiled predicate.
            candidates = (
                f"SELECT e.event_id FROM {self._candidate_from(compiled)} "
                f"WHERE {' AND '.join(conditions)} "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction} LIMIT ?"
            )
            rows = connection.execute(
                f"SELECT {EventRepository._select_columns()} "
                f"WHERE e.event_id IN ({candidates}) "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction}",
                (*parameters, limit + 1),
            ).fetchall()
            freshness_row = connection.execute(
                "SELECT ingested_at FROM security_events ORDER BY ingested_at DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            raise self._translate_sqlite(exc, cancel_event) from exc
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)
                connection.close()
            self._slots.release()
        has_more = len(rows) > limit
        visible = rows[:limit]
        freshness = (
            datetime.fromisoformat(str(freshness_row[0])) if freshness_row is not None else None
        )
        return CQQLSearchResult(
            items=[EventRepository._summary(row) for row in visible],
            next_cursor=(
                _encode_cursor(visible[-1], binding, sort) if has_more and visible else None
            ),
            truncated=has_more,
            execution_ms=round((time.perf_counter() - started) * 1_000, 3),
            data_freshness=freshness,
        )

    def analytics(
        self,
        compiled: CompiledCQQL,
        *,
        start_time: datetime,
        end_time: datetime,
        group_by: list[str],
        top_n: int,
        interval: Literal["hour", "day"],
        cancel_event: threading.Event | None = None,
    ) -> CQQLAnalyticsResult:
        if (len(group_by) > 3 or len(set(group_by)) != len(group_by)
                or not 1 <= top_n <= 20 or interval not in {"hour", "day"}
                or any(field not in GROUP_COLUMNS for field in group_by)):
            raise ValueError("invalid bounded CQQL analytics dimensions")
        self._acquire_slot(cancel_event)
        started = time.perf_counter()
        deadline = started + CQQL_QUERY_DEADLINE_SECONDS
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._install_deadline(connection, deadline, cancel_event)
            self._require_fts(connection, compiled)
            where = f"e.occurred_at BETWEEN ? AND ? AND {self._predicate(connection, compiled)}"
            parameters: tuple[object, ...] = (
                _utc_iso(start_time),
                _utc_iso(end_time),
                *compiled.parameters,
            )
            projection = ["e.occurred_at"] + [
                f"{GROUP_COLUMNS[field]} AS g{index}" for index, field in enumerate(group_by)
            ]
            # Rowid gathering preserves predicates while fetching wide-table
            # pages in physical order. Only requested dimensions/time enter the
            # materialized relation, shared by all exact aggregates in ONE SQL
            # statement/snapshot. No sampling/capped candidate scan is used.
            matched = (
                f"SELECT {', '.join(projection)} FROM security_events e WHERE e.rowid IN ("
                f"SELECT e.rowid FROM {self._candidate_from(compiled)} WHERE {where})"
            )
            if (not compiled.uses_fts
                    and all(FIELD_CATALOG[field].column in {'e.' + name for name in COVER_COLUMNS}
                            for field in compiled.referenced_fields)
                    and analytics_cover_available(connection)):
                # An explicitly installed, definition-verified covering index
                # avoids reading wide evidence pages. This only selects an
                # existing index; no migration/DDL is ever run here.
                matched = (f"SELECT {', '.join(projection)} FROM security_events e "
                           f"INDEXED BY {INDEX_NAME} WHERE {where}")
            branches = [
                f"SELECT {index} AS dimension, name, event_count FROM ("
                f"SELECT CAST(g{index} AS TEXT) AS name, COUNT(*) AS event_count "
                f"FROM matched WHERE g{index} IS NOT NULL GROUP BY g{index} "
                "ORDER BY event_count DESC, name LIMIT ?)"
                for index in range(len(group_by))
            ]
            bucket_expression = (
                "substr(occurred_at, 1, 13) || ':00:00+00:00'"
                if interval == "hour"
                else "substr(occurred_at, 1, 10) || 'T00:00:00+00:00'"
            )
            branches.append(
                f"SELECT -1 AS dimension, {bucket_expression} AS name, COUNT(*) AS event_count "
                "FROM matched GROUP BY name"
            )
            rows = connection.execute(
                f"WITH matched AS MATERIALIZED ({matched}) " + " UNION ALL ".join(branches),
                (*parameters, *([top_n + 1] * len(group_by))),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise self._translate_sqlite(exc, cancel_event) from exc
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)
                connection.close()
            self._slots.release()
        groups = []
        for index, field in enumerate(group_by):
            buckets = sorted((row for row in rows if row["dimension"] == index),
                             key=lambda row: (-int(row["event_count"]), str(row["name"])))
            groups.append(CQQLGroupResult(field=field, buckets=[
                CQQLNamedBucket(name=str(row["name"]), count=int(row["event_count"]))
                for row in buckets[:top_n]], truncated=len(buckets) > top_n))
        time_series = sorted([
            CQQLTimeBucket(
                timestamp=datetime.fromisoformat(str(row["name"])),
                count=int(row["event_count"]),
            )
            for row in rows if row["dimension"] == -1
        ], key=lambda point: point.timestamp)
        return CQQLAnalyticsResult(
            groups=groups,
            time_series=time_series,
            matching_events=sum(point.count for point in time_series),
            execution_ms=round((time.perf_counter() - started) * 1_000, 3),
        )

    def export(
        self,
        compiled: CompiledCQQL,
        *,
        start_time: datetime,
        end_time: datetime,
        sort: Literal["newest", "oldest"],
        limit: int,
        cancel_event: threading.Event | None = None,
    ) -> CQQLExportResult:
        """Return one bounded, read-only result set under one SQLite deadline."""

        if not 1 <= limit <= 1_000:
            raise ValueError("export limit must be between 1 and 1000")
        self._acquire_slot(cancel_event)
        started = time.perf_counter()
        deadline = started + CQQL_QUERY_DEADLINE_SECONDS
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._install_deadline(connection, deadline, cancel_event)
            self._require_fts(connection, compiled)
            direction = "DESC" if sort == "newest" else "ASC"
            rows = connection.execute(
                f"SELECT {EventRepository._select_columns()} WHERE e.event_id IN ("
                f"SELECT e.event_id FROM {self._candidate_from(compiled)} "
                f"WHERE e.occurred_at BETWEEN ? AND ? AND {self._predicate(connection, compiled)} "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction} LIMIT ?) "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction}",
                (
                    _utc_iso(start_time),
                    _utc_iso(end_time),
                    *compiled.parameters,
                    limit + 1,
                ),
            ).fetchall()
        except sqlite3.OperationalError as exc:
            raise self._translate_sqlite(exc, cancel_event) from exc
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)
                connection.close()
            self._slots.release()
        return CQQLExportResult(
            items=[EventRepository._summary(row) for row in rows[:limit]],
            truncated=len(rows) > limit,
            execution_ms=round((time.perf_counter() - started) * 1_000, 3),
        )
