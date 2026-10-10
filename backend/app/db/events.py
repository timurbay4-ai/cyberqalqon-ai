"""SQLite persistence, indexed search, retention, and aggregations for SIEM events."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from app.schemas.events import (
    IngestionHealth,
    NamedCount,
    NormalizedSecurityEvent,
    PipelineActivity,
    RetentionStatus,
    SavedEventSearch,
    SavedEventSearchCreate,
    SavedEventSearchQuery,
    SecurityEventDetail,
    SecurityEventSummary,
    SecurityOverview,
    SeverityCount,
    TimeSeriesPoint,
)
from app.services.wazuh_normalizer import canonical_json


class EventIdConflictError(RuntimeError):
    pass


class InvalidEventCursorError(ValueError):
    pass


class DuplicateSavedSearchError(RuntimeError):
    pass


class SavedSearchNotFoundError(LookupError):
    pass


class SavedSearchLimitError(RuntimeError):
    pass


class EventOutsideRetentionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event: SecurityEventSummary
    duplicate: bool


@dataclass(frozen=True, slots=True)
class EventFilters:
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    event_identifier: str | None = None
    rule_id: str | None = None
    event_category: str | None = None
    outcome: str | None = None
    severity_min: int | None = None
    severity_max: int | None = None
    source_type: str | None = None
    keyword: str | None = None
    related_alert_id: str | None = None


@dataclass(frozen=True, slots=True)
class EventListResult:
    items: list[SecurityEventSummary]
    total: int
    next_cursor: str | None


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(timezone.utc).isoformat()


def _encode_cursor(occurred_at: str, event_id: str, sort: str) -> str:
    payload = canonical_json(
        {"event_id": event_id, "occurred_at": occurred_at, "sort": sort, "v": 1}
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str, sort: str) -> tuple[str, str]:
    if not cursor or len(cursor) > 2048:
        raise InvalidEventCursorError("cursor is malformed")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        payload: Any = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEventCursorError("cursor is malformed") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"event_id", "occurred_at", "sort", "v"}
        or payload["v"] != 1
        or payload["sort"] != sort
        or not isinstance(payload["event_id"], str)
        or not isinstance(payload["occurred_at"], str)
    ):
        raise InvalidEventCursorError("cursor is malformed")
    try:
        occurred = datetime.fromisoformat(payload["occurred_at"])
    except ValueError as exc:
        raise InvalidEventCursorError("cursor is malformed") from exc
    if occurred.tzinfo is None or occurred.utcoffset() is None or not payload["event_id"]:
        raise InvalidEventCursorError("cursor is malformed")
    return _utc_iso(occurred), payload["event_id"]


def _search_document(event: NormalizedSecurityEvent) -> str:
    values = (
        event.event_id,
        event.source_event_id,
        event.event_code,
        event.source_type,
        event.hostname,
        event.agent_id,
        event.agent_name,
        str(event.source_ip) if event.source_ip else None,
        str(event.destination_ip) if event.destination_ip else None,
        event.username,
        event.event_category,
        event.event_action,
        event.outcome,
        event.rule_id,
        event.message,
        event.ingestion_source,
    )
    return " ".join(str(value) for value in values if value is not None).casefold()


def _fts_query(keyword: str) -> str | None:
    tokens = re.findall(r"[\w.@:/\\-]+", keyword.casefold(), flags=re.UNICODE)[:20]
    if not tokens:
        return None
    return " AND ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in tokens)


class EventRepository:
    def __init__(
        self,
        database_path: Path,
        *,
        retention_days: int,
        max_records: int,
    ) -> None:
        self.path = database_path
        self.retention_days = retention_days
        self.max_records = max_records

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _summary(row: sqlite3.Row) -> SecurityEventSummary:
        return SecurityEventSummary(
            event_id=row["event_id"],
            source_event_id=row["source_event_id"],
            event_code=row["event_code"],
            timestamp=datetime.fromisoformat(row["occurred_at"]),
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
            source_type=row["source_type"],
            hostname=row["hostname"],
            agent_id=row["agent_id"],
            agent_name=row["agent_name"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            username=row["username"],
            event_category=row["event_category"],
            event_action=row["event_action"],
            outcome=row["outcome"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            message=row["message"],
            ingestion_source=row["ingestion_source"],
            related_alert_id=row["resolved_alert_id"],
        )

    @staticmethod
    def _select_columns() -> str:
        return (
            "e.*, COALESCE(e.related_alert_id, a.alert_id) AS resolved_alert_id "
            "FROM security_events e "
            "LEFT JOIN alerts a ON a.alert_id = e.source_event_id"
        )

    def _enforce_retention(self, connection: sqlite3.Connection, now: datetime) -> None:
        row = connection.execute(
            "SELECT last_retention_at, retained_records FROM security_event_store_state "
            "WHERE singleton = 1"
        ).fetchone()
        last = datetime.fromisoformat(row[0]) if row and row[0] else None
        retained_before = int(row[1]) if row else 0
        if (
            last is not None
            and now - last < timedelta(minutes=5)
            and retained_before <= self.max_records
        ):
            return
        cutoff = _utc_iso(now - timedelta(days=self.retention_days))
        deleted_by_age = connection.execute(
            "DELETE FROM security_events WHERE occurred_at < ?", (cutoff,)
        ).rowcount
        count = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        overflow = count - self.max_records
        if overflow > 0:
            deleted_by_limit = connection.execute(
                "DELETE FROM security_events WHERE event_id IN ("
                "SELECT event_id FROM security_events ORDER BY occurred_at ASC, event_id ASC LIMIT ?"
                ")",
                (overflow,),
            ).rowcount
        else:
            deleted_by_limit = 0
        retained = int(connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0])
        connection.execute(
            "UPDATE security_event_store_state SET last_retention_at = ?, "
            "last_deleted_count = ?, retained_records = ? WHERE singleton = 1",
            (_utc_iso(now), max(0, deleted_by_age) + max(0, deleted_by_limit), retained),
        )

    def ingest(
        self,
        event: NormalizedSecurityEvent,
        *,
        related_alert_id: str | None = None,
        now: datetime | None = None,
    ) -> StoredEvent:
        ingested_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        occurred_at = event.timestamp.astimezone(timezone.utc)
        if occurred_at < ingested_at - timedelta(days=self.retention_days):
            raise EventOutsideRetentionError(
                f"event timestamp is older than the {self.retention_days}-day retention window"
            )
        if occurred_at > ingested_at + timedelta(days=1):
            raise EventOutsideRetentionError("event timestamp is more than 24 hours in the future")
        structured_json = canonical_json(event.structured_payload)
        raw_json = canonical_json(event.raw_payload)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT event_id, deduplication_id FROM security_events "
                "WHERE deduplication_id = ? OR event_id = ?",
                (event.deduplication_id, event.event_id),
            ).fetchone()
            if existing is not None:
                if existing["deduplication_id"] != event.deduplication_id:
                    connection.rollback()
                    raise EventIdConflictError(
                        f"event_id '{event.event_id}' exists with different evidence"
                    )
                if related_alert_id:
                    connection.execute(
                        "UPDATE security_events SET related_alert_id = COALESCE(related_alert_id, ?) "
                        "WHERE event_id = ?",
                        (related_alert_id, existing["event_id"]),
                    )
                row = connection.execute(
                    f"SELECT {self._select_columns()} WHERE e.event_id = ?",
                    (existing["event_id"],),
                ).fetchone()
                connection.commit()
                if row is None:
                    raise RuntimeError("duplicate event disappeared during ingestion")
                return StoredEvent(event=self._summary(row), duplicate=True)

            if related_alert_id is None and event.source_event_id:
                linked = connection.execute(
                    "SELECT alert_id FROM alerts WHERE alert_id = ?",
                    (event.source_event_id,),
                ).fetchone()
                related_alert_id = str(linked[0]) if linked else None
            connection.execute(
                """
                INSERT INTO security_events (
                    event_id, deduplication_id, source_event_id, event_code,
                    occurred_at, ingested_at, source_type, hostname, agent_id, agent_name,
                    source_ip, destination_ip, source_port, destination_port, username,
                    event_category, event_action, outcome, rule_id, severity, message,
                    structured_json, raw_event_json, ingestion_source, related_alert_id,
                    raw_size_bytes, search_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.deduplication_id,
                    event.source_event_id,
                    event.event_code,
                    _utc_iso(occurred_at),
                    _utc_iso(ingested_at),
                    event.source_type,
                    event.hostname,
                    event.agent_id,
                    event.agent_name,
                    str(event.source_ip) if event.source_ip else None,
                    str(event.destination_ip) if event.destination_ip else None,
                    event.source_port,
                    event.destination_port,
                    event.username,
                    event.event_category,
                    event.event_action,
                    event.outcome,
                    event.rule_id,
                    event.severity,
                    event.message,
                    structured_json,
                    raw_json,
                    event.ingestion_source,
                    related_alert_id,
                    event.raw_size_bytes,
                    _search_document(event),
                ),
            )
            connection.execute(
                "UPDATE security_event_store_state SET retained_records = retained_records + 1 "
                "WHERE singleton = 1"
            )
            self._enforce_retention(connection, ingested_at)
            row = connection.execute(
                f"SELECT {self._select_columns()} WHERE e.event_id = ?",
                (event.event_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("event was removed immediately by retention policy")
        return StoredEvent(event=self._summary(row), duplicate=False)

    def _conditions(self, filters: EventFilters) -> tuple[list[str], list[object], bool]:
        conditions: list[str] = []
        parameters: list[object] = []
        if filters.start_time:
            conditions.append("e.occurred_at >= ?")
            parameters.append(_utc_iso(filters.start_time))
        if filters.end_time:
            conditions.append("e.occurred_at <= ?")
            parameters.append(_utc_iso(filters.end_time))
        exact_fields = (
            (filters.source_ip, "e.source_ip", False),
            (filters.destination_ip, "e.destination_ip", False),
            (filters.hostname, "e.hostname", True),
            (filters.username, "e.username", True),
            (filters.rule_id, "e.rule_id", False),
            (filters.event_category, "e.event_category", True),
            (filters.outcome, "e.outcome", True),
            (filters.source_type, "e.source_type", False),
            (filters.related_alert_id, "COALESCE(e.related_alert_id, a.alert_id)", False),
        )
        for value, column, case_insensitive in exact_fields:
            if value is not None:
                collation = " COLLATE NOCASE" if case_insensitive else ""
                conditions.append(f"{column} = ?{collation}")
                parameters.append(value)
        if filters.event_identifier:
            conditions.append("(e.event_id = ? OR e.source_event_id = ? OR e.event_code = ?)")
            parameters.extend([filters.event_identifier] * 3)
        if filters.severity_min is not None:
            conditions.append("e.severity >= ?")
            parameters.append(filters.severity_min)
        if filters.severity_max is not None:
            conditions.append("e.severity <= ?")
            parameters.append(filters.severity_max)

        use_fts = False
        if filters.keyword:
            query = _fts_query(filters.keyword)
            if query:
                use_fts = True
                conditions.append(
                    "e.event_id IN (SELECT event_id FROM security_events_fts "
                    "WHERE security_events_fts MATCH ?)"
                )
                parameters.append(query)
            else:
                conditions.append("e.search_text LIKE ?")
                parameters.append(f"%{filters.keyword.casefold()}%")
        return conditions, parameters, use_fts

    def list(
        self,
        filters: EventFilters,
        *,
        limit: int,
        sort: Literal["newest", "oldest"],
        cursor: str | None = None,
    ) -> EventListResult:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        conditions, parameters, uses_fts = self._conditions(filters)
        direction = "DESC" if sort == "newest" else "ASC"
        if cursor:
            occurred, event_id = _decode_cursor(cursor, sort)
            operator = "<" if sort == "newest" else ">"
            conditions.append(f"(e.occurred_at, e.event_id) {operator} (?, ?)")
            parameters.extend((occurred, event_id))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._connect() as connection:
            if uses_fts and connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'security_events_fts'"
            ).fetchone() is None:
                fallback = replace(filters, keyword=None)
                conditions, parameters, _ = self._conditions(fallback)
                if filters.keyword:
                    conditions.append("e.search_text LIKE ?")
                    parameters.append(f"%{filters.keyword.casefold()}%")
                if cursor:
                    occurred, event_id = _decode_cursor(cursor, sort)
                    operator = "<" if sort == "newest" else ">"
                    conditions.append(f"(e.occurred_at, e.event_id) {operator} (?, ?)")
                    parameters.extend((occurred, event_id))
                where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

            count_conditions, count_parameters, count_fts = self._conditions(filters)
            if count_fts and connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'security_events_fts'"
            ).fetchone() is None:
                count_conditions = [item for item in count_conditions if "security_events_fts" not in item]
                count_parameters = count_parameters[:-1]
                count_conditions.append("e.search_text LIKE ?")
                count_parameters.append(f"%{filters.keyword.casefold()}%")
            count_where = f" WHERE {' AND '.join(count_conditions)}" if count_conditions else ""
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM security_events e "
                    f"LEFT JOIN alerts a ON a.alert_id = e.source_event_id{count_where}",
                    count_parameters,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"SELECT {self._select_columns()}{where} "
                f"ORDER BY e.occurred_at {direction}, e.event_id {direction} LIMIT ?",
                (*parameters, limit + 1),
            ).fetchall()

        has_more = len(rows) > limit
        visible = rows[:limit]
        items = [self._summary(row) for row in visible]
        next_cursor = None
        if has_more and visible:
            last = visible[-1]
            next_cursor = _encode_cursor(last["occurred_at"], last["event_id"], sort)
        return EventListResult(items=items, total=total, next_cursor=next_cursor)

    @staticmethod
    def _saved_search(row: sqlite3.Row) -> SavedEventSearch:
        return SavedEventSearch(
            saved_search_id=row["saved_search_id"],
            name=row["name"],
            query=SavedEventSearchQuery.model_validate_json(row["query_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_saved_searches(self, analyst_id: str) -> list[SavedEventSearch]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM saved_event_searches WHERE analyst_id = ? "
                "ORDER BY updated_at DESC, saved_search_id DESC LIMIT 50",
                (analyst_id,),
            ).fetchall()
        return [self._saved_search(row) for row in rows]

    def create_saved_search(
        self,
        analyst_id: str,
        request: SavedEventSearchCreate,
    ) -> SavedEventSearch:
        now = datetime.now(timezone.utc).isoformat()
        saved_search_id = f"SSR-{uuid4().hex.upper()}"
        query_json = canonical_json(request.query.model_dump(mode="json", exclude_none=True))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM saved_event_searches WHERE analyst_id = ?",
                    (analyst_id,),
                ).fetchone()[0]
            )
            if count >= 50:
                raise SavedSearchLimitError("An analyst may store at most 50 saved searches")
            try:
                connection.execute(
                    "INSERT INTO saved_event_searches "
                    "(saved_search_id, analyst_id, name, query_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (saved_search_id, analyst_id, request.name, query_json, now, now),
                )
            except sqlite3.IntegrityError as exc:
                if "saved_event_searches.analyst_id" in str(exc):
                    raise DuplicateSavedSearchError(request.name) from exc
                raise
            row = connection.execute(
                "SELECT * FROM saved_event_searches WHERE saved_search_id = ?",
                (saved_search_id,),
            ).fetchone()
        if row is None:
            raise SavedSearchNotFoundError(saved_search_id)
        return self._saved_search(row)

    def update_saved_search(
        self,
        analyst_id: str,
        saved_search_id: str,
        request: SavedEventSearchCreate,
    ) -> SavedEventSearch:
        now = datetime.now(timezone.utc).isoformat()
        query_json = canonical_json(request.query.model_dump(mode="json", exclude_none=True))
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = connection.execute(
                    "UPDATE saved_event_searches SET name = ?, query_json = ?, updated_at = ? "
                    "WHERE saved_search_id = ? AND analyst_id = ?",
                    (request.name, query_json, now, saved_search_id, analyst_id),
                )
            except sqlite3.IntegrityError as exc:
                if "saved_event_searches.analyst_id" in str(exc):
                    raise DuplicateSavedSearchError(request.name) from exc
                raise
            if result.rowcount != 1:
                raise SavedSearchNotFoundError(saved_search_id)
            row = connection.execute(
                "SELECT * FROM saved_event_searches WHERE saved_search_id = ?",
                (saved_search_id,),
            ).fetchone()
        if row is None:
            raise SavedSearchNotFoundError(saved_search_id)
        return self._saved_search(row)

    def delete_saved_search(self, analyst_id: str, saved_search_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            result = connection.execute(
                "DELETE FROM saved_event_searches WHERE saved_search_id = ? AND analyst_id = ?",
                (saved_search_id, analyst_id),
            )
            if result.rowcount != 1:
                raise SavedSearchNotFoundError(saved_search_id)

    def get(self, event_id: str) -> SecurityEventDetail | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {self._select_columns()} WHERE e.event_id = ?",
                (event_id,),
            ).fetchone()
            if row is None:
                return None
            incident_rows = connection.execute(
                "SELECT ia.incident_id FROM incident_alerts ia "
                "WHERE ia.alert_id = COALESCE(?, ?) ORDER BY ia.incident_id",
                (row["related_alert_id"], row["source_event_id"]),
            ).fetchall()
        summary = self._summary(row)
        return SecurityEventDetail(
            **summary.model_dump(),
            structured_payload=json.loads(row["structured_json"]),
            raw_payload=json.loads(row["raw_event_json"]),
            related_incident_ids=[str(item[0]) for item in incident_rows],
        )

    @staticmethod
    def _named_counts(connection: sqlite3.Connection, sql: str, parameters: tuple[object, ...]) -> list[NamedCount]:
        return [NamedCount(name=str(row[0]), count=int(row[1])) for row in connection.execute(sql, parameters)]

    def overview(self, start_time: datetime, end_time: datetime) -> SecurityOverview:
        start = _utc_iso(start_time)
        end = _utc_iso(end_time)
        parameters = (start, end)
        range_seconds = (end_time - start_time).total_seconds()
        bucket = "%Y-%m-%dT%H:00:00+00:00" if range_seconds <= 259_200 else "%Y-%m-%dT00:00:00+00:00"
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            total_events = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events WHERE occurred_at BETWEEN ? AND ?",
                    parameters,
                ).fetchone()[0]
            )
            total_alerts = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alerts WHERE occurred_at BETWEEN ? AND ?",
                    parameters,
                ).fetchone()[0]
            )
            active_incidents = int(
                connection.execute(
                    "SELECT COUNT(*) FROM incidents WHERE status IN ('NEW','TRIAGED','INVESTIGATING')"
                ).fetchone()[0]
            )
            reporting_agents = int(
                connection.execute(
                    "SELECT COUNT(DISTINCT agent_id) FROM security_events "
                    "WHERE agent_id IS NOT NULL AND occurred_at >= ?",
                    (_utc_iso(now - timedelta(minutes=15)),),
                ).fetchone()[0]
            )
            incident_statuses = self._named_counts(
                connection,
                "SELECT status, COUNT(*) FROM incidents GROUP BY status "
                "ORDER BY COUNT(*) DESC, status",
                (),
            )
            source_health_rows = connection.execute(
                """
                SELECT MAX(occurred_at) AS last_seen
                FROM security_events
                GROUP BY source_type, hostname, agent_id, agent_name, ingestion_source
                """
            ).fetchall()
            active_sources = sum(
                1 for row in source_health_rows
                if now - datetime.fromisoformat(row[0]) <= timedelta(minutes=15)
            )
            stale_sources = len(source_health_rows) - active_sources
            severity_rows = connection.execute(
                """
                SELECT CASE
                    WHEN rule_level >= 13 THEN 'CRITICAL'
                    WHEN rule_level >= 10 THEN 'HIGH'
                    WHEN rule_level >= 7 THEN 'MEDIUM'
                    WHEN rule_level >= 4 THEN 'LOW'
                    ELSE 'INFORMATIONAL'
                END AS band, COUNT(*)
                FROM alerts WHERE occurred_at BETWEEN ? AND ?
                GROUP BY band
                """,
                parameters,
            ).fetchall()
            event_series = connection.execute(
                f"SELECT strftime('{bucket}', occurred_at), COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? GROUP BY 1 ORDER BY 1",
                parameters,
            ).fetchall()
            alert_series = connection.execute(
                f"SELECT strftime('{bucket}', occurred_at), COUNT(*) FROM alerts "
                "WHERE occurred_at BETWEEN ? AND ? GROUP BY 1 ORDER BY 1",
                parameters,
            ).fetchall()
            top_source_ips = self._named_counts(
                connection,
                "SELECT source_ip, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND source_ip IS NOT NULL "
                "GROUP BY source_ip ORDER BY COUNT(*) DESC, source_ip LIMIT 8",
                parameters,
            )
            top_hosts = self._named_counts(
                connection,
                "SELECT hostname, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND hostname IS NOT NULL "
                "GROUP BY hostname ORDER BY COUNT(*) DESC, hostname LIMIT 8",
                parameters,
            )
            top_destination_hosts = self._named_counts(
                connection,
                "SELECT destination_ip, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND destination_ip IS NOT NULL "
                "GROUP BY destination_ip ORDER BY COUNT(*) DESC, destination_ip LIMIT 8",
                parameters,
            )
            top_rules = self._named_counts(
                connection,
                "SELECT rule_id, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND rule_id IS NOT NULL "
                "GROUP BY rule_id ORDER BY COUNT(*) DESC, rule_id LIMIT 8",
                parameters,
            )
            event_sources = self._named_counts(
                connection,
                "SELECT source_type, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? GROUP BY source_type "
                "ORDER BY COUNT(*) DESC, source_type LIMIT 8",
                parameters,
            )
            top_event_categories = self._named_counts(
                connection,
                "SELECT event_category, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND event_category IS NOT NULL "
                "GROUP BY event_category ORDER BY COUNT(*) DESC, event_category LIMIT 8",
                parameters,
            )
            latest_rows = connection.execute(
                "SELECT normalized_json FROM alerts WHERE occurred_at BETWEEN ? AND ? "
                "AND rule_level >= 10 ORDER BY occurred_at DESC, alert_id DESC LIMIT 8",
                parameters,
            ).fetchall()
            latest = []
            for row in latest_rows:
                alert = json.loads(row[0])
                latest.append(
                    {
                        "alert_id": alert["alert_id"],
                        "timestamp": alert["timestamp"],
                        "rule_id": alert["rule"]["id"],
                        "severity": alert["rule"]["level"],
                        "description": alert["rule"]["description"],
                        "agent_name": alert["agent"]["name"],
                    }
                )
            health_row = connection.execute(
                "SELECT occurred_at, ingested_at FROM security_events "
                "ORDER BY ingested_at DESC LIMIT 1"
            ).fetchone()
            sender_row = connection.execute(
                "SELECT MAX(ingested_at), COUNT(*) FROM alerts "
                "WHERE occurred_at BETWEEN ? AND ?",
                parameters,
            ).fetchone()
            shipper_row = connection.execute(
                "SELECT MAX(ingested_at), COUNT(*) FROM security_events "
                "WHERE ingestion_source = 'wazuh_archives' AND occurred_at BETWEEN ? AND ?",
                parameters,
            ).fetchone()
            retention_row = connection.execute(
                "SELECT last_retention_at, last_deleted_count, retained_records "
                "FROM security_event_store_state WHERE singleton = 1"
            ).fetchone()

        if health_row is None:
            ingestion = IngestionHealth(state="EMPTY")
        else:
            last_event = datetime.fromisoformat(health_row[0])
            last_ingested = datetime.fromisoformat(health_row[1])
            lag = max(0.0, (last_ingested - last_event).total_seconds())
            state = "ACTIVE" if now - last_ingested <= timedelta(minutes=15) else "STALE"
            ingestion = IngestionHealth(
                state=state,
                last_event_at=last_event,
                last_ingested_at=last_ingested,
                lag_seconds=lag,
            )

        def pipeline_activity(component: str, row: sqlite3.Row) -> PipelineActivity:
            last_delivery = datetime.fromisoformat(row[0]) if row[0] else None
            if last_delivery is None:
                state = "EMPTY"
            else:
                state = "ACTIVE" if now - last_delivery <= timedelta(minutes=15) else "STALE"
            return PipelineActivity(
                component=component,
                state=state,
                last_delivery_at=last_delivery,
                delivered_records=int(row[1]),
            )

        retained_records = int(retention_row[2]) if retention_row else 0
        retention = RetentionStatus(
            state="AT_LIMIT" if retained_records >= self.max_records else "WITHIN_LIMIT",
            retention_days=self.retention_days,
            max_records=self.max_records,
            retained_records=retained_records,
            last_run_at=datetime.fromisoformat(retention_row[0]) if retention_row and retention_row[0] else None,
            last_deleted_count=int(retention_row[1]) if retention_row else 0,
        )
        return SecurityOverview(
            start_time=start_time,
            end_time=end_time,
            total_events=total_events,
            total_alerts=total_alerts,
            events_per_minute=round(total_events / max(1.0, range_seconds / 60.0), 3),
            active_incidents=active_incidents,
            reporting_agents=reporting_agents,
            active_sources=active_sources,
            stale_sources=stale_sources,
            database_size_bytes=self.path.stat().st_size,
            alerts_by_severity=[SeverityCount(severity=str(row[0]), count=int(row[1])) for row in severity_rows],
            incidents_by_status=incident_statuses,
            events_over_time=[TimeSeriesPoint(timestamp=datetime.fromisoformat(row[0]), count=int(row[1])) for row in event_series if row[0]],
            alerts_over_time=[TimeSeriesPoint(timestamp=datetime.fromisoformat(row[0]), count=int(row[1])) for row in alert_series if row[0]],
            top_source_ips=top_source_ips,
            top_hosts=top_hosts,
            top_destination_hosts=top_destination_hosts,
            top_rules=top_rules,
            top_event_categories=top_event_categories,
            event_sources=event_sources,
            latest_high_alerts=latest,
            ingestion=ingestion,
            pipeline_activity=[
                pipeline_activity("wazuh_sender", sender_row),
                pipeline_activity("event_shipper", shipper_row),
            ],
            retention=retention,
        )
