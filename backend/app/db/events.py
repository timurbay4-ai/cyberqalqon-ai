"""SQLite persistence, indexed search, retention, and aggregations for SIEM events."""

from __future__ import annotations

import base64
import binascii
import json
import re
import sqlite3
import time
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
    TelemetryCoverageEntry,
    TelemetryCoverageReport,
    TimeSeriesPoint,
)
from app.services.wazuh_normalizer import canonical_json
from app.schemas.cuse import CUSEMetadata


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


class RetentionCapacityError(RuntimeError):
    """Protected evidence leaves no capacity for a new acknowledged event."""


class BatchProcessingTimeoutError(TimeoutError):
    """Raised when a batch crosses its pre-commit budget.

    ``stage`` and ``timing`` contain bounded numeric diagnostics only. They
    intentionally exclude event bodies, identifiers, credentials, and SQL.
    """

    def __init__(
        self,
        message: str,
        *,
        stage: str = "pre_commit",
        timing: dict[str, float | int | bool] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.timing = dict(timing or {})


class BatchItemValidationError(ValueError):
    def __init__(self, index: int, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.index = index
        self.field = field


class BatchItemConflictError(EventIdConflictError):
    def __init__(self, index: int, event_id: str) -> None:
        super().__init__(f"event_id '{event_id}' exists with different evidence")
        self.index = index
        self.event_id = event_id


@dataclass(frozen=True, slots=True)
class StoredEvent:
    event: SecurityEventSummary
    duplicate: bool


@dataclass(frozen=True, slots=True)
class BatchStoredEvent:
    index: int
    event_id: str
    deduplication_id: str
    duplicate: bool


@dataclass(frozen=True, slots=True)
class BatchIngestResult:
    items: list[BatchStoredEvent]
    inserted: int
    duplicates: int
    database_ms: float
    transaction_ms: float
    retention_ms: float
    commit_ms: float
    connection_ms: float
    lock_wait_ms: float
    deduplication_ms: float
    alert_lookup_ms: float
    insert_ms: float
    retention_state_ms: float
    retention_age_delete_ms: float
    retention_count_ms: float
    retention_candidate_ms: float
    protected_check_ms: float
    retention_delete_ms: float
    protected_count_ms: float
    retention_metadata_ms: float
    retention_audit_ms: float
    sql_statement_count: int
    retention_rows_considered: int
    retention_rows_deleted: int
    protected_row_skips: int
    full_age_sweep: bool


@dataclass(frozen=True, slots=True)
class RetentionProfile:
    state_ms: float = 0.0
    age_delete_ms: float = 0.0
    count_ms: float = 0.0
    candidate_ms: float = 0.0
    protected_check_ms: float = 0.0
    delete_ms: float = 0.0
    protected_count_ms: float = 0.0
    metadata_ms: float = 0.0
    audit_ms: float = 0.0
    rows_considered: int = 0
    rows_deleted: int = 0
    protected_skips: int = 0
    full_age_sweep: bool = False


@dataclass(frozen=True, slots=True)
class EventFilters:
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    operating_system: str | None = None
    event_provider: str | None = None
    event_channel: str | None = None
    process_name: str | None = None
    event_identifier: str | None = None
    rule_id: str | None = None
    event_category: str | None = None
    event_action: str | None = None
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
        event.operating_system,
        event.manager_identity,
        event.event_provider,
        event.event_channel,
        event.process_name,
        event.process_path,
        event.command_line,
        event.process_id,
        event.parent_process_name,
        event.parent_process_path,
        event.parent_process_id,
        str(event.source_ip) if event.source_ip else None,
        str(event.destination_ip) if event.destination_ip else None,
        event.username,
        event.event_category,
        event.event_action,
        event.outcome,
        event.rule_id,
        *event.mitre.ids,
        *event.mitre.tactics,
        *event.mitre.techniques,
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
            operating_system=row["operating_system"],
            manager_identity=row["manager_identity"],
            event_provider=row["event_provider"],
            event_channel=row["event_channel"],
            process_name=row["process_name"],
            process_path=row["process_path"],
            command_line=row["command_line"],
            process_id=row["process_id"],
            parent_process_name=row["parent_process_name"],
            parent_process_path=row["parent_process_path"],
            parent_process_id=row["parent_process_id"],
            normalization_schema=row["normalization_schema"],
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
            mitre={
                "ids": json.loads(row["mitre_ids_json"]),
                "tactics": json.loads(row["mitre_tactics_json"]),
                "techniques": json.loads(row["mitre_techniques_json"]),
            },
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

    @staticmethod
    def _protected_event_filter(alias: str = "security_events") -> str:
        """Return the schema-17 evidence protection predicate for a trusted alias."""

        if alias not in {"security_events", "e"}:
            raise ValueError("unsupported security event alias")
        return (
            f"(EXISTS (SELECT 1 FROM case_events ce WHERE ce.event_id = {alias}.event_id) "
            f"OR EXISTS (SELECT 1 FROM incident_evidence_pins iep "
            f"WHERE iep.evidence_type = 'EVENT' AND iep.evidence_id = {alias}.event_id) "
            f"OR EXISTS (SELECT 1 FROM case_evidence_refs cer "
            f"WHERE cer.reference_type = 'EVENT' AND cer.reference_id = {alias}.event_id) "
            f"OR EXISTS (SELECT 1 FROM alerts a WHERE a.alert_id = "
            f"COALESCE({alias}.related_alert_id, {alias}.source_event_id)))"
        )

    @staticmethod
    def _bulk_protected_event_ids(
        connection: sqlite3.Connection,
        rows: list[sqlite3.Row],
    ) -> tuple[set[str], float]:
        """Resolve evidence protection for one bounded keyset page.

        This replaces one correlated protection lookup per retention candidate
        with four bounded set lookups. The oldest-event scan remains driven by
        ``idx_security_events_occurred_id`` and no protection decision is
        cached across transactions.
        """

        if not rows:
            return set(), 0.0
        started = time.monotonic()
        event_ids = tuple(str(row["event_id"]) for row in rows)
        placeholders = ",".join("?" for _ in event_ids)
        protected: set[str] = {
            str(row[0])
            for row in connection.execute(
                f"SELECT event_id FROM case_events WHERE event_id IN ({placeholders})",
                event_ids,
            )
        }
        protected.update(
            str(row[0])
            for row in connection.execute(
                "SELECT evidence_id FROM incident_evidence_pins "
                f"WHERE evidence_type='EVENT' AND evidence_id IN ({placeholders})",
                event_ids,
            )
        )
        protected.update(
            str(row[0])
            for row in connection.execute(
                "SELECT reference_id FROM case_evidence_refs "
                f"WHERE reference_type='EVENT' AND reference_id IN ({placeholders})",
                event_ids,
            )
        )
        linked_events: dict[str, list[str]] = {}
        for row in rows:
            reference = (
                row["related_alert_id"]
                if row["related_alert_id"] is not None
                else row["source_event_id"]
            )
            if reference:
                linked_events.setdefault(str(reference), []).append(str(row["event_id"]))
        if linked_events:
            alert_ids = tuple(linked_events)
            alert_placeholders = ",".join("?" for _ in alert_ids)
            for alert_row in connection.execute(
                f"SELECT alert_id FROM alerts WHERE alert_id IN ({alert_placeholders})",
                alert_ids,
            ):
                protected.update(linked_events.get(str(alert_row[0]), ()))
        return protected, round((time.monotonic() - started) * 1000, 3)

    def _select_retention_candidates(
        self,
        connection: sqlite3.Connection,
        *,
        needed: int,
        preserved: set[str],
    ) -> tuple[list[str], int, int, float, float]:
        """Select exactly the oldest deletable rows with bounded keyset pages."""

        if needed <= 0:
            return [], 0, 0, 0.0, 0.0
        selected: list[str] = []
        considered = 0
        protected_skips = 0
        candidate_ms = 0.0
        protected_check_ms = 0.0
        after_occurred: str | None = None
        after_event_id: str | None = None
        page_size = min(512, max(64, needed * 4))
        while len(selected) < needed:
            where = ""
            parameters: tuple[object, ...]
            if after_occurred is None:
                parameters = (page_size,)
            else:
                where = "WHERE (e.occurred_at, e.event_id) > (?, ?)"
                parameters = (after_occurred, after_event_id, page_size)
            started = time.monotonic()
            rows = connection.execute(
                "SELECT e.event_id, e.occurred_at, e.related_alert_id, e.source_event_id "
                f"FROM security_events e {where} "
                "ORDER BY e.occurred_at ASC, e.event_id ASC LIMIT ?",
                parameters,
            ).fetchall()
            candidate_ms += (time.monotonic() - started) * 1000
            if not rows:
                break
            considered += len(rows)
            protected, elapsed = self._bulk_protected_event_ids(connection, rows)
            protected_check_ms += elapsed
            for row in rows:
                event_id = str(row["event_id"])
                if event_id in preserved:
                    continue
                if event_id in protected:
                    protected_skips += 1
                    continue
                selected.append(event_id)
                if len(selected) >= needed:
                    break
            after_occurred = str(rows[-1]["occurred_at"])
            after_event_id = str(rows[-1]["event_id"])
        return (
            selected,
            considered,
            protected_skips,
            round(candidate_ms, 3),
            round(protected_check_ms, 3),
        )

    @staticmethod
    def _count_protected_records(connection: sqlite3.Connection) -> int:
        return int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM (
                    SELECT ce.event_id AS protected_event_id
                    FROM case_events ce
                    UNION
                    SELECT e.event_id
                    FROM incident_evidence_pins iep
                    JOIN security_events e ON e.event_id = iep.evidence_id
                    WHERE iep.evidence_type = 'EVENT'
                    UNION
                    SELECT e.event_id
                    FROM case_evidence_refs cer
                    JOIN security_events e ON e.event_id = cer.reference_id
                    WHERE cer.reference_type = 'EVENT'
                    UNION
                    SELECT e2.event_id FROM security_events e2
                    JOIN alerts a ON a.alert_id =
                        COALESCE(e2.related_alert_id, e2.source_event_id)
                ) protected
                """
            ).fetchone()[0]
        )

    def _audit_retention(
        self,
        connection: sqlite3.Connection,
        now: datetime,
        *,
        deleted_by_age: int,
        deleted_by_limit: int,
        protected_records: int | None,
        protected_records_measurement: str | None,
        retained_records: int,
    ) -> None:
        """Aggregate cleanup decisions into one bounded audit record per five minutes."""

        bucket_minute = now.minute - (now.minute % 5)
        bucket = now.replace(minute=bucket_minute, second=0, microsecond=0)
        bucket_key = bucket.strftime("%Y%m%dT%H%MZ")
        audit_id = f"AUD-RETENTION-{bucket_key}"
        existing = connection.execute(
            "SELECT details_json FROM security_audit_events WHERE audit_id = ?",
            (audit_id,),
        ).fetchone()
        details: dict[str, Any] = {}
        if existing is not None:
            try:
                parsed = json.loads(existing[0])
                if isinstance(parsed, dict):
                    details = parsed
            except (TypeError, ValueError, json.JSONDecodeError):
                details = {}
        cumulative_age = max(0, int(details.get("deleted_by_age", 0))) + max(
            0, deleted_by_age
        )
        cumulative_limit = max(0, int(details.get("deleted_by_limit", 0))) + max(
            0, deleted_by_limit
        )
        over_limit = max(0, retained_records - self.max_records)
        prior_protected = max(0, int(details.get("protected_records", 0)))
        if protected_records is None:
            measured_protected = prior_protected
            measurement = "CACHED" if existing is not None else "NOT_MEASURED"
            measured_at = details.get("protected_records_measured_at")
        else:
            measured_protected = max(0, protected_records)
            measurement = protected_records_measurement or "EXACT"
            measured_at = _utc_iso(now)
        details = {
            "version": 1,
            "window_started_at": _utc_iso(bucket),
            "runs": max(0, int(details.get("runs", 0))) + 1,
            "deleted_by_age": cumulative_age,
            "deleted_by_limit": cumulative_limit,
            "protected_records": measured_protected,
            "protected_records_measurement": measurement,
            "protected_records_measured_at": measured_at,
            "retained_records": max(0, retained_records),
            "max_records": self.max_records,
            "retention_days": self.retention_days,
            "over_limit_records": over_limit,
            "decision": "PROTECTED_OVER_LIMIT" if over_limit else "ENFORCED",
        }
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, 'SECURITY_EVENT_RETENTION', NULL,
                      'CyberQalqon retention policy', 'security_event_store',
                      ?, 'SUCCESS', ?, ?)
            ON CONFLICT(audit_id) DO UPDATE SET
                occurred_at=excluded.occurred_at,
                details_json=excluded.details_json
            """,
            (audit_id, bucket_key, _utc_iso(now), canonical_json(details)),
        )

    def _enforce_retention(
        self,
        connection: sqlite3.Connection,
        now: datetime,
        *,
        preserve_event_id: str | None = None,
        preserve_event_ids: tuple[str, ...] = (),
    ) -> RetentionProfile:
        preserved = tuple(
            dict.fromkeys(
                item
                for item in (
                    *((preserve_event_id,) if preserve_event_id is not None else ()),
                    *preserve_event_ids,
                )
                if item
            )
        )
        stage_started = time.monotonic()
        row = connection.execute(
            "SELECT last_retention_at, retained_records FROM security_event_store_state "
            "WHERE singleton = 1"
        ).fetchone()
        state_ms = (time.monotonic() - stage_started) * 1000
        last = datetime.fromisoformat(row[0]) if row and row[0] else None
        retained_before = int(row[1]) if row else 0
        full_age_sweep_due = last is None or now - last >= timedelta(minutes=5)
        if not full_age_sweep_due and retained_before <= self.max_records:
            return RetentionProfile(state_ms=round(state_ms, 3))
        protected = self._protected_event_filter("security_events")
        age_delete_ms = 0.0
        count_ms = 0.0
        if full_age_sweep_due:
            cutoff = _utc_iso(now - timedelta(days=self.retention_days))
            stage_started = time.monotonic()
            deleted_by_age = connection.execute(
                f"DELETE FROM security_events WHERE occurred_at < ? AND NOT {protected}",
                (cutoff,),
            ).rowcount
            age_delete_ms = (time.monotonic() - stage_started) * 1000
            # Reconcile the durable counter during the bounded five-minute full sweep.
            stage_started = time.monotonic()
            count = int(
                connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
            )
            count_ms = (time.monotonic() - stage_started) * 1000
        else:
            # At capacity, avoid repeating an archive-wide age predicate for every
            # inserted row. BEGIN IMMEDIATE serializes writers, so this counter is
            # exact inside the transaction; the next full sweep reconciles it.
            deleted_by_age = 0
            count = retained_before
        overflow = count - self.max_records
        considered = 0
        protected_skips = 0
        candidate_ms = 0.0
        protected_check_ms = 0.0
        delete_ms = 0.0
        if overflow > 0:
            (
                deletion_ids,
                considered,
                protected_skips,
                candidate_ms,
                protected_check_ms,
            ) = self._select_retention_candidates(
                connection,
                needed=overflow,
                preserved=set(preserved),
            )
            if deletion_ids:
                placeholders = ",".join("?" for _ in deletion_ids)
                stage_started = time.monotonic()
                deleted_by_limit = connection.execute(
                    f"DELETE FROM security_events WHERE event_id IN ({placeholders})",
                    tuple(deletion_ids),
                ).rowcount
                delete_ms = (time.monotonic() - stage_started) * 1000
            else:
                deleted_by_limit = 0
        else:
            deleted_by_limit = 0
        retained = max(0, count - max(0, deleted_by_limit))
        if retained > self.max_records:
            # Roll back the whole insert/cleanup, not protected evidence. An
            # over-cap insert must never be reported as durably accepted.
            raise RetentionCapacityError("Protected evidence exhausts event retention capacity")
        protected_count_ms = 0.0
        protected_records: int | None = None
        protected_measurement: str | None = None
        stage_started = time.monotonic()
        if full_age_sweep_due:
            connection.execute(
                "UPDATE security_event_store_state SET last_retention_at = ?, "
                "last_deleted_count = ?, retained_records = ? WHERE singleton = 1",
                (
                    _utc_iso(now),
                    max(0, deleted_by_age) + max(0, deleted_by_limit),
                    retained,
                ),
            )
        else:
            connection.execute(
                "UPDATE security_event_store_state SET last_deleted_count = ?, "
                "retained_records = ? WHERE singleton = 1",
                (max(0, deleted_by_limit), retained),
            )
        metadata_ms = (time.monotonic() - stage_started) * 1000
        stage_started = time.monotonic()
        self._audit_retention(
            connection,
            now,
            deleted_by_age=deleted_by_age,
            deleted_by_limit=deleted_by_limit,
            protected_records=protected_records,
            protected_records_measurement=protected_measurement,
            retained_records=retained,
        )
        audit_ms = (time.monotonic() - stage_started) * 1000
        return RetentionProfile(
            state_ms=round(state_ms, 3),
            age_delete_ms=round(age_delete_ms, 3),
            count_ms=round(count_ms, 3),
            candidate_ms=round(candidate_ms, 3),
            protected_check_ms=round(protected_check_ms, 3),
            delete_ms=round(delete_ms, 3),
            protected_count_ms=round(protected_count_ms, 3),
            metadata_ms=round(metadata_ms, 3),
            audit_ms=round(audit_ms, 3),
            rows_considered=considered,
            rows_deleted=max(0, deleted_by_age) + max(0, deleted_by_limit),
            protected_skips=protected_skips,
            full_age_sweep=full_age_sweep_due,
        )

    def _insert_event_row(
        self,
        connection: sqlite3.Connection,
        event: NormalizedSecurityEvent,
        *,
        occurred_at: datetime,
        ingested_at: datetime,
        related_alert_id: str | None,
    ) -> None:
        """Insert one normalized row inside an already-owned transaction."""

        connection.execute(
            """
            INSERT INTO security_events (
                event_id, deduplication_id, source_event_id, event_code,
                occurred_at, ingested_at, source_type, hostname, agent_id, agent_name,
                operating_system,
                manager_identity, event_provider, event_channel,
                process_name, process_path, command_line, process_id,
                parent_process_name, parent_process_path, parent_process_id,
                normalization_schema,
                source_ip, destination_ip, source_port, destination_port, username,
                event_category, event_action, outcome, rule_id, severity,
                mitre_ids_json, mitre_tactics_json, mitre_techniques_json, message,
                structured_json, raw_event_json, ingestion_source, related_alert_id,
                raw_size_bytes, search_text
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?
            )
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
                event.operating_system,
                event.manager_identity,
                event.event_provider,
                event.event_channel,
                event.process_name,
                event.process_path,
                event.command_line,
                event.process_id,
                event.parent_process_name,
                event.parent_process_path,
                event.parent_process_id,
                event.normalization_schema,
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
                canonical_json(event.mitre.ids),
                canonical_json(event.mitre.tactics),
                canonical_json(event.mitre.techniques),
                event.message,
                canonical_json(event.structured_payload),
                canonical_json(event.raw_payload),
                event.ingestion_source,
                related_alert_id,
                event.raw_size_bytes,
                _search_document(event),
            ),
        )

    def _validate_retention_time(
        self,
        event: NormalizedSecurityEvent,
        ingested_at: datetime,
    ) -> datetime:
        occurred_at = event.timestamp.astimezone(timezone.utc)
        if occurred_at < ingested_at - timedelta(days=self.retention_days):
            raise EventOutsideRetentionError(
                f"event timestamp is older than the {self.retention_days}-day retention window"
            )
        if occurred_at > ingested_at + timedelta(days=1):
            raise EventOutsideRetentionError(
                "event timestamp is more than 24 hours in the future"
            )
        return occurred_at

    def ingest(
        self,
        event: NormalizedSecurityEvent,
        *,
        related_alert_id: str | None = None,
        now: datetime | None = None,
    ) -> StoredEvent:
        ingested_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        occurred_at = self._validate_retention_time(event, ingested_at)
        with closing(self._connect()) as connection, connection:
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
            self._insert_event_row(
                connection,
                event,
                occurred_at=occurred_at,
                ingested_at=ingested_at,
                related_alert_id=related_alert_id,
            )
            connection.execute(
                "UPDATE security_event_store_state SET retained_records = retained_records + 1 "
                "WHERE singleton = 1"
            )
            self._enforce_retention(
                connection,
                ingested_at,
                preserve_event_id=event.event_id,
            )
            row = connection.execute(
                f"SELECT {self._select_columns()} WHERE e.event_id = ?",
                (event.event_id,),
            ).fetchone()
            connection.commit()
        if row is None:
            raise RuntimeError("event was removed immediately by retention policy")
        return StoredEvent(event=self._summary(row), duplicate=False)

    def ingest_batch(
        self,
        events: list[NormalizedSecurityEvent],
        *,
        now: datetime | None = None,
        max_processing_seconds: float = 15.0,
    ) -> BatchIngestResult:
        """Atomically persist one bounded ordered batch.

        Either every item is durably classified as inserted/duplicate and the
        transaction commits, or the transaction rolls back and no item is
        acknowledged. Normalization happens before this method is entered.
        """

        if not 1 <= len(events) <= 100:
            raise ValueError("batch must contain between one and 100 events")
        if max_processing_seconds <= 0:
            raise ValueError("max_processing_seconds must be positive")
        started = time.monotonic()
        deadline = started + max_processing_seconds
        ingested_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        occurred: list[datetime] = []
        for index, event in enumerate(events):
            try:
                occurred.append(self._validate_retention_time(event, ingested_at))
            except EventOutsideRetentionError as exc:
                raise BatchItemValidationError(
                    index,
                    str(exc),
                    field="timestamp",
                ) from exc
        connection_started = time.monotonic()
        connection = self._connect()
        connection_ms = (time.monotonic() - connection_started) * 1000
        transaction_started = time.monotonic()
        retention_ms = 0.0
        commit_ms = 0.0
        lock_wait_ms = 0.0
        deduplication_ms = 0.0
        alert_lookup_ms = 0.0
        insert_ms = 0.0
        retention_profile = RetentionProfile()
        sql_statement_count = 0
        results: list[BatchStoredEvent] = []
        inserted_ids: list[str] = []

        def count_statement(_: str) -> None:
            nonlocal sql_statement_count
            sql_statement_count += 1

        def timeout_error(stage: str) -> BatchProcessingTimeoutError:
            return BatchProcessingTimeoutError(
                "batch processing exceeded its pre-commit deadline",
                stage=stage,
                timing={
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    "connection_ms": round(connection_ms, 3),
                    "lock_wait_ms": round(lock_wait_ms, 3),
                    "deduplication_ms": round(deduplication_ms, 3),
                    "alert_lookup_ms": round(alert_lookup_ms, 3),
                    "insert_ms": round(insert_ms, 3),
                    "retention_ms": round(retention_ms, 3),
                    "sql_statement_count": sql_statement_count,
                    "full_age_sweep": retention_profile.full_age_sweep,
                },
            )

        connection.set_trace_callback(count_statement)
        try:
            stage_started = time.monotonic()
            connection.execute("BEGIN IMMEDIATE")
            lock_wait_ms = (time.monotonic() - stage_started) * 1000
            if time.monotonic() >= deadline:
                raise timeout_error("write_lock")
            event_ids = tuple(dict.fromkeys(event.event_id for event in events))
            deduplication_ids = tuple(
                dict.fromkeys(event.deduplication_id for event in events)
            )
            placeholders_event = ",".join("?" for _ in event_ids)
            placeholders_dedup = ",".join("?" for _ in deduplication_ids)
            stage_started = time.monotonic()
            existing_rows = connection.execute(
                "SELECT event_id, deduplication_id FROM security_events WHERE "
                f"event_id IN ({placeholders_event}) OR "
                f"deduplication_id IN ({placeholders_dedup})",
                (*event_ids, *deduplication_ids),
            ).fetchall()
            deduplication_ms = (time.monotonic() - stage_started) * 1000
            if time.monotonic() >= deadline:
                raise timeout_error("deduplication")
            by_event_id = {str(row["event_id"]): row for row in existing_rows}
            by_deduplication_id = {
                str(row["deduplication_id"]): row for row in existing_rows
            }

            source_ids = tuple(
                dict.fromkeys(
                    event.source_event_id
                    for event in events
                    if event.source_event_id
                )
            )
            linked_alerts: set[str] = set()
            stage_started = time.monotonic()
            if source_ids:
                placeholders = ",".join("?" for _ in source_ids)
                linked_alerts = {
                    str(row[0])
                    for row in connection.execute(
                        f"SELECT alert_id FROM alerts WHERE alert_id IN ({placeholders})",
                        source_ids,
                    )
                }
            alert_lookup_ms = (time.monotonic() - stage_started) * 1000
            if time.monotonic() >= deadline:
                raise timeout_error("alert_lookup")

            inserts_started = time.monotonic()
            for index, (event, occurred_at) in enumerate(zip(events, occurred, strict=True)):
                if time.monotonic() >= deadline:
                    insert_ms = (time.monotonic() - inserts_started) * 1000
                    raise timeout_error("insert")
                existing_by_id = by_event_id.get(event.event_id)
                if (
                    existing_by_id is not None
                    and str(existing_by_id["deduplication_id"])
                    != event.deduplication_id
                ):
                    raise BatchItemConflictError(index, event.event_id)
                existing = existing_by_id or by_deduplication_id.get(
                    event.deduplication_id
                )
                if existing is not None:
                    results.append(
                        BatchStoredEvent(
                            index=index,
                            event_id=str(existing["event_id"]),
                            deduplication_id=event.deduplication_id,
                            duplicate=True,
                        )
                    )
                    continue

                related_alert_id = (
                    event.source_event_id
                    if event.source_event_id in linked_alerts
                    else None
                )
                self._insert_event_row(
                    connection,
                    event,
                    occurred_at=occurred_at,
                    ingested_at=ingested_at,
                    related_alert_id=related_alert_id,
                )
                inserted_ids.append(event.event_id)
                synthetic_row = {
                    "event_id": event.event_id,
                    "deduplication_id": event.deduplication_id,
                }
                by_event_id[event.event_id] = synthetic_row
                by_deduplication_id[event.deduplication_id] = synthetic_row
                results.append(
                    BatchStoredEvent(
                        index=index,
                        event_id=event.event_id,
                        deduplication_id=event.deduplication_id,
                        duplicate=False,
                    )
                )
            insert_ms = (time.monotonic() - inserts_started) * 1000

            if inserted_ids:
                connection.execute(
                    "UPDATE security_event_store_state SET "
                    "retained_records = retained_records + ? WHERE singleton = 1",
                    (len(inserted_ids),),
                )
                retention_started = time.monotonic()
                retention_profile = self._enforce_retention(
                    connection,
                    ingested_at,
                    preserve_event_ids=tuple(inserted_ids),
                ) or RetentionProfile()
                retention_ms = (time.monotonic() - retention_started) * 1000
            if time.monotonic() >= deadline:
                raise timeout_error("retention")
            commit_started = time.monotonic()
            connection.commit()
            commit_ms = (time.monotonic() - commit_started) * 1000
            transaction_completed = time.monotonic()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.set_trace_callback(None)
            connection.close()

        completed = time.monotonic()
        duplicates = sum(1 for item in results if item.duplicate)
        return BatchIngestResult(
            items=results,
            inserted=len(inserted_ids),
            duplicates=duplicates,
            database_ms=round((completed - started) * 1000, 3),
            transaction_ms=round((transaction_completed - transaction_started) * 1000, 3),
            retention_ms=round(retention_ms, 3),
            commit_ms=round(commit_ms, 3),
            connection_ms=round(connection_ms, 3),
            lock_wait_ms=round(lock_wait_ms, 3),
            deduplication_ms=round(deduplication_ms, 3),
            alert_lookup_ms=round(alert_lookup_ms, 3),
            insert_ms=round(insert_ms, 3),
            retention_state_ms=retention_profile.state_ms,
            retention_age_delete_ms=retention_profile.age_delete_ms,
            retention_count_ms=retention_profile.count_ms,
            retention_candidate_ms=retention_profile.candidate_ms,
            protected_check_ms=retention_profile.protected_check_ms,
            retention_delete_ms=retention_profile.delete_ms,
            protected_count_ms=retention_profile.protected_count_ms,
            retention_metadata_ms=retention_profile.metadata_ms,
            retention_audit_ms=retention_profile.audit_ms,
            sql_statement_count=sql_statement_count,
            retention_rows_considered=retention_profile.rows_considered,
            retention_rows_deleted=retention_profile.rows_deleted,
            protected_row_skips=retention_profile.protected_skips,
            full_age_sweep=retention_profile.full_age_sweep,
        )

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
            (filters.operating_system, "e.operating_system", True),
            (filters.event_provider, "e.event_provider", True),
            (filters.event_channel, "e.event_channel", True),
            (filters.process_name, "e.process_name", True),
            (filters.rule_id, "e.rule_id", False),
            (filters.event_category, "e.event_category", True),
            (filters.event_action, "e.event_action", True),
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
            case_rows = connection.execute(
                "SELECT DISTINCT c.case_id FROM soc_cases c WHERE "
                "c.case_id IN (SELECT case_id FROM case_events WHERE event_id = ?) OR "
                "c.case_id IN (SELECT case_id FROM case_alerts WHERE alert_id = COALESCE(?, ?)) OR "
                "c.case_id IN (SELECT ci.case_id FROM case_incidents ci JOIN incident_alerts ia "
                "ON ia.incident_id = ci.incident_id WHERE ia.alert_id = COALESCE(?, ?)) "
                "ORDER BY c.case_id",
                (event_id, row["related_alert_id"], row["source_event_id"],
                 row["related_alert_id"], row["source_event_id"]),
            ).fetchall()
        summary = self._summary(row)
        structured = json.loads(row["structured_json"])
        return SecurityEventDetail(
            **summary.model_dump(),
            cuse=CUSEMetadata.model_validate(structured["_cuse"])
            if summary.normalization_schema in {"wazuh-event-v3", "collection-event-v1"} and isinstance(structured.get("_cuse"), dict)
            else None,
            structured_payload=structured,
            raw_payload=json.loads(row["raw_event_json"]),
            related_incident_ids=[str(item[0]) for item in incident_rows],
            related_case_ids=[str(item[0]) for item in case_rows],
            raw_evidence_ref=summary.event_id,
        )

    def telemetry_coverage(
        self,
        start_time: datetime,
        end_time: datetime,
        *,
        limit: int = 100,
    ) -> TelemetryCoverageReport:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        start = _utc_iso(start_time)
        end = _utc_iso(end_time)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT source_type, event_category, operating_system, event_provider,
                       event_channel, COUNT(*) AS event_count,
                       MIN(occurred_at) AS first_event_at,
                       MAX(occurred_at) AS last_event_at,
                       MAX(ingested_at) AS last_ingested_at
                FROM security_events
                WHERE occurred_at BETWEEN ? AND ?
                GROUP BY source_type, event_category, operating_system,
                         event_provider, event_channel
                ORDER BY event_count DESC, source_type, event_category,
                         event_provider, event_channel
                LIMIT ?
                """,
                (start, end, limit),
            ).fetchall()
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM security_events WHERE occurred_at BETWEEN ? AND ?",
                    (start, end),
                ).fetchone()[0]
            )
        return TelemetryCoverageReport(
            start_time=start_time,
            end_time=end_time,
            generated_at=datetime.now(timezone.utc),
            total_events=total,
            entries=[
                TelemetryCoverageEntry(
                    source_type=row["source_type"],
                    event_category=row["event_category"],
                    operating_system=row["operating_system"],
                    event_provider=row["event_provider"],
                    event_channel=row["event_channel"],
                    event_count=int(row["event_count"]),
                    first_event_at=datetime.fromisoformat(row["first_event_at"]),
                    last_event_at=datetime.fromisoformat(row["last_event_at"]),
                    last_ingested_at=datetime.fromisoformat(row["last_ingested_at"]),
                )
                for row in rows
            ],
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
            protected = self._protected_event_filter("security_events")
            retention_stats = connection.execute(
                f"SELECT COUNT(*), SUM(CASE WHEN {protected} THEN 1 ELSE 0 END), "
                "MIN(occurred_at), MAX(occurred_at) FROM security_events"
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

        retained_records = int(retention_stats[0] or 0)
        protected_records = int(retention_stats[1] or 0)
        over_limit_records = max(0, retained_records - self.max_records)
        retention_state = (
            "OVER_LIMIT_PROTECTED"
            if over_limit_records
            else "AT_LIMIT"
            if retained_records >= self.max_records
            else "WITHIN_LIMIT"
        )
        retention = RetentionStatus(
            state=retention_state,
            retention_days=self.retention_days,
            max_records=self.max_records,
            retained_records=retained_records,
            protected_records=protected_records,
            over_limit_records=over_limit_records,
            usage_percent=round((retained_records / self.max_records) * 100.0, 3),
            oldest_event_at=(
                datetime.fromisoformat(retention_stats[2]) if retention_stats[2] else None
            ),
            newest_event_at=(
                datetime.fromisoformat(retention_stats[3]) if retention_stats[3] else None
            ),
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
