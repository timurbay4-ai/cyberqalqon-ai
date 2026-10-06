"""SQLite persistence and deterministic reads for normalized alerts."""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import REPOSITORY_ROOT
from app.db.migrations import apply_migrations
from app.schemas.alerts import JsonObject, NormalizedAlert
from app.services.alert_index import alert_search_document, mitre_ids_document
from app.services.wazuh_normalizer import canonical_json


class AlertIdConflictError(RuntimeError):
    pass


class InvalidAlertCursorError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StoredAlert:
    alert: NormalizedAlert
    ingested_at: datetime
    duplicate: bool


@dataclass(frozen=True, slots=True)
class AlertFilters:
    rule_levels: tuple[int, ...] = ()
    agent: str | None = None
    mitre_mapped: bool | None = None
    mitre_id: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class AlertListResult:
    items: list[NormalizedAlert]
    total: int
    next_cursor: str | None


def _database_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("Only sqlite:/// DATABASE_URL values are supported in the current release")
    raw_path = database_url[len(prefix) :]
    if not raw_path or raw_path == ":memory:":
        raise ValueError("DATABASE_URL must point to a file-backed SQLite database")
    path = Path(raw_path)
    if not path.is_absolute():
        path = REPOSITORY_ROOT / path
    return path.resolve()


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp filters must include a UTC offset")
    return value.astimezone(timezone.utc).isoformat()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _encode_cursor(occurred_at: str, alert_id: str) -> str:
    payload = canonical_json({"alert_id": alert_id, "occurred_at": occurred_at, "v": 1})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    if not cursor or len(cursor) > 2048:
        raise InvalidAlertCursorError("cursor is malformed")
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        payload: Any = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidAlertCursorError("cursor is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"alert_id", "occurred_at", "v"}:
        raise InvalidAlertCursorError("cursor is malformed")
    if payload["v"] != 1 or not isinstance(payload["alert_id"], str) or not isinstance(payload["occurred_at"], str):
        raise InvalidAlertCursorError("cursor is malformed")
    try:
        occurred_at = datetime.fromisoformat(payload["occurred_at"])
    except ValueError as exc:
        raise InvalidAlertCursorError("cursor is malformed") from exc
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None or not payload["alert_id"]:
        raise InvalidAlertCursorError("cursor is malformed")
    return _utc_iso(occurred_at), payload["alert_id"]


class AlertRepository:
    def __init__(self, database_url: str) -> None:
        self.path = _database_path(database_url)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            apply_migrations(connection)

    def ingest(self, alert: NormalizedAlert, raw_event: JsonObject, fingerprint: str) -> StoredAlert:
        normalized_json = canonical_json(alert.model_dump(mode="json", exclude_none=True))
        raw_event_json = canonical_json(raw_event)
        ingested_at = datetime.now(timezone.utc)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT fingerprint, normalized_json, ingested_at FROM alerts WHERE alert_id = ?",
                (alert.alert_id,),
            ).fetchone()
            if existing is not None:
                if existing["fingerprint"] != fingerprint:
                    raise AlertIdConflictError(
                        f"alert_id '{alert.alert_id}' already exists with different event content"
                    )
                return StoredAlert(
                    alert=NormalizedAlert.model_validate_json(existing["normalized_json"]),
                    ingested_at=datetime.fromisoformat(existing["ingested_at"]),
                    duplicate=True,
                )

            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, fingerprint, occurred_at, agent_id, agent_name,
                    rule_id, rule_level, has_mitre, mitre_ids_text, search_text,
                    normalized_json, raw_event_json, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    fingerprint,
                    _utc_iso(alert.timestamp),
                    alert.agent.id,
                    alert.agent.name,
                    alert.rule.id,
                    alert.rule.level,
                    bool(alert.mitre.ids),
                    mitre_ids_document(alert),
                    alert_search_document(alert),
                    normalized_json,
                    raw_event_json,
                    ingested_at.isoformat(),
                ),
            )
        return StoredAlert(alert=alert, ingested_at=ingested_at, duplicate=False)

    def get(self, alert_id: str) -> NormalizedAlert | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT normalized_json FROM alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
        if row is None:
            return None
        return NormalizedAlert.model_validate_json(row["normalized_json"])

    def list(
        self,
        filters: AlertFilters,
        *,
        limit: int,
        cursor: str | None = None,
    ) -> AlertListResult:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")

        conditions: list[str] = []
        parameters: list[object] = []
        if filters.rule_levels:
            if any(level < 0 or level > 16 for level in filters.rule_levels):
                raise ValueError("rule levels must be between 0 and 16")
            placeholders = ", ".join("?" for _ in filters.rule_levels)
            conditions.append(f"rule_level IN ({placeholders})")
            parameters.extend(filters.rule_levels)
        if filters.agent:
            conditions.append("(agent_id = ? COLLATE NOCASE OR agent_name = ? COLLATE NOCASE)")
            parameters.extend((filters.agent, filters.agent))
        if filters.mitre_mapped is not None:
            conditions.append("has_mitre = ?")
            parameters.append(filters.mitre_mapped)
        if filters.mitre_id:
            conditions.append("instr(mitre_ids_text, ?) > 0")
            parameters.append(f"|{filters.mitre_id}|")
        if filters.start_time:
            conditions.append("occurred_at >= ?")
            parameters.append(_utc_iso(filters.start_time))
        if filters.end_time:
            conditions.append("occurred_at <= ?")
            parameters.append(_utc_iso(filters.end_time))
        if filters.search:
            conditions.append("search_text LIKE ? ESCAPE '\\'")
            parameters.append(f"%{_escape_like(filters.search.casefold())}%")

        base_where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM alerts" + base_where,
                    parameters,
                ).fetchone()[0]
            )

            page_conditions = list(conditions)
            page_parameters = list(parameters)
            if cursor:
                occurred_at, alert_id = _decode_cursor(cursor)
                page_conditions.append(
                    "(occurred_at < ? OR (occurred_at = ? AND alert_id < ?))"
                )
                page_parameters.extend((occurred_at, occurred_at, alert_id))
            page_where = f" WHERE {' AND '.join(page_conditions)}" if page_conditions else ""
            rows = connection.execute(
                "SELECT alert_id, occurred_at, normalized_json FROM alerts"
                + page_where
                + " ORDER BY occurred_at DESC, alert_id DESC LIMIT ?",
                (*page_parameters, limit + 1),
            ).fetchall()

        has_more = len(rows) > limit
        visible_rows = rows[:limit]
        items = [NormalizedAlert.model_validate_json(row["normalized_json"]) for row in visible_rows]
        next_cursor = None
        if has_more and visible_rows:
            last = visible_rows[-1]
            next_cursor = _encode_cursor(last["occurred_at"], last["alert_id"])
        return AlertListResult(items=items, total=total, next_cursor=next_cursor)
