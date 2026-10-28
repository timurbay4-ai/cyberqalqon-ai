"""Bounded, read-only projections for the M12 analyst investigation workbench."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sqlite3
import time
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from app.db.events import EventRepository
from app.schemas.cuse import CUSEMetadata
from app.schemas.detection_engineering import AdvancedDetectionFinding, AdvancedDetectionRule
from app.schemas.events import SecurityEventDetail, SecurityEventSummary
from app.schemas.investigation_workbench import (
    InvestigationCorrelationGroup,
    InvestigationDetectionContext,
    InvestigationEntity,
    InvestigationIOCMatch,
    InvestigationLink,
    InvestigationQueryMetadata,
    InvestigationSummary,
    InvestigationTimelineItem,
    InvestigationWorkbench,
    RelatedInvestigationEvent,
    WorkbenchRequest,
)


class WorkbenchTargetNotFoundError(LookupError):
    pass


class WorkbenchEvaluationLimitError(RuntimeError):
    pass


class InvalidWorkbenchCursorError(ValueError):
    pass


_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
_HASH_RE = re.compile(r"(?i)\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b")
_SEVERITY_NUMBER = {"INFORMATIONAL": 2, "LOW": 4, "MEDIUM": 7, "HIGH": 10, "CRITICAL": 13}


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _safe_json(value: object) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _cursor_binding(request: WorkbenchRequest, start: str, end: str) -> str:
    payload = {
        "end": end,
        "entity_type": request.entity_type,
        "entity_value": request.entity_value,
        "finding_key": request.finding_key,
        "shadow_revision": request.shadow_revision,
        "rule_id": request.rule_id,
        "start": start,
        "target_id": request.target_id,
        "target_type": request.target_type,
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _encode_related_cursor(row: sqlite3.Row, binding: str) -> str:
    payload = json.dumps(
        {
            "binding": binding,
            "event_id": str(row["event_id"]),
            "occurred_at": str(row["occurred_at"]),
            "v": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_related_cursor(cursor: str, binding: str) -> tuple[str, str]:
    try:
        padding = "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(cursor + padding, altchars=b"-_", validate=True)
        payload = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidWorkbenchCursorError("related-event cursor is malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"binding", "event_id", "occurred_at", "v"}:
        raise InvalidWorkbenchCursorError("related-event cursor is malformed")
    if (
        payload["v"] != 1
        or payload["binding"] != binding
        or not isinstance(payload["event_id"], str)
        or not payload["event_id"]
        or not isinstance(payload["occurred_at"], str)
    ):
        raise InvalidWorkbenchCursorError("related-event cursor does not match this investigation")
    try:
        occurred_at = datetime.fromisoformat(payload["occurred_at"])
    except ValueError as exc:
        raise InvalidWorkbenchCursorError("related-event cursor is malformed") from exc
    if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise InvalidWorkbenchCursorError("related-event cursor is malformed")
    return _utc(occurred_at).isoformat(), payload["event_id"]


def _walk_strings(value: object, *, depth: int = 0) -> Iterable[tuple[str, str]]:
    if depth >= 10:
        return
    if isinstance(value, dict):
        for index, (key, child) in enumerate(value.items()):
            if index >= 150:
                break
            path = str(key)
            if isinstance(child, str):
                yield path, child
            else:
                for suffix, text in _walk_strings(child, depth=depth + 1):
                    yield f"{path}.{suffix}", text
    elif isinstance(value, list):
        for index, child in enumerate(value[:100]):
            if isinstance(child, str):
                yield f"[{index}]", child
            else:
                for suffix, text in _walk_strings(child, depth=depth + 1):
                    yield f"[{index}].{suffix}", text


class InvestigationWorkbenchRepository:
    """Compose existing SOC records without creating new investigative state."""

    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")}

    @staticmethod
    def _indexes(connection: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in connection.execute(f"PRAGMA index_list({table})")}

    @staticmethod
    def _event_select(columns: set[str], *, alias: str = "e") -> str:
        optional = (
            "operating_system", "manager_identity", "event_provider", "event_channel",
            "process_name", "process_path", "command_line", "process_id",
            "parent_process_name", "parent_process_path", "parent_process_id",
            "normalization_schema", "mitre_ids_json", "mitre_tactics_json",
            "mitre_techniques_json",
        )
        expressions = [f"{alias}.*"]
        for column in optional:
            if column not in columns:
                fallback = "'wazuh-event-v1'" if column == "normalization_schema" else "'[]'" if column.startswith("mitre_") else "NULL"
                expressions.append(f"{fallback} AS {column}")
        expressions.append(f"COALESCE({alias}.related_alert_id, a.alert_id) AS resolved_alert_id")
        return ", ".join(expressions)

    @staticmethod
    def _summary(row: sqlite3.Row) -> SecurityEventSummary:
        return EventRepository._summary(row)

    def _event_row(self, connection: sqlite3.Connection, event_id: str, columns: set[str]) -> sqlite3.Row:
        row = connection.execute(
            f"SELECT {self._event_select(columns)} FROM security_events e "
            "LEFT JOIN alerts a ON a.alert_id = e.source_event_id WHERE e.event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise WorkbenchTargetNotFoundError(event_id)
        return row

    def _resolve_target(
        self, connection: sqlite3.Connection, request: WorkbenchRequest, start: str, end: str,
        indexes: set[str],
    ) -> tuple[str, str]:
        if request.target_type == "EVENT":
            return str(request.target_id), f"Event {request.target_id}"
        if request.target_type == "ALERT":
            row = connection.execute(
                "SELECT event_id FROM security_events WHERE related_alert_id = ? OR source_event_id = ? "
                "ORDER BY occurred_at, event_id LIMIT 1", (request.target_id, request.target_id),
            ).fetchone()
            label = f"Alert {request.target_id}"
        elif request.target_type in {"INCIDENT", "CORRELATION_GROUP"}:
            if request.target_type == "CORRELATION_GROUP":
                exists = connection.execute(
                    "SELECT 1 FROM incident_correlations WHERE incident_id = ? OR correlation_key = ?",
                    (request.target_id, request.target_id),
                ).fetchone()
                if exists is None:
                    raise WorkbenchTargetNotFoundError(str(request.target_id))
            row = connection.execute(
                "SELECT e.event_id FROM incident_alerts ia JOIN alerts a ON a.alert_id = ia.alert_id "
                "JOIN security_events e ON e.related_alert_id = a.alert_id OR e.source_event_id = a.alert_id "
                "WHERE ia.incident_id = ? ORDER BY e.occurred_at, e.event_id LIMIT 1",
                (request.target_id,),
            ).fetchone()
            label = f"{'Correlation group' if request.target_type == 'CORRELATION_GROUP' else 'Incident'} {request.target_id}"
        elif request.target_type == "CASE":
            row = connection.execute(
                "SELECT event_id FROM ("
                "SELECT ce.event_id, 0 AS priority FROM case_events ce WHERE ce.case_id = ? "
                "UNION ALL "
                "SELECT e.event_id, 1 FROM case_alerts ca JOIN security_events e "
                "ON e.related_alert_id = ca.alert_id OR e.source_event_id = ca.alert_id WHERE ca.case_id = ? "
                "UNION ALL "
                "SELECT e.event_id, 2 FROM case_incidents ci JOIN incident_alerts ia ON ia.incident_id = ci.incident_id "
                "JOIN security_events e ON e.related_alert_id = ia.alert_id OR e.source_event_id = ia.alert_id "
                "WHERE ci.case_id = ?) ORDER BY priority, event_id LIMIT 1",
                (request.target_id, request.target_id, request.target_id),
            ).fetchone()
            label = f"Case {request.target_id}"
        elif request.target_type == "ENTITY":
            column = {
                "IPV4": "source_ip", "IPV6": "source_ip", "HOSTNAME": "hostname",
                "USERNAME": "username", "AGENT_ID": "agent_id", "RULE_ID": "rule_id",
                "PROCESS_NAME": "process_name", "PROCESS_ID": "process_id",
            }.get(str(request.entity_type))
            if column is None:
                # Domain and hash values are stored in the bounded FTS document rather than a
                # dedicated normalized column. Resolve through FTS, then verify in structured JSON.
                token = str(request.entity_value).replace('"', '""')
                row = connection.execute(
                    "SELECT e.event_id FROM security_events_fts f JOIN security_events e ON e.event_id = f.event_id "
                    "WHERE f.search_text MATCH ? AND e.occurred_at BETWEEN ? AND ? "
                    "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT 1", (f'"{token}"', start, end),
                ).fetchone()
            else:
                required_process_index = {
                    "PROCESS_NAME": "idx_security_events_process_name_time",
                    "PROCESS_ID": "idx_security_events_process_id_time",
                }.get(str(request.entity_type))
                if required_process_index and required_process_index not in indexes:
                    raise WorkbenchTargetNotFoundError(
                        f"{request.entity_type} pivot is unavailable until its additive index is applied"
                    )
                row = connection.execute(
                    f"SELECT event_id FROM security_events WHERE {column} = ? COLLATE NOCASE "
                    "AND occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
                    (request.entity_value, start, end),
                ).fetchone()
                if row is None and request.entity_type in {"IPV4", "IPV6"}:
                    row = connection.execute(
                        "SELECT event_id FROM security_events WHERE destination_ip = ? "
                        "AND occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
                        (request.entity_value, start, end),
                    ).fetchone()
            label = f"{request.entity_type} investigation"
        else:
            raise WorkbenchTargetNotFoundError(str(request.target_id or request.finding_key))
        if row is None:
            raise WorkbenchTargetNotFoundError(str(request.target_id or request.entity_value))
        return str(row[0]), label

    @staticmethod
    def _entities(row: sqlite3.Row, structured: dict[str, Any], indexes: set[str]) -> list[InvestigationEntity]:
        values: list[tuple[str, object, str, bool, str]] = [
            ("HOSTNAME", row["hostname"], "Hostname", False, "hostname"),
            ("USERNAME", row["username"], "Username", True, "username"),
            ("AGENT_ID", row["agent_id"], "Agent ID", False, "agent_id"),
            ("RULE_ID", row["rule_id"], "Rule ID", False, "rule_id"),
            ("PROCESS_NAME", row["process_name"], "Process name", False, "process_name"),
            ("PROCESS_ID", row["process_id"], "Process ID", False, "process_id"),
        ]
        for field, label in (("source_ip", "Source IP"), ("destination_ip", "Destination IP")):
            value = row[field]
            if value:
                kind = "IPV6" if ipaddress.ip_address(str(value)).version == 6 else "IPV4"
                values.append((kind, value, label, True, field))
        seen = {(str(kind), str(value).casefold()) for kind, value, *_ in values if value}
        # Provenance/checksum hashes are not observed file hashes. Source-specific
        # evidence already exists in the original structured data fields.
        entity_payload = {key: value for key, value in structured.items() if key != "_cuse"}
        for path, text in _walk_strings(entity_payload):
            for match in _DOMAIN_RE.findall(text):
                key = ("DOMAIN", match.casefold())
                if key not in seen and len(seen) < 50:
                    values.append(("DOMAIN", match.casefold(), "Domain", True, f"structured_payload.{path}")); seen.add(key)
            for match in _HASH_RE.findall(text):
                key = ("FILE_HASH", match.casefold())
                if key not in seen and len(seen) < 50:
                    values.append(("FILE_HASH", match.casefold(), "File hash", True, f"structured_payload.{path}")); seen.add(key)
        result: list[InvestigationEntity] = []
        for kind, value, label, sensitive, field in values:
            if value is None or not str(value).strip():
                continue
            process_index = {
                "PROCESS_NAME": "idx_security_events_process_name_time",
                "PROCESS_ID": "idx_security_events_process_id_time",
            }.get(str(kind))
            supported = process_index is None or process_index in indexes
            result.append(InvestigationEntity(
                entity_type=kind, value=str(value), label=label, sensitive=sensitive,
                pivot_supported=supported, evidence_field=field,
            ))
        return result

    def _related(
        self, connection: sqlite3.Connection, row: sqlite3.Row, columns: set[str], indexes: set[str],
        start: str, end: str, limit: int, deadline: float, cursor: str | None,
        binding: str,
    ) -> tuple[list[RelatedInvestigationEvent], bool, list[str], str | None]:
        relation_fields = [
            ("source_ip", "SAME_SOURCE_IP", False),
            ("destination_ip", "SAME_DESTINATION_IP", False),
            ("hostname", "SAME_HOST", True),
            ("username", "SAME_ACCOUNT", True),
            ("agent_id", "SAME_AGENT", False),
            ("rule_id", "SAME_RULE", False),
        ]
        unavailable: list[str] = []
        if "process_name" in columns and "idx_security_events_process_name_time" in indexes:
            relation_fields.append(("process_name", "SAME_PROCESS_NAME", True))
        else:
            unavailable.append("SAME_PROCESS_NAME")
        if "process_id" in columns and "idx_security_events_process_id_time" in indexes:
            relation_fields.append(("process_id", "SAME_PROCESS_ID", False))
        else:
            unavailable.append("SAME_PROCESS_ID")
        relationships: dict[str, set[str]] = defaultdict(set)
        rows_by_id: dict[str, sqlite3.Row] = {}
        per_relation_limit = min(limit + 1, 101)
        source_truncated = False
        cursor_values = _decode_related_cursor(cursor, binding) if cursor else None
        cursor_clause = (
            " AND (e.occurred_at < ? OR (e.occurred_at = ? AND e.event_id < ?))"
            if cursor_values
            else ""
        )
        cursor_parameters: tuple[str, ...] = (
            (cursor_values[0], cursor_values[0], cursor_values[1]) if cursor_values else ()
        )

        def record(candidates: list[sqlite3.Row], relation: str) -> None:
            nonlocal source_truncated
            source_truncated = source_truncated or len(candidates) > limit
            for candidate in candidates:
                event_id = str(candidate["event_id"])
                relationships[event_id].add(relation)
                rows_by_id[event_id] = candidate

        for field, relation, insensitive in relation_fields:
            value = row[field]
            if value is None or not str(value).strip():
                continue
            if time.perf_counter() >= deadline:
                raise WorkbenchEvaluationLimitError("related-event query exceeded its execution budget")
            collation = " COLLATE NOCASE" if insensitive else ""
            candidates = connection.execute(
                f"SELECT {self._event_select(columns)} FROM security_events e "
                "LEFT JOIN alerts a ON a.alert_id = e.source_event_id "
                f"WHERE e.{field} = ?{collation} AND e.occurred_at BETWEEN ? AND ? AND e.event_id <> ? "
                f"{cursor_clause} "
                "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT ?",
                (value, start, end, row["event_id"], *cursor_parameters, per_relation_limit),
            ).fetchall()
            record(candidates, relation)

        alert_id = row["resolved_alert_id"] or row["source_event_id"]
        incident_ids = []
        if alert_id:
            incident_ids = [
                str(item[0]) for item in connection.execute(
                    "SELECT incident_id FROM incident_alerts WHERE alert_id = ? ORDER BY incident_id LIMIT 20",
                    (alert_id,),
                ).fetchall()
            ]

        def incident_candidates(ids: list[str]) -> list[sqlite3.Row]:
            if not ids:
                return []
            placeholders = ",".join("?" for _ in ids)
            return connection.execute(
                f"SELECT DISTINCT {self._event_select(columns)} FROM security_events e "
                "LEFT JOIN alerts a ON a.alert_id = e.source_event_id "
                "JOIN incident_alerts ia ON ia.alert_id = COALESCE(e.related_alert_id, e.source_event_id) "
                f"WHERE ia.incident_id IN ({placeholders}) AND e.occurred_at BETWEEN ? AND ? "
                f"AND e.event_id <> ? {cursor_clause} "
                "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT ?",
                (*ids, start, end, row["event_id"], *cursor_parameters, per_relation_limit),
            ).fetchall()

        if incident_ids:
            record(incident_candidates(incident_ids), "SAME_INCIDENT")
            correlated_ids = [
                str(item[0]) for item in connection.execute(
                    "SELECT incident_id FROM incident_correlations WHERE incident_id IN ("
                    + ",".join("?" for _ in incident_ids) + ") ORDER BY incident_id LIMIT 20",
                    incident_ids,
                ).fetchall()
            ]
            if correlated_ids:
                record(incident_candidates(correlated_ids), "SAME_CORRELATION_GROUP")

        case_rows = connection.execute(
            "SELECT case_id FROM case_events WHERE event_id = ? "
            "UNION SELECT case_id FROM case_alerts WHERE alert_id = ? "
            "UNION SELECT ci.case_id FROM case_incidents ci JOIN incident_alerts ia "
            "ON ia.incident_id = ci.incident_id WHERE ia.alert_id = ? LIMIT 20",
            (row["event_id"], alert_id, alert_id),
        ).fetchall()
        case_ids = [str(item[0]) for item in case_rows]
        if case_ids:
            placeholders = ",".join("?" for _ in case_ids)
            case_candidates = connection.execute(
                f"SELECT DISTINCT {self._event_select(columns)} FROM security_events e "
                "LEFT JOIN alerts a ON a.alert_id = e.source_event_id "
                f"WHERE (e.event_id IN (SELECT event_id FROM case_events WHERE case_id IN ({placeholders})) "
                f"OR COALESCE(e.related_alert_id, e.source_event_id) IN (SELECT alert_id FROM case_alerts WHERE case_id IN ({placeholders})) "
                "OR COALESCE(e.related_alert_id, e.source_event_id) IN (SELECT ia.alert_id FROM incident_alerts ia "
                f"JOIN case_incidents ci ON ci.incident_id = ia.incident_id WHERE ci.case_id IN ({placeholders}))) "
                "AND e.occurred_at BETWEEN ? AND ? AND e.event_id <> ? "
                f"{cursor_clause} "
                "ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT ?",
                (
                    *case_ids, *case_ids, *case_ids, start, end, row["event_id"],
                    *cursor_parameters, per_relation_limit,
                ),
            ).fetchall()
            record(case_candidates, "SAME_CASE")
        ordered = sorted(
            rows_by_id.values(), key=lambda item: (str(item["occurred_at"]), str(item["event_id"])), reverse=True
        )
        truncated = source_truncated or len(ordered) > limit
        page_rows = ordered[:limit]
        related = [
            RelatedInvestigationEvent(
                event=self._summary(item), relationship_types=sorted(relationships[str(item["event_id"])]),
            ) for item in page_rows
        ]
        next_cursor = (
            _encode_related_cursor(page_rows[-1], binding) if truncated and page_rows else None
        )
        return related, truncated, unavailable, next_cursor

    @staticmethod
    def _links(connection: sqlite3.Connection, row: sqlite3.Row) -> list[InvestigationLink]:
        alert_id = row["resolved_alert_id"] or row["source_event_id"]
        links: dict[tuple[str, str], InvestigationLink] = {}
        if alert_id and connection.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone():
            alert = connection.execute(
                "SELECT a.alert_id, a.rule_level, COALESCE(w.status, 'NEW') AS status "
                "FROM alerts a LEFT JOIN alert_workflows w ON w.alert_id = a.alert_id WHERE a.alert_id = ?",
                (alert_id,),
            ).fetchone()
            links[("ALERT", str(alert_id))] = InvestigationLink(
                target_type="ALERT", target_id=str(alert_id), title=f"Alert {alert_id}",
                status=alert["status"], severity=str(alert["rule_level"]),
            )
        incident_rows = connection.execute(
            "SELECT DISTINCT i.incident_id, i.title, i.status, i.severity FROM incidents i "
            "JOIN incident_alerts ia ON ia.incident_id = i.incident_id WHERE ia.alert_id = ?",
            (alert_id,),
        ).fetchall() if alert_id else []
        for item in incident_rows:
            links[("INCIDENT", item["incident_id"])] = InvestigationLink(
                target_type="INCIDENT", target_id=item["incident_id"], title=item["title"],
                status=item["status"], severity=item["severity"],
            )
            correlation = connection.execute(
                "SELECT correlation_rule FROM incident_correlations WHERE incident_id = ?", (item["incident_id"],)
            ).fetchone()
            if correlation:
                links[("CORRELATION_GROUP", item["incident_id"])] = InvestigationLink(
                    target_type="CORRELATION_GROUP", target_id=item["incident_id"],
                    title=f"{correlation['correlation_rule']} correlation group", status="LINKED",
                )
        case_rows = connection.execute(
            "SELECT DISTINCT c.case_id, c.title, c.status, c.severity FROM soc_cases c WHERE "
            "c.case_id IN (SELECT case_id FROM case_events WHERE event_id = ?) OR "
            "c.case_id IN (SELECT case_id FROM case_alerts WHERE alert_id = ?) OR "
            "c.case_id IN (SELECT ci.case_id FROM case_incidents ci JOIN incident_alerts ia "
            "ON ia.incident_id = ci.incident_id WHERE ia.alert_id = ?)",
            (row["event_id"], alert_id, alert_id),
        ).fetchall()
        for item in case_rows:
            links[("CASE", item["case_id"])] = InvestigationLink(
                target_type="CASE", target_id=item["case_id"], title=item["title"],
                status=item["status"], severity=item["severity"],
            )
        return sorted(links.values(), key=lambda item: (item.target_type, item.target_id))

    @staticmethod
    def _correlations(connection: sqlite3.Connection, links: list[InvestigationLink]) -> list[InvestigationCorrelationGroup]:
        incident_ids = [item.target_id for item in links if item.target_type == "INCIDENT"]
        result: list[InvestigationCorrelationGroup] = []
        for incident_id in incident_ids[:20]:
            row = connection.execute(
                "SELECT * FROM incident_correlations WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if row:
                result.append(InvestigationCorrelationGroup(
                    group_id=row["correlation_key"], correlation_rule=row["correlation_rule"],
                    classification=row["classification"], confidence=row["confidence"],
                    grouping_keys={"source_identity": row["source_identity"], "target_identity": row["target_identity"]},
                    first_seen=datetime.fromisoformat(row["first_seen"]), last_seen=datetime.fromisoformat(row["last_seen"]),
                    evidence_count=int(row["related_alert_count"]), explanation=row["explanation"], incident_id=incident_id,
                ))
        return result

    @staticmethod
    def _ioc_matches(
        connection: sqlite3.Connection, entities: list[InvestigationEntity], now: datetime
    ) -> list[InvestigationIOCMatch]:
        lookup = {(entity.entity_type, entity.value.casefold()): entity for entity in entities}
        rows = connection.execute(
            "SELECT * FROM ioc_indicators WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?) "
            "ORDER BY confidence DESC, indicator_id LIMIT 200", (now.isoformat(),),
        ).fetchall()
        result: list[InvestigationIOCMatch] = []
        for row in rows:
            entity = lookup.get((str(row["indicator_type"]), str(row["normalized_value"]).casefold()))
            if entity:
                result.append(InvestigationIOCMatch(
                    indicator_id=row["indicator_id"], indicator_type=row["indicator_type"],
                    value=row["normalized_value"], source=row["source"], confidence=int(row["confidence"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                    evidence_field=entity.evidence_field,
                ))
        return result[:50]

    @staticmethod
    def _timeline(
        connection: sqlite3.Connection, primary: SecurityEventSummary,
        related: list[RelatedInvestigationEvent], links: list[InvestigationLink],
        detection: InvestigationDetectionContext | None, limit: int, sort: str, now: datetime,
    ) -> list[InvestigationTimelineItem]:
        items: dict[tuple[str, str], InvestigationTimelineItem] = {}
        event_relations = {primary.event_id: ["PRIMARY_EVIDENCE"]}
        event_relations.update({entry.event.event_id: entry.relationship_types for entry in related})
        events = [primary, *(entry.event for entry in related)]
        for event in events:
            items[("SECURITY_EVENT", event.event_id)] = InvestigationTimelineItem(
                item_id=f"event:{event.event_id}", item_type="SECURITY_EVENT", timestamp=event.timestamp,
                timestamp_kind="EVENT_TIME", timestamp_status="FUTURE" if event.timestamp > now else "NORMAL",
                title=event.message, source_id=event.event_id, severity=event.severity,
                relationship_types=event_relations[event.event_id],
                details={"source_type": event.source_type, "rule_id": event.rule_id, "event_code": event.event_code},
            )
        alert_ids = [link.target_id for link in links if link.target_type == "ALERT"]
        for alert_id in alert_ids:
            row = connection.execute("SELECT occurred_at, rule_level, rule_id FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row:
                timestamp = datetime.fromisoformat(row["occurred_at"])
                items[("ALERT", alert_id)] = InvestigationTimelineItem(
                    item_id=f"alert:{alert_id}", item_type="ALERT", timestamp=timestamp,
                    timestamp_kind="EVENT_TIME", timestamp_status="FUTURE" if timestamp > now else "NORMAL",
                    title=f"Alert {alert_id} · rule {row['rule_id']}", source_id=alert_id,
                    severity=int(row["rule_level"]), relationship_types=["LINKED_ALERT"],
                )
        incident_ids = [link.target_id for link in links if link.target_type == "INCIDENT"]
        for incident_id in incident_ids[:20]:
            rows = connection.execute(
                "SELECT event_id, event_type, actor_display, actor, occurred_at, details_json "
                "FROM incident_history WHERE incident_id = ? ORDER BY occurred_at, event_id LIMIT 100",
                (incident_id,),
            ).fetchall()
            for row in rows:
                timestamp = datetime.fromisoformat(row["occurred_at"])
                kind = "ANALYST_NOTE" if row["event_type"] == "NOTE_ADDED" else "INCIDENT_ACTIVITY"
                items[(kind, row["event_id"])] = InvestigationTimelineItem(
                    item_id=f"incident:{row['event_id']}", item_type=kind, timestamp=timestamp,
                    timestamp_kind="ANALYST_ACTION_TIME", timestamp_status="FUTURE" if timestamp > now else "NORMAL",
                    title=f"{incident_id}: {str(row['event_type']).replace('_', ' ').title()}", source_id=incident_id,
                    actor_display=row["actor_display"] or row["actor"], details=_safe_json(row["details_json"]),
                )
        case_ids = [link.target_id for link in links if link.target_type == "CASE"]
        for case_id in case_ids[:20]:
            activity = connection.execute(
                "SELECT activity_id, activity_type, actor_display, occurred_at, details_json "
                "FROM case_activity WHERE case_id = ? ORDER BY occurred_at, activity_id LIMIT 100", (case_id,),
            ).fetchall()
            comments = connection.execute(
                "SELECT comment_id, comment_type, author_display, created_at FROM case_comments "
                "WHERE case_id = ? ORDER BY created_at, comment_id LIMIT 100", (case_id,),
            ).fetchall()
            for row in activity:
                timestamp = datetime.fromisoformat(row["occurred_at"])
                item_type = "EVIDENCE_ACTION" if "EVIDENCE" in str(row["activity_type"]) else "CASE_ACTIVITY"
                items[(item_type, row["activity_id"])] = InvestigationTimelineItem(
                    item_id=f"case:{row['activity_id']}", item_type=item_type, timestamp=timestamp,
                    timestamp_kind="ANALYST_ACTION_TIME", timestamp_status="FUTURE" if timestamp > now else "NORMAL",
                    title=f"{case_id}: {str(row['activity_type']).replace('_', ' ').title()}", source_id=case_id,
                    actor_display=row["actor_display"], details=_safe_json(row["details_json"]),
                )
            for row in comments:
                timestamp = datetime.fromisoformat(row["created_at"])
                items[("CASE_COMMENT", row["comment_id"])] = InvestigationTimelineItem(
                    item_id=f"comment:{row['comment_id']}", item_type="CASE_COMMENT", timestamp=timestamp,
                    timestamp_kind="ANALYST_ACTION_TIME", timestamp_status="FUTURE" if timestamp > now else "NORMAL",
                    title=f"{case_id}: {str(row['comment_type']).title()}", source_id=case_id,
                    actor_display=row["author_display"],
                )
        if detection:
            timestamp = detection.finding.last_event_at
            items[("DETECTION_FINDING", detection.finding.deduplication_key)] = InvestigationTimelineItem(
                item_id=f"finding:{detection.finding.deduplication_key}", item_type="DETECTION_FINDING",
                timestamp=timestamp, timestamp_kind="EVENT_TIME", timestamp_status="FUTURE" if timestamp > now else "NORMAL",
                title=f"{detection.rule.rule_id}: {detection.rule.name}", source_id=detection.finding.deduplication_key,
                severity=detection.finding.severity, relationship_types=["MATCHED_DETECTION_EVIDENCE"],
                details={"threshold": detection.finding.threshold, "window_seconds": detection.rule.window_seconds,
                         "event_ids": detection.finding.event_ids, "group": detection.finding.group},
            )
        ordered = sorted(items.values(), key=lambda item: (item.timestamp, item.item_id), reverse=sort == "newest")
        return ordered[:limit]

    @staticmethod
    def _summary_text(primary: SecurityEventSummary, links: list[InvestigationLink]) -> InvestigationSummary:
        observations = [
            f"Observed {primary.source_type.replace('_', ' ')} evidence at {primary.timestamp.isoformat()}.",
            f"The evidence is stored as event {primary.event_id} with rule {primary.rule_id or 'unavailable'}.",
        ]
        if primary.hostname or primary.username:
            observations.append(
                f"Recorded context includes host {primary.hostname or 'unavailable'} and account {primary.username or 'unavailable'}."
            )
        if links:
            counts: dict[str, int] = defaultdict(int)
            for link in links:
                counts[link.target_type.lower()] += 1
            observations.append("Linked records: " + ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items())) + ".")
        required = {
            "hostname": primary.hostname, "username": primary.username, "source_ip": primary.source_ip,
            "destination_ip": primary.destination_ip, "rule_id": primary.rule_id,
        }
        missing = [field for field, value in required.items() if value is None]
        return InvestigationSummary(
            observations=observations,
            interpretations=["These facts support investigation but do not by themselves establish attacker intent or confirmed compromise."],
            missing_fields=missing,
        )

    def build(
        self, request: WorkbenchRequest, *, start: datetime, end: datetime,
        detection_rule: AdvancedDetectionRule | None = None,
        detection_finding: AdvancedDetectionFinding | None = None,
        evaluated_event_count: int = 0,
        detection_source: str = "HISTORICAL_DRY_RUN",
        shadow_run_id: str | None = None,
        durable_shadow_context=None,
    ) -> InvestigationWorkbench:
        started = time.perf_counter()
        deadline = started + request.max_execution_ms / 1000
        start_iso, end_iso = _utc(start).isoformat(), _utc(end).isoformat()
        now = datetime.now(timezone.utc)
        with closing(self._connect()) as connection:
            connection.set_progress_handler(lambda: 1 if time.perf_counter() >= deadline else 0, 1000)
            try:
                columns = self._columns(connection, "security_events")
                indexes = self._indexes(connection, "security_events")
                if request.target_type == "DURABLE_SHADOW_FINDING":
                    if durable_shadow_context is None:
                        raise WorkbenchTargetNotFoundError(str(request.target_id))
                    event_id = durable_shadow_context.matching_evidence.evidence[0].event_id
                    label = f"{durable_shadow_context.finding_id} revision {durable_shadow_context.revision}"
                elif request.target_type in {"M11_FINDING", "SHADOW_FINDING"}:
                    if detection_finding is None:
                        raise WorkbenchTargetNotFoundError(
                            str(request.finding_key or request.target_id)
                        )
                    event_id = detection_finding.event_ids[0]
                    label = (
                        f"{detection_finding.rule_id} shadow finding"
                        if request.target_type == "SHADOW_FINDING"
                        else f"{request.rule_id} dry-run finding"
                    )
                else:
                    event_id, label = self._resolve_target(connection, request, start_iso, end_iso, indexes)
                row = self._event_row(connection, event_id, columns)
                primary = self._summary(row)
                structured = _safe_json(row["structured_json"])
                detail = SecurityEventDetail(
                    **primary.model_dump(), structured_payload=structured,
                    cuse=CUSEMetadata.model_validate(structured["_cuse"])
                    if isinstance(structured.get("_cuse"), dict) else None,
                    raw_payload=_safe_json(row["raw_event_json"]), related_incident_ids=[], related_case_ids=[],
                    raw_evidence_ref=primary.event_id,
                )
                entities = self._entities(row, detail.structured_payload, indexes)
                binding = _cursor_binding(request, start_iso, end_iso)
                related, truncated, unavailable, next_cursor = self._related(
                    connection, row, columns, indexes, start_iso, end_iso,
                    request.related_limit, deadline, request.related_cursor, binding,
                )
                links = self._links(connection, row)
                detail.related_incident_ids = [item.target_id for item in links if item.target_type == "INCIDENT"]
                detail.related_case_ids = [item.target_id for item in links if item.target_type == "CASE"]
                correlations = self._correlations(connection, links)
                iocs = self._ioc_matches(connection, entities, now)
                detection = None
                if detection_rule and detection_finding:
                    detection = InvestigationDetectionContext(
                        rule=detection_rule, finding=detection_finding,
                        evaluated_event_count=evaluated_event_count,
                        execution_budget_ms=request.max_execution_ms,
                        source_kind=detection_source,
                        shadow_run_id=shadow_run_id,
                    )
                timeline = self._timeline(
                    connection, primary, related, links, detection,
                    request.timeline_limit, request.sort, now,
                )
                schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            except sqlite3.OperationalError as exc:
                if "interrupted" in str(exc).casefold():
                    raise WorkbenchEvaluationLimitError("investigation query exceeded its execution budget") from exc
                raise
            finally:
                connection.set_progress_handler(None, 0)
        elapsed = (time.perf_counter() - started) * 1000
        if elapsed > request.max_execution_ms:
            raise WorkbenchEvaluationLimitError("investigation query exceeded its execution budget")
        return InvestigationWorkbench(
            target_type=request.target_type, target_label=label, primary_event=detail,
            summary=self._summary_text(primary, links), entities=entities,
            related_events=related, links=links, timeline=timeline, ioc_matches=iocs,
            correlation_groups=correlations, detection_context=detection,
            durable_shadow_context=durable_shadow_context,
            query=InvestigationQueryMetadata(
                start_time=start, end_time=end, related_limit=request.related_limit,
                related_cursor=request.related_cursor, related_next_cursor=next_cursor,
                timeline_limit=request.timeline_limit, sort=request.sort, execution_ms=round(elapsed, 3),
                related_truncated=truncated, schema_version=schema_version,
                unavailable_relationships=unavailable,
            ),
        )
