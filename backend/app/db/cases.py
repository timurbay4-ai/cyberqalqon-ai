"""Transactional SQLite repository for durable SOC case work."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal, AnalystRole
from app.schemas.cases import (
    CaseActivity,
    CaseAnalytics,
    CaseAnalyticsCount,
    CaseComment,
    CaseCreate,
    CaseDetail,
    CaseEvidence,
    CaseEvidenceCreate,
    CaseOwner,
    CasePlaybook,
    CasePriority,
    CaseReportRecord,
    CaseSeverity,
    CaseSla,
    CaseSourceType,
    CaseStatus,
    CaseSummary,
    CustodyEvent,
    EvidenceIntegrityStatus,
    EvidenceReferenceType,
    PlaybookStep,
    PlaybookTemplate,
    PlaybookTemplateStep,
)
from app.services.wazuh_normalizer import canonical_json


class CaseNotFoundError(LookupError):
    pass


class CaseReferenceNotFoundError(LookupError):
    pass


class CaseOwnerNotFoundError(LookupError):
    pass


class CaseConflictError(RuntimeError):
    pass


class InvalidCaseTransitionError(RuntimeError):
    pass


class InvalidCaseCursorError(ValueError):
    pass


class PlaybookTemplateNotFoundError(LookupError):
    pass


SLA_TARGETS_MINUTES: dict[CasePriority, tuple[int, int]] = {
    CasePriority.CRITICAL: (15, 240),
    CasePriority.HIGH: (30, 480),
    CasePriority.MEDIUM: (240, 4320),
    CasePriority.LOW: (480, 10080),
}

ALLOWED_CASE_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.TRIAGING}),
    CaseStatus.TRIAGING: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.WAITING, CaseStatus.RESOLVED}
    ),
    CaseStatus.INVESTIGATING: frozenset(
        {CaseStatus.TRIAGING, CaseStatus.WAITING, CaseStatus.RESOLVED}
    ),
    CaseStatus.WAITING: frozenset(
        {CaseStatus.TRIAGING, CaseStatus.INVESTIGATING, CaseStatus.RESOLVED}
    ),
    CaseStatus.RESOLVED: frozenset({CaseStatus.INVESTIGATING, CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset(),
}


PLAYBOOK_TEMPLATES: dict[str, dict[str, Any]] = {
    "login-investigation": {
        "name": "Suspicious login investigation",
        "description": "Validate identity, source context, and observed authentication telemetry.",
        "steps": (
            ("review-auth", "Review authentication telemetry", "Review linked login events and their authoritative fields.", "ACTION"),
            ("preserve-auth", "Preserve supporting evidence", "Attach at least one relevant alert or event reference.", "EVIDENCE"),
            ("validate-user", "Validate account context", "Document whether the account and source are expected.", "ACTION"),
            ("approve-close", "Approve disposition", "An administrator reviews the documented disposition before closure.", "APPROVAL"),
        ),
    },
    "network-investigation": {
        "name": "Network activity investigation",
        "description": "Review network evidence without initiating scans or automated blocking.",
        "steps": (
            ("review-network", "Review network telemetry", "Review source, destination, ports, direction, and time window.", "ACTION"),
            ("preserve-network", "Preserve network evidence", "Attach a relevant alert or event reference.", "EVIDENCE"),
            ("scope-related", "Scope related telemetry", "Document bounded searches used to assess related activity.", "ACTION"),
            ("approve-disposition", "Approve disposition", "An administrator reviews the disposition; no response action is executed.", "APPROVAL"),
        ),
    },
    "fim-investigation": {
        "name": "File integrity investigation",
        "description": "Validate a file integrity observation and preserve its stored telemetry.",
        "steps": (
            ("review-fim", "Review FIM change", "Review path, action, actor, timestamps, and available hashes.", "ACTION"),
            ("preserve-fim", "Preserve FIM evidence", "Attach the relevant event or alert reference.", "EVIDENCE"),
            ("validate-change", "Validate change context", "Document whether the observed change was expected.", "ACTION"),
            ("approve-disposition", "Approve disposition", "An administrator reviews the documented finding.", "APPROVAL"),
        ),
    },
    "ioc-investigation": {
        "name": "IOC match investigation",
        "description": "Validate an indicator match against locally stored telemetry.",
        "steps": (
            ("review-ioc", "Review indicator context", "Review indicator source, type, value, and expiration state.", "ACTION"),
            ("preserve-match", "Preserve match evidence", "Attach the matching event or alert reference.", "EVIDENCE"),
            ("assess-scope", "Assess bounded scope", "Document related local observations without active scanning.", "ACTION"),
            ("approve-disposition", "Approve disposition", "An administrator reviews the disposition.", "APPROVAL"),
        ),
    },
    "powershell-investigation": {
        "name": "PowerShell investigation",
        "description": "Review stored PowerShell telemetry without executing content.",
        "steps": (
            ("review-powershell", "Review PowerShell telemetry", "Review event code, host, user, and available script metadata as inert text.", "ACTION"),
            ("preserve-powershell", "Preserve PowerShell evidence", "Attach the relevant stored event or alert reference.", "EVIDENCE"),
            ("assess-intent", "Assess observed intent", "Document the behavior indicated by telemetry; do not execute payloads.", "ACTION"),
            ("approve-disposition", "Approve disposition", "An administrator reviews the disposition.", "APPROVAL"),
        ),
    },
}


@dataclass(frozen=True, slots=True)
class CaseFilters:
    statuses: tuple[CaseStatus, ...] = ()
    severities: tuple[CaseSeverity, ...] = ()
    priorities: tuple[CasePriority, ...] = ()
    owner_id: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class CaseListResult:
    items: list[CaseSummary]
    total: int
    next_cursor: str | None


def _identifier(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex.upper()}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(canonical_json({"o": offset, "v": 1}).encode()).rstrip(b"=").decode()


def _decode_cursor(cursor: str) -> int:
    try:
        payload = json.loads(base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCaseCursorError("cursor is malformed") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1 or not isinstance(payload.get("o"), int) or payload["o"] < 0:
        raise InvalidCaseCursorError("cursor is malformed")
    return payload["o"]


class CaseRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def templates() -> list[PlaybookTemplate]:
        return [
            PlaybookTemplate(
                key=key,
                version=1,
                name=value["name"],
                description=value["description"],
                steps=[
                    PlaybookTemplateStep(key=step[0], title=step[1], description=step[2], step_type=step[3])
                    for step in value["steps"]
                ],
            )
            for key, value in PLAYBOOK_TEMPLATES.items()
        ]

    @staticmethod
    def _require_case(connection: sqlite3.Connection, case_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM soc_cases WHERE case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        return row

    @staticmethod
    def _require_owner(connection: sqlite3.Connection, owner_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT analyst_id, username, display_name FROM analysts "
            "WHERE analyst_id = ? AND is_active = 1 AND role IN ('ADMIN', 'ANALYST')",
            (owner_id,),
        ).fetchone()
        if row is None:
            raise CaseOwnerNotFoundError(owner_id)
        return row

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        action: str,
        actor: AnalystPrincipal,
        case_id: str,
        now: datetime,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO security_audit_events (audit_id, action, actor_id, actor_display, "
            "target_type, target_id, outcome, occurred_at, details_json) "
            "VALUES (?, ?, ?, ?, 'case', ?, 'SUCCESS', ?, ?)",
            (_identifier("AUD"), action, actor.analyst_id, actor.audit_display, case_id, now.isoformat(), canonical_json(details)),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN (SELECT audit_id FROM "
            "security_audit_events ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    @staticmethod
    def _activity(
        connection: sqlite3.Connection,
        case_id: str,
        activity_type: str,
        actor: AnalystPrincipal,
        entity_type: str,
        entity_id: str,
        now: datetime,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO case_activity (activity_id, case_id, activity_type, actor_id, "
            "actor_display, entity_type, entity_id, occurred_at, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (_identifier("CACT"), case_id, activity_type, actor.analyst_id, actor.audit_display, entity_type, entity_id, now.isoformat(), canonical_json(details)),
        )

    @staticmethod
    def _notification(
        connection: sqlite3.Connection,
        analyst_id: str | None,
        category: str,
        case_id: str,
        title: str,
        preview: str,
        event_key: str,
        now: datetime,
    ) -> bool:
        if analyst_id is None:
            return False
        inserted = connection.execute(
            "INSERT OR IGNORE INTO analyst_notifications (notification_id, analyst_id, category, "
            "title, preview, target_type, target_id, event_key, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'case', ?, ?, ?)",
            (_identifier("NTF"), analyst_id, category, title[:160], preview[:320], case_id, event_key[:512], now.isoformat()),
        ).rowcount == 1
        connection.execute(
            "DELETE FROM analyst_notifications WHERE notification_id IN ("
            "SELECT notification_id FROM analyst_notifications WHERE analyst_id = ? "
            "ORDER BY created_at DESC, notification_id DESC LIMIT -1 OFFSET 500)",
            (analyst_id,),
        )
        return inserted

    @staticmethod
    def _sla_for(row: sqlite3.Row, at: datetime | None = None) -> CaseSla:
        now = at or _now()
        response_due = datetime.fromisoformat(row["response_due_at"])
        resolution_due = datetime.fromisoformat(row["resolution_due_at"])
        first_response = datetime.fromisoformat(row["first_response_at"]) if row["first_response_at"] else None
        resolved = datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None
        response_state: Literal["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"]
        resolution_state: Literal["PENDING", "MET", "OVERDUE", "NOT_APPLICABLE"]
        if first_response is None:
            response_state = "OVERDUE" if now > response_due else "PENDING"
        else:
            response_state = "MET" if first_response <= response_due else "OVERDUE"
        if resolved is None:
            resolution_state = "OVERDUE" if now > resolution_due else "PENDING"
        else:
            resolution_state = "MET" if resolved <= resolution_due else "OVERDUE"
        escalation: Literal["NONE", "RESPONSE_OVERDUE", "RESOLUTION_OVERDUE"] = "NONE"
        if resolution_state == "OVERDUE":
            escalation = "RESOLUTION_OVERDUE"
        elif response_state == "OVERDUE":
            escalation = "RESPONSE_OVERDUE"
        return CaseSla(
            response_due_at=response_due,
            resolution_due_at=resolution_due,
            first_response_at=first_response,
            response_state=response_state,
            resolution_state=resolution_state,
            escalation_state=escalation,
        )

    @staticmethod
    def _summary_select() -> str:
        return """
            SELECT c.*, a.username AS owner_username, a.display_name AS owner_display,
                (SELECT COUNT(*) FROM case_alerts ca WHERE ca.case_id = c.case_id) AS alert_count,
                (SELECT COUNT(*) FROM case_incidents ci WHERE ci.case_id = c.case_id) AS incident_count,
                (SELECT COUNT(*) FROM case_events ce WHERE ce.case_id = c.case_id) AS event_count,
                (SELECT COUNT(*) FROM case_evidence_refs er WHERE er.case_id = c.case_id) AS evidence_count,
                (SELECT COUNT(*) FROM case_comments cc WHERE cc.case_id = c.case_id) AS comment_count
            FROM soc_cases c
            LEFT JOIN analysts a ON a.analyst_id = c.owner_id
        """

    @classmethod
    def _summary_from_row(cls, row: sqlite3.Row, at: datetime | None = None) -> CaseSummary:
        owner = None
        if row["owner_id"] is not None:
            owner = CaseOwner(
                analyst_id=row["owner_id"],
                username=row["owner_username"] or "deleted-analyst",
                display_name=row["owner_display"] or "Deleted analyst",
            )
        return CaseSummary(
            case_id=row["case_id"], title=row["title"], description=row["description"],
            severity=CaseSeverity(row["severity"]), priority=CasePriority(row["priority"]),
            status=CaseStatus(row["status"]), owner=owner,
            source_type=CaseSourceType(row["source_type"]), source_id=row["source_id"],
            created_by_display=row["created_by_display"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            resolved_at=datetime.fromisoformat(row["resolved_at"]) if row["resolved_at"] else None,
            closed_at=datetime.fromisoformat(row["closed_at"]) if row["closed_at"] else None,
            version=int(row["version"]), alert_count=int(row["alert_count"]),
            incident_count=int(row["incident_count"]), event_count=int(row["event_count"]),
            evidence_count=int(row["evidence_count"]), comment_count=int(row["comment_count"]),
            sla=cls._sla_for(row, at),
        )

    def _detail(self, connection: sqlite3.Connection, case_id: str) -> CaseDetail:
        row = connection.execute(self._summary_select() + " WHERE c.case_id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseNotFoundError(case_id)
        summary = self._summary_from_row(row)
        comments = [
            CaseComment(
                comment_id=item["comment_id"], comment_type=item["comment_type"], body=item["body"],
                author_display=item["author_display"], from_owner_id=item["from_owner_id"],
                to_owner_id=item["to_owner_id"], created_at=datetime.fromisoformat(item["created_at"]),
            )
            for item in connection.execute(
                "SELECT * FROM case_comments WHERE case_id = ? ORDER BY created_at, comment_id LIMIT 500", (case_id,)
            ).fetchall()
        ]
        evidence: list[CaseEvidence] = []
        for item in connection.execute(
            "SELECT * FROM case_evidence_refs WHERE case_id = ? ORDER BY acquired_at, evidence_ref_id LIMIT 200",
            (case_id,),
        ).fetchall():
            custody = [
                CustodyEvent(
                    custody_event_id=event["custody_event_id"], event_type=event["event_type"],
                    actor_display=event["actor_display"], occurred_at=datetime.fromisoformat(event["occurred_at"]),
                    details=json.loads(event["details_json"]),
                )
                for event in connection.execute(
                    "SELECT * FROM evidence_custody_events WHERE evidence_ref_id = ? "
                    "ORDER BY occurred_at, custody_event_id LIMIT 500", (item["evidence_ref_id"],)
                ).fetchall()
            ]
            evidence.append(CaseEvidence(
                evidence_ref_id=item["evidence_ref_id"], reference_type=EvidenceReferenceType(item["reference_type"]),
                reference_id=item["reference_id"], source_label=item["source_label"],
                source_timestamp=datetime.fromisoformat(item["source_timestamp"]),
                acquisition_method="DATABASE_REFERENCE", digest_algorithm="SHA-256", digest=item["digest"],
                integrity_status=EvidenceIntegrityStatus(item["integrity_status"]),
                acquired_by_display=item["acquired_by_display"], acquired_at=datetime.fromisoformat(item["acquired_at"]),
                last_verified_at=datetime.fromisoformat(item["last_verified_at"]), annotation=item["annotation"],
                version=int(item["version"]), custody=custody,
            ))
        activity = [
            CaseActivity(
                activity_id=item["activity_id"], activity_type=item["activity_type"],
                actor_display=item["actor_display"], entity_type=item["entity_type"],
                entity_id=item["entity_id"], occurred_at=datetime.fromisoformat(item["occurred_at"]),
                details=json.loads(item["details_json"]),
            )
            for item in connection.execute(
                "SELECT * FROM case_activity WHERE case_id = ? ORDER BY occurred_at, activity_id LIMIT 1000", (case_id,)
            ).fetchall()
        ]
        playbooks = self._playbooks(connection, case_id)
        reports = [
            CaseReportRecord(
                report_id=item["report_id"], format=item["format"],
                generated_by_display=item["generated_by_display"],
                generated_at=datetime.fromisoformat(item["generated_at"]), sha256=item["sha256"],
                size_bytes=int(item["size_bytes"]), redaction_profile="CASE_REPORT_V1",
            )
            for item in connection.execute(
                "SELECT * FROM case_report_history WHERE case_id = ? "
                "ORDER BY generated_at DESC, report_id DESC LIMIT 50", (case_id,)
            ).fetchall()
        ]
        return CaseDetail(
            **summary.model_dump(), resolution=row["resolution"], closure_reason=row["closure_reason"],
            alert_ids=[r[0] for r in connection.execute("SELECT alert_id FROM case_alerts WHERE case_id = ? ORDER BY alert_id", (case_id,))],
            incident_ids=[r[0] for r in connection.execute("SELECT incident_id FROM case_incidents WHERE case_id = ? ORDER BY incident_id", (case_id,))],
            event_ids=[r[0] for r in connection.execute("SELECT event_id FROM case_events WHERE case_id = ? ORDER BY event_id", (case_id,))],
            comments=comments, evidence=evidence, activity=activity, playbooks=playbooks, report_history=reports,
        )

    def get(self, case_id: str) -> CaseDetail:
        with self._connect() as connection:
            return self._detail(connection, case_id)

    def create(self, payload: CaseCreate, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        case_id = _identifier("CASE")
        response_minutes, resolution_minutes = SLA_TARGETS_MINUTES[payload.priority]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if payload.owner_id:
                self._require_owner(connection, payload.owner_id)
            if payload.source_type is CaseSourceType.ALERT:
                if connection.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (payload.source_id,)).fetchone() is None:
                    raise CaseReferenceNotFoundError(payload.source_id or "")
            elif payload.source_type is CaseSourceType.INCIDENT:
                if connection.execute("SELECT 1 FROM incidents WHERE incident_id = ?", (payload.source_id,)).fetchone() is None:
                    raise CaseReferenceNotFoundError(payload.source_id or "")
            connection.execute(
                "INSERT INTO soc_cases (case_id, title, description, severity, priority, status, owner_id, "
                "source_type, source_id, created_by, created_by_display, created_at, updated_at, "
                "response_due_at, resolution_due_at) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, payload.title, payload.description, payload.severity.value, payload.priority.value,
                 payload.owner_id, payload.source_type.value, payload.source_id, actor.analyst_id, actor.audit_display,
                 now.isoformat(), now.isoformat(), (now + timedelta(minutes=response_minutes)).isoformat(),
                 (now + timedelta(minutes=resolution_minutes)).isoformat()),
            )
            if payload.source_type is CaseSourceType.ALERT:
                connection.execute(
                    "INSERT INTO case_alerts VALUES (?, ?, ?, ?, ?)",
                    (case_id, payload.source_id, now.isoformat(), actor.analyst_id, actor.audit_display),
                )
            elif payload.source_type is CaseSourceType.INCIDENT:
                connection.execute(
                    "INSERT INTO case_incidents VALUES (?, ?, ?, ?, ?)",
                    (case_id, payload.source_id, now.isoformat(), actor.analyst_id, actor.audit_display),
                )
            details = {"source_type": payload.source_type.value, "source_id": payload.source_id,
                       "priority": payload.priority.value, "severity": payload.severity.value,
                       "owner_id": payload.owner_id}
            self._activity(connection, case_id, "CASE_CREATED", actor, "case", case_id, now, details)
            self._audit(connection, "CASE_CREATED", actor, case_id, now, details)
            self._notification(connection, payload.owner_id, "CASE_ASSIGNED", case_id,
                               "SOC case assigned", f"{case_id}: {payload.title}", f"case-assigned:{case_id}:1", now)
            return self._detail(connection, case_id)

    def list(self, filters: CaseFilters, *, sort: str, limit: int, cursor: str | None) -> CaseListResult:
        offset = _decode_cursor(cursor) if cursor else 0
        conditions: list[str] = []
        params: list[Any] = []
        for column, values in (("c.status", filters.statuses), ("c.severity", filters.severities), ("c.priority", filters.priorities)):
            if values:
                conditions.append(f"{column} IN ({','.join('?' for _ in values)})")
                params.extend(value.value for value in values)
        if filters.owner_id:
            conditions.append("c.owner_id = ?")
            params.append(filters.owner_id)
        if filters.search:
            escaped = filters.search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("(c.case_id LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')")
            params.extend([f"%{escaped}%"] * 3)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        order = {
            "newest": "c.created_at DESC, c.case_id DESC",
            "oldest": "c.created_at, c.case_id",
            "updated": "c.updated_at DESC, c.case_id DESC",
            "priority": "CASE c.priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, c.resolution_due_at, c.case_id",
        }[sort]
        with self._connect() as connection:
            total = int(connection.execute("SELECT COUNT(*) FROM soc_cases c" + where, params).fetchone()[0])
            rows = connection.execute(
                self._summary_select() + where + f" ORDER BY {order} LIMIT ? OFFSET ?",
                (*params, limit + 1, offset),
            ).fetchall()
        return CaseListResult(
            items=[self._summary_from_row(row) for row in rows[:limit]], total=total,
            next_cursor=_encode_cursor(offset + limit) if len(rows) > limit else None,
        )

    @staticmethod
    def _optimistic_touch(connection: sqlite3.Connection, case_id: str, expected: int, now: datetime) -> None:
        if connection.execute(
            "UPDATE soc_cases SET updated_at = ?, version = version + 1 WHERE case_id = ? AND version = ?",
            (now.isoformat(), case_id, expected),
        ).rowcount != 1:
            if connection.execute("SELECT 1 FROM soc_cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                raise CaseNotFoundError(case_id)
            raise CaseConflictError("case was changed by another analyst")

    def update_metadata(self, case_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_case(connection, case_id)
            changes: dict[str, Any] = {}
            for field in ("title", "description", "severity", "priority"):
                if field in payload.model_fields_set:
                    value = getattr(payload, field)
                    value = value.value if hasattr(value, "value") else value
                    if value != row[field]:
                        changes[field] = value
            if not changes:
                raise CaseConflictError("case fields are unchanged")
            if "priority" in changes:
                response_minutes, resolution_minutes = SLA_TARGETS_MINUTES[CasePriority(changes["priority"])]
                created = datetime.fromisoformat(row["created_at"])
                changes["response_due_at"] = (created + timedelta(minutes=response_minutes)).isoformat()
                changes["resolution_due_at"] = (created + timedelta(minutes=resolution_minutes)).isoformat()
            assignments = ", ".join(f"{field} = ?" for field in changes)
            if connection.execute(
                f"UPDATE soc_cases SET {assignments}, updated_at = ?, version = version + 1 "
                "WHERE case_id = ? AND version = ?",
                (*changes.values(), now.isoformat(), case_id, payload.expected_version),
            ).rowcount != 1:
                raise CaseConflictError("case was changed by another analyst")
            self._activity(connection, case_id, "CASE_UPDATED", actor, "case", case_id, now, changes)
            self._audit(connection, "CASE_UPDATED", actor, case_id, now, changes)
            return self._detail(connection, case_id)

    def transition(self, case_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_case(connection, case_id)
            previous = CaseStatus(row["status"])
            target = payload.status
            if target not in ALLOWED_CASE_TRANSITIONS[previous]:
                raise InvalidCaseTransitionError(f"{previous.value} cannot transition to {target.value}")
            resolution = payload.resolution if payload.resolution is not None else row["resolution"]
            closure_reason = payload.closure_reason if payload.closure_reason is not None else row["closure_reason"]
            if target is CaseStatus.RESOLVED and not resolution:
                raise InvalidCaseTransitionError("resolution is required before resolving a case")
            if target is CaseStatus.CLOSED and not closure_reason:
                raise InvalidCaseTransitionError("closure_reason is required before closing a case")
            first_response = row["first_response_at"]
            if first_response is None and target in {CaseStatus.TRIAGING, CaseStatus.INVESTIGATING}:
                first_response = now.isoformat()
            resolved_at = row["resolved_at"]
            closed_at = row["closed_at"]
            if target is CaseStatus.RESOLVED:
                resolved_at = now.isoformat()
            elif previous is CaseStatus.RESOLVED and target is CaseStatus.INVESTIGATING:
                resolved_at = None
                closed_at = None
            if target is CaseStatus.CLOSED:
                closed_at = now.isoformat()
            if connection.execute(
                "UPDATE soc_cases SET status = ?, resolution = ?, closure_reason = ?, first_response_at = ?, "
                "resolved_at = ?, closed_at = ?, updated_at = ?, version = version + 1 "
                "WHERE case_id = ? AND version = ?",
                (target.value, resolution, closure_reason, first_response, resolved_at, closed_at,
                 now.isoformat(), case_id, payload.expected_version),
            ).rowcount != 1:
                raise CaseConflictError("case was changed by another analyst")
            details = {"from": previous.value, "to": target.value}
            self._activity(connection, case_id, "STATUS_CHANGED", actor, "case", case_id, now, details)
            self._audit(connection, "CASE_STATUS_CHANGED", actor, case_id, now, details)
            return self._detail(connection, case_id)

    def assign(self, case_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_case(connection, case_id)
            if payload.owner_id:
                self._require_owner(connection, payload.owner_id)
            if payload.owner_id == row["owner_id"]:
                raise CaseConflictError("case owner is unchanged")
            self._optimistic_touch(connection, case_id, payload.expected_version, now)
            connection.execute("UPDATE soc_cases SET owner_id = ? WHERE case_id = ?", (payload.owner_id, case_id))
            is_handoff = row["owner_id"] is not None and payload.owner_id is not None
            details = {"from_owner_id": row["owner_id"], "to_owner_id": payload.owner_id}
            self._activity(connection, case_id, "HANDOFF" if is_handoff else "ASSIGNMENT_CHANGED", actor, "case", case_id, now, details)
            if payload.handoff_note:
                connection.execute(
                    "INSERT INTO case_comments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (_identifier("CCM"), case_id, "HANDOFF" if is_handoff else "COMMENT", payload.handoff_note,
                     actor.analyst_id, actor.audit_display, row["owner_id"], payload.owner_id, now.isoformat()),
                )
            self._audit(connection, "CASE_HANDOFF" if is_handoff else "CASE_ASSIGNMENT_CHANGED", actor, case_id, now, details)
            self._notification(connection, payload.owner_id, "CASE_HANDOFF" if is_handoff else "CASE_ASSIGNED", case_id,
                               "SOC case handed off" if is_handoff else "SOC case assigned",
                               f"{case_id}: {row['title']}", f"case-owner:{case_id}:{payload.expected_version + 1}", now)
            return self._detail(connection, case_id)

    def add_comment(self, case_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        comment_id = _identifier("CCM")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._optimistic_touch(connection, case_id, payload.expected_version, now)
            connection.execute(
                "INSERT INTO case_comments (comment_id, case_id, comment_type, body, author_id, author_display, created_at) "
                "VALUES (?, ?, 'COMMENT', ?, ?, ?, ?)",
                (comment_id, case_id, payload.body, actor.analyst_id, actor.audit_display, now.isoformat()),
            )
            self._activity(connection, case_id, "COMMENT_ADDED", actor, "comment", comment_id, now, {"length": len(payload.body)})
            self._audit(connection, "CASE_COMMENT_ADDED", actor, case_id, now, {"comment_id": comment_id})
            return self._detail(connection, case_id)

    def link_reference(self, case_id: str, kind: Literal["alert", "incident", "event"], payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        config = {
            "alert": ("alerts", "alert_id", "case_alerts"),
            "incident": ("incidents", "incident_id", "case_incidents"),
            "event": ("security_events", "event_id", "case_events"),
        }[kind]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_case(connection, case_id)
            if connection.execute(f"SELECT 1 FROM {config[0]} WHERE {config[1]} = ?", (payload.reference_id,)).fetchone() is None:
                raise CaseReferenceNotFoundError(payload.reference_id)
            self._optimistic_touch(connection, case_id, payload.expected_version, now)
            try:
                connection.execute(
                    f"INSERT INTO {config[2]} (case_id, {config[1]}, linked_at, linked_by, linked_by_display) VALUES (?, ?, ?, ?, ?)",
                    (case_id, payload.reference_id, now.isoformat(), actor.analyst_id, actor.audit_display),
                )
            except sqlite3.IntegrityError as exc:
                raise CaseConflictError(f"{kind} is already linked to this case") from exc
            details = {"reference_type": kind.upper(), "reference_id": payload.reference_id}
            self._activity(connection, case_id, "REFERENCE_LINKED", actor, kind, payload.reference_id, now, details)
            self._audit(connection, "CASE_REFERENCE_LINKED", actor, case_id, now, details)
            return self._detail(connection, case_id)

    @staticmethod
    def _evidence_snapshot(connection: sqlite3.Connection, reference_type: EvidenceReferenceType, reference_id: str) -> tuple[str, str, bytes]:
        if reference_type is EvidenceReferenceType.ALERT:
            row = connection.execute(
                "SELECT alert_id, occurred_at, rule_id, rule_level, agent_id, agent_name, normalized_json, raw_event_json, ingested_at "
                "FROM alerts WHERE alert_id = ?", (reference_id,),
            ).fetchone()
            label = f"Alert {reference_id}" if row else ""
        elif reference_type is EvidenceReferenceType.EVENT:
            row = connection.execute(
                "SELECT event_id, occurred_at, event_code, source_type, hostname, agent_id, agent_name, rule_id, severity, "
                "structured_json, raw_event_json, ingested_at FROM security_events WHERE event_id = ?", (reference_id,),
            ).fetchone()
            label = f"Security event {reference_id}" if row else ""
        else:
            base = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (reference_id,)).fetchone()
            if base is None:
                row = None
                label = ""
            else:
                snapshot = {
                    "incident": dict(base),
                    "alert_ids": [r[0] for r in connection.execute("SELECT alert_id FROM incident_alerts WHERE incident_id = ? ORDER BY alert_id", (reference_id,))],
                    "notes": [dict(r) for r in connection.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at, note_id", (reference_id,))],
                    "history": [dict(r) for r in connection.execute("SELECT * FROM incident_history WHERE incident_id = ? ORDER BY occurred_at, history_id", (reference_id,))],
                }
                return f"Incident {reference_id}", base["created_at"], canonical_json(snapshot).encode("utf-8")
        if row is None:
            raise CaseReferenceNotFoundError(reference_id)
        return label, row["occurred_at"], canonical_json(dict(row)).encode("utf-8")

    def acquire_evidence(self, case_id: str, payload: CaseEvidenceCreate, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        evidence_id = _identifier("EVD")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_case(connection, case_id)
            label, source_timestamp, snapshot = self._evidence_snapshot(connection, payload.reference_type, payload.reference_id)
            digest = hashlib.sha256(snapshot).hexdigest()
            self._optimistic_touch(connection, case_id, payload.expected_version, now)
            try:
                connection.execute(
                    "INSERT INTO case_evidence_refs (evidence_ref_id, case_id, reference_type, reference_id, "
                    "source_label, source_timestamp, acquisition_method, digest_algorithm, digest, integrity_status, "
                    "acquired_by, acquired_by_display, acquired_at, last_verified_at, annotation) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'DATABASE_REFERENCE', 'SHA-256', ?, 'VERIFIED', ?, ?, ?, ?, ?)",
                    (evidence_id, case_id, payload.reference_type.value, payload.reference_id, label, source_timestamp,
                     digest, actor.analyst_id, actor.audit_display, now.isoformat(), now.isoformat(), payload.annotation),
                )
            except sqlite3.IntegrityError as exc:
                raise CaseConflictError("evidence reference is already attached to this case") from exc
            details = {"reference_type": payload.reference_type.value, "reference_id": payload.reference_id,
                       "digest_algorithm": "SHA-256", "digest": digest}
            connection.execute(
                "INSERT INTO evidence_custody_events VALUES (?, ?, 'ACQUIRED', ?, ?, ?, ?)",
                (_identifier("CUST"), evidence_id, actor.analyst_id, actor.audit_display, now.isoformat(), canonical_json(details)),
            )
            self._activity(connection, case_id, "EVIDENCE_ACQUIRED", actor, "evidence", evidence_id, now, details)
            self._audit(connection, "CASE_EVIDENCE_ACQUIRED", actor, case_id, now, {**details, "evidence_ref_id": evidence_id})
            return self._detail(connection, case_id)

    def verify_evidence(self, case_id: str, evidence_id: str, expected_version: int, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM case_evidence_refs WHERE case_id = ? AND evidence_ref_id = ?", (case_id, evidence_id)
            ).fetchone()
            if row is None:
                raise CaseReferenceNotFoundError(evidence_id)
            try:
                _, _, snapshot = self._evidence_snapshot(connection, EvidenceReferenceType(row["reference_type"]), row["reference_id"])
                observed = hashlib.sha256(snapshot).hexdigest()
                status = "VERIFIED" if observed == row["digest"] else "MISMATCH"
            except CaseReferenceNotFoundError:
                observed = None
                status = "UNAVAILABLE"
            if connection.execute(
                "UPDATE case_evidence_refs SET integrity_status = ?, last_verified_at = ?, version = version + 1 "
                "WHERE evidence_ref_id = ? AND version = ?",
                (status, now.isoformat(), evidence_id, expected_version),
            ).rowcount != 1:
                raise CaseConflictError("evidence reference was changed by another analyst")
            details = {"expected_digest": row["digest"], "observed_digest": observed, "status": status}
            connection.execute(
                "INSERT INTO evidence_custody_events VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_identifier("CUST"), evidence_id, status,
                 actor.analyst_id, actor.audit_display, now.isoformat(), canonical_json(details)),
            )
            self._activity(connection, case_id, "EVIDENCE_VERIFIED", actor, "evidence", evidence_id, now, details)
            self._audit(connection, "CASE_EVIDENCE_VERIFIED", actor, case_id, now, {"evidence_ref_id": evidence_id, "status": status})
            return self._detail(connection, case_id)

    def annotate_evidence(self, case_id: str, evidence_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT annotation FROM case_evidence_refs WHERE case_id = ? AND evidence_ref_id = ?", (case_id, evidence_id)
            ).fetchone()
            if row is None:
                raise CaseReferenceNotFoundError(evidence_id)
            if row["annotation"] == payload.annotation:
                raise CaseConflictError("evidence annotation is unchanged")
            if connection.execute(
                "UPDATE case_evidence_refs SET annotation = ?, version = version + 1 WHERE evidence_ref_id = ? AND version = ?",
                (payload.annotation, evidence_id, payload.expected_version),
            ).rowcount != 1:
                raise CaseConflictError("evidence reference was changed by another analyst")
            details = {"annotation_length": len(payload.annotation)}
            connection.execute(
                "INSERT INTO evidence_custody_events VALUES (?, ?, 'ANNOTATED', ?, ?, ?, ?)",
                (_identifier("CUST"), evidence_id, actor.analyst_id, actor.audit_display, now.isoformat(), canonical_json(details)),
            )
            self._activity(connection, case_id, "EVIDENCE_ANNOTATED", actor, "evidence", evidence_id, now, details)
            self._audit(connection, "CASE_EVIDENCE_ANNOTATED", actor, case_id, now, {"evidence_ref_id": evidence_id})
            return self._detail(connection, case_id)

    def _playbooks(self, connection: sqlite3.Connection, case_id: str) -> list[CasePlaybook]:
        result: list[CasePlaybook] = []
        for row in connection.execute(
            "SELECT * FROM case_playbooks WHERE case_id = ? ORDER BY created_at, playbook_id LIMIT 50", (case_id,)
        ).fetchall():
            steps: list[PlaybookStep] = []
            for step in connection.execute(
                "SELECT s.*, a.username AS assigned_username, a.display_name AS assigned_display "
                "FROM case_playbook_steps s LEFT JOIN analysts a ON a.analyst_id = s.assigned_to "
                "WHERE s.playbook_id = ? ORDER BY s.sequence", (row["playbook_id"],)
            ).fetchall():
                assigned = None
                if step["assigned_to"]:
                    assigned = CaseOwner(analyst_id=step["assigned_to"], username=step["assigned_username"] or "deleted-analyst", display_name=step["assigned_display"] or "Deleted analyst")
                steps.append(PlaybookStep(
                    step_id=step["step_id"], template_step_key=step["template_step_key"], sequence=int(step["sequence"]),
                    title=step["title"], description=step["description"], step_type=step["step_type"],
                    status=step["status"], assigned_to=assigned, evidence_ref_id=step["evidence_ref_id"],
                    completion_note=step["completion_note"], completed_by_display=step["completed_by_display"],
                    completed_at=datetime.fromisoformat(step["completed_at"]) if step["completed_at"] else None,
                    version=int(step["version"]),
                ))
            result.append(CasePlaybook(
                playbook_id=row["playbook_id"], template_key=row["template_key"], template_version=int(row["template_version"]),
                name=row["name"], status=row["status"], created_by_display=row["created_by_display"],
                created_at=datetime.fromisoformat(row["created_at"]),
                completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
                version=int(row["version"]), completed_steps=sum(s.status == "COMPLETED" for s in steps),
                total_steps=len(steps), steps=steps,
            ))
        return result

    def instantiate_playbook(self, case_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        template = PLAYBOOK_TEMPLATES.get(payload.template_key)
        if template is None:
            raise PlaybookTemplateNotFoundError(payload.template_key)
        now = _now()
        playbook_id = _identifier("PBK")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._optimistic_touch(connection, case_id, payload.expected_version, now)
            try:
                connection.execute(
                    "INSERT INTO case_playbooks (playbook_id, case_id, template_key, template_version, name, status, "
                    "created_by, created_by_display, created_at) VALUES (?, ?, ?, 1, ?, 'ACTIVE', ?, ?, ?)",
                    (playbook_id, case_id, payload.template_key, template["name"], actor.analyst_id, actor.audit_display, now.isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise CaseConflictError("this playbook template is already attached to the case") from exc
            for sequence, step in enumerate(template["steps"]):
                connection.execute(
                    "INSERT INTO case_playbook_steps (step_id, playbook_id, template_step_key, sequence, title, "
                    "description, step_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING')",
                    (_identifier("PBS"), playbook_id, step[0], sequence, step[1], step[2], step[3]),
                )
            self._activity(connection, case_id, "PLAYBOOK_STARTED", actor, "playbook", playbook_id, now, {"template_key": payload.template_key, "template_version": 1})
            self._audit(connection, "CASE_PLAYBOOK_STARTED", actor, case_id, now, {"playbook_id": playbook_id, "template_key": payload.template_key})
            return self._detail(connection, case_id)

    def update_playbook_step(self, case_id: str, playbook_id: str, step_id: str, payload: Any, actor: AnalystPrincipal) -> CaseDetail:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            step = connection.execute(
                "SELECT s.* FROM case_playbook_steps s JOIN case_playbooks p ON p.playbook_id = s.playbook_id "
                "WHERE p.case_id = ? AND p.playbook_id = ? AND s.step_id = ?", (case_id, playbook_id, step_id)
            ).fetchone()
            if step is None:
                raise CaseReferenceNotFoundError(step_id)
            if payload.assigned_to:
                self._require_owner(connection, payload.assigned_to)
            if payload.evidence_ref_id and connection.execute(
                "SELECT 1 FROM case_evidence_refs WHERE case_id = ? AND evidence_ref_id = ?",
                (case_id, payload.evidence_ref_id),
            ).fetchone() is None:
                raise CaseReferenceNotFoundError(payload.evidence_ref_id)
            if step["status"] == "COMPLETED":
                raise CaseConflictError("completed playbook steps are immutable")
            completing = payload.status == "COMPLETED"
            if completing:
                incomplete_prior = connection.execute(
                    "SELECT COUNT(*) FROM case_playbook_steps WHERE playbook_id = ? AND sequence < ? AND status != 'COMPLETED'",
                    (playbook_id, step["sequence"]),
                ).fetchone()[0]
                if incomplete_prior:
                    raise CaseConflictError("complete earlier playbook steps first")
                if step["step_type"] == "EVIDENCE" and not payload.evidence_ref_id:
                    raise CaseConflictError("an evidence reference is required for this step")
                if step["step_type"] == "APPROVAL" and actor.role is not AnalystRole.ADMIN:
                    raise CaseConflictError("administrator approval is required for this step")
                if not payload.completion_note:
                    raise CaseConflictError("completion_note is required when completing a step")
            if connection.execute(
                "UPDATE case_playbook_steps SET status = ?, assigned_to = ?, evidence_ref_id = ?, completion_note = ?, "
                "completed_by = ?, completed_by_display = ?, completed_at = ?, version = version + 1 "
                "WHERE step_id = ? AND version = ?",
                (payload.status, payload.assigned_to, payload.evidence_ref_id, payload.completion_note,
                 actor.analyst_id if completing else None, actor.audit_display if completing else None,
                 now.isoformat() if completing else None, step_id, payload.expected_version),
            ).rowcount != 1:
                raise CaseConflictError("playbook step was changed by another analyst")
            remaining = int(connection.execute(
                "SELECT COUNT(*) FROM case_playbook_steps WHERE playbook_id = ? AND status != 'COMPLETED'", (playbook_id,)
            ).fetchone()[0])
            if remaining == 0:
                connection.execute(
                    "UPDATE case_playbooks SET status = 'COMPLETED', completed_at = ?, version = version + 1 WHERE playbook_id = ?",
                    (now.isoformat(), playbook_id),
                )
            self._activity(connection, case_id, "PLAYBOOK_STEP_UPDATED", actor, "playbook_step", step_id, now,
                           {"status": payload.status, "step_type": step["step_type"], "playbook_completed": remaining == 0})
            self._audit(connection, "CASE_PLAYBOOK_STEP_UPDATED", actor, case_id, now, {"playbook_id": playbook_id, "step_id": step_id, "status": payload.status})
            return self._detail(connection, case_id)

    def analytics(self, days: int) -> CaseAnalytics:
        now = _now()
        start = now - timedelta(days=days)
        with self._connect() as connection:
            open_cases = int(connection.execute("SELECT COUNT(*) FROM soc_cases WHERE status != 'CLOSED'").fetchone()[0])
            overdue_response = int(connection.execute(
                "SELECT COUNT(*) FROM soc_cases WHERE first_response_at IS NULL AND response_due_at < ? AND status != 'CLOSED'",
                (now.isoformat(),),
            ).fetchone()[0])
            overdue_resolution = int(connection.execute(
                "SELECT COUNT(*) FROM soc_cases WHERE resolved_at IS NULL AND resolution_due_at < ? AND status != 'CLOSED'",
                (now.isoformat(),),
            ).fetchone()[0])
            response_values = [float(r[0]) for r in connection.execute(
                "SELECT (julianday(first_response_at)-julianday(created_at))*1440 FROM soc_cases "
                "WHERE first_response_at IS NOT NULL AND created_at >= ?", (start.isoformat(),)
            )]
            resolution_values = [float(r[0]) for r in connection.execute(
                "SELECT (julianday(resolved_at)-julianday(created_at))*1440 FROM soc_cases "
                "WHERE resolved_at IS NOT NULL AND created_at >= ?", (start.isoformat(),)
            )]
            def counts(query: str, params: tuple[Any, ...] = ()) -> list[CaseAnalyticsCount]:
                return [CaseAnalyticsCount(name=str(r[0]), count=int(r[1])) for r in connection.execute(query, params)]
            by_severity = counts("SELECT severity, COUNT(*) FROM soc_cases WHERE status != 'CLOSED' GROUP BY severity ORDER BY severity")
            by_owner = counts(
                "SELECT COALESCE(a.display_name, 'Unassigned'), COUNT(*) FROM soc_cases c LEFT JOIN analysts a ON a.analyst_id = c.owner_id "
                "WHERE c.status != 'CLOSED' GROUP BY COALESCE(a.display_name, 'Unassigned') ORDER BY COUNT(*) DESC"
            )
            aging = counts(
                "SELECT CASE WHEN julianday(?) - julianday(created_at) < 1 THEN '<24h' "
                "WHEN julianday(?) - julianday(created_at) < 3 THEN '1-3d' "
                "WHEN julianday(?) - julianday(created_at) < 7 THEN '3-7d' ELSE '7d+' END, COUNT(*) "
                "FROM soc_cases WHERE status != 'CLOSED' GROUP BY 1 ORDER BY 1",
                (now.isoformat(), now.isoformat(), now.isoformat()),
            )
            trend = counts(
                "SELECT substr(created_at,1,10), COUNT(*) FROM soc_cases WHERE created_at >= ? GROUP BY 1 ORDER BY 1",
                (start.isoformat(),),
            )
            closed_trend = counts(
                "SELECT substr(closed_at,1,10), COUNT(*) FROM soc_cases "
                "WHERE closed_at IS NOT NULL AND closed_at >= ? GROUP BY 1 ORDER BY 1",
                (start.isoformat(),),
            )
        return CaseAnalytics(
            generated_at=now, window_days=days, open_cases=open_cases,
            overdue_response=overdue_response, overdue_resolution=overdue_resolution,
            mtta_minutes=round(sum(response_values) / len(response_values), 2) if response_values else None,
            mttr_minutes=round(sum(resolution_values) / len(resolution_values), 2) if resolution_values else None,
            by_severity=by_severity, by_owner=by_owner, aging_buckets=aging,
            created_trend=trend, closed_trend=closed_trend,
            definitions={
                "open_cases": "Cases whose status is not CLOSED at generation time.",
                "overdue_response": "Open cases with no first TRIAGING/INVESTIGATING transition after the priority response deadline.",
                "overdue_resolution": "Open cases with no RESOLVED transition after the priority resolution deadline.",
                "mtta_minutes": "Mean minutes from case creation to the first TRIAGING or INVESTIGATING transition within the selected creation window.",
                "mttr_minutes": "Mean minutes from case creation to the latest RESOLVED transition within the selected creation window.",
            },
        )

    def evaluate_sla(self, actor: AnalystPrincipal) -> tuple[int, int, datetime]:
        """Persist deduplicated owner notices for currently overdue case deadlines."""

        now = _now()
        evaluated = 0
        created = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM soc_cases WHERE status != 'CLOSED' AND owner_id IS NOT NULL"
            ).fetchall()
            for row in rows:
                evaluated += 1
                breaches: list[tuple[str, str]] = []
                if row["first_response_at"] is None and row["response_due_at"] < now.isoformat():
                    breaches.append(("response", "The response deadline is overdue."))
                if row["resolved_at"] is None and row["resolution_due_at"] < now.isoformat():
                    breaches.append(("resolution", "The resolution deadline is overdue."))
                for breach, preview in breaches:
                    inserted = self._notification(
                        connection, row["owner_id"], "CASE_SLA", row["case_id"],
                        f"Case {breach} SLA overdue", f"{row['case_id']}: {preview}",
                        f"case-sla:{row['case_id']}:{breach}", now,
                    )
                    if not inserted:
                        continue
                    created += 1
                    details = {"breach": breach, "owner_id": row["owner_id"],
                               "response_due_at": row["response_due_at"],
                               "resolution_due_at": row["resolution_due_at"]}
                    self._activity(connection, row["case_id"], "SLA_ESCALATED", actor, "case", row["case_id"], now, details)
                    self._audit(connection, "CASE_SLA_ESCALATED", actor, row["case_id"], now, details)
        return evaluated, created, now

    def report_payload(self, case_id: str) -> dict[str, Any]:
        detail = self.get(case_id)
        return {
            "report_schema": "cyberqalqon.case-report.v1",
            "generated_at": _now().isoformat(),
            "redaction_profile": "CASE_REPORT_V1",
            "case": detail.model_dump(mode="json", exclude={"report_history"}),
            "integrity_statement": (
                "Evidence entries are application-level references with SHA-256 change-detection digests. "
                "They are not represented as legal-grade forensic acquisition."
            ),
            "limits": {"raw_evidence_embedded": False, "activity_max": 1000, "comments_max": 500, "evidence_max": 200},
        }

    def record_report(self, case_id: str, format_name: str, content: bytes, actor: AnalystPrincipal) -> None:
        now = _now()
        report_id = _identifier("RPT")
        digest = hashlib.sha256(content).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_case(connection, case_id)
            connection.execute(
                "INSERT INTO case_report_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'CASE_REPORT_V1')",
                (report_id, case_id, format_name, actor.analyst_id, actor.audit_display, now.isoformat(), digest, len(content)),
            )
            self._activity(connection, case_id, "REPORT_GENERATED", actor, "report", report_id, now,
                           {"format": format_name, "sha256": digest, "size_bytes": len(content)})
            self._audit(connection, "CASE_REPORT_GENERATED", actor, case_id, now,
                        {"report_id": report_id, "format": format_name, "sha256": digest, "size_bytes": len(content)})
