"""Durable, bounded detection-engineering and threat-hunting operations."""

from __future__ import annotations

import base64
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from app.schemas.auth import AnalystPrincipal
from app.schemas.detection_engineering import (
    AnalyticsPoint,
    AnalystDispositionMetric,
    DeploymentConfirmationResult,
    DetectionAnalytics,
    DetectionCoverage,
    FalsePositiveRuleMetric,
    HuntEvent,
    IndicatorType,
    IOCDefinition,
    IOCImportResult,
    IOCIndicator,
    IOCMatch,
    IOCMatchSummary,
    NamedMetric,
    RuleCondition,
    RuleConditionOperator,
    RuleDraft,
    RuleDraftCreate,
    RuleDraftStatus,
    RuleDraftUpdate,
    RuleDraftVersion,
    RuleDryRunRequest,
    RuleDryRunResult,
    RuleRollbackRequest,
    RuleValidationResult,
    SavedHunt,
    SavedHuntCreate,
    ThreatHuntPage,
    ThreatHuntQuery,
    TechniqueCoverage,
    normalize_indicator,
)
from app.schemas.siem import DetectionRuleSummary
from app.services.wazuh_normalizer import canonical_json


class DetectionEngineeringNotFoundError(LookupError):
    pass


class DetectionEngineeringConflictError(RuntimeError):
    pass


class DetectionEngineeringLimitError(RuntimeError):
    pass


class DetectionEngineeringLifecycleError(RuntimeError):
    pass


class InvalidHuntCursorError(ValueError):
    pass


_EVENT_COLUMNS = {
    "source_type": "source_type",
    "hostname": "hostname",
    "agent_id": "agent_id",
    "agent_name": "agent_name",
    "source_ip": "source_ip",
    "destination_ip": "destination_ip",
    "username": "username",
    "event_category": "event_category",
    "event_action": "event_action",
    "outcome": "outcome",
    "rule_id": "rule_id",
    "event_code": "event_code",
    "message": "message",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"hunt:{offset}".encode()).decode().rstrip("=")


def _offset(cursor: str | None) -> int:
    if cursor is None:
        return 0
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        prefix, value = decoded.split(":", 1)
        result = int(value)
        if prefix != "hunt" or result < 0 or result > 1_000_000:
            raise ValueError
        return result
    except (ValueError, UnicodeDecodeError) as exc:
        raise InvalidHuntCursorError("Invalid threat-hunt cursor") from exc


def _like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class DetectionEngineeringRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        action: str,
        actor: AnalystPrincipal,
        target_type: str,
        target_id: str,
        details: dict[str, object] | None = None,
        occurred_at: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', ?, ?)
            """,
            (
                f"AUD-{uuid4().hex.upper()}", action, actor.analyst_id,
                actor.audit_display, target_type, target_id, occurred_at or _now(),
                canonical_json(details or {}),
            ),
        )
        connection.execute(
            "DELETE FROM security_audit_events WHERE audit_id IN ("
            "SELECT audit_id FROM security_audit_events "
            "ORDER BY occurred_at DESC, audit_id DESC LIMIT -1 OFFSET 10000)"
        )

    @staticmethod
    def _draft(row: sqlite3.Row) -> RuleDraft:
        return RuleDraft(
            draft_id=row["draft_id"],
            name=row["name"],
            description=row["description"],
            severity=int(row["severity"]),
            source_type=row["source_type"],
            mitre_ids=json.loads(row["mitre_ids_json"]),
            conditions=json.loads(row["conditions_json"]),
            documentation=row["documentation"],
            status=row["status"],
            version=int(row["version"]),
            owner_analyst_id=row["owner_analyst_id"],
            owner_display=row["owner_display"],
            last_tested_at=(datetime.fromisoformat(row["last_tested_at"]) if row["last_tested_at"] else None),
            last_test_match_count=row["last_test_match_count"],
            last_test_execution_ms=row["last_test_execution_ms"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _snapshot(draft: RuleDraft) -> str:
        return canonical_json(draft.model_dump(mode="json"))

    def _version(
        self,
        connection: sqlite3.Connection,
        draft: RuleDraft,
        change_summary: str,
        actor: AnalystPrincipal,
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO detection_rule_versions (
                version_id, draft_id, version_number, snapshot_json,
                change_summary, actor_id, actor_display, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"DRV-{uuid4().hex.upper()}", draft.draft_id, draft.version,
                self._snapshot(draft), change_summary.strip(), actor.analyst_id,
                actor.audit_display, created_at,
            ),
        )

    def list_drafts(self, *, limit: int = 100) -> list[RuleDraft]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM detection_rule_drafts "
                "ORDER BY updated_at DESC, draft_id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._draft(row) for row in rows]

    def get_draft(self, draft_id: str) -> RuleDraft:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
        if row is None:
            raise DetectionEngineeringNotFoundError(draft_id)
        return self._draft(row)

    def create_draft(self, payload: RuleDraftCreate, actor: AnalystPrincipal) -> RuleDraft:
        draft_id = f"DRF-{uuid4().hex.upper()}"
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute("SELECT COUNT(*) FROM detection_rule_drafts").fetchone()[0])
            if count >= 200:
                raise DetectionEngineeringLimitError("At most 200 local rule drafts are allowed")
            connection.execute(
                """
                INSERT INTO detection_rule_drafts (
                    draft_id, name, description, severity, source_type,
                    mitre_ids_json, conditions_json, documentation, status,
                    version, owner_analyst_id, owner_display, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'DRAFT', 1, ?, ?, ?, ?)
                """,
                (
                    draft_id, payload.name, payload.description, payload.severity,
                    payload.source_type, canonical_json(payload.mitre_ids),
                    canonical_json([item.model_dump(mode="json") for item in payload.conditions]),
                    payload.documentation, actor.analyst_id, actor.audit_display, now, now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert row is not None
            draft = self._draft(row)
            self._version(connection, draft, payload.change_summary, actor, now)
            self._audit(
                connection, action="DETECTION_DRAFT_CREATED", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={"version": 1, "name": draft.name}, occurred_at=now,
            )
        return draft

    def update_draft(
        self, draft_id: str, payload: RuleDraftUpdate, actor: AnalystPrincipal
    ) -> RuleDraft:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if row is None:
                raise DetectionEngineeringNotFoundError(draft_id)
            if int(row["version"]) != payload.expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {payload.expected_version}; current version is {row['version']}"
                )
            connection.execute(
                """
                UPDATE detection_rule_drafts SET
                    name = ?, description = ?, severity = ?, source_type = ?,
                    mitre_ids_json = ?, conditions_json = ?, documentation = ?,
                    status = 'DRAFT', version = version + 1,
                    last_tested_at = NULL, last_test_match_count = NULL,
                    last_test_execution_ms = NULL, updated_at = ?
                WHERE draft_id = ? AND version = ?
                """,
                (
                    payload.name, payload.description, payload.severity,
                    payload.source_type, canonical_json(payload.mitre_ids),
                    canonical_json([item.model_dump(mode="json") for item in payload.conditions]),
                    payload.documentation, now, draft_id, payload.expected_version,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert updated is not None
            draft = self._draft(updated)
            self._version(connection, draft, payload.change_summary, actor, now)
            self._audit(
                connection, action="DETECTION_DRAFT_UPDATED", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={"version": draft.version}, occurred_at=now,
            )
        return draft

    @staticmethod
    def _warnings(draft: RuleDraft) -> list[str]:
        warnings: list[str] = []
        if not draft.mitre_ids:
            warnings.append("No MITRE ATT&CK technique is mapped; this does not invalidate the rule.")
        if not draft.documentation:
            warnings.append("Rule documentation is empty.")
        if any(item.field.value == "message" for item in draft.conditions):
            warnings.append("Message matching may be noisy; confirm against representative history.")
        return warnings

    def validate_draft(
        self, draft_id: str, expected_version: int, actor: AnalystPrincipal
    ) -> RuleValidationResult:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if row is None:
                raise DetectionEngineeringNotFoundError(draft_id)
            current = self._draft(row)
            if current.version != expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {expected_version}; current version is {current.version}"
                )
            connection.execute(
                "UPDATE detection_rule_drafts SET status = 'VALIDATED', "
                "version = version + 1, updated_at = ? WHERE draft_id = ? AND version = ?",
                (now, draft_id, expected_version),
            )
            updated = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert updated is not None
            draft = self._draft(updated)
            self._version(connection, draft, "Validated declarative rule schema", actor, now)
            self._audit(
                connection, action="DETECTION_DRAFT_VALIDATED", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={"version": draft.version, "warnings": self._warnings(draft)}, occurred_at=now,
            )
        return RuleValidationResult(draft=draft, valid=True, errors=[], warnings=self._warnings(draft))

    @staticmethod
    def _condition_sql(conditions: Iterable[RuleCondition], *, prefix: str = "") -> tuple[str, list[object]]:
        fragments: list[str] = []
        parameters: list[object] = []
        for condition in conditions:
            column = prefix + _EVENT_COLUMNS[condition.field.value]
            if condition.operator is RuleConditionOperator.EQUALS:
                fragments.append(f"{column} = ? COLLATE NOCASE")
                parameters.append(condition.value)
            elif condition.operator is RuleConditionOperator.CONTAINS:
                fragments.append(f"{column} LIKE ? ESCAPE '\\' COLLATE NOCASE")
                parameters.append(f"%{_like(condition.value)}%")
            else:
                fragments.append(f"{column} LIKE ? ESCAPE '\\' COLLATE NOCASE")
                parameters.append(f"{_like(condition.value)}%")
        return " AND ".join(fragments) if fragments else "1 = 1", parameters

    def dry_run(
        self, draft_id: str, payload: RuleDryRunRequest, actor: AnalystPrincipal
    ) -> RuleDryRunResult:
        draft = self.get_draft(draft_id)
        if draft.version != payload.expected_version:
            raise DetectionEngineeringConflictError(
                f"Expected version {payload.expected_version}; current version is {draft.version}"
            )
        if draft.status not in {RuleDraftStatus.VALIDATED, RuleDraftStatus.TESTED}:
            raise DetectionEngineeringLifecycleError(
                "Validate the current draft version before running historical evaluation"
            )
        start, end = payload.resolved()
        where, parameters = self._condition_sql(draft.conditions, prefix="c.")
        start_clock = time.perf_counter()
        with self._connect() as connection:
            evaluated = int(connection.execute(
                "SELECT COUNT(*) FROM (SELECT 1 FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC, event_id DESC LIMIT ?)",
                (start.isoformat(), end.isoformat(), payload.max_events),
            ).fetchone()[0])
            matched_rows = connection.execute(
                f"""
                WITH candidates AS (
                    SELECT * FROM security_events
                    WHERE occurred_at BETWEEN ? AND ?
                    ORDER BY occurred_at DESC, event_id DESC LIMIT ?
                )
                SELECT c.event_id FROM candidates c WHERE {where}
                ORDER BY c.occurred_at DESC, c.event_id DESC
                """,
                [start.isoformat(), end.isoformat(), payload.max_events, *parameters],
            ).fetchall()
        execution_ms = max(0.0, (time.perf_counter() - start_clock) * 1000)
        matched_ids = [str(row["event_id"]) for row in matched_rows]
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT version FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if current is None:
                raise DetectionEngineeringNotFoundError(draft_id)
            if int(current["version"]) != payload.expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {payload.expected_version}; current version is {current['version']}"
                )
            connection.execute(
                """
                UPDATE detection_rule_drafts SET status = 'TESTED', version = version + 1,
                    last_tested_at = ?, last_test_match_count = ?,
                    last_test_execution_ms = ?, updated_at = ?
                WHERE draft_id = ? AND version = ?
                """,
                (now, len(matched_ids), execution_ms, now, draft_id, payload.expected_version),
            )
            row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert row is not None
            updated = self._draft(row)
            self._version(connection, updated, "Bounded historical dry-run", actor, now)
            self._audit(
                connection, action="DETECTION_DRAFT_DRY_RUN", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={
                    "version": updated.version, "evaluated_events": evaluated,
                    "matches": len(matched_ids), "execution_ms": round(execution_ms, 3),
                    "start_time": start.isoformat(), "end_time": end.isoformat(),
                }, occurred_at=now,
            )
        return RuleDryRunResult(
            draft=updated, start_time=start, end_time=end,
            evaluated_event_count=evaluated, match_count=len(matched_ids),
            matched_event_ids=matched_ids[:100], execution_ms=execution_ms,
            result_ids_truncated=len(matched_ids) > 100,
        )

    def confirm_manual_deployment(
        self, draft_id: str, expected_version: int, reason: str, actor: AnalystPrincipal
    ) -> DeploymentConfirmationResult:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if row is None:
                raise DetectionEngineeringNotFoundError(draft_id)
            current = self._draft(row)
            if current.version != expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {expected_version}; current version is {current.version}"
                )
            if current.status is not RuleDraftStatus.TESTED:
                raise DetectionEngineeringLifecycleError(
                    "A draft must have a current successful dry-run before deployment review"
                )
            connection.execute(
                "UPDATE detection_rule_drafts SET status = 'READY_FOR_MANUAL_DEPLOYMENT', "
                "version = version + 1, updated_at = ? WHERE draft_id = ? AND version = ?",
                (now, draft_id, expected_version),
            )
            updated_row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert updated_row is not None
            updated = self._draft(updated_row)
            self._version(connection, updated, "Manual deployment review confirmed", actor, now)
            self._audit(
                connection, action="DETECTION_MANUAL_DEPLOYMENT_CONFIRMED", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={"version": updated.version, "reason": reason, "live_wazuh_modified": False},
                occurred_at=now,
            )
        return DeploymentConfirmationResult(
            draft=updated,
            message="Review recorded. Export and deploy through the documented manual Wazuh change process; no live rule was modified.",
        )

    def versions(self, draft_id: str) -> list[RuleDraftVersion]:
        self.get_draft(draft_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM detection_rule_versions WHERE draft_id = ? "
                "ORDER BY version_number DESC LIMIT 100", (draft_id,)
            ).fetchall()
        return [
            RuleDraftVersion(
                version_id=row["version_id"], draft_id=row["draft_id"],
                version_number=int(row["version_number"]), snapshot=json.loads(row["snapshot_json"]),
                change_summary=row["change_summary"], actor_display=row["actor_display"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def rollback(
        self, draft_id: str, payload: RuleRollbackRequest, actor: AnalystPrincipal
    ) -> RuleDraft:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current_row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if current_row is None:
                raise DetectionEngineeringNotFoundError(draft_id)
            current = self._draft(current_row)
            if current.version != payload.expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {payload.expected_version}; current version is {current.version}"
                )
            version_row = connection.execute(
                "SELECT snapshot_json FROM detection_rule_versions "
                "WHERE draft_id = ? AND version_number = ?",
                (draft_id, payload.source_version),
            ).fetchone()
            if version_row is None:
                raise DetectionEngineeringNotFoundError(
                    f"{draft_id} version {payload.source_version}"
                )
            snapshot = RuleDraft.model_validate(json.loads(version_row["snapshot_json"]))
            connection.execute(
                """
                UPDATE detection_rule_drafts SET name = ?, description = ?, severity = ?,
                    source_type = ?, mitre_ids_json = ?, conditions_json = ?, documentation = ?,
                    status = 'DRAFT', version = version + 1, last_tested_at = NULL,
                    last_test_match_count = NULL, last_test_execution_ms = NULL, updated_at = ?
                WHERE draft_id = ? AND version = ?
                """,
                (
                    snapshot.name, snapshot.description, snapshot.severity, snapshot.source_type,
                    canonical_json(snapshot.mitre_ids),
                    canonical_json([item.model_dump(mode="json") for item in snapshot.conditions]),
                    snapshot.documentation, now, draft_id, payload.expected_version,
                ),
            )
            updated_row = connection.execute(
                "SELECT * FROM detection_rule_drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            assert updated_row is not None
            updated = self._draft(updated_row)
            self._version(connection, updated, payload.change_summary, actor, now)
            self._audit(
                connection, action="DETECTION_DRAFT_ROLLED_BACK", actor=actor,
                target_type="detection_rule_draft", target_id=draft_id,
                details={"source_version": payload.source_version, "new_version": updated.version},
                occurred_at=now,
            )
        return updated

    @staticmethod
    def _hunt_where(query: ThreatHuntQuery, start: datetime, end: datetime) -> tuple[str, list[object]]:
        conditions = ["e.occurred_at BETWEEN ? AND ?"]
        parameters: list[object] = [start.isoformat(), end.isoformat()]
        if query.ip:
            conditions.append("(e.source_ip = ? OR e.destination_ip = ?)")
            parameters.extend((query.ip, query.ip))
        if query.hostname:
            conditions.append("(e.hostname = ? COLLATE NOCASE OR e.agent_name = ? COLLATE NOCASE)")
            parameters.extend((query.hostname, query.hostname))
        if query.username:
            conditions.append("e.username = ? COLLATE NOCASE")
            parameters.append(query.username)
        if query.event_category:
            conditions.append("e.event_category = ? COLLATE NOCASE")
            parameters.append(query.event_category)
        if query.rule_id:
            conditions.append("e.rule_id = ?")
            parameters.append(query.rule_id)
        if query.mitre_id:
            conditions.append(
                "EXISTS (SELECT 1 FROM alerts a, json_each(a.normalized_json, '$.mitre.ids') m "
                "WHERE a.alert_id = e.related_alert_id AND m.value = ?)"
            )
            parameters.append(query.mitre_id)
        if query.search:
            conditions.append("e.search_text LIKE ? ESCAPE '\\' COLLATE NOCASE")
            parameters.append(f"%{_like(query.search)}%")
        return " AND ".join(conditions), parameters

    def hunt(
        self, query: ThreatHuntQuery, *, limit: int = 50, cursor: str | None = None
    ) -> ThreatHuntPage:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        start, end = query.resolved()
        where, parameters = self._hunt_where(query, start, end)
        offset = _offset(cursor)
        direction = "DESC" if query.sort == "newest" else "ASC"
        with self._connect() as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) FROM security_events e WHERE {where}", parameters
            ).fetchone()[0])
            rows = connection.execute(
                f"""
                SELECT e.event_id, e.occurred_at, e.source_type, e.hostname,
                       e.source_ip, e.destination_ip, e.username, e.event_category,
                       e.rule_id, e.severity, e.message, e.related_alert_id,
                       (SELECT GROUP_CONCAT(ia.incident_id)
                        FROM incident_alerts ia
                        WHERE ia.alert_id = e.related_alert_id) AS incident_ids
                FROM security_events e WHERE {where}
                ORDER BY e.occurred_at {direction}, e.event_id {direction}
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit + 1, offset],
            ).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return ThreatHuntPage(
            items=[
                HuntEvent(
                    event_id=row["event_id"], timestamp=datetime.fromisoformat(row["occurred_at"]),
                    source_type=row["source_type"], hostname=row["hostname"],
                    source_ip=row["source_ip"], destination_ip=row["destination_ip"],
                    username=row["username"], event_category=row["event_category"],
                    rule_id=row["rule_id"], severity=row["severity"], message=row["message"],
                    related_alert_id=row["related_alert_id"],
                    related_incident_ids=(row["incident_ids"].split(",") if row["incident_ids"] else []),
                )
                for row in rows
            ],
            total=total, limit=limit,
            next_cursor=_cursor(offset + limit) if has_more else None,
            start_time=start, end_time=end,
        )

    @staticmethod
    def _saved_hunt(row: sqlite3.Row) -> SavedHunt:
        return SavedHunt(
            saved_hunt_id=row["saved_hunt_id"], name=row["name"],
            query=ThreatHuntQuery.model_validate(json.loads(row["query_json"])),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_saved_hunts(self, analyst_id: str) -> list[SavedHunt]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM saved_hunts WHERE analyst_id = ? "
                "ORDER BY updated_at DESC, saved_hunt_id DESC LIMIT 50", (analyst_id,)
            ).fetchall()
        return [self._saved_hunt(row) for row in rows]

    def create_saved_hunt(
        self, payload: SavedHuntCreate, actor: AnalystPrincipal
    ) -> SavedHunt:
        saved_id = f"HNT-{uuid4().hex.upper()}"
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute(
                "SELECT COUNT(*) FROM saved_hunts WHERE analyst_id = ?", (actor.analyst_id,)
            ).fetchone()[0])
            if count >= 50:
                raise DetectionEngineeringLimitError("An analyst may save at most 50 hunts")
            try:
                connection.execute(
                    "INSERT INTO saved_hunts "
                    "(saved_hunt_id, analyst_id, name, query_json, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        saved_id, actor.analyst_id, payload.name,
                        canonical_json(payload.query.model_dump(mode="json", exclude_none=True)),
                        now, now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DetectionEngineeringConflictError(
                    "A saved hunt with this name already exists"
                ) from exc
            row = connection.execute(
                "SELECT * FROM saved_hunts WHERE saved_hunt_id = ?", (saved_id,)
            ).fetchone()
            assert row is not None
            saved = self._saved_hunt(row)
            self._audit(
                connection, action="THREAT_HUNT_SAVED", actor=actor,
                target_type="saved_hunt", target_id=saved_id,
                details={"name": saved.name}, occurred_at=now,
            )
        return saved

    def delete_saved_hunt(self, saved_id: str, actor: AnalystPrincipal) -> None:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT name FROM saved_hunts WHERE saved_hunt_id = ? AND analyst_id = ?",
                (saved_id, actor.analyst_id),
            ).fetchone()
            if row is None:
                raise DetectionEngineeringNotFoundError(saved_id)
            connection.execute(
                "DELETE FROM saved_hunts WHERE saved_hunt_id = ? AND analyst_id = ?",
                (saved_id, actor.analyst_id),
            )
            self._audit(
                connection, action="THREAT_HUNT_DELETED", actor=actor,
                target_type="saved_hunt", target_id=saved_id,
                details={"name": row["name"]}, occurred_at=now,
            )

    @staticmethod
    def _indicator(row: sqlite3.Row, now: datetime | None = None) -> IOCIndicator:
        expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        reference = now or datetime.now(timezone.utc)
        return IOCIndicator(
            indicator_id=row["indicator_id"], indicator_type=row["indicator_type"],
            value=row["normalized_value"], hash_algorithm=row["hash_algorithm"],
            source=row["source"], confidence=int(row["confidence"]),
            description=row["description"], expires_at=expires,
            is_active=bool(row["is_active"]), expired=bool(expires and expires <= reference),
            version=int(row["version"]), created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def list_iocs(
        self, *, indicator_type: IndicatorType | None = None,
        active_only: bool = False, search: str | None = None, limit: int = 200,
    ) -> list[IOCIndicator]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        conditions = ["1 = 1"]
        parameters: list[object] = []
        if indicator_type:
            conditions.append("indicator_type = ?")
            parameters.append(indicator_type.value)
        if active_only:
            conditions.append("is_active = 1 AND (expires_at IS NULL OR expires_at > ?)")
            parameters.append(_now())
        if search:
            conditions.append(
                "(normalized_value LIKE ? ESCAPE '\\' COLLATE NOCASE "
                "OR source LIKE ? ESCAPE '\\' COLLATE NOCASE)"
            )
            pattern = f"%{_like(search)}%"
            parameters.extend((pattern, pattern))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ioc_indicators WHERE " + " AND ".join(conditions)
                + " ORDER BY updated_at DESC, indicator_id DESC LIMIT ?",
                [*parameters, limit],
            ).fetchall()
        return [self._indicator(row) for row in rows]

    def export_iocs(self) -> list[IOCIndicator]:
        """Return the complete bounded local IOC repository for an authorized export."""

        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ioc_indicators "
                "ORDER BY updated_at DESC, indicator_id DESC LIMIT 5000"
            ).fetchall()
        return [self._indicator(row) for row in rows]

    def _insert_indicator(
        self,
        connection: sqlite3.Connection,
        definition: IOCDefinition,
        actor: AnalystPrincipal,
        now: str,
    ) -> IOCIndicator:
        normalized, algorithm = normalize_indicator(definition.indicator_type, definition.value)
        indicator_id = f"IOC-{uuid4().hex.upper()}"
        connection.execute(
            """
            INSERT INTO ioc_indicators (
                indicator_id, indicator_type, normalized_value, hash_algorithm,
                source, confidence, description, expires_at, is_active, version,
                created_by, updated_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?)
            """,
            (
                indicator_id, definition.indicator_type.value, normalized, algorithm,
                definition.source, definition.confidence, definition.description,
                definition.expires_at.astimezone(timezone.utc).isoformat()
                if definition.expires_at else None,
                actor.analyst_id, actor.analyst_id, now, now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM ioc_indicators WHERE indicator_id = ?", (indicator_id,)
        ).fetchone()
        assert row is not None
        return self._indicator(row)

    def create_ioc(self, definition: IOCDefinition, actor: AnalystPrincipal) -> IOCIndicator:
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = int(connection.execute("SELECT COUNT(*) FROM ioc_indicators").fetchone()[0])
            if count >= 5000:
                raise DetectionEngineeringLimitError("At most 5000 local indicators are allowed")
            try:
                indicator = self._insert_indicator(connection, definition, actor, now)
            except sqlite3.IntegrityError as exc:
                raise DetectionEngineeringConflictError("The normalized indicator already exists") from exc
            self._audit(
                connection, action="IOC_CREATED", actor=actor,
                target_type="ioc", target_id=indicator.indicator_id,
                details={"type": indicator.indicator_type.value, "source": indicator.source},
                occurred_at=now,
            )
        return indicator

    def import_iocs(
        self, definitions: list[IOCDefinition], actor: AnalystPrincipal
    ) -> IOCImportResult:
        now = _now()
        created: list[IOCIndicator] = []
        duplicates = 0
        seen: set[tuple[str, str]] = set()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = int(connection.execute("SELECT COUNT(*) FROM ioc_indicators").fetchone()[0])
            if current + len(definitions) > 5000:
                raise DetectionEngineeringLimitError("Import would exceed the 5000-indicator bound")
            for definition in definitions:
                normalized, _ = normalize_indicator(definition.indicator_type, definition.value)
                key = (definition.indicator_type.value, normalized)
                exists = key in seen or connection.execute(
                    "SELECT 1 FROM ioc_indicators WHERE indicator_type = ? AND normalized_value = ?",
                    key,
                ).fetchone() is not None
                if exists:
                    duplicates += 1
                    continue
                seen.add(key)
                created.append(self._insert_indicator(connection, definition, actor, now))
            self._audit(
                connection, action="IOC_BULK_IMPORTED", actor=actor,
                target_type="ioc_import", target_id=f"IMP-{uuid4().hex.upper()}",
                details={"created": len(created), "duplicates": duplicates}, occurred_at=now,
            )
        return IOCImportResult(created=len(created), duplicates=duplicates, indicators=created)

    def update_ioc(
        self, indicator_id: str, definition: IOCDefinition, expected_version: int,
        is_active: bool, actor: AnalystPrincipal,
    ) -> IOCIndicator:
        normalized, algorithm = normalize_indicator(definition.indicator_type, definition.value)
        now = _now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM ioc_indicators WHERE indicator_id = ?", (indicator_id,)
            ).fetchone()
            if row is None:
                raise DetectionEngineeringNotFoundError(indicator_id)
            if int(row["version"]) != expected_version:
                raise DetectionEngineeringConflictError(
                    f"Expected version {expected_version}; current version is {row['version']}"
                )
            try:
                connection.execute(
                    """
                    UPDATE ioc_indicators SET indicator_type = ?, normalized_value = ?,
                        hash_algorithm = ?, source = ?, confidence = ?, description = ?,
                        expires_at = ?, is_active = ?, version = version + 1,
                        updated_by = ?, updated_at = ?
                    WHERE indicator_id = ? AND version = ?
                    """,
                    (
                        definition.indicator_type.value, normalized, algorithm,
                        definition.source, definition.confidence, definition.description,
                        definition.expires_at.astimezone(timezone.utc).isoformat()
                        if definition.expires_at else None,
                        int(is_active), actor.analyst_id, now, indicator_id, expected_version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DetectionEngineeringConflictError("The normalized indicator already exists") from exc
            updated_row = connection.execute(
                "SELECT * FROM ioc_indicators WHERE indicator_id = ?", (indicator_id,)
            ).fetchone()
            assert updated_row is not None
            updated = self._indicator(updated_row)
            self._audit(
                connection, action="IOC_UPDATED", actor=actor,
                target_type="ioc", target_id=indicator_id,
                details={"version": updated.version, "active": updated.is_active}, occurred_at=now,
            )
        return updated

    @staticmethod
    def _structured_values(
        value: object, *, path: str = "$", depth: int = 0
    ) -> Iterable[tuple[str, str, str]]:
        if depth >= 12:
            return
        if isinstance(value, dict):
            for index, (key, child) in enumerate(value.items()):
                if index >= 200:
                    break
                next_path = f"{path}.{key}"
                if isinstance(child, str):
                    yield next_path, key.lower(), child
                else:
                    yield from DetectionEngineeringRepository._structured_values(
                        child, path=next_path, depth=depth + 1
                    )
        elif isinstance(value, list):
            for index, child in enumerate(value[:100]):
                yield from DetectionEngineeringRepository._structured_values(
                    child, path=f"{path}[{index}]", depth=depth + 1
                )

    def ioc_matches(self, *, days: int = 7, limit: int = 500) -> IOCMatchSummary:
        if not 1 <= days <= 31:
            raise ValueError("days must be between 1 and 31")
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        with self._connect() as connection:
            indicator_rows = connection.execute(
                "SELECT * FROM ioc_indicators WHERE is_active = 1 "
                "AND (expires_at IS NULL OR expires_at > ?) "
                "ORDER BY updated_at DESC LIMIT 200", (end.isoformat(),)
            ).fetchall()
            if not indicator_rows:
                return IOCMatchSummary(
                    start_time=start, end_time=end, total_matches=0,
                    matches=[], truncated=False,
                )
            event_rows = connection.execute(
                """
                SELECT event_id, occurred_at, source_ip, destination_ip, hostname, structured_json
                FROM security_events WHERE occurred_at BETWEEN ? AND ?
                ORDER BY occurred_at DESC, event_id DESC LIMIT 5000
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
        indicators = [self._indicator(row, end) for row in indicator_rows]
        ip_indicators = {
            item.value: item.indicator_id for item in indicators
            if item.indicator_type in {IndicatorType.IPV4, IndicatorType.IPV6}
        }
        domain_indicators = {
            item.value: item.indicator_id for item in indicators
            if item.indicator_type is IndicatorType.DOMAIN
        }
        hash_indicators = {
            item.value: item.indicator_id for item in indicators
            if item.indicator_type is IndicatorType.FILE_HASH
        }
        matches: list[IOCMatch] = []
        total = 0
        for event in event_rows:
            structured_values: list[tuple[str, str, str]] = []
            if domain_indicators or hash_indicators:
                structured = json.loads(event["structured_json"])
                structured_values = list(self._structured_values(structured))
            matched_fields: dict[str, str] = {}
            for field in ("source_ip", "destination_ip"):
                indicator_id = ip_indicators.get(str(event[field] or ""))
                if indicator_id:
                    matched_fields.setdefault(indicator_id, field)
            hostname = str(event["hostname"] or "").rstrip(".").lower()
            indicator_id = domain_indicators.get(hostname)
            if indicator_id:
                matched_fields.setdefault(indicator_id, "hostname")
            for path, key, value in structured_values:
                if any(token in key for token in ("domain", "hostname", "query_name")):
                    indicator_id = domain_indicators.get(value.rstrip(".").lower())
                    if indicator_id:
                        matched_fields.setdefault(indicator_id, f"structured_json:{path}")
                if any(token in key for token in ("hash", "md5", "sha1", "sha256")):
                    indicator_id = hash_indicators.get(value.lower())
                    if indicator_id:
                        matched_fields.setdefault(indicator_id, f"structured_json:{path}")
            for indicator in indicators:
                matched_field = matched_fields.get(indicator.indicator_id)
                if matched_field:
                    total += 1
                    if len(matches) < limit:
                        matches.append(IOCMatch(
                            indicator_id=indicator.indicator_id,
                            indicator_type=indicator.indicator_type,
                            value=indicator.value, event_id=event["event_id"],
                            event_timestamp=datetime.fromisoformat(event["occurred_at"]),
                            matched_field=matched_field,
                        ))
        return IOCMatchSummary(
            start_time=start, end_time=end, total_matches=total,
            matches=matches, truncated=total > len(matches),
        )

    def coverage(self, rules: list[DetectionRuleSummary]) -> DetectionCoverage:
        mapped: dict[str, list[DetectionRuleSummary]] = {}
        for rule in rules:
            for technique in rule.mitre_ids:
                mapped.setdefault(technique, []).append(rule)
        techniques: list[TechniqueCoverage] = []
        validation_gaps = 0
        for technique, entries in sorted(mapped.items()):
            enabled = sum(rule.enabled_state == "ENABLED" for rule in entries)
            triggered = sum(rule.alert_count > 0 for rule in entries)
            tested = sum(rule.tested_state == "TESTED" for rule in entries)
            if tested == 0:
                validation_gaps += 1
            state = "TRIGGERED" if triggered else ("ENABLED_NOT_TRIGGERED" if enabled else "MAPPED_ONLY")
            techniques.append(TechniqueCoverage(
                technique_id=technique,
                rule_ids=sorted(rule.rule_id for rule in entries),
                mapped_detection_count=len(entries), enabled_detection_count=enabled,
                triggered_detection_count=triggered, tested_detection_count=tested,
                alert_count=sum(rule.alert_count for rule in entries),
                sources=sorted({rule.source_type for rule in entries}), coverage_state=state,
            ))
        return DetectionCoverage(
            techniques=techniques,
            mapped_rule_count=sum(bool(rule.mitre_ids) for rule in rules),
            unmapped_rule_count=sum(not rule.mitre_ids for rule in rules),
            validation_gap_count=validation_gaps,
        )

    def analytics(self, *, days: int = 30) -> DetectionAnalytics:
        if not 1 <= days <= 31:
            raise ValueError("days must be between 1 and 31")
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        start_iso, end_iso = start.isoformat(), end.isoformat()
        with self._connect() as connection:
            def metrics(sql: str, params: tuple[object, ...]) -> list[NamedMetric]:
                return [NamedMetric(name=str(row[0]), count=int(row[1])) for row in connection.execute(sql, params)]

            alert_trend = [AnalyticsPoint(bucket=row[0], count=int(row[1])) for row in connection.execute(
                "SELECT substr(a.occurred_at,1,10), COUNT(*) FROM alerts a "
                "WHERE a.occurred_at BETWEEN ? AND ? GROUP BY 1 ORDER BY 1", (start_iso, end_iso)
            )]
            fp_trend = [AnalyticsPoint(bucket=row[0], count=int(row[1])) for row in connection.execute(
                "SELECT substr(a.occurred_at,1,10), COUNT(*) FROM alerts a "
                "JOIN alert_workflows w ON w.alert_id=a.alert_id "
                "WHERE a.occurred_at BETWEEN ? AND ? AND w.status='FALSE_POSITIVE' "
                "GROUP BY 1 ORDER BY 1", (start_iso, end_iso)
            )]
            top_rules = metrics(
                "SELECT rule_id, COUNT(*) FROM alerts WHERE occurred_at BETWEEN ? AND ? "
                "GROUP BY rule_id ORDER BY COUNT(*) DESC, rule_id LIMIT 20", (start_iso, end_iso)
            )
            top_ips = metrics(
                "SELECT source_ip, COUNT(*) FROM security_events "
                "WHERE occurred_at BETWEEN ? AND ? AND source_ip IS NOT NULL "
                "GROUP BY source_ip ORDER BY COUNT(*) DESC, source_ip LIMIT 20", (start_iso, end_iso)
            )
            top_hosts = metrics(
                "SELECT COALESCE(hostname,agent_name,agent_id,'Unattributed'), COUNT(*) "
                "FROM security_events WHERE occurred_at BETWEEN ? AND ? GROUP BY 1 "
                "ORDER BY COUNT(*) DESC, 1 LIMIT 20", (start_iso, end_iso)
            )
            mitre = metrics(
                "SELECT m.value, COUNT(*) FROM alerts a, "
                "json_each(a.normalized_json, '$.mitre.ids') m "
                "WHERE a.occurred_at BETWEEN ? AND ? GROUP BY m.value "
                "ORDER BY COUNT(*) DESC, m.value LIMIT 50", (start_iso, end_iso)
            )
            fp_rows = connection.execute(
                """
                SELECT a.rule_id, COUNT(*) AS total,
                       SUM(CASE WHEN w.status IN ('RESOLVED','FALSE_POSITIVE') THEN 1 ELSE 0 END) AS disposed,
                       SUM(CASE WHEN w.status='FALSE_POSITIVE' THEN 1 ELSE 0 END) AS fp
                FROM alerts a JOIN alert_workflows w ON w.alert_id=a.alert_id
                WHERE a.occurred_at BETWEEN ? AND ? GROUP BY a.rule_id
                ORDER BY total DESC, a.rule_id LIMIT 100
                """, (start_iso, end_iso)
            ).fetchall()
            disposition_rows = connection.execute(
                """
                SELECT h.actor_display,
                       SUM(CASE WHEN json_extract(h.details_json, '$.to') = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved,
                       SUM(CASE WHEN json_extract(h.details_json, '$.to') = 'FALSE_POSITIVE' THEN 1 ELSE 0 END) AS fp,
                       COUNT(*) AS total
                FROM alert_history h
                WHERE h.event_type = 'STATUS_CHANGED'
                  AND h.occurred_at BETWEEN ? AND ?
                  AND json_extract(h.details_json, '$.to') IN ('RESOLVED', 'FALSE_POSITIVE')
                GROUP BY h.actor_display
                ORDER BY total DESC, h.actor_display
                LIMIT 50
                """, (start_iso, end_iso)
            ).fetchall()
        false_positive_rules: list[FalsePositiveRuleMetric] = []
        for row in fp_rows:
            disposed = int(row["disposed"] or 0)
            fp = int(row["fp"] or 0)
            rate = fp / disposed if disposed else None
            false_positive_rules.append(FalsePositiveRuleMetric(
                rule_id=row["rule_id"], total_alerts=int(row["total"]),
                dispositioned_alerts=disposed, false_positive_count=fp,
                false_positive_rate=rate,
                tuning_candidate=bool(disposed >= 5 and rate is not None and rate >= 0.4),
            ))
        ioc_summary = self.ioc_matches(days=days, limit=1000)
        ioc_counts: dict[str, int] = {}
        for match in ioc_summary.matches:
            ioc_counts[match.indicator_type.value] = ioc_counts.get(match.indicator_type.value, 0) + 1
        return DetectionAnalytics(
            start_time=start, end_time=end, alert_trend=alert_trend,
            false_positive_trend=fp_trend, top_rules=top_rules,
            top_source_ips=top_ips, top_hosts=top_hosts, mitre_distribution=mitre,
            ioc_matches=[NamedMetric(name=name, count=count) for name, count in sorted(ioc_counts.items())],
            analyst_dispositions=[
                AnalystDispositionMetric(
                    analyst=str(row["actor_display"]),
                    resolved_count=int(row["resolved"] or 0),
                    false_positive_count=int(row["fp"] or 0),
                    total_count=int(row["total"]),
                )
                for row in disposition_rows
            ],
            false_positive_rules=false_positive_rules,
            suggested_tuning_candidates=[item.rule_id for item in false_positive_rules if item.tuning_candidate],
        )
