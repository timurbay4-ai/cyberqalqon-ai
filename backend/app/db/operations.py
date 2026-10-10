"""Durable operational state, transition deduplication, and diagnostics."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.schemas.operations import (
    ComponentObservation,
    DataQualitySummary,
    OperationalComponent,
    OperationalEvent,
    OperationalOverview,
    OperationalSnapshot,
    WazuhInventoryStatus,
)
from app.services.wazuh_normalizer import canonical_json


NOTIFICATION_COOLDOWN = timedelta(minutes=15)


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _severity(state: str) -> str:
    return {
        "HEALTHY": "INFO",
        "UNKNOWN": "LOW",
        "DEGRADED": "HIGH",
        "UNAVAILABLE": "HIGH",
    }[state]


class OperationalRepository:
    def __init__(self, database_path: Path) -> None:
        self.path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _component(row: sqlite3.Row) -> OperationalComponent:
        return OperationalComponent(
            component_key=row["component_key"],
            component_kind=row["component_kind"],
            state=row["state"],
            authority=row["authority"],
            summary=row["summary"],
            metrics=json.loads(row["metrics_json"]),
            last_error=row["last_error"],
            observed_at=datetime.fromisoformat(row["observed_at"]),
            first_observed_at=datetime.fromisoformat(row["first_observed_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            version=int(row["version"]),
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> OperationalEvent:
        return OperationalEvent(
            event_id=row["event_id"],
            component_key=row["component_key"],
            event_type=row["event_type"],
            severity=row["severity"],
            previous_state=row["previous_state"],
            current_state=row["current_state"],
            authority=row["authority"],
            summary=row["summary"],
            details=json.loads(row["details_json"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
        )

    def record_snapshot(self, snapshot: OperationalSnapshot) -> int:
        """Record only new observations and notify once per real state transition."""

        now = datetime.now(timezone.utc)
        transition_count = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for observation in snapshot.components:
                existing = connection.execute(
                    "SELECT * FROM operational_component_state WHERE component_key = ?",
                    (observation.component_key,),
                ).fetchone()
                observed_at = _utc(observation.observed_at)
                if existing is not None:
                    previous_observed = datetime.fromisoformat(existing["observed_at"])
                    if observed_at <= _utc(previous_observed):
                        continue
                previous_state = str(existing["state"]) if existing is not None else None
                first_observed = (
                    str(existing["first_observed_at"])
                    if existing is not None
                    else observed_at.isoformat()
                )
                version = int(existing["version"]) + 1 if existing is not None else 1
                metrics_json = canonical_json(observation.metrics)
                connection.execute(
                    """
                    INSERT INTO operational_component_state (
                        component_key, component_kind, state, authority, summary,
                        metrics_json, last_error, observed_at, first_observed_at,
                        updated_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(component_key) DO UPDATE SET
                        component_kind=excluded.component_kind,
                        state=excluded.state,
                        authority=excluded.authority,
                        summary=excluded.summary,
                        metrics_json=excluded.metrics_json,
                        last_error=excluded.last_error,
                        observed_at=excluded.observed_at,
                        updated_at=excluded.updated_at,
                        version=excluded.version
                    """,
                    (
                        observation.component_key,
                        observation.component_kind,
                        observation.state,
                        observation.authority,
                        observation.summary,
                        metrics_json,
                        observation.last_error,
                        observed_at.isoformat(),
                        first_observed,
                        now.isoformat(),
                        version,
                    ),
                )
                should_emit = previous_state != observation.state and (
                    previous_state is not None or observation.state != "HEALTHY"
                )
                if not should_emit:
                    continue
                if observation.state == "HEALTHY" and previous_state in {
                    "DEGRADED", "UNAVAILABLE", "UNKNOWN"
                }:
                    event_type = "RECOVERY"
                elif observation.state in {"DEGRADED", "UNAVAILABLE"}:
                    event_type = "ISSUE"
                else:
                    event_type = "STATUS_CHANGE"
                event_id = f"OPE-{uuid4().hex.upper()}"
                digest_source = (
                    f"{observation.component_key}|{previous_state}|{observation.state}|"
                    f"{observed_at.isoformat()}"
                )
                deduplication_key = hashlib.sha256(digest_source.encode()).hexdigest()
                previous_issue = connection.execute(
                    "SELECT occurred_at FROM operational_events "
                    "WHERE component_key = ? AND event_type IN ('ISSUE', 'STATUS_CHANGE') "
                    "ORDER BY occurred_at DESC, event_id DESC LIMIT 1",
                    (observation.component_key,),
                ).fetchone()
                notification_allowed = event_type == "RECOVERY" or previous_issue is None
                if previous_issue is not None and event_type != "RECOVERY":
                    previous_issue_at = _utc(datetime.fromisoformat(previous_issue["occurred_at"]))
                    notification_allowed = observed_at - previous_issue_at >= NOTIFICATION_COOLDOWN
                details = {
                    "metrics": observation.metrics,
                    "last_error": observation.last_error,
                    "notification_suppressed_by_cooldown": not notification_allowed,
                }
                connection.execute(
                    """
                    INSERT OR IGNORE INTO operational_events (
                        event_id, component_key, event_type, severity,
                        previous_state, current_state, authority, summary,
                        details_json, deduplication_key, occurred_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        observation.component_key,
                        event_type,
                        _severity(observation.state),
                        previous_state,
                        observation.state,
                        observation.authority,
                        observation.summary,
                        canonical_json(details),
                        deduplication_key,
                        observed_at.isoformat(),
                    ),
                )
                if connection.execute("SELECT changes()").fetchone()[0] == 0:
                    continue
                transition_count += 1
                category = (
                    "OPERATIONAL_RECOVERY" if event_type == "RECOVERY" else "OPERATIONAL_ISSUE"
                )
                title = (
                    f"Recovered: {observation.component_key}"
                    if event_type == "RECOVERY"
                    else f"Operational issue: {observation.component_key}"
                )
                if notification_allowed:
                    analysts = connection.execute(
                        "SELECT analyst_id FROM analysts WHERE is_active = 1"
                    ).fetchall()
                    for analyst in analysts:
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO analyst_notifications (
                                notification_id, analyst_id, category, title, preview,
                                target_type, target_id, event_key, created_at
                            ) VALUES (?, ?, ?, ?, ?, 'operational', ?, ?, ?)
                            """,
                            (
                                f"NTF-{uuid4().hex.upper()}",
                                analyst["analyst_id"],
                                category,
                                title[:160],
                                observation.summary[:320],
                                event_id,
                                f"operational:{event_id}",
                                observed_at.isoformat(),
                            ),
                        )
                connection.execute(
                    """
                    INSERT INTO security_audit_events (
                        audit_id, action, actor_id, actor_display, target_type,
                        target_id, outcome, occurred_at, details_json
                    ) VALUES (?, ?, NULL, 'CyberQalqon operational collector',
                              'operational', ?, 'SUCCESS', ?, ?)
                    """,
                    (
                        f"AUD-{uuid4().hex.upper()}",
                        f"OPERATIONAL_{event_type}",
                        event_id,
                        observed_at.isoformat(),
                        canonical_json(
                            {
                                "component_key": observation.component_key,
                                "previous_state": previous_state,
                                "current_state": observation.state,
                                "authority": observation.authority,
                            }
                        ),
                    ),
                )
            connection.execute(
                "DELETE FROM operational_events WHERE event_id IN ("
                "SELECT event_id FROM operational_events ORDER BY occurred_at DESC, event_id DESC "
                "LIMIT -1 OFFSET 1000)"
            )
            connection.execute(
                "DELETE FROM security_audit_events WHERE audit_id IN ("
                "SELECT audit_id FROM security_audit_events ORDER BY occurred_at DESC, audit_id DESC "
                "LIMIT -1 OFFSET 10000)"
            )
        return transition_count

    def overview(self, *, limit: int = 50) -> OperationalOverview:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            component_rows = connection.execute(
                "SELECT * FROM operational_component_state ORDER BY component_key"
            ).fetchall()
            event_rows = connection.execute(
                "SELECT * FROM operational_events "
                "ORDER BY occurred_at DESC, event_id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            quality = connection.execute(
                """
                SELECT COUNT(*) AS total_events,
                       SUM(CASE WHEN raw_event_json IS NOT NULL AND length(raw_event_json) >= 2
                                THEN 1 ELSE 0 END) AS raw_evidence_records,
                       SUM(CASE WHEN hostname IS NULL OR hostname = '' THEN 1 ELSE 0 END)
                           AS missing_hostname,
                       SUM(CASE WHEN username IS NULL OR username = '' THEN 1 ELSE 0 END)
                           AS missing_username,
                       SUM(CASE WHEN rule_id IS NULL OR rule_id = '' THEN 1 ELSE 0 END)
                           AS missing_rule_id
                FROM security_events
                """
            ).fetchone()
        components = [self._component(row) for row in component_rows]
        shipper = next(
            (item for item in components if item.component_kind == "event_shipper"), None
        )
        shipper_metrics = shipper.metrics if shipper is not None else {}
        latest = max((item.observed_at for item in components), default=None)
        api_component = next(
            (item for item in components if item.component_kind == "wazuh_api"), None
        )
        manager_component = next(
            (item for item in components if item.component_kind == "manager"), None
        )
        inventory_available = api_component is not None and api_component.state == "HEALTHY"
        return OperationalOverview(
            generated_at=now,
            snapshot_collected_at=latest,
            snapshot_age_seconds=(now - _utc(latest)).total_seconds() if latest else None,
            components=components,
            recent_events=[self._event(row) for row in event_rows],
            data_quality=DataQualitySummary(
                total_events=int(quality["total_events"] or 0),
                raw_evidence_records=int(quality["raw_evidence_records"] or 0),
                missing_hostname=int(quality["missing_hostname"] or 0),
                missing_username=int(quality["missing_username"] or 0),
                missing_rule_id=int(quality["missing_rule_id"] or 0),
                duplicate_events=None,
                malformed_events=_metric_int(shipper_metrics, "malformed_json"),
                oversized_events=_metric_int(shipper_metrics, "oversized_lines"),
                delivery_rejected=_metric_int(shipper_metrics, "delivery_rejected"),
            ),
            wazuh_inventory=WazuhInventoryStatus(
                state="AVAILABLE" if inventory_available else "UNAVAILABLE",
                reason=(
                    "Read-only Wazuh API inventory was collected."
                    if inventory_available
                    else "Read-only Wazuh API credentials or trusted CA are not configured; agent states remain UNKNOWN."
                ),
                manager_identity=(
                    str(manager_component.metrics.get("identity"))
                    if manager_component and manager_component.metrics.get("identity")
                    else None
                ),
                agent_count=(
                    _metric_int(api_component.metrics, "agent_count")
                    if inventory_available and api_component is not None
                    else None
                ),
            ),
        )


def _metric_int(metrics: dict[str, object], key: str) -> int | None:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value
