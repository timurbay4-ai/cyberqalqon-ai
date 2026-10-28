"""Bounded, deterministic Wazuh alert correlation for automatic SOC incidents."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import posixpath
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from app.schemas.alerts import NormalizedAlert
from app.services.wazuh_normalizer import canonical_json


LOGGER = logging.getLogger(__name__)
SUPPORTED_RULE_IDS = frozenset({"100101", "100111", "100120", "100130", "100131"})
CLOSED_STATUSES = frozenset({"RESOLVED", "FALSE_POSITIVE"})
SYSTEM_ACTOR = "system:correlation"


def _identifier(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex.upper()}"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("correlation timestamps must include a UTC offset")
    return value.astimezone(timezone.utc)


def normalize_ip(value: object) -> str | None:
    """Return a canonical IP string, folding IPv4-mapped IPv6 into IPv4."""

    if value is None:
        return None
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return address.compressed


def normalize_file_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        return None
    path = value.strip().replace("\\", "/")
    normalized = posixpath.normpath(path)
    if normalized in {"", "."}:
        return None
    # Windows paths are case-insensitive; POSIX paths intentionally retain case.
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.casefold()
    return normalized


@dataclass(frozen=True, slots=True)
class AlertEvidence:
    alert_id: str
    occurred_at: datetime
    agent_id: str
    agent_name: str
    rule_id: str
    rule_level: int
    source_ip: str | None
    destination_ip: str | None
    file_path: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "AlertEvidence":
        alert = NormalizedAlert.model_validate_json(row["normalized_json"])
        raw: dict[str, Any]
        try:
            decoded = json.loads(row["raw_event_json"])
            raw = decoded if isinstance(decoded, dict) else {}
        except json.JSONDecodeError:
            raw = {}
        syscheck = raw.get("syscheck")
        path = syscheck.get("path") if isinstance(syscheck, dict) else None
        return cls(
            alert_id=alert.alert_id,
            occurred_at=_utc(alert.timestamp),
            agent_id=alert.agent.id,
            agent_name=alert.agent.name,
            rule_id=alert.rule.id,
            rule_level=alert.rule.level,
            source_ip=normalize_ip(alert.source.ip if alert.source else None),
            destination_ip=normalize_ip(alert.destination.ip if alert.destination else None),
            file_path=normalize_file_path(path),
        )


@dataclass(frozen=True, slots=True)
class CorrelationPlan:
    rule_id: Literal["CORR-001", "CORR-002", "CORR-003", "CORR-004"]
    family: Literal["NETWORK_RECON", "FILE_INTEGRITY"]
    classification: str
    severity: Literal["MEDIUM", "HIGH"]
    confidence: Literal["EXACT_MATCH", "STRONG_MATCH"]
    title: str
    explanation: str
    source_identity: str
    target_identity: str
    alerts: tuple[AlertEvidence, ...]

    @property
    def first_seen(self) -> datetime:
        return self.alerts[0].occurred_at

    @property
    def last_seen(self) -> datetime:
        return self.alerts[-1].occurred_at

    @property
    def interval_seconds(self) -> float:
        return (self.last_seen - self.first_seen).total_seconds()


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    status: Literal[
        "created", "updated", "no_match", "disabled", "manual_membership", "closed_incident"
    ]
    incident_id: str | None = None
    rule_id: str | None = None


def _same_recon_identity(alerts: list[AlertEvidence]) -> tuple[str, str] | None:
    if not alerts or any(alert.source_ip is None for alert in alerts):
        return None
    agent_ids = {alert.agent_id for alert in alerts}
    sources = {alert.source_ip for alert in alerts}
    if len(agent_ids) != 1 or len(sources) != 1:
        return None
    explicit_targets = {alert.destination_ip for alert in alerts if alert.destination_ip is not None}
    if len(explicit_targets) > 1:
        return None
    agent_id = next(iter(agent_ids))
    source = next(iter(sources))
    # Agent scoping makes loopback and repeated RFC1918 sources local to a monitored target.
    source_identity = f"agent:{agent_id}|source:{source}"
    target = next(iter(explicit_targets), None)
    target_identity = f"agent:{agent_id}" + (f"|destination:{target}" if target else "")
    return source_identity, target_identity


def _select_recon_alerts(
    candidates: list[AlertEvidence],
    required_rules: tuple[str, ...],
    *,
    window_seconds: int,
) -> list[AlertEvidence] | None:
    ordered = sorted(candidates, key=lambda item: (item.occurred_at, item.alert_id))
    for start_index, first in enumerate(ordered):
        if first.rule_id != required_rules[0]:
            continue
        chosen = [first]
        position = start_index + 1
        for required in required_rules[1:]:
            match = next((item for item in ordered[position:] if item.rule_id == required), None)
            if match is None:
                break
            chosen.append(match)
            position = ordered.index(match, position) + 1
        if len(chosen) != len(required_rules):
            continue
        if (chosen[-1].occurred_at - chosen[0].occurred_at).total_seconds() > window_seconds:
            continue
        if _same_recon_identity(chosen) is not None:
            return chosen
    return None


def build_correlation_plan(
    candidates: list[AlertEvidence],
    *,
    pivot_alert_id: str,
    window_seconds: int,
    max_links: int,
) -> CorrelationPlan | None:
    """Evaluate a bounded candidate set, preferring the most specific rule."""

    unique = {candidate.alert_id: candidate for candidate in candidates}
    if pivot_alert_id not in unique:
        return None
    ordered = sorted(unique.values(), key=lambda item: (item.occurred_at, item.alert_id))

    chain = _select_recon_alerts(
        [item for item in ordered if item.rule_id in {"100111", "100101", "100120"}],
        ("100111", "100101", "100120"),
        window_seconds=window_seconds,
    )
    if chain and any(item.alert_id == pivot_alert_id for item in chain):
        identity = _same_recon_identity(chain)
        if not (identity is not None):
            raise RuntimeError("Internal incident_correlation invariant failed")
        source_identity, target_identity = identity
        return CorrelationPlan(
            rule_id="CORR-001",
            family="NETWORK_RECON",
            classification="MULTI_STAGE_RECONNAISSANCE",
            severity="HIGH",
            confidence="EXACT_MATCH",
            title="Multi-stage reconnaissance sequence",
            explanation=(
                "A TCP port scan was followed by directory enumeration and a sensitive-path "
                f"probe from the same agent-scoped source toward a compatible target within "
                f"{int((chain[-1].occurred_at - chain[0].occurred_at).total_seconds())} seconds. "
                "This is reconnaissance evidence, not confirmation of compromise."
            ),
            source_identity=source_identity,
            target_identity=target_identity,
            alerts=tuple(chain[:max_links]),
        )

    escalation = _select_recon_alerts(
        [item for item in ordered if item.rule_id in {"100101", "100120"}],
        ("100101", "100120"),
        window_seconds=window_seconds,
    )
    if escalation and any(item.alert_id == pivot_alert_id for item in escalation):
        identity = _same_recon_identity(escalation)
        if not (identity is not None):
            raise RuntimeError("Internal incident_correlation invariant failed")
        source_identity, target_identity = identity
        return CorrelationPlan(
            rule_id="CORR-003",
            family="NETWORK_RECON",
            classification="WEB_RECONNAISSANCE_ESCALATION",
            severity="HIGH",
            confidence="STRONG_MATCH",
            title="Web reconnaissance escalation",
            explanation=(
                "Directory enumeration was followed by a sensitive-path probe from the same "
                f"agent-scoped source toward a compatible target within "
                f"{int((escalation[-1].occurred_at - escalation[0].occurred_at).total_seconds())} "
                "seconds. This does not establish data access or exfiltration."
            ),
            source_identity=source_identity,
            target_identity=target_identity,
            alerts=tuple(escalation[:max_links]),
        )

    enumerations = [item for item in ordered if item.rule_id == "100101"]
    for index, first in enumerate(enumerations):
        for second in enumerations[index + 1 :]:
            pair = [first, second]
            if (second.occurred_at - first.occurred_at).total_seconds() > window_seconds:
                break
            identity = _same_recon_identity(pair)
            if identity is None or pivot_alert_id not in {first.alert_id, second.alert_id}:
                continue
            source_identity, target_identity = identity
            return CorrelationPlan(
                rule_id="CORR-002",
                family="NETWORK_RECON",
                classification="REPEATED_WEB_ENUMERATION",
                severity="HIGH",
                confidence="STRONG_MATCH",
                title="Repeated web directory enumeration",
                explanation=(
                    "Multiple directory-enumeration alerts shared the same agent-scoped source "
                    f"and compatible target within {int((second.occurred_at - first.occurred_at).total_seconds())} seconds."
                ),
                source_identity=source_identity,
                target_identity=target_identity,
                alerts=(first, second)[:max_links],
            )

    fim = [item for item in ordered if item.rule_id in {"100130", "100131"}]
    for index, created in enumerate(fim):
        if created.rule_id != "100130" or created.file_path is None:
            continue
        for modified in fim[index + 1 :]:
            if (modified.occurred_at - created.occurred_at).total_seconds() > window_seconds:
                break
            if modified.rule_id != "100131" or modified.file_path is None:
                continue
            if created.agent_id != modified.agent_id or created.file_path != modified.file_path:
                continue
            if pivot_alert_id not in {created.alert_id, modified.alert_id}:
                continue
            return CorrelationPlan(
                rule_id="CORR-004",
                family="FILE_INTEGRITY",
                classification="FILE_INTEGRITY_SEQUENCE",
                severity="MEDIUM",
                confidence="EXACT_MATCH",
                title="File creation followed by modification",
                explanation=(
                    "A monitored file was created and then modified on the same agent and exact "
                    f"normalized path within {int((modified.occurred_at - created.occurred_at).total_seconds())} seconds. "
                    "The sequence requires analyst review and is not automatically classified as malicious."
                ),
                source_identity=f"agent:{created.agent_id}",
                target_identity=f"agent:{created.agent_id}|file:{created.file_path}",
                alerts=(created, modified)[:max_links],
            )
    return None


class IncidentCorrelationEngine:
    """Correlate one persisted alert using short-lived SQLite transactions only."""

    def __init__(
        self,
        database_path: Path,
        *,
        enabled: bool = True,
        window_seconds: int = 900,
        max_candidates: int = 200,
        max_links: int = 50,
        retry_attempts: int = 1,
    ) -> None:
        self.path = database_path
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.max_candidates = max_candidates
        self.max_links = max_links
        self.retry_attempts = retry_attempts

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _candidate_rows(
        self, connection: sqlite3.Connection, pivot: sqlite3.Row
    ) -> list[sqlite3.Row]:
        occurred_at = datetime.fromisoformat(pivot["occurred_at"])
        start = (occurred_at - timedelta(seconds=self.window_seconds)).isoformat()
        end = (occurred_at + timedelta(seconds=self.window_seconds)).isoformat()
        placeholders = ", ".join("?" for _ in SUPPORTED_RULE_IDS)
        return connection.execute(
            f"""
            SELECT alert_id, occurred_at, normalized_json, raw_event_json
            FROM alerts
            WHERE rule_id IN ({placeholders})
              AND occurred_at BETWEEN ? AND ?
              AND agent_id = ?
            ORDER BY occurred_at, alert_id
            LIMIT ?
            """,
            (*sorted(SUPPORTED_RULE_IDS), start, end, pivot["agent_id"], self.max_candidates),
        ).fetchall()

    @staticmethod
    def _correlation_key(plan: CorrelationPlan) -> str:
        seed = canonical_json(
            {
                "family": plan.family,
                "source": plan.source_identity,
                "target": plan.target_identity,
                "anchor": plan.alerts[0].alert_id,
            }
        )
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    @staticmethod
    def _append_system_history(
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        event_type: str,
        occurred_at: datetime,
        details: dict[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO incident_history (
                event_id, incident_id, event_type, actor, occurred_at, details_json,
                actor_id, actor_display
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?)
            """,
            (
                _identifier("EVT"), incident_id, event_type, SYSTEM_ACTOR,
                occurred_at.isoformat(), canonical_json(details), SYSTEM_ACTOR,
            ),
        )

    def _find_membership(
        self, connection: sqlite3.Connection, alert_ids: tuple[str, ...]
    ) -> tuple[set[str], bool]:
        placeholders = ", ".join("?" for _ in alert_ids)
        auto_rows = connection.execute(
            f"SELECT DISTINCT incident_id FROM auto_correlation_alerts WHERE alert_id IN ({placeholders})",
            alert_ids,
        ).fetchall()
        auto_incidents = {str(row["incident_id"]) for row in auto_rows}
        manual_row = connection.execute(
            f"""
            SELECT 1
            FROM incident_alerts ia
            LEFT JOIN incident_correlations ic ON ic.incident_id = ia.incident_id
            WHERE ia.alert_id IN ({placeholders}) AND ic.incident_id IS NULL
            LIMIT 1
            """,
            alert_ids,
        ).fetchone()
        return auto_incidents, manual_row is not None

    def _write_plan(
        self, connection: sqlite3.Connection, plan: CorrelationPlan
    ) -> CorrelationResult:
        alert_ids = tuple(item.alert_id for item in plan.alerts)
        auto_incidents, has_manual_membership = self._find_membership(connection, alert_ids)
        if has_manual_membership:
            return CorrelationResult("manual_membership", rule_id=plan.rule_id)
        if len(auto_incidents) > 1:
            LOGGER.warning("correlation skipped because evidence spans multiple automatic incidents")
            return CorrelationResult("closed_incident", rule_id=plan.rule_id)

        now = datetime.now(timezone.utc)
        incident_id = next(iter(auto_incidents), None)
        if incident_id is not None:
            incident = connection.execute(
                "SELECT status FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if incident is None or incident["status"] in CLOSED_STATUSES:
                return CorrelationResult("closed_incident", incident_id, plan.rule_id)
            correlation = connection.execute(
                "SELECT correlation_rule FROM incident_correlations WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            priorities = {"CORR-002": 1, "CORR-003": 2, "CORR-004": 2, "CORR-001": 3}
            existing_rule = str(correlation["correlation_rule"])
            use_plan_metadata = priorities[plan.rule_id] >= priorities[existing_rule]
            for evidence in plan.alerts:
                existing = connection.execute(
                    "SELECT incident_id FROM auto_correlation_alerts WHERE alert_id = ?",
                    (evidence.alert_id,),
                ).fetchone()
                if existing is not None:
                    if existing["incident_id"] != incident_id:
                        raise sqlite3.IntegrityError("alert belongs to a different automatic incident")
                    continue
                connection.execute(
                    "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (?, ?, ?)",
                    (incident_id, evidence.alert_id, now.isoformat()),
                )
                connection.execute(
                    "INSERT INTO auto_correlation_alerts (alert_id, incident_id, correlation_rule, linked_at) "
                    "VALUES (?, ?, ?, ?)",
                    (evidence.alert_id, incident_id, plan.rule_id, now.isoformat()),
                )
                self._append_system_history(
                    connection,
                    incident_id=incident_id,
                    event_type="ALERT_LINKED",
                    occurred_at=now,
                    details={"alert_id": evidence.alert_id, "correlation_rule": plan.rule_id},
                )
            first_seen, last_seen, count = connection.execute(
                """
                SELECT MIN(a.occurred_at), MAX(a.occurred_at), COUNT(*)
                FROM auto_correlation_alerts aca
                JOIN alerts a ON a.alert_id = aca.alert_id
                WHERE aca.incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if use_plan_metadata:
                connection.execute(
                    """
                    UPDATE incident_correlations
                    SET correlation_rule = ?, classification = ?, confidence = ?,
                        source_identity = ?, target_identity = ?, explanation = ?,
                        first_seen = ?, last_seen = ?, related_alert_count = ?, updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (
                        plan.rule_id, plan.classification, plan.confidence,
                        plan.source_identity, plan.target_identity, plan.explanation,
                        first_seen, last_seen, count, now.isoformat(), incident_id,
                    ),
                )
                connection.execute(
                    "UPDATE incidents SET title = ?, description = ?, updated_at = ? WHERE incident_id = ?",
                    (plan.title, plan.explanation, now.isoformat(), incident_id),
                )
            else:
                connection.execute(
                    """
                    UPDATE incident_correlations
                    SET first_seen = ?, last_seen = ?, related_alert_count = ?, updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (first_seen, last_seen, count, now.isoformat(), incident_id),
                )
                connection.execute(
                    "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                    (now.isoformat(), incident_id),
                )
            return CorrelationResult("updated", incident_id, plan.rule_id)

        incident_id = _identifier("INC")
        connection.execute(
            """
            INSERT INTO incidents (
                incident_id, title, description, severity, status,
                assigned_to, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'NEW', NULL, ?, ?)
            """,
            (
                incident_id, plan.title, plan.explanation, plan.severity,
                now.isoformat(), now.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO incident_correlations (
                incident_id, correlation_key, correlation_family, correlation_rule,
                classification, confidence, source_identity, target_identity,
                explanation, first_seen, last_seen, related_alert_count,
                created_at, updated_at, auto_generated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                incident_id, self._correlation_key(plan), plan.family, plan.rule_id,
                plan.classification, plan.confidence, plan.source_identity,
                plan.target_identity, plan.explanation, plan.first_seen.isoformat(),
                plan.last_seen.isoformat(), len(plan.alerts), now.isoformat(), now.isoformat(),
            ),
        )
        self._append_system_history(
            connection,
            incident_id=incident_id,
            event_type="CREATED",
            occurred_at=now,
            details={
                "severity": plan.severity,
                "status": "NEW",
                "correlation_rule": plan.rule_id,
                "classification": plan.classification,
                "confidence": plan.confidence,
            },
        )
        for evidence in plan.alerts:
            connection.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id, linked_at) VALUES (?, ?, ?)",
                (incident_id, evidence.alert_id, now.isoformat()),
            )
            connection.execute(
                "INSERT INTO auto_correlation_alerts (alert_id, incident_id, correlation_rule, linked_at) "
                "VALUES (?, ?, ?, ?)",
                (evidence.alert_id, incident_id, plan.rule_id, now.isoformat()),
            )
            self._append_system_history(
                connection,
                incident_id=incident_id,
                event_type="ALERT_LINKED",
                occurred_at=now,
                details={"alert_id": evidence.alert_id, "correlation_rule": plan.rule_id},
            )
        return CorrelationResult("created", incident_id, plan.rule_id)

    def correlate(self, alert_id: str) -> CorrelationResult:
        if not self.enabled:
            return CorrelationResult("disabled")
        for attempt in range(self.retry_attempts + 1):
            try:
                with closing(self._connect()) as connection:
                    with connection:
                        connection.execute("BEGIN IMMEDIATE")
                        pivot = connection.execute(
                            "SELECT alert_id, occurred_at, agent_id, rule_id FROM alerts WHERE alert_id = ?",
                            (alert_id,),
                        ).fetchone()
                        if pivot is None or pivot["rule_id"] not in SUPPORTED_RULE_IDS:
                            return CorrelationResult("no_match")
                        candidates = [AlertEvidence.from_row(row) for row in self._candidate_rows(connection, pivot)]
                        plan = build_correlation_plan(
                            candidates,
                            pivot_alert_id=alert_id,
                            window_seconds=self.window_seconds,
                            max_links=self.max_links,
                        )
                        if plan is None:
                            return CorrelationResult("no_match")
                        return self._write_plan(connection, plan)
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).casefold() or attempt >= self.retry_attempts:
                    raise
                LOGGER.warning("correlation database was busy; retrying once")
        return CorrelationResult("no_match")  # pragma: no cover
