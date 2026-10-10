"""Bounded read models for sources, hosts, detection rules, and reports."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.schemas.siem import (
    DetectionRuleSummary,
    HostSummary,
    LogSourceSummary,
    ReportCount,
    ReportFilters,
    SecurityActivityReport,
)


CUSTOM_RULES: tuple[dict[str, Any], ...] = (
    {"rule_id": "100101", "name": "Web enumeration", "description": "Web directory enumeration detected by the deployed Wazuh rule.", "severity": 10, "source_type": "web", "mitre_ids": [], "correlation_relationship": "CORR-001, CORR-002, CORR-003"},
    {"rule_id": "100111", "name": "TCP port scan", "description": "Distinct-port TCP scan against the authorized local lab target.", "severity": 10, "source_type": "network", "mitre_ids": ["T1046"], "correlation_relationship": "CORR-001"},
    {"rule_id": "100120", "name": "Sensitive path probe", "description": "Request for a configured sensitive web path.", "severity": 8, "source_type": "web", "mitre_ids": ["T1595.002"], "correlation_relationship": "CORR-001, CORR-003"},
    {"rule_id": "100130", "name": "Monitored file creation", "description": "File created in the authorized lab FIM directory.", "severity": 7, "source_type": "file_integrity", "mitre_ids": [], "correlation_relationship": "CORR-004"},
    {"rule_id": "100131", "name": "Monitored file modification", "description": "File modified in the authorized lab FIM directory.", "severity": 9, "source_type": "file_integrity", "mitre_ids": ["T1565.001"], "correlation_relationship": "CORR-004"},
)

CORRELATION_RULES: tuple[dict[str, Any], ...] = (
    {"rule_id": "CORR-001", "name": "Multi-stage reconnaissance", "description": "Port scan followed by web enumeration and a sensitive-path probe for the same agent-scoped source.", "severity": 10, "source_type": "correlation", "mitre_ids": [], "correlation_relationship": "100111 → 100101 → 100120"},
    {"rule_id": "CORR-002", "name": "Repeated web enumeration", "description": "Two related web-enumeration alerts within the bounded correlation window.", "severity": 10, "source_type": "correlation", "mitre_ids": [], "correlation_relationship": "100101 + 100101"},
    {"rule_id": "CORR-003", "name": "Web reconnaissance escalation", "description": "Web enumeration followed by a sensitive-path probe.", "severity": 10, "source_type": "correlation", "mitre_ids": [], "correlation_relationship": "100101 → 100120"},
    {"rule_id": "CORR-004", "name": "File integrity sequence", "description": "File creation followed by modification on the same agent and normalized path.", "severity": 6, "source_type": "correlation", "mitre_ids": [], "correlation_relationship": "100130 → 100131"},
)

CUSTOM_RULE_DOCUMENTATION = {
    "100101": "wazuh/rules/cyberqalqon_web_probe_rules.xml",
    "100111": "wazuh/rules/cyberqalqon_network_rules.xml",
    "100120": "wazuh/rules/cyberqalqon_web_probe_rules.xml",
    "100130": "wazuh/rules/cyberqalqon_fim_rules.xml",
    "100131": "wazuh/rules/cyberqalqon_fim_rules.xml",
}


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include an offset")
    return value.astimezone(timezone.utc).isoformat()


def _health(last_seen: datetime, now: datetime) -> str:
    return "ACTIVE" if now - last_seen <= timedelta(minutes=15) else "STALE"


class SiemRepository:
    def __init__(self, database_path: Path, *, correlation_enabled: bool = True) -> None:
        self.path = database_path
        self.correlation_enabled = correlation_enabled

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def sources(self, *, limit: int = 200) -> list[LogSourceSummary]:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT source_type, hostname, agent_id, agent_name, ingestion_source,
                       MAX(occurred_at) AS last_event_at,
                       MAX(ingested_at) AS last_ingested_at,
                       MAX(MAX(0.0, (julianday(ingested_at) - julianday(occurred_at)) * 86400.0))
                           AS max_ingestion_lag_seconds,
                       COUNT(*) AS event_count
                FROM security_events
                GROUP BY source_type, hostname, agent_id, agent_name, ingestion_source
                ORDER BY last_event_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        result: list[LogSourceSummary] = []
        for row in rows:
            last_seen = datetime.fromisoformat(row["last_event_at"])
            last_ingested = datetime.fromisoformat(row["last_ingested_at"])
            pipeline_health = "ACTIVE" if now - last_ingested <= timedelta(minutes=15) else "STALE"
            identity = row["agent_name"] or row["hostname"] or row["agent_id"] or "unattributed"
            result.append(
                LogSourceSummary(
                    source_name=f"{identity} · {row['source_type']}",
                    source_type=row["source_type"],
                    hostname=row["hostname"],
                    agent_id=row["agent_id"],
                    agent_name=row["agent_name"],
                    last_event_at=last_seen,
                    last_ingested_at=last_ingested,
                    ingestion_lag_seconds=max(0.0, float(row["max_ingestion_lag_seconds"] or 0.0)),
                    event_count=int(row["event_count"]),
                    source_health=_health(last_seen, now),
                    collection_method=row["ingestion_source"],
                    pipeline_health=pipeline_health,
                    data_availability="AVAILABLE",
                )
            )
        return result

    def hosts(self, *, limit: int = 200) -> list[HostSummary]:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT COALESCE(NULLIF(agent_id, ''), NULLIF(hostname, ''), NULLIF(agent_name, '')) AS host_key,
                       COALESCE(MAX(NULLIF(hostname, '')), MAX(NULLIF(agent_name, '')), MAX(NULLIF(agent_id, '')), 'Unattributed') AS hostname,
                       MAX(NULLIF(agent_id, '')) AS agent_id,
                       MAX(NULLIF(agent_name, '')) AS agent_name,
                       MAX(occurred_at) AS last_seen, COUNT(*) AS event_count,
                       MAX(CASE WHEN source_type = 'windows_event' THEN 1 ELSE 0 END) AS has_windows,
                       MAX(CASE WHEN source_type IN ('authentication','file_integrity','network','web') THEN 1 ELSE 0 END) AS has_linux
                FROM security_events
                WHERE agent_id IS NOT NULL OR hostname IS NOT NULL OR agent_name IS NOT NULL
                GROUP BY host_key ORDER BY last_seen DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            alert_counts_by_id = {
                str(row["agent_id"]): int(row["alert_count"])
                for row in connection.execute(
                    "SELECT agent_id, COUNT(*) AS alert_count FROM alerts "
                    "WHERE agent_id IS NOT NULL AND agent_id != '' GROUP BY agent_id"
                )
            }
            alert_counts_by_name = {
                str(row["agent_name"]).casefold(): int(row["alert_count"])
                for row in connection.execute(
                    "SELECT agent_name, COUNT(*) AS alert_count FROM alerts "
                    "WHERE agent_name != '' GROUP BY agent_name COLLATE NOCASE"
                )
            }
            detections_by_id: dict[str, list[str]] = {}
            detections_by_name: dict[str, list[str]] = {}
            detection_rows = connection.execute(
                "SELECT agent_id, agent_name, rule_id, MAX(occurred_at) AS last_seen "
                "FROM alerts GROUP BY agent_id, agent_name, rule_id "
                "ORDER BY last_seen DESC LIMIT 5000"
            ).fetchall()
            for detection in detection_rows:
                rule_id = str(detection["rule_id"])
                if detection["agent_id"]:
                    values = detections_by_id.setdefault(str(detection["agent_id"]), [])
                    if len(values) < 5:
                        values.append(rule_id)
                elif detection["agent_name"]:
                    values = detections_by_name.setdefault(
                        str(detection["agent_name"]).casefold(), []
                    )
                    if len(values) < 5:
                        values.append(rule_id)
            results: list[HostSummary] = []
            for row in rows:
                last_seen = datetime.fromisoformat(row["last_seen"])
                agent_id = row["agent_id"]
                hostname = str(row["hostname"])
                agent_name_key = str(row["agent_name"] or "").casefold()
                alert_count = (
                    alert_counts_by_id.get(str(agent_id), 0)
                    if agent_id is not None
                    else alert_counts_by_name.get(agent_name_key, 0)
                )
                detections = (
                    detections_by_id.get(str(agent_id), [])
                    if agent_id is not None
                    else detections_by_name.get(agent_name_key, [])
                )
                platform = "WINDOWS" if row["has_windows"] else ("LINUX" if row["has_linux"] else "UNKNOWN")
                results.append(
                    HostSummary(
                        hostname=hostname,
                        agent_id=agent_id,
                        agent_name=row["agent_name"],
                        platform=platform,
                        source_health=_health(last_seen, now),
                        last_seen=last_seen,
                        alert_count=alert_count,
                        event_count=int(row["event_count"]),
                        recent_detections=detections,
                    )
                )
        return results

    def rules(self) -> list[DetectionRuleSummary]:
        with self._connect() as connection:
            alert_stats = {
                str(row["rule_id"]): row
                for row in connection.execute(
                    """
                    WITH ranked AS (
                        SELECT rule_id, occurred_at, normalized_json,
                               COUNT(*) OVER (PARTITION BY rule_id) AS count,
                               ROW_NUMBER() OVER (
                                   PARTITION BY rule_id
                                   ORDER BY occurred_at DESC, alert_id DESC
                               ) AS position
                        FROM alerts
                    )
                    SELECT rule_id, count, occurred_at AS last_triggered,
                           normalized_json AS sample
                    FROM ranked WHERE position = 1
                    """
                )
            }
            correlation_stats = {
                str(row["correlation_rule"]): row
                for row in connection.execute(
                    "SELECT correlation_rule, COUNT(*) AS count, MAX(last_seen) AS last_triggered "
                    "FROM incident_correlations GROUP BY correlation_rule"
                )
            }
        entries: list[DetectionRuleSummary] = []
        for definition in CUSTOM_RULES:
            values = dict(definition)
            stat = alert_stats.get(values["rule_id"])
            if stat:
                try:
                    sample = json.loads(stat["sample"])
                    rule = sample.get("rule", {})
                    mitre = sample.get("mitre", {})
                    values["description"] = rule.get("description") or values["description"]
                    values["severity"] = rule.get("level", values["severity"])
                    values["mitre_ids"] = mitre.get("ids") or values["mitre_ids"]
                except (json.JSONDecodeError, TypeError):
                    pass
            entries.append(
                DetectionRuleSummary(
                    **values,
                    last_triggered=datetime.fromisoformat(stat["last_triggered"]) if stat else None,
                    alert_count=int(stat["count"]) if stat else 0,
                    owner="CyberQalqon local detection engineering",
                    documentation=CUSTOM_RULE_DOCUMENTATION.get(values["rule_id"]),
                    enabled_state="UNKNOWN",
                    enabled_evidence="WAZUH_API_UNAVAILABLE",
                    tested_state="NOT_RECORDED",
                    management_mode="READ_ONLY_WAZUH",
                )
            )
        for definition in CORRELATION_RULES:
            stat = correlation_stats.get(definition["rule_id"])
            entries.append(
                DetectionRuleSummary(
                    **definition,
                    last_triggered=datetime.fromisoformat(stat["last_triggered"]) if stat else None,
                    alert_count=int(stat["count"]) if stat else 0,
                    owner="CyberQalqon deterministic correlation engine",
                    documentation="docs/CORRELATION_ENGINE.md",
                    enabled_state="ENABLED" if self.correlation_enabled else "DISABLED",
                    enabled_evidence="APPLICATION_SETTING",
                    tested_state="NOT_RECORDED",
                    management_mode="LOCAL_CORRELATION",
                )
            )
        known = {entry.rule_id for entry in entries}
        for rule_id, stat in sorted(alert_stats.items()):
            if rule_id in known:
                continue
            name = f"Observed Wazuh rule {rule_id}"
            description = "Rule metadata is available only from the latest persisted alert."
            severity: int | None = None
            mitre_ids: list[str] = []
            try:
                sample = json.loads(stat["sample"])
                rule = sample.get("rule", {})
                mitre = sample.get("mitre", {})
                description = rule.get("description") or description
                name = description
                severity = rule.get("level")
                mitre_ids = mitre.get("ids") or []
            except (json.JSONDecodeError, TypeError):
                pass
            entries.append(
                DetectionRuleSummary(
                    rule_id=rule_id, name=name, description=description,
                    severity=severity, source_type="wazuh_alert", mitre_ids=mitre_ids,
                    last_triggered=datetime.fromisoformat(stat["last_triggered"]),
                    alert_count=int(stat["count"]), owner=None, documentation=None,
                    enabled_state="UNKNOWN", enabled_evidence="OBSERVED_ALERT_ONLY",
                    tested_state="NOT_RECORDED", management_mode="READ_ONLY_WAZUH",
                )
            )
        return entries

    def report(
        self,
        start_time: datetime,
        end_time: datetime,
        filters: ReportFilters | None = None,
    ) -> SecurityActivityReport:
        filters = filters or ReportFilters()
        start, end = _utc_iso(start_time), _utc_iso(end_time)
        event_conditions = ["occurred_at BETWEEN ? AND ?"]
        event_params: list[object] = [start, end]
        alert_conditions = ["occurred_at BETWEEN ? AND ?"]
        alert_params: list[object] = [start, end]
        if filters.severity_min is not None:
            event_conditions.append("severity >= ?")
            event_params.append(filters.severity_min)
            alert_conditions.append("rule_level >= ?")
            alert_params.append(filters.severity_min)
        if filters.severity_max is not None:
            event_conditions.append("severity <= ?")
            event_params.append(filters.severity_max)
            alert_conditions.append("rule_level <= ?")
            alert_params.append(filters.severity_max)
        if filters.host:
            event_conditions.append(
                "(hostname = ? COLLATE NOCASE OR agent_name = ? COLLATE NOCASE OR agent_id = ?)"
            )
            event_params.extend((filters.host, filters.host, filters.host))
            alert_conditions.append("(agent_name = ? COLLATE NOCASE OR agent_id = ?)")
            alert_params.extend((filters.host, filters.host))
        if filters.rule_id:
            event_conditions.append("rule_id = ?")
            event_params.append(filters.rule_id)
            alert_conditions.append("rule_id = ?")
            alert_params.append(filters.rule_id)
        event_where = " AND ".join(event_conditions)
        alert_where = " AND ".join(alert_conditions)
        with self._connect() as connection:
            def scalar(sql: str, parameters: list[object]) -> int:
                return int(connection.execute(sql, parameters).fetchone()[0])

            def counts(sql: str, parameters: list[object]) -> list[ReportCount]:
                return [
                    ReportCount(name=str(row[0]), count=int(row[1]))
                    for row in connection.execute(sql, parameters)
                ]

            incident_conditions = ["i.created_at BETWEEN ? AND ?"]
            incident_params: list[object] = [start, end]
            if len(alert_conditions) > 1:
                related_conditions = " AND ".join(
                    condition.replace("occurred_at", "a.occurred_at")
                    .replace("rule_level", "a.rule_level")
                    .replace("agent_name", "a.agent_name")
                    .replace("agent_id", "a.agent_id")
                    .replace("rule_id", "a.rule_id")
                    for condition in alert_conditions[1:]
                )
                incident_conditions.append(
                    "EXISTS (SELECT 1 FROM incident_alerts ia JOIN alerts a "
                    "ON a.alert_id = ia.alert_id WHERE ia.incident_id = i.incident_id AND "
                    + related_conditions + ")"
                )
                incident_params.extend(alert_params[2:])
            return SecurityActivityReport(
                start_time=start_time,
                end_time=end_time,
                generated_at=datetime.now(timezone.utc),
                filters=filters,
                total_events=scalar(f"SELECT COUNT(*) FROM security_events WHERE {event_where}", event_params),
                total_alerts=scalar(f"SELECT COUNT(*) FROM alerts WHERE {alert_where}", alert_params),
                total_incidents=scalar(
                    "SELECT COUNT(*) FROM incidents i WHERE " + " AND ".join(incident_conditions),
                    incident_params,
                ),
                event_sources=counts(f"SELECT source_type, COUNT(*) FROM security_events WHERE {event_where} GROUP BY source_type ORDER BY COUNT(*) DESC LIMIT 20", event_params),
                alert_severities=counts(f"SELECT CASE WHEN rule_level >= 13 THEN 'CRITICAL' WHEN rule_level >= 10 THEN 'HIGH' WHEN rule_level >= 7 THEN 'MEDIUM' WHEN rule_level >= 4 THEN 'LOW' ELSE 'INFORMATIONAL' END, COUNT(*) FROM alerts WHERE {alert_where} GROUP BY 1 ORDER BY COUNT(*) DESC", alert_params),
                top_rules=counts(f"SELECT rule_id, COUNT(*) FROM alerts WHERE {alert_where} GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 20", alert_params),
                host_activity=counts(f"SELECT COALESCE(hostname, agent_name, agent_id, 'Unattributed'), COUNT(*) FROM security_events WHERE {event_where} GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT 20", event_params),
                authentication_failures=scalar(f"SELECT COUNT(*) FROM security_events WHERE {event_where} AND source_type = 'authentication' AND (outcome = 'failure' OR message LIKE '%fail%')", event_params),
                file_integrity_events=scalar(f"SELECT COUNT(*) FROM security_events WHERE {event_where} AND source_type = 'file_integrity'", event_params),
            )
