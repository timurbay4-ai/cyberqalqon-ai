"""Durable, namespaced Wazuh inventory and telemetry relationships."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.schemas.agents import (
    AgentDetail,
    AgentHealthRecord,
    AgentHealthResponse,
    AgentListResponse,
    AgentPage,
    AgentSummary,
    AgentTelemetrySource,
    WazuhIntegrationStatus,
)
from app.services.wazuh_api import WazuhAgentRecord, WazuhApiClient, WazuhInventoryResult
from app.services.wazuh_normalizer import canonical_json


NOTIFICATION_COOLDOWN = timedelta(minutes=15)


def _utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return _utc(parsed)


def _key(prefix: str, manager: str, agent_id: str) -> str:
    digest = hashlib.sha256(f"{prefix}\0{manager}\0{agent_id}".encode()).hexdigest()
    return f"{prefix.lower()}_{digest[:48]}"


def _connection_status(value: str) -> str:
    normalized = value.strip().casefold().replace("-", "_").replace(" ", "_")
    if normalized in {"active", "online", "connected"}:
        return "ONLINE"
    if normalized in {"disconnected", "offline"}:
        return "DISCONNECTED"
    if normalized in {"never_connected", "pending"}:
        return "NEVER_CONNECTED"
    return "UNKNOWN"


class AgentRepository:
    def __init__(self, database_path: Path, settings: Settings) -> None:
        self.path = database_path
        self.settings = settings
        self.client = WazuhApiClient(settings)
        self._refresh_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _cache_row(self, connection: sqlite3.Connection) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM wazuh_integration_cache WHERE singleton = 1"
        ).fetchone()

    def refresh_if_needed(self, *, force: bool = False) -> None:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            row = self._cache_row(connection)
        if not force and row is not None:
            expires = _parse_timestamp(str(row["expires_at"]))
            if expires is not None and expires > now:
                return
        if not self._refresh_lock.acquire(blocking=False):
            return
        try:
            with self._connect() as connection:
                row = self._cache_row(connection)
            if not force and row is not None:
                expires = _parse_timestamp(str(row["expires_at"]))
                if expires is not None and expires > datetime.now(timezone.utc):
                    return
            self.record_inventory(self.client.fetch_inventory())
        finally:
            self._refresh_lock.release()

    def record_inventory(self, result: WazuhInventoryResult) -> None:
        observed = _utc(result.observed_at)
        expires = observed + timedelta(seconds=self.settings.wazuh_inventory_cache_seconds)
        manager = result.manager_identity or "loopback-wazuh-manager"
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO wazuh_integration_cache (
                    singleton, state, reason, manager_identity, manager_version,
                    manager_health, agent_count, rejected_agent_count, observed_at, expires_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(singleton) DO UPDATE SET
                    state=excluded.state, reason=excluded.reason,
                    manager_identity=excluded.manager_identity,
                    manager_version=excluded.manager_version,
                    manager_health=excluded.manager_health,
                    agent_count=excluded.agent_count,
                    rejected_agent_count=excluded.rejected_agent_count,
                    observed_at=excluded.observed_at, expires_at=excluded.expires_at
                """,
                (
                    "AVAILABLE" if result.available else "UNAVAILABLE",
                    result.reason,
                    result.manager_identity,
                    result.manager_version,
                    result.manager_health,
                    len(result.agents) if result.available else None,
                    result.rejected_agent_count,
                    observed.isoformat(),
                    expires.isoformat(),
                ),
            )
            if result.available:
                for agent in result.agents:
                    self._record_agent(connection, manager, agent, observed, expires)
                connection.execute(
                    "DELETE FROM agent_health_history WHERE history_id IN ("
                    "SELECT history_id FROM agent_health_history "
                    "ORDER BY observed_at DESC, history_id DESC LIMIT -1 OFFSET ?) ",
                    (self.settings.agent_health_history_max_records,),
                )

    def _record_agent(
        self,
        connection: sqlite3.Connection,
        manager: str,
        agent: WazuhAgentRecord,
        observed: datetime,
        expires: datetime,
    ) -> None:
        agent_key = _key("WAZUH", manager, agent.agent_id)
        status = _connection_status(agent.status)
        existing = connection.execute(
            "SELECT connection_status, first_observed_at FROM agent_inventory WHERE agent_key = ?",
            (agent_key,),
        ).fetchone()
        previous = str(existing["connection_status"]) if existing else None
        first_observed = str(existing["first_observed_at"]) if existing else observed.isoformat()
        connection.execute(
            """
            INSERT INTO agent_inventory (
                agent_key, provider, manager_identity, agent_id, name,
                os_name, os_platform, os_version, agent_version, ip_address,
                groups_json, connection_status, enrollment_status, status_authority,
                last_keepalive, disconnected_at, enrolled_at, first_observed_at,
                observed_at, expires_at
            ) VALUES (?, 'WAZUH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ENROLLED',
                      'WAZUH_API', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_key) DO UPDATE SET
                name=excluded.name, os_name=excluded.os_name,
                os_platform=excluded.os_platform, os_version=excluded.os_version,
                agent_version=excluded.agent_version, ip_address=excluded.ip_address,
                groups_json=excluded.groups_json,
                connection_status=excluded.connection_status,
                enrollment_status=excluded.enrollment_status,
                last_keepalive=excluded.last_keepalive,
                disconnected_at=excluded.disconnected_at, enrolled_at=excluded.enrolled_at,
                observed_at=excluded.observed_at, expires_at=excluded.expires_at
            """,
            (
                agent_key,
                manager,
                agent.agent_id,
                agent.name,
                agent.os_name,
                agent.os_platform,
                agent.os_version,
                agent.agent_version,
                agent.ip,
                canonical_json(list(agent.groups)),
                status,
                _parse_timestamp(agent.last_keepalive).isoformat()
                if _parse_timestamp(agent.last_keepalive)
                else None,
                _parse_timestamp(agent.disconnected_at).isoformat()
                if _parse_timestamp(agent.disconnected_at)
                else None,
                _parse_timestamp(agent.enrolled_at).isoformat()
                if _parse_timestamp(agent.enrolled_at)
                else None,
                first_observed,
                observed.isoformat(),
                expires.isoformat(),
            ),
        )
        if previous == status:
            return
        digest = hashlib.sha256(
            f"{agent_key}|{previous}|{status}|{observed.isoformat()}".encode()
        ).hexdigest()
        history_id = f"AGH-{uuid4().hex.upper()}"
        connection.execute(
            """
            INSERT OR IGNORE INTO agent_health_history (
                history_id, agent_key, connection_status, previous_status,
                authority, observed_at, details_json, deduplication_key
            ) VALUES (?, ?, ?, ?, 'WAZUH_API', ?, ?, ?)
            """,
            (
                history_id,
                agent_key,
                status,
                previous,
                observed.isoformat(),
                canonical_json({"manager": manager, "agent_id": agent.agent_id}),
                digest,
            ),
        )
        if previous is None or status not in {"ONLINE", "DISCONNECTED"}:
            return
        self._notify_transition(connection, agent_key, agent.name, previous, status, observed)

    @staticmethod
    def _notify_transition(
        connection: sqlite3.Connection,
        agent_key: str,
        name: str,
        previous: str,
        current: str,
        observed: datetime,
    ) -> None:
        category = "OPERATIONAL_RECOVERY" if current == "ONLINE" else "OPERATIONAL_ISSUE"
        prior = connection.execute(
            "SELECT created_at FROM analyst_notifications WHERE target_type = 'operational' "
            "AND target_id = ? AND category = ? ORDER BY created_at DESC LIMIT 1",
            (agent_key, category),
        ).fetchone()
        if prior is not None and current != "ONLINE":
            prior_at = _parse_timestamp(str(prior["created_at"]))
            if prior_at is not None and observed - prior_at < NOTIFICATION_COOLDOWN:
                return
        title = f"Agent reconnected: {name}" if current == "ONLINE" else f"Agent disconnected: {name}"
        preview = f"Authoritative Wazuh API status changed from {previous} to {current}."
        transition_id = f"AGT-{uuid4().hex.upper()}"
        for analyst in connection.execute(
            "SELECT analyst_id FROM analysts WHERE is_active = 1"
        ).fetchall():
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
                    preview,
                    agent_key,
                    f"agent-transition:{transition_id}:{analyst['analyst_id']}",
                    observed.isoformat(),
                ),
            )
        connection.execute(
            """
            INSERT INTO security_audit_events (
                audit_id, action, actor_id, actor_display, target_type,
                target_id, outcome, occurred_at, details_json
            ) VALUES (?, ?, NULL, 'CyberQalqon agent inventory', 'operational',
                      ?, 'SUCCESS', ?, ?)
            """,
            (
                f"AUD-{uuid4().hex.upper()}",
                "AGENT_RECONNECTED" if current == "ONLINE" else "AGENT_DISCONNECTED",
                agent_key,
                observed.isoformat(),
                canonical_json(
                    {
                        "previous_status": previous,
                        "current_status": current,
                        "authority": "WAZUH_API",
                    }
                ),
            ),
        )

    def integration_status(self) -> WazuhIntegrationStatus:
        self.refresh_if_needed()
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            row = self._cache_row(connection)
        if row is None:
            observed = now
            expires = now
            return WazuhIntegrationStatus(
                state="UNAVAILABLE",
                configured=bool(self.settings.wazuh_api_username and self.settings.wazuh_api_password),
                reason="No Wazuh API observation has been recorded.",
                observed_at=observed,
                cache_expires_at=expires,
                cache_age_seconds=0,
                cache_stale=True,
                tls_verification="CUSTOM_CA" if self.settings.wazuh_api_ca_bundle else "SYSTEM_TRUST",
            )
        observed = _parse_timestamp(str(row["observed_at"])) or now
        expires = _parse_timestamp(str(row["expires_at"])) or observed
        return WazuhIntegrationStatus(
            state=row["state"],
            configured=bool(self.settings.wazuh_api_username and self.settings.wazuh_api_password),
            reason=row["reason"],
            manager_identity=row["manager_identity"],
            manager_version=row["manager_version"],
            manager_health=row["manager_health"],
            agent_count=row["agent_count"],
            rejected_agent_count=int(row["rejected_agent_count"]),
            observed_at=observed,
            cache_expires_at=expires,
            cache_age_seconds=max(0.0, (now - observed).total_seconds()),
            cache_stale=now > expires,
            tls_verification="CUSTOM_CA" if self.settings.wazuh_api_ca_bundle else "SYSTEM_TRUST",
        )

    def _telemetry_rows(self, connection: sqlite3.Connection) -> list[sqlite3.Row]:
        return connection.execute(
            """
            SELECT COALESCE(NULLIF(manager_identity, ''), 'unknown-manager') AS manager_scope,
                   COALESCE(NULLIF(agent_id, ''), NULLIF(agent_name, ''), NULLIF(hostname, '')) AS identity,
                   MAX(NULLIF(agent_id, '')) AS agent_id,
                   COALESCE(MAX(NULLIF(agent_name, '')), MAX(NULLIF(hostname, '')),
                            MAX(NULLIF(agent_id, ''))) AS display_name,
                   MAX(NULLIF(hostname, '')) AS hostname,
                   MAX(occurred_at) AS last_event_at,
                   MAX(ingested_at) AS last_ingested_at,
                   MAX(CASE WHEN source_type = 'windows_event' THEN 1 ELSE 0 END) AS has_windows,
                   MAX(CASE WHEN source_type IN (
                       'authentication','file_integrity','network','web','wazuh_alert','wazuh_archive'
                   ) THEN 1 ELSE 0 END) AS has_linux
            FROM security_events
            WHERE agent_id IS NOT NULL OR agent_name IS NOT NULL OR hostname IS NOT NULL
            GROUP BY manager_scope, identity
            ORDER BY last_event_at DESC
            LIMIT 2000
            """
        ).fetchall()

    def _event_freshness(self, value: datetime | None, now: datetime) -> str:
        if value is None:
            return "NO_DATA"
        return "ACTIVE" if now - value <= timedelta(minutes=15) else "STALE"

    def _authoritative_summary(
        self,
        row: sqlite3.Row,
        telemetry: sqlite3.Row | None,
        now: datetime,
        *,
        provider_available: bool,
    ) -> AgentSummary:
        last_event = _parse_timestamp(str(telemetry["last_event_at"])) if telemetry else None
        last_ingested = _parse_timestamp(str(telemetry["last_ingested_at"])) if telemetry else None
        expires = _parse_timestamp(str(row["expires_at"]))
        cache_stale = expires is None or now > expires
        operating_system = " ".join(
            value for value in (row["os_name"], row["os_version"]) if value
        ) or None
        return AgentSummary(
            agent_key=row["agent_key"],
            agent_id=row["agent_id"],
            name=row["name"],
            operating_system=operating_system,
            os_platform=row["os_platform"],
            os_version=row["os_version"],
            agent_version=row["agent_version"],
            manager=row["manager_identity"],
            ip_address=row["ip_address"],
            groups=json.loads(row["groups_json"]),
            enrollment_status=row["enrollment_status"],
            # A historical provider observation remains useful inventory, but
            # an expired/unavailable provider cannot assert current connection.
            connection_status=(
                row["connection_status"]
                if provider_available and not cache_stale
                else "UNKNOWN"
            ),
            status_authority="WAZUH_API",
            last_keepalive=_parse_timestamp(row["last_keepalive"]),
            disconnected_at=_parse_timestamp(row["disconnected_at"]),
            enrolled_at=_parse_timestamp(row["enrolled_at"]),
            last_security_event=last_event,
            data_freshness=self._event_freshness(last_event, now),
            pipeline_health=(
                "EMPTY" if last_ingested is None else self._event_freshness(last_ingested, now)
            ),
            observed_at=_parse_timestamp(row["observed_at"]) or now,
            cache_expires_at=expires,
            cache_stale=cache_stale,
            observed_only=False,
        )

    def _observed_summary(self, row: sqlite3.Row, now: datetime) -> AgentSummary:
        agent_id = str(row["agent_id"] or row["identity"])
        last_event = _parse_timestamp(str(row["last_event_at"]))
        last_ingested = _parse_timestamp(str(row["last_ingested_at"]))
        platform = "windows" if row["has_windows"] else ("linux" if row["has_linux"] else None)
        return AgentSummary(
            agent_key=_key("OBSERVED", str(row["manager_scope"]), agent_id),
            agent_id=agent_id,
            name=str(row["display_name"] or agent_id),
            operating_system=platform.upper() if platform else None,
            os_platform=platform,
            manager=None if row["manager_scope"] == "unknown-manager" else row["manager_scope"],
            enrollment_status="UNKNOWN",
            connection_status="UNKNOWN",
            status_authority="TELEMETRY_EVIDENCE",
            last_security_event=last_event,
            data_freshness=self._event_freshness(last_event, now),
            pipeline_health=(
                "EMPTY" if last_ingested is None else self._event_freshness(last_ingested, now)
            ),
            observed_at=last_ingested or last_event or now,
            cache_stale=False,
            observed_only=True,
        )

    def _all_summaries(self) -> tuple[list[AgentSummary], WazuhIntegrationStatus]:
        status = self.integration_status()
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            authoritative = connection.execute(
                "SELECT * FROM agent_inventory ORDER BY manager_identity, agent_id"
            ).fetchall()
            telemetry = self._telemetry_rows(connection)
        by_scoped_id = {
            (str(row["manager_scope"]), str(row["agent_id"])): row
            for row in telemetry
            if row["agent_id"]
        }
        by_id = {}
        for row in telemetry:
            if row["agent_id"]:
                by_id.setdefault(str(row["agent_id"]), []).append(row)
        consumed: set[int] = set()
        summaries: list[AgentSummary] = []
        for row in authoritative:
            match = by_scoped_id.get((str(row["manager_identity"]), str(row["agent_id"])))
            if match is None and len(by_id.get(str(row["agent_id"]), [])) == 1:
                match = by_id[str(row["agent_id"])][0]
            if match is not None:
                consumed.add(id(match))
            summaries.append(
                self._authoritative_summary(
                    row,
                    match,
                    now,
                    provider_available=status.state == "AVAILABLE",
                )
            )
        for row in telemetry:
            if id(row) not in consumed:
                summaries.append(self._observed_summary(row, now))
        return summaries, status

    def list_agents(
        self,
        *,
        search: str | None,
        os_platform: str | None,
        connection_status: str | None,
        version: str | None,
        manager: str | None,
        source_type: str | None,
        last_seen_minutes: int | None,
        sort: str,
        order: str,
        limit: int,
        offset: int,
    ) -> AgentListResponse:
        summaries, integration = self._all_summaries()
        now = datetime.now(timezone.utc)
        needle = (search or "").casefold()
        filtered: list[AgentSummary] = []
        for item in summaries:
            if needle and needle not in " ".join(
                filter(None, (item.agent_id, item.name, item.manager, item.ip_address))
            ).casefold():
                continue
            if os_platform and (item.os_platform or "").casefold() != os_platform.casefold():
                continue
            if connection_status and item.connection_status != connection_status:
                continue
            if version and version.casefold() not in (item.agent_version or "").casefold():
                continue
            if manager and manager.casefold() not in (item.manager or "").casefold():
                continue
            if last_seen_minutes is not None:
                if item.last_security_event is None or now - item.last_security_event > timedelta(
                    minutes=last_seen_minutes
                ):
                    continue
            if source_type and not self._agent_has_source(item, source_type):
                continue
            filtered.append(item)
        key = {
            "name": lambda item: item.name.casefold(),
            "agent_id": lambda item: item.agent_id,
            "status": lambda item: item.connection_status,
            "last_seen": lambda item: item.last_security_event or datetime.min.replace(tzinfo=timezone.utc),
            "version": lambda item: (item.agent_version or "").casefold(),
        }[sort]
        filtered.sort(key=lambda item: (key(item), item.agent_key), reverse=order == "desc")
        return AgentListResponse(
            items=filtered[offset : offset + limit],
            page=AgentPage(limit=limit, offset=offset, total=len(filtered)),
            authoritative_inventory=integration.state == "AVAILABLE",
            partial=integration.state != "AVAILABLE" or any(item.observed_only for item in filtered),
            observation_timestamp=integration.observed_at,
            cache_age_seconds=integration.cache_age_seconds,
            message=(
                "Authoritative Wazuh inventory with telemetry relationships."
                if integration.state == "AVAILABLE"
                else "Wazuh API unavailable; observed sources are shown with UNKNOWN connection state."
            ),
        )

    def _agent_has_source(self, item: AgentSummary, source_type: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM security_events WHERE source_type = ? AND "
                "((agent_id IS NOT NULL AND agent_id = ?) OR "
                "(agent_id IS NULL AND (agent_name = ? COLLATE NOCASE OR hostname = ? COLLATE NOCASE))) "
                "LIMIT 1",
                (source_type, item.agent_id, item.name, item.name),
            ).fetchone()
        return row is not None

    def get_agent(self, agent_key: str) -> AgentDetail | None:
        summaries, _ = self._all_summaries()
        summary = next((item for item in summaries if item.agent_key == agent_key), None)
        if summary is None:
            return None
        with self._connect() as connection:
            source_rows = connection.execute(
                """
                SELECT source_type, ingestion_source, MAX(occurred_at) AS last_event_at,
                       MAX(ingested_at) AS last_ingested_at, COUNT(*) AS event_count
                FROM security_events
                WHERE agent_id = ? OR (agent_id IS NULL AND
                    (agent_name = ? COLLATE NOCASE OR hostname = ? COLLATE NOCASE))
                GROUP BY source_type, ingestion_source ORDER BY last_event_at DESC LIMIT 50
                """,
                (summary.agent_id, summary.name, summary.name),
            ).fetchall()
            event_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT event_id FROM security_events WHERE agent_id = ? OR "
                    "(agent_id IS NULL AND (agent_name = ? COLLATE NOCASE OR hostname = ? COLLATE NOCASE)) "
                    "ORDER BY occurred_at DESC, event_id DESC LIMIT 25",
                    (summary.agent_id, summary.name, summary.name),
                )
            ]
            alert_ids = [
                str(row[0])
                for row in connection.execute(
                    "SELECT alert_id FROM alerts WHERE agent_id = ? OR "
                    "(agent_id IS NULL AND agent_name = ? COLLATE NOCASE) "
                    "ORDER BY occurred_at DESC, alert_id DESC LIMIT 25",
                    (summary.agent_id, summary.name),
                )
            ]
            incident_ids: list[str] = []
            if alert_ids:
                placeholders = ",".join("?" for _ in alert_ids)
                incident_ids = [
                    str(row[0])
                    for row in connection.execute(
                        f"SELECT DISTINCT incident_id FROM incident_alerts WHERE alert_id IN ({placeholders}) "
                        "ORDER BY incident_id LIMIT 25",
                        alert_ids,
                    )
                ]
        now = datetime.now(timezone.utc)
        sources = [
            AgentTelemetrySource(
                source_type=row["source_type"],
                ingestion_source=row["ingestion_source"],
                last_event_at=_parse_timestamp(row["last_event_at"]) or now,
                last_ingested_at=_parse_timestamp(row["last_ingested_at"]) or now,
                event_count=int(row["event_count"]),
                freshness=self._event_freshness(_parse_timestamp(row["last_event_at"]), now),
            )
            for row in source_rows
        ]
        guidance = [
            "Connection state is authoritative only when status authority is WAZUH_API.",
            "Telemetry freshness does not prove that the agent is currently connected.",
        ]
        if summary.connection_status == "UNKNOWN":
            guidance.append("Configure an approved read-only Wazuh API account and trusted CA.")
        if summary.cache_stale:
            guidance.append("The provider cache is stale; validate API reachability before acting.")
        return AgentDetail(
            **summary.model_dump(),
            telemetry_sources=sources,
            recent_event_ids=event_ids,
            related_alert_ids=alert_ids,
            related_incident_ids=incident_ids,
            troubleshooting=guidance,
        )

    def health(self, agent_key: str, *, limit: int = 100) -> AgentHealthResponse | None:
        detail = self.get_agent(agent_key)
        if detail is None:
            return None
        if detail.status_authority != "WAZUH_API":
            return AgentHealthResponse(
                agent_key=agent_key,
                status_authority=detail.status_authority,
                items=[],
            )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM agent_health_history WHERE agent_key = ? "
                "ORDER BY observed_at DESC, history_id DESC LIMIT ?",
                (agent_key, limit),
            ).fetchall()
        return AgentHealthResponse(
            agent_key=agent_key,
            status_authority="WAZUH_API",
            items=[
                AgentHealthRecord(
                    history_id=row["history_id"],
                    connection_status=row["connection_status"],
                    previous_status=row["previous_status"],
                    authority="WAZUH_API",
                    observed_at=_parse_timestamp(row["observed_at"]) or datetime.now(timezone.utc),
                    details=json.loads(row["details_json"]),
                )
                for row in rows
            ],
        )
