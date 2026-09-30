"""Wazuh ingestion orchestration."""

import hashlib
import json
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.exceptions import InvalidAlertError
from app.detection.normalizer import normalize_wazuh_alert
from app.detection.priority_engine import calculate_priority, severity_for_level
from app.models.incident import Incident
from app.repositories.incidents import IncidentRepository
from app.services.ai_service import NoOpAIAnalyzer


def _dedupe_key(normalized_payload: dict) -> str:
    alert_id = normalized_payload.get("alert_id")
    if alert_id:
        material = f"wazuh-id:{alert_id}"
    else:
        material = json.dumps(normalized_payload.get("raw_event", {}), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class IngestService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repository = IncidentRepository(session)

    def ingest(self, raw: dict) -> tuple[Incident, bool]:
        try:
            normalized = normalize_wazuh_alert(raw)
        except ValueError as exc:
            raise InvalidAlertError(str(exc)) from exc
        payload = normalized.model_dump(mode="json")
        key = _dedupe_key(payload)
        existing = self.repository.get_by_dedupe_key(key)
        if existing:
            return existing, False
        incident = Incident(
            dedupe_key=key,
            alert_id=normalized.alert_id,
            event_timestamp=normalized.timestamp,
            agent_id=normalized.agent.id,
            agent_name=normalized.agent.name,
            agent_ip=normalized.agent.ip,
            rule_id=normalized.rule.id,
            rule_level=normalized.rule.level,
            rule_description=normalized.rule.description,
            rule_metadata=normalized.rule_metadata,
            mitre_ids=normalized.mitre.ids,
            mitre_tactics=normalized.mitre.tactics,
            mitre_techniques=normalized.mitre.techniques,
            source_ip=normalized.source.ip,
            destination_ip=normalized.destination.ip,
            user=normalized.user,
            source_user=normalized.source_user,
            destination_user=normalized.destination_user,
            location=normalized.location,
            decoder=normalized.decoder,
            full_log=normalized.full_log,
            raw_event=normalized.raw_event,
            severity=severity_for_level(normalized.rule.level),
            priority_score=calculate_priority(normalized.rule.level),
            ai_status=NoOpAIAnalyzer().status,
        )
        try:
            return self.repository.add(incident), True
        except IntegrityError:
            self.session.rollback()
            existing = self.repository.get_by_dedupe_key(key)
            if existing:
                return existing, False
            raise
