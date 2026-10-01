"""Build a bounded evidence document without mutating stored evidence."""
import json
import re
from typing import Any
from app.models.incident import Incident

SENSITIVE_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|authorization|credential)", re.I)

def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if SENSITIVE_KEY.search(str(k)) else _redact(v) for k, v in value.items()}
    if isinstance(value, list): return [_redact(item) for item in value[:100]]
    if isinstance(value, str): return value[:8000]
    return value

def prepare_incident_evidence(incident: Incident, max_chars: int) -> tuple[str, bool]:
    evidence = {"event_timestamp": incident.event_timestamp.isoformat() if incident.event_timestamp else None,
        "rule": {"id": incident.rule_id, "level": incident.rule_level, "description": incident.rule_description},
        "agent": {"id": incident.agent_id, "name": incident.agent_name, "ip": incident.agent_ip},
        "observables": {"source_ip": incident.source_ip, "destination_ip": incident.destination_ip, "user": incident.user, "source_user": incident.source_user, "destination_user": incident.destination_user},
        "location": incident.location, "mitre_from_source": {"ids": incident.mitre_ids, "tactics": incident.mitre_tactics, "techniques": incident.mitre_techniques},
        "full_log": incident.full_log, "raw_event": _redact(incident.raw_event)}
    rendered = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(rendered) <= max_chars: return rendered, False
    evidence["raw_event"] = {"omitted": "input limit exceeded"}
    rendered = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(rendered) > max_chars:
        evidence["full_log"] = (incident.full_log or "")[:max(0, max_chars // 3)] + "[TRUNCATED]"
        rendered = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(rendered) > max_chars:
        rendered = json.dumps({"omitted": "incident evidence exceeded configured input limit"})
    return rendered, True
