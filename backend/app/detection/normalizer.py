"""Defensive extraction of common fields from raw Wazuh alerts."""

from datetime import datetime
from typing import Any
from pydantic import TypeAdapter, ValidationError
from app.schemas.alert import AgentData, EndpointData, MitreData, NormalizedAlert, RuleData

DATETIME_ADAPTER = TypeAdapter(datetime)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any, maximum: int = 1024) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    text = str(value).strip()
    return text[:maximum] if text else None


def _list(value: Any, maximum_items: int = 100) -> list[str]:
    values = value if isinstance(value, list) else [value] if value is not None else []
    result: list[str] = []
    for item in values[:maximum_items]:
        text = _text(item, 128)
        if text and text not in result:
            result.append(text)
    return result


def _timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return DATETIME_ADAPTER.validate_python(value)
    except ValidationError as exc:
        raise ValueError("timestamp must be a valid ISO 8601 date-time") from exc


def _rule_level(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("rule.level must be an integer from 0 to 15")
    try:
        level = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("rule.level must be an integer from 0 to 15") from exc
    if not 0 <= level <= 15:
        raise ValueError("rule.level must be an integer from 0 to 15")
    return level


def normalize_wazuh_alert(raw: dict[str, Any]) -> NormalizedAlert:
    agent = _mapping(raw.get("agent"))
    rule = _mapping(raw.get("rule"))
    mitre = _mapping(rule.get("mitre"))
    data = _mapping(raw.get("data"))
    decoder_value = raw.get("decoder")
    decoder = decoder_value if isinstance(decoder_value, dict) else ({"name": _text(decoder_value, 256)} if _text(decoder_value, 256) else None)
    source_user = _text(data.get("srcuser"), 256)
    destination_user = _text(data.get("dstuser"), 256)
    return NormalizedAlert(
        alert_id=_text(raw.get("id"), 256),
        timestamp=_timestamp(raw.get("timestamp")),
        agent=AgentData(id=_text(agent.get("id"), 128), name=_text(agent.get("name"), 256), ip=_text(agent.get("ip"), 64)),
        rule=RuleData(id=_text(rule.get("id"), 128), level=_rule_level(rule.get("level")), description=_text(rule.get("description"), 1024)),
        mitre=MitreData(ids=_list(mitre.get("id")), tactics=_list(mitre.get("tactic")), techniques=_list(mitre.get("technique"))),
        source=EndpointData(ip=_text(data.get("srcip"), 64)),
        destination=EndpointData(ip=_text(data.get("dstip"), 64)),
        user=source_user or destination_user,
        source_user=source_user,
        destination_user=destination_user,
        location=_text(raw.get("location"), 512),
        decoder=decoder,
        full_log=_text(raw.get("full_log"), 100_000),
        rule_metadata=rule,
        raw_event=raw,
    )
