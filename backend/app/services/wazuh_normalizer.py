"""Deterministic normalization of untrusted Wazuh alert JSON."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from app.schemas.alerts import (
    Agent,
    JsonObject,
    MitreContext,
    NetworkEndpoint,
    NormalizedAlert,
    Rule,
)


MITRE_ID_PATTERN = re.compile(r"^T[0-9]{4}(?:\.[0-9]{3})?$")


class AlertNormalizationError(ValueError):
    def __init__(self, message: str, *, field: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def raw_event_fingerprint(raw_event: JsonObject) -> str:
    return hashlib.sha256(canonical_json(raw_event).encode("utf-8")).hexdigest()


def raw_event_size(raw_event: JsonObject) -> int:
    return len(canonical_json(raw_event).encode("utf-8"))


def _mapping(value: Any, field: str, *, required: bool = True) -> Mapping[str, Any]:
    if value is None and not required:
        return {}
    if not isinstance(value, Mapping):
        raise AlertNormalizationError("must be a JSON object", field=field)
    return value


def _required_text(value: Any, field: str, *, allow_integer: bool = False) -> str:
    if value is None:
        raise AlertNormalizationError("is required", field=field)
    allowed_types = (str, int) if allow_integer else (str,)
    if isinstance(value, bool) or not isinstance(value, allowed_types):
        raise AlertNormalizationError("must be a string", field=field)
    text = str(value).strip()
    if not text:
        raise AlertNormalizationError("must not be empty", field=field)
    return text


def _optional_text(value: Any, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AlertNormalizationError("must be a string", field=field)
    text = str(value).strip()
    return text or None


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AlertNormalizationError("must be an integer", field=field)
    if isinstance(value, str) and not re.fullmatch(r"[+-]?\d+", value.strip()):
        raise AlertNormalizationError("must be an integer", field=field)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise AlertNormalizationError("must be an integer", field=field) from exc


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        text = _required_text(item, field)
        if text not in result:
            result.append(text)
    return result


def _nested_value(mapping: Mapping[str, Any], dotted_path: str) -> Any:
    current: Any = mapping
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return None
        current = current[part]
    return current


def _first(mapping: Mapping[str, Any], *paths: str) -> Any:
    for path in paths:
        value = _nested_value(mapping, path)
        if value is not None and value != "":
            return value
    return None


def _normalization_error(exc: ValidationError, *, prefix: str | None = None) -> AlertNormalizationError:
    first_error = exc.errors(include_url=False)[0]
    location = ".".join(str(part) for part in first_error["loc"])
    field = ".".join(part for part in (prefix, location) if part)
    return AlertNormalizationError(first_error["msg"], field=field or None)


def _endpoint(
    explicit: Any,
    data: Mapping[str, Any],
    *,
    name: str,
    ip_keys: tuple[str, ...],
    port_keys: tuple[str, ...],
) -> NetworkEndpoint | None:
    explicit_mapping = _mapping(explicit, name, required=False)
    ip = _first(explicit_mapping, "ip") or _first(data, *ip_keys)
    port_value = _first(explicit_mapping, "port") or _first(data, *port_keys)
    if ip is None and port_value is None:
        return None
    port = _integer(port_value, f"{name}.port") if port_value is not None else None
    try:
        return NetworkEndpoint(ip=ip, port=port)
    except ValidationError as exc:
        raise _normalization_error(exc, prefix=name) from exc


def normalize_wazuh_alert(raw_event: JsonObject) -> NormalizedAlert:
    """Normalize one raw Wazuh alert without inferring security conclusions."""

    if not isinstance(raw_event, dict):
        raise AlertNormalizationError("payload must be a JSON object")

    agent_raw = _mapping(raw_event.get("agent"), "agent")
    rule_raw = _mapping(raw_event.get("rule"), "rule")
    data_raw = _mapping(raw_event.get("data"), "data", required=False)

    mitre_raw = _mapping(rule_raw.get("mitre", raw_event.get("mitre")), "rule.mitre", required=False)
    mitre_ids = _string_list(mitre_raw.get("id", mitre_raw.get("ids")), "rule.mitre.id")
    invalid_mitre_ids = [technique_id for technique_id in mitre_ids if not MITRE_ID_PATTERN.fullmatch(technique_id)]
    if invalid_mitre_ids:
        raise AlertNormalizationError(
            f"contains invalid MITRE ATT&CK technique ID: {invalid_mitre_ids[0]}",
            field="rule.mitre.id",
        )

    alert_id_value = raw_event.get("alert_id") or raw_event.get("id")
    alert_id = (
        _required_text(alert_id_value, "alert_id", allow_integer=True)
        if alert_id_value is not None
        else None
    )
    if alert_id is None:
        alert_id = f"sha256:{raw_event_fingerprint(raw_event)}"

    decoder_raw = _mapping(raw_event.get("decoder"), "decoder", required=False)
    user = _optional_text(
        raw_event.get("user")
        or _first(
            data_raw,
            "srcuser",
            "dstuser",
            "user",
            "src_user",
            "dst_user",
            "win.eventdata.targetUserName",
            "win.eventdata.subjectUserName",
        ),
        "user",
    )

    try:
        return NormalizedAlert(
            alert_id=alert_id,
            timestamp=_required_text(raw_event.get("timestamp"), "timestamp"),
            agent=Agent(
                id=_required_text(agent_raw.get("id"), "agent.id", allow_integer=True),
                name=_required_text(agent_raw.get("name"), "agent.name"),
                ip=_optional_text(agent_raw.get("ip"), "agent.ip"),
            ),
            rule=Rule(
                id=_required_text(rule_raw.get("id"), "rule.id", allow_integer=True),
                level=_integer(rule_raw.get("level"), "rule.level"),
                description=_required_text(rule_raw.get("description"), "rule.description"),
                groups=_string_list(rule_raw.get("groups"), "rule.groups"),
            ),
            mitre=MitreContext(
                ids=mitre_ids,
                tactics=_string_list(mitre_raw.get("tactic", mitre_raw.get("tactics")), "rule.mitre.tactic"),
                techniques=_string_list(
                    mitre_raw.get("technique", mitre_raw.get("techniques")),
                    "rule.mitre.technique",
                ),
            ),
            source=_endpoint(
                raw_event.get("source"),
                data_raw,
                name="source",
                ip_keys=("srcip", "src_ip", "source_ip"),
                port_keys=("srcport", "src_port", "source_port"),
            ),
            destination=_endpoint(
                raw_event.get("destination"),
                data_raw,
                name="destination",
                ip_keys=("dstip", "dst_ip", "dest_ip", "destination_ip"),
                port_keys=("dstport", "dst_port", "dest_port", "destination_port"),
            ),
            user=user,
            location=_optional_text(raw_event.get("location"), "location"),
            decoder_name=_optional_text(decoder_raw.get("name"), "decoder.name"),
        )
    except ValidationError as exc:
        raise _normalization_error(exc) from exc
