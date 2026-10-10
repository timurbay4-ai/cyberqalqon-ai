"""Deterministic query-index values derived from normalized alerts."""

from __future__ import annotations

from app.schemas.alerts import NormalizedAlert


def alert_search_document(alert: NormalizedAlert) -> str:
    """Build a bounded, case-folded search document from typed alert fields."""

    values: list[object | None] = [
        alert.alert_id,
        alert.agent.id,
        alert.agent.name,
        alert.agent.ip,
        alert.rule.id,
        alert.rule.description,
        *alert.rule.groups,
        *alert.mitre.ids,
        *alert.mitre.tactics,
        *alert.mitre.techniques,
        alert.source.ip if alert.source else None,
        alert.source.port if alert.source else None,
        alert.destination.ip if alert.destination else None,
        alert.destination.port if alert.destination else None,
        alert.user,
        alert.location,
        alert.decoder_name,
        alert.windows.event_id if alert.windows else None,
        alert.windows.channel if alert.windows else None,
        alert.windows.provider if alert.windows else None,
        alert.windows.computer if alert.windows else None,
    ]
    return "\n".join(str(value).casefold() for value in values if value is not None)


def mitre_ids_document(alert: NormalizedAlert) -> str:
    """Create an exact-match-safe token string for validated MITRE IDs."""

    return "|" + "|".join(alert.mitre.ids) + "|"
