"""Deterministic Investigation Priority Score and display severity."""

ASSET_POINTS = {"low": 0, "normal": 3, "high": 7, "critical": 10}


def clamp(value: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(value, maximum))


def severity_for_level(rule_level: int | None) -> str:
    level = clamp(rule_level or 0, 0, 15)
    if level <= 3:
        return "low"
    if level <= 7:
        return "medium"
    if level <= 11:
        return "high"
    return "critical"


def calculate_priority(rule_level: int | None, repetition_count: int = 1, asset_importance: str = "normal") -> int:
    level = clamp(rule_level or 0, 0, 15)
    rule_component = round(level / 15 * 70)
    repetition_component = min(max(repetition_count - 1, 0) * 5, 20)
    asset_component = ASSET_POINTS.get(asset_importance, ASSET_POINTS["normal"])
    return clamp(rule_component + repetition_component + asset_component, 0, 100)
