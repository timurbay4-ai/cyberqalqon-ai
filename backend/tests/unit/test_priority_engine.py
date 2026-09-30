import pytest
from app.detection.priority_engine import calculate_priority, severity_for_level


@pytest.mark.parametrize(
    ("level", "expected"),
    [(0, "low"), (3, "low"), (4, "medium"), (7, "medium"), (8, "high"), (11, "high"), (12, "critical"), (15, "critical")],
)
def test_severity_boundaries(level, expected):
    assert severity_for_level(level) == expected


def test_priority_rule_level_zero_uses_normal_asset_default():
    assert calculate_priority(0) == 3


def test_priority_rule_level_fifteen():
    assert calculate_priority(15) == 73


def test_priority_lower_bound():
    assert calculate_priority(-100, asset_importance="low") == 0


def test_priority_upper_bound():
    assert calculate_priority(100, repetition_count=100, asset_importance="critical") == 100


def test_repetition_component_is_capped():
    assert calculate_priority(0, repetition_count=100) == 23
