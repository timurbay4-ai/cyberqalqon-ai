"""Validated, isolated analyst preference contracts."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator

from app.schemas.alert_workflows import AlertWorkflowSort
from app.schemas.alerts import StrictModel


DiscoverColumn = Literal["time", "source", "host", "identity", "rule", "event"]
DEFAULT_DISCOVER_COLUMNS: list[DiscoverColumn] = [
    "time", "source", "host", "identity", "rule", "event"
]


class DashboardRange(str, Enum):
    DAY = "24h"
    WEEK = "7d"
    MONTH = "30d"


class TableDensity(str, Enum):
    COMFORTABLE = "COMFORTABLE"
    COMPACT = "COMPACT"


class TimeDisplay(str, Enum):
    LOCAL = "LOCAL"
    UTC = "UTC"
    RELATIVE = "RELATIVE"


class AnalystPreferences(StrictModel):
    dashboard_range: DashboardRange = DashboardRange.DAY
    discover_page_size: Literal[25, 50, 100] = 25
    alert_page_size: Literal[25, 50, 100] = 25
    incident_page_size: Literal[25, 50, 100] = 25
    table_density: TableDensity = TableDensity.COMFORTABLE
    time_display: TimeDisplay = TimeDisplay.LOCAL
    alert_default_sort: AlertWorkflowSort = AlertWorkflowSort.TIME_DESC
    discover_columns: list[DiscoverColumn] = Field(
        default_factory=lambda: list(DEFAULT_DISCOVER_COLUMNS), min_length=2, max_length=6
    )
    version: int = Field(ge=1)

    @field_validator("discover_columns")
    @classmethod
    def valid_columns(cls, value: list[DiscoverColumn]) -> list[DiscoverColumn]:
        if len(value) != len(set(value)):
            raise ValueError("discover_columns must be unique")
        if not {"time", "event"}.issubset(value):
            raise ValueError("time and event columns are required")
        return value


class AnalystPreferencesUpdate(StrictModel):
    dashboard_range: DashboardRange
    discover_page_size: Literal[25, 50, 100]
    alert_page_size: Literal[25, 50, 100]
    incident_page_size: Literal[25, 50, 100]
    table_density: TableDensity
    time_display: TimeDisplay
    alert_default_sort: AlertWorkflowSort
    discover_columns: list[DiscoverColumn] = Field(min_length=2, max_length=6)
    expected_version: int = Field(ge=1)

    @field_validator("discover_columns")
    @classmethod
    def valid_columns(cls, value: list[DiscoverColumn]) -> list[DiscoverColumn]:
        if len(value) != len(set(value)):
            raise ValueError("discover_columns must be unique")
        if not {"time", "event"}.issubset(value):
            raise ValueError("time and event columns are required")
        return value
