"""Wazuh ingestion request validation."""

from typing import Any
from pydantic import RootModel, field_validator


class WazuhAlert(RootModel[dict[str, Any]]):
    @field_validator("root")
    @classmethod
    def require_json_object(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value
