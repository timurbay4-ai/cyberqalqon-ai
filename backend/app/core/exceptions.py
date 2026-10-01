"""Domain exceptions and stable public error responses."""

from dataclasses import dataclass
from typing import Mapping


@dataclass
class AppError(Exception):
    code: str
    message: str
    status_code: int
    headers: Mapping[str, str] | None = None


class IncidentNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("INCIDENT_NOT_FOUND", "Incident not found", 404)


class InvalidAlertError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__("INVALID_WAZUH_ALERT", message, 422)


class AuthenticationError(AppError):
    def __init__(self) -> None:
        super().__init__(
            "UNAUTHORIZED",
            "Valid bearer token required",
            401,
            {"WWW-Authenticate": "Bearer"},
        )
