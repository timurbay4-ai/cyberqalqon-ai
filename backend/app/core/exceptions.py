"""Domain exceptions and stable public error responses."""

from dataclasses import dataclass


@dataclass
class AppError(Exception):
    code: str
    message: str
    status_code: int


class IncidentNotFoundError(AppError):
    def __init__(self) -> None:
        super().__init__("INCIDENT_NOT_FOUND", "Incident not found", 404)


class InvalidAlertError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__("INVALID_WAZUH_ALERT", message, 422)
