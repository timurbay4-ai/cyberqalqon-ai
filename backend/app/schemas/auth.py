"""Public contracts for human analyst authentication and authorization."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.alerts import StrictModel


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$")
Username = Annotated[str, Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN.pattern)]
Password = Annotated[str, Field(min_length=12, max_length=128)]


class AnalystRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    SOC_READ = "soc:read"
    ALERT_WRITE = "alert:write"
    INCIDENT_WRITE = "incident:write"
    ANALYST_MANAGE = "analyst:manage"


ROLE_PERMISSIONS: dict[AnalystRole, tuple[Permission, ...]] = {
    AnalystRole.ADMIN: (
        Permission.SOC_READ,
        Permission.ALERT_WRITE,
        Permission.INCIDENT_WRITE,
        Permission.ANALYST_MANAGE,
    ),
    AnalystRole.ANALYST: (
        Permission.SOC_READ,
        Permission.ALERT_WRITE,
        Permission.INCIDENT_WRITE,
    ),
    AnalystRole.VIEWER: (Permission.SOC_READ,),
}


class CredentialModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginRequest(CredentialModel):
    username: Username
    password: str = Field(min_length=1, max_length=1024)


class AnalystCreate(CredentialModel):
    username: Username
    display_name: str = Field(min_length=1, max_length=128)
    password: Password
    role: AnalystRole

    @field_validator("display_name")
    @classmethod
    def display_name_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("display_name must not be blank")
        return normalized


class AnalystUpdate(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    role: AnalystRole | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def at_least_one_change(self) -> "AnalystUpdate":
        if self.display_name is None and self.role is None and self.is_active is None:
            raise ValueError("At least one analyst field must be supplied")
        return self


class AnalystPublic(StrictModel):
    analyst_id: str
    username: str
    display_name: str
    role: AnalystRole
    is_active: bool
    created_at: datetime
    updated_at: datetime


class AnalystPrincipal(StrictModel):
    analyst_id: str
    username: str
    display_name: str
    role: AnalystRole
    permissions: list[Permission]

    @property
    def audit_display(self) -> str:
        return f"{self.display_name} ({self.username})"


class SessionResponse(StrictModel):
    analyst: AnalystPrincipal
    csrf_token: str


class PasswordChange(CredentialModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: Password

    @model_validator(mode="after")
    def passwords_must_differ(self) -> "PasswordChange":
        if self.current_password == self.new_password:
            raise ValueError("new_password must differ from current_password")
        return self


class AnalystSessionStatus(StrictModel):
    active_sessions: int = Field(ge=1, le=10)
    current_expires_at: datetime
