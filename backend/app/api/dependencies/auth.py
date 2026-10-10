"""Server-enforced analyst authentication, authorization, origin, and CSRF checks."""

from __future__ import annotations

import hmac
from typing import Any

from fastapi import Header, HTTPException, Request, status

from app.db.auth import AuthRepository, SessionCredentials
from app.schemas.auth import AnalystPrincipal, Permission


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def session_cookie_name(request: Request) -> str:
    return (
        "__Host-cyberqalqon_session"
        if request.app.state.settings.session_cookie_secure
        else "cyberqalqon_session"
    )


def _repository(request: Request) -> AuthRepository:
    return request.app.state.auth_repository


def _session(request: Request) -> SessionCredentials:
    cached = getattr(request.state, "analyst_session", None)
    if cached is not None:
        return cached
    token = request.cookies.get(session_cookie_name(request))
    session = _repository(request).resolve_session(token) if token else None
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_error("authentication_required", "A valid analyst session is required"),
            headers={"WWW-Authenticate": "Session"},
        )
    request.state.analyst_session = session
    return session


def require_authenticated(request: Request) -> AnalystPrincipal:
    return _session(request).principal


def _require_permission(request: Request, permission: Permission) -> AnalystPrincipal:
    principal = require_authenticated(request)
    if permission not in principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return principal


def require_soc_reader(request: Request) -> AnalystPrincipal:
    return _require_permission(request, Permission.SOC_READ)


def require_incident_writer(request: Request) -> AnalystPrincipal:
    return _require_permission(request, Permission.INCIDENT_WRITE)


def require_alert_writer(request: Request) -> AnalystPrincipal:
    return _require_permission(request, Permission.ALERT_WRITE)


def require_analyst_admin(request: Request) -> AnalystPrincipal:
    return _require_permission(request, Permission.ANALYST_MANAGE)


def require_trusted_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    trusted = request.app.state.settings.cors_origins
    if origin is None or origin.rstrip("/") not in trusted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error("untrusted_origin", "The request origin is not allowed"),
        )


def _require_csrf(request: Request, csrf_token: str | None) -> SessionCredentials:
    session = _session(request)
    require_trusted_origin(request)
    if csrf_token is None or not hmac.compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error("invalid_csrf_token", "A valid CSRF token is required"),
        )
    return session


def require_authenticated_mutation(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    return _require_csrf(request, x_csrf_token).principal


def require_soc_mutation(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    session = _require_csrf(request, x_csrf_token)
    if Permission.SOC_READ not in session.principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return session.principal


def require_alert_mutation(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    session = _require_csrf(request, x_csrf_token)
    if Permission.ALERT_WRITE not in session.principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return session.principal


def require_ai_analysis(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    session = _require_csrf(request, x_csrf_token)
    if Permission.SOC_READ not in session.principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return session.principal


def require_incident_mutation(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    session = _require_csrf(request, x_csrf_token)
    if Permission.INCIDENT_WRITE not in session.principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return session.principal

def require_admin_mutation(
    request: Request,
    x_csrf_token: str | None = Header(default=None),
) -> AnalystPrincipal:
    session = _require_csrf(request, x_csrf_token)
    if Permission.ANALYST_MANAGE not in session.principal.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_error(
                "permission_denied",
                "The authenticated analyst lacks permission for this operation",
            ),
        )
    return session.principal
