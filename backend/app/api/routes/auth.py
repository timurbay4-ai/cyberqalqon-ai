"""Human analyst session and account-administration APIs."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status

from app.api.dependencies.auth import (
    require_admin_mutation,
    require_analyst_admin,
    require_authenticated,
    require_authenticated_mutation,
    require_trusted_origin,
    session_cookie_name,
)
from app.db.auth import (
    AnalystNotFoundError,
    AuthRepository,
    DuplicateUsernameError,
    SelfAdministrationError,
)
from app.schemas.alerts import ErrorResponse
from app.schemas.auth import (
    AnalystCreate,
    AnalystPrincipal,
    AnalystPublic,
    AnalystUpdate,
    LoginRequest,
    SessionResponse,
)


router = APIRouter(prefix="/api/v1/auth", tags=["Analyst authentication"])


def _error(code: str, message: str, *, field: str | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        body["field"] = field
    return body


def _repository(request: Request) -> AuthRepository:
    return request.app.state.auth_repository


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    settings = request.app.state.settings
    response.set_cookie(
        key=session_cookie_name(request),
        value=token,
        max_age=settings.analyst_session_ttl_seconds,
        httponly=True,
        secure=settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.delete_cookie(
        key=session_cookie_name(request),
        httponly=True,
        secure=request.app.state.settings.session_cookie_secure,
        samesite="strict",
        path="/",
    )


@router.post(
    "/login",
    response_model=SessionResponse,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    _: Annotated[None, Depends(require_trusted_origin)],
) -> SessionResponse:
    repository = _repository(request)
    principal = repository.authenticate(payload.username, payload.password)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_error("invalid_credentials", "Invalid username or password"),
            headers={"WWW-Authenticate": "Session"},
        )
    existing = request.cookies.get(session_cookie_name(request))
    if existing:
        repository.invalidate_session(existing)
    session = repository.create_session(principal)
    _set_session_cookie(response, request, session.token)
    return SessionResponse(analyst=principal, csrf_token=session.csrf_token)


@router.get(
    "/session",
    response_model=SessionResponse,
    responses={401: {"model": ErrorResponse}},
)
async def current_session(
    request: Request,
    principal: Annotated[AnalystPrincipal, Depends(require_authenticated)],
) -> SessionResponse:
    session = request.state.analyst_session
    return SessionResponse(analyst=principal, csrf_token=session.csrf_token)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
async def logout(
    request: Request,
    response: Response,
    _: Annotated[AnalystPrincipal, Depends(require_authenticated_mutation)],
) -> Response:
    token = request.cookies.get(session_cookie_name(request))
    if token:
        _repository(request).invalidate_session(token)
    _clear_session_cookie(response, request)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get(
    "/analysts",
    response_model=list[AnalystPublic],
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
async def list_analysts(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_analyst_admin)],
) -> list[AnalystPublic]:
    return _repository(request).list_analysts()


@router.post(
    "/analysts",
    response_model=AnalystPublic,
    status_code=status.HTTP_201_CREATED,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def create_analyst(
    request: Request,
    payload: AnalystCreate,
    _: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
) -> AnalystPublic:
    try:
        return _repository(request).create_analyst(payload)
    except DuplicateUsernameError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error("username_exists", "An analyst with this username already exists", field="username"),
        ) from exc


@router.patch(
    "/analysts/{analyst_id}",
    response_model=AnalystPublic,
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
async def update_analyst(
    request: Request,
    payload: AnalystUpdate,
    analyst_id: Annotated[str, Path(min_length=1, max_length=64)],
    principal: Annotated[AnalystPrincipal, Depends(require_admin_mutation)],
) -> AnalystPublic:
    try:
        return _repository(request).update_analyst(analyst_id, payload, principal.analyst_id)
    except AnalystNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_error("analyst_not_found", "No analyst exists with the requested identifier", field="analyst_id"),
        ) from exc
    except SelfAdministrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_error("self_administration_forbidden", str(exc)),
        ) from exc
