"""Authenticated, read-only agent inventory endpoints."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status

from app.api.dependencies.auth import require_soc_reader
from app.schemas.agents import (
    AgentDetail,
    AgentHealthResponse,
    AgentListResponse,
    WazuhIntegrationStatus,
)
from app.schemas.auth import AnalystPrincipal


router = APIRouter(tags=["Agent Management"])


@router.get("/api/v1/agents", response_model=AgentListResponse)
async def list_agents(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    os: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    connection_status: Annotated[
        Literal["ONLINE", "DISCONNECTED", "NEVER_CONNECTED", "UNKNOWN"] | None,
        Query(),
    ] = None,
    version: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    manager: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    source_type: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    last_seen_minutes: Annotated[int | None, Query(ge=1, le=525_600)] = None,
    sort: Annotated[
        Literal["name", "agent_id", "status", "last_seen", "version"], Query()
    ] = "name",
    order: Annotated[Literal["asc", "desc"], Query()] = "asc",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> AgentListResponse:
    return request.app.state.agent_repository.list_agents(
        search=search,
        os_platform=os,
        connection_status=connection_status,
        version=version,
        manager=manager,
        source_type=source_type,
        last_seen_minutes=last_seen_minutes,
        sort=sort,
        order=order,
        limit=limit,
        offset=offset,
    )


@router.get("/api/v1/agents/{agent_key}", response_model=AgentDetail)
async def get_agent(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    agent_key: Annotated[str, Path(min_length=16, max_length=96, pattern=r"^[a-z]+_[0-9a-f]{48}$")],
) -> AgentDetail:
    item = request.app.state.agent_repository.get_agent(agent_key)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "agent_not_found", "message": "Agent was not found"},
        )
    return item


@router.get("/api/v1/agents/{agent_key}/health", response_model=AgentHealthResponse)
async def get_agent_health(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    agent_key: Annotated[str, Path(min_length=16, max_length=96, pattern=r"^[a-z]+_[0-9a-f]{48}$")],
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> AgentHealthResponse:
    item = request.app.state.agent_repository.health(agent_key, limit=limit)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "agent_not_found", "message": "Agent was not found"},
        )
    return item


@router.get(
    "/api/v1/integrations/wazuh/status",
    response_model=WazuhIntegrationStatus,
)
async def wazuh_integration_status(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> WazuhIntegrationStatus:
    return request.app.state.agent_repository.integration_status()
