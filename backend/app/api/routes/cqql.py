"""Authenticated CQQL v1 search, field catalog, and bounded analytics APIs."""

from __future__ import annotations

import asyncio
import csv
import io
import threading
from contextlib import suppress
from datetime import timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_soc_reader
from app.db.cqql import (
    CQQL_MAX_CONCURRENT_QUERIES,
    CQQL_QUERY_DEADLINE_MS,
    CQQLExecutionError,
    CQQLQueryBusyError,
    CQQLQueryCancelledError,
    CQQLQueryTimeoutError,
    InvalidCQQLCursorError,
)
from app.schemas.auth import AnalystPrincipal
from app.schemas.cqql import (
    CQQLAnalyticsRequest,
    CQQLAnalyticsResponse,
    CQQLCatalogLimits,
    CQQLExportRequest,
    CQQLFieldCatalogResponse,
    CQQLFieldDescriptor,
    CQQLSearchMetadata,
    CQQLSearchPage,
    CQQLSearchRequest,
    CQQLSearchResponse,
)
from app.services.cqql import (
    MAX_AST_DEPTH,
    MAX_BOOLEAN_CLAUSES,
    MAX_QUERY_LENGTH,
    MAX_TOKENS,
    CQQLQueryError,
    compile_cqql,
    public_field_catalog,
)


router = APIRouter(prefix="/api/v1/siem/search", tags=["SIEM Search"])


def _error(
    code: str,
    message: str,
    *,
    field: str | None = None,
    position: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {"code": code, "message": message}
    if field is not None:
        result["field"] = field
    if position is not None:
        result["position"] = position
    return result


def _compile(query: str):  # type: ignore[no-untyped-def]
    try:
        return compile_cqql(query)
    except CQQLQueryError as exc:
        raise HTTPException(
            422,
            detail=_error(
                exc.code,
                exc.message,
                field=exc.field or "query",
                position=exc.position,
            ),
        ) from exc


def _execution_error(exc: Exception) -> HTTPException:
    if isinstance(exc, InvalidCQQLCursorError):
        return HTTPException(422, detail=_error("invalid_cursor", str(exc), field="cursor"))
    if isinstance(exc, CQQLQueryTimeoutError):
        return HTTPException(408, detail=_error("query_timeout", str(exc), field="query"))
    if isinstance(exc, CQQLQueryCancelledError):
        return HTTPException(499, detail=_error("query_cancelled", str(exc), field="query"))
    if isinstance(exc, CQQLQueryBusyError):
        return HTTPException(429, detail=_error("query_capacity_exceeded", str(exc)))
    if isinstance(exc, CQQLExecutionError):
        return HTTPException(503, detail=_error("query_unavailable", str(exc)))
    raise exc


async def _wait_for_disconnect(request: Request) -> None:
    """Wait for the transport's ASGI disconnect without zero-timeout polling.

    Starlette's ``is_disconnected`` probe uses a pre-cancelled receive scope.
    On the Windows/asyncio transport that probe can miss an already queued
    disconnect.  CQQL request bodies have been parsed before route execution,
    so a dedicated receive task can safely wait for the terminal ASGI event.
    """

    receive = getattr(request, "receive", None)
    if callable(receive):
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
    # Lightweight request doubles used by unit tests do not expose receive().
    while not await request.is_disconnected():
        await asyncio.sleep(0.02)


async def _run_cancellable(request: Request, function, /, *args, **kwargs):  # type: ignore[no-untyped-def]
    """Propagate an ASGI disconnect into one connection-local SQLite worker."""

    cancel_event = threading.Event()
    worker = asyncio.create_task(
        run_in_threadpool(function, *args, cancel_event=cancel_event, **kwargs)
    )
    disconnect = asyncio.create_task(_wait_for_disconnect(request))
    try:
        done, _ = await asyncio.wait(
            {worker, disconnect}, return_when=asyncio.FIRST_COMPLETED
        )
        if worker in done:
            disconnect.cancel()
            with suppress(asyncio.CancelledError):
                await disconnect
            return await worker
        cancel_event.set()
        with suppress(CQQLQueryCancelledError):
            await worker
        raise CQQLQueryCancelledError("CQQL query was cancelled by the client")
    except asyncio.CancelledError:
        cancel_event.set()
        with suppress(Exception, asyncio.CancelledError):
            await asyncio.shield(worker)
        raise
    finally:
        if not disconnect.done():
            disconnect.cancel()
        with suppress(asyncio.CancelledError):
            await disconnect


CQQL_EXPORT_BYTE_LIMIT = 1_000_000


def _safe_csv_cell(value: object) -> object:
    if value is None:
        return ""
    if hasattr(value, "isoformat"):
        value = value.isoformat()  # type: ignore[union-attr]
    if isinstance(value, str) and value.lstrip(" \t\r\n")[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def _render_csv(items: list[object], fields: list[str]) -> tuple[bytes, int, bool]:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(fields)
    encoded_size = len(output.getvalue().encode("utf-8"))
    rows_written = 0
    for item in items:
        row_output = io.StringIO(newline="")
        row_writer = csv.writer(row_output, lineterminator="\r\n")
        row_writer.writerow([_safe_csv_cell(getattr(item, field)) for field in fields])
        rendered = row_output.getvalue()
        row_bytes = rendered.encode("utf-8")
        if encoded_size + len(row_bytes) > CQQL_EXPORT_BYTE_LIMIT:
            break
        output.write(rendered)
        encoded_size += len(row_bytes)
        rows_written += 1
    return output.getvalue().encode("utf-8"), rows_written, rows_written < len(items)


@router.get("/fields", response_model=CQQLFieldCatalogResponse)
async def cqql_fields(
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> CQQLFieldCatalogResponse:
    return CQQLFieldCatalogResponse(
        fields=[CQQLFieldDescriptor.model_validate(item) for item in public_field_catalog()],
        limits=CQQLCatalogLimits(
            maximum_query_length=MAX_QUERY_LENGTH,
            maximum_tokens=MAX_TOKENS,
            maximum_ast_depth=MAX_AST_DEPTH,
            maximum_boolean_clauses=MAX_BOOLEAN_CLAUSES,
            maximum_page_size=100,
            maximum_time_range_days=31,
            execution_deadline_ms=CQQL_QUERY_DEADLINE_MS,
            maximum_concurrent_queries=CQQL_MAX_CONCURRENT_QUERIES,
        ),
    )


@router.post("", response_model=CQQLSearchResponse, response_model_exclude_none=True)
async def cqql_search(
    request: Request,
    payload: CQQLSearchRequest,
    response: Response,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> CQQLSearchResponse:
    compiled = _compile(payload.query)
    try:
        result = await _run_cancellable(
            request,
            request.app.state.cqql_search_repository.search,
            compiled,
            start_time=payload.start_time,
            end_time=payload.end_time,
            sort=payload.sort,
            limit=payload.limit,
            cursor=payload.cursor,
        )
    except (InvalidCQQLCursorError, CQQLQueryTimeoutError, CQQLQueryBusyError, CQQLQueryCancelledError, CQQLExecutionError) as exc:
        raise _execution_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-CQQL-Version"] = "cqql-v1"
    warnings = ["Exact result count is intentionally not computed for CQQL searches."]
    if compiled.uses_fts:
        warnings.append("Full-text input was reduced to bounded literal FTS5 tokens.")
    return CQQLSearchResponse(
        items=result.items,
        page=CQQLSearchPage(
            limit=payload.limit,
            next_cursor=result.next_cursor,
            sort=payload.sort,
        ),
        metadata=CQQLSearchMetadata(
            execution_ms=result.execution_ms,
            warnings=warnings,
            truncated=result.truncated,
            data_freshness=result.data_freshness,
            clause_count=compiled.clause_count,
            ast_depth=compiled.depth,
            fts_used=compiled.uses_fts,
            cost_class=compiled.cost_class,
            plan_class=compiled.plan_class,
            planner_strategy=compiled.planner_strategy,
            diagnostic_reasons=list(compiled.diagnostic_reasons),
        ),
    )


@router.post("/analytics", response_model=CQQLAnalyticsResponse)
async def cqql_analytics(
    request: Request,
    payload: CQQLAnalyticsRequest,
    response: Response,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> CQQLAnalyticsResponse:
    compiled = _compile(payload.query)
    try:
        result = await _run_cancellable(
            request,
            request.app.state.cqql_search_repository.analytics,
            compiled,
            start_time=payload.start_time,
            end_time=payload.end_time,
            group_by=list(payload.group_by),
            top_n=payload.top_n,
            interval=payload.interval,
        )
    except (CQQLQueryTimeoutError, CQQLQueryBusyError, CQQLQueryCancelledError, CQQLExecutionError) as exc:
        raise _execution_error(exc) from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-CQQL-Version"] = "cqql-v1"
    return CQQLAnalyticsResponse(
        execution_ms=result.execution_ms,
        matching_events=result.matching_events,
        groups=result.groups,
        time_series=result.time_series,
        clause_count=compiled.clause_count,
        fts_used=compiled.uses_fts,
    )


@router.post("/export.csv", response_class=Response)
async def cqql_export_csv(
    request: Request,
    payload: CQQLExportRequest,
    principal: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
) -> Response:
    compiled = _compile(payload.query)
    try:
        result = await _run_cancellable(
            request,
            request.app.state.cqql_search_repository.export,
            compiled,
            start_time=payload.start_time,
            end_time=payload.end_time,
            sort=payload.sort,
            limit=payload.limit,
        )
    except (CQQLQueryTimeoutError, CQQLQueryBusyError, CQQLQueryCancelledError, CQQLExecutionError) as exc:
        raise _execution_error(exc) from exc

    fields = list(payload.fields)
    content, rows_written, byte_truncated = _render_csv(result.items, fields)
    truncated = result.truncated or byte_truncated
    stamp = payload.end_time.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    request.app.state.audit_repository.append(
        action="CQQL_RESULTS_EXPORTED",
        actor_id=principal.analyst_id,
        actor_display=principal.audit_display,
        target_type="cqql_export",
        target_id=f"cqql-{compiled.fingerprint[:16]}.csv",
        details={
            "query_fingerprint": compiled.fingerprint,
            "clause_count": compiled.clause_count,
            "cost_class": compiled.cost_class,
            "planner_strategy": compiled.planner_strategy,
            "start_time": payload.start_time.isoformat(),
            "end_time": payload.end_time.isoformat(),
            "sort": payload.sort,
            "requested_limit": payload.limit,
            "rows_exported": rows_written,
            "bytes_exported": len(content),
            "truncated": truncated,
            "fields": fields,
        },
    )
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": f"attachment; filename=cyberqalqon-cqql-{stamp}.csv",
            "X-Content-Type-Options": "nosniff",
            "X-CQQL-Version": "cqql-v1",
            "X-CQQL-Export-Rows": str(rows_written),
            "X-CQQL-Export-Truncated": str(truncated).lower(),
        },
    )
