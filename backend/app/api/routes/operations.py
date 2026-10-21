"""Authenticated read-only operational diagnostics."""

from __future__ import annotations

import asyncio
import threading
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from app.api.dependencies.auth import require_soc_reader
from app.db.operations import (
    OperationalQueryCancelled,
    OperationalQueryError,
    OperationalQueryTimeout,
)
from app.schemas.auth import AnalystPrincipal
from app.schemas.operations import IngestionPerformanceSummary, OperationalOverview


router = APIRouter(prefix="/api/v1/operations", tags=["Operations"])


async def _bounded_overview(request: Request, *, event_limit: int) -> OperationalOverview:
    cancel_event = threading.Event()
    repository = request.app.state.operational_repository
    task = asyncio.create_task(
        run_in_threadpool(
            repository.overview,
            limit=event_limit,
            cancel_event=cancel_event,
            deadline_seconds=repository.overview_query_deadline_seconds,
        )
    )
    try:
        while not task.done():
            await asyncio.wait({task}, timeout=0.05)
            if not task.done() and await request.is_disconnected():
                cancel_event.set()
                done, _ = await asyncio.wait({task}, timeout=0.25)
                for finished in done:
                    if not finished.cancelled():
                        finished.exception()
                raise HTTPException(
                    status_code=499,
                    detail={
                        "code": "OPERATIONS_CLIENT_DISCONNECTED",
                        "message": "Operations query cancelled after client disconnect.",
                        "retryable": True,
                    },
                )
        return await task
    except asyncio.CancelledError:
        cancel_event.set()

        def consume_result(finished: asyncio.Task[OperationalOverview]) -> None:
            if not finished.cancelled():
                finished.exception()

        task.add_done_callback(consume_result)
        raise
    except OperationalQueryCancelled as error:
        raise HTTPException(
            status_code=499,
            detail={
                "code": "OPERATIONS_QUERY_CANCELLED",
                "message": "Operations query was cancelled.",
                "retryable": True,
            },
        ) from error
    except OperationalQueryError as error:
        code = (
            "OPERATIONS_QUERY_TIMEOUT"
            if isinstance(error, OperationalQueryTimeout)
            else "OPERATIONS_QUERY_UNAVAILABLE"
        )
        raise HTTPException(
            status_code=503,
            detail={
                "code": code,
                "message": "Operations snapshot is temporarily unavailable.",
                "retryable": True,
            },
            headers={"Retry-After": "2"},
        ) from error


@router.get("/overview", response_model=OperationalOverview)
async def operational_overview(
    request: Request,
    _: Annotated[AnalystPrincipal, Depends(require_soc_reader)],
    event_limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> OperationalOverview:
    # Each read owns a read-only SQLite connection with a hard deadline and
    # progress-handler interrupt. The single-flight repository bounds duplicate
    # cold work while this coroutine propagates disconnect cancellation.
    overview = await _bounded_overview(request, event_limit=event_limit)
    return overview.model_copy(
        update={
            "ingestion_performance": IngestionPerformanceSummary.model_validate(
                request.app.state.ingestion_metrics.snapshot()
            )
        }
    )
