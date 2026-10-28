"""Bounded, constructor-only diagnostics for disposable applications.

No headers, SQL, parameters, URLs, bodies or exception messages are retained.
Intervals share perf_counter_ns across AnyIO workers; children are NOT additive.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import inspect
import threading
import time
from uuid import uuid4


_current: ContextVar[RequestTrace | None] = ContextVar("disposable_trace", default=None)
_parent: ContextVar[int | None] = ContextVar("disposable_span", default=None)


def current_request_id():
    trace = _current.get()
    return trace.request_id if trace is not None else None


@dataclass
class RequestTrace:
    request_id: str = field(default_factory=lambda: uuid4().hex)
    start_ns: int = field(default_factory=time.perf_counter_ns)
    end_ns: int | None = None
    status: int | None = None
    spans: list[dict] = field(default_factory=list)
    milestones: dict[str, int] = field(default_factory=dict)
    overflow: bool = False
    max_spans: int = 2048
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def export(self):
        with self.lock:
            return {"request_id": self.request_id, "start_ns": self.start_ns,
                    "end_ns": self.end_ns, "status": self.status,
                    "spans": [dict(s) for s in self.spans],
                    "milestones": dict(self.milestones), "incomplete": self.overflow}


class TraceCollector:
    def __init__(self, *, capacity: int = 2048, max_spans: int = 2048):
        if not 1 <= capacity <= 16384 or not 1 <= max_spans <= 8192:
            raise ValueError("Trace bounds invalid")
        self.capacity, self.max_spans = capacity, max_spans
        self._rows: list[RequestTrace] = []
        self._lock = threading.Lock()
        self.dropped = 0

    def begin(self, *, start_ns=None):
        with self._lock:
            if len(self._rows) >= self.capacity:
                self.dropped += 1
                return None
            row = RequestTrace(max_spans=self.max_spans, **({'start_ns':start_ns} if start_ns is not None else {}))
            self._rows.append(row)
            return row

    def export(self):
        with self._lock:
            rows = list(self._rows)
        return {"dropped": self.dropped, "requests": [r.export() for r in rows]}

    def clear_completed(self):
        """Begin an isolated measurement AFTER completed bootstrap/login."""
        with self._lock:
            if any(row.end_ns is None for row in self._rows):
                raise RuntimeError("Cannot clear an active request trace")
            self._rows.clear()
            self.dropped = 0


@contextmanager
def span(label: str, *, start_ns: int | None = None,
         resource: str | None = None, connection_id: int | None = None):
    """Labels MUST be constant developer-owned stage names, never user input."""
    trace = _current.get()
    if trace is None:
        yield
        return
    if not label.isascii() or not label.replace("_", "").isalnum() or len(label) > 80:
        raise ValueError("Invalid trace stage")
    if resource not in (None, "SOURCE", "SIDECAR", "OTHER") or (
        connection_id is not None and (type(connection_id) is not int or not 0 <= connection_id < 2**63)
    ):
        raise ValueError("Invalid trace resource")
    with trace.lock:
        if len(trace.spans) >= trace.max_spans:
            trace.overflow = True
            row = None
        else:
            row = {"id": len(trace.spans), "parent": _parent.get(), "stage": label,
                   "start_ns": start_ns if start_ns is not None else time.perf_counter_ns(),
                   "end_ns": None, "failed": False}
            if resource is not None:
                row["resource"] = resource
                row["connection_id"] = connection_id
            trace.spans.append(row)
    token = _parent.set(row["id"] if row else _parent.get())
    cpu_started = time.thread_time_ns()
    try:
        yield
    except BaseException as exc:
        if row is not None and not isinstance(exc, (StopIteration, StopAsyncIteration)):
            row["failed"] = True
        raise
    finally:
        if row is not None:
            row["end_ns"] = time.perf_counter_ns()
            row["thread_cpu_ns"] = time.thread_time_ns() - cpu_started
        _parent.reset(token)


def stage(label):
    def decorate(function):
        if inspect.iscoroutinefunction(function):
            @wraps(function)
            async def asynchronous(*args, **kwargs):
                with span(label):
                    return await function(*args, **kwargs)
            return asynchronous
        @wraps(function)
        def synchronous(*args, **kwargs):
            with span(label):
                return function(*args, **kwargs)
        return synchronous
    return decorate


async def traced_threadpool(function, *args):
    from starlette.concurrency import run_in_threadpool
    if _current.get() is None:
        return await run_in_threadpool(function, *args)
    queued = time.perf_counter_ns()
    def work():
        with span("INGEST_WORKER_QUEUE", start_ns=queued):
            pass
        with span("INGEST_WORKER"):
            return function(*args)
    return await run_in_threadpool(work)


class TraceMiddleware:
    def __init__(self, app, collector: TraceCollector):
        self.app, self.collector = app, collector

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        trace = self.collector.begin(start_ns=time.perf_counter_ns())
        if trace is None:
            return await self.app(scope, receive, send)
        token, parent = _current.set(trace), _parent.set(None)
        async def traced_send(message):
            if message["type"] == "http.response.start":
                trace.status = message["status"]
                trace.milestones["response_start_ns"] = time.perf_counter_ns()
                message = dict(message)
                message["headers"] = [(k,v) for k,v in message.get("headers", []) if k.lower()!=b"x-perf-trace-id"] + [
                    (b"x-perf-trace-id", trace.request_id.encode("ascii"))]
            with span("ASGI_RESPONSE_SEND"):
                await send(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                trace.milestones["response_complete_ns"] = time.perf_counter_ns()
        try:
            await self.app(scope, receive, traced_send)
        finally:
            trace.end_ns = time.perf_counter_ns()
            _parent.reset(parent)
            _current.reset(token)


def union_ns(intervals):
    """Union (not sum) of half-open monotonic intervals."""
    total, right = 0, None
    for start, end in sorted(intervals):
        if end < start:
            raise ValueError("Reversed trace interval")
        total += max(0, end - (max(right, start) if right is not None else start))
        right = max(end, right) if right is not None else end
    return total


def accounting(row, client_start_ns, client_end_ns):
    """All terms clipped to client observation; exact nanosecond identity."""
    start, end = max(client_start_ns, row["start_ns"]), min(client_end_ns, row["end_ns"])
    if end < start:
        raise ValueError("Trace/client clock mismatch")
    intervals = [(max(start, s["start_ns"]), min(end, s["end_ns"]))
                 for s in row["spans"] if s["end_ns"] is not None
                 and s["end_ns"] >= start and s["start_ns"] <= end]
    measured = union_ns(intervals)
    total = client_end_ns - client_start_ns
    return {"http_total_ns": total, "measured_union_ns": measured,
            "server_unattributed_ns": end - start - measured,
            "transport_or_client_ns": total - (end - start)}
