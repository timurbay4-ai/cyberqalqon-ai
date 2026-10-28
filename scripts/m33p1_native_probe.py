"""User-level, own-process diagnostic observations; never an app/runtime switch."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
import threading
import time

from app.services.request_tracing import TraceMiddleware, current_request_id


class OwnProcessCounters:
    """Fixed Win32 APIs and pseudo handles only; no process enumeration/elevation."""
    def __init__(self):
        self.available = os.name == 'nt'
        if not self.available:
            return
        self.library = ctypes.WinDLL('kernel32', use_last_error=True)
        self.library.GetCurrentProcess.restype = wintypes.HANDLE
        self.library.GetCurrentThread.restype = wintypes.HANDLE
        self.library.QueryThreadCycleTime.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_ulonglong)]
        self.library.QueryThreadCycleTime.restype = wintypes.BOOL
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ('read_operations', 'write_operations', 'other_operations',
                         'read_bytes', 'write_bytes', 'other_bytes')]
        self.io_type = IO
        self.library.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO)]
        self.library.GetProcessIoCounters.restype = wintypes.BOOL

    def snapshot(self):
        if not self.available:
            return None
        cycles, io = ctypes.c_ulonglong(), self.io_type()
        if not self.library.QueryThreadCycleTime(self.library.GetCurrentThread(), ctypes.byref(cycles)):
            raise OSError('Own-thread cycle observation unavailable')
        if not self.library.GetProcessIoCounters(self.library.GetCurrentProcess(), ctypes.byref(io)):
            raise OSError('Own-process I/O observation unavailable')
        return {'thread_cycles': cycles.value, **{name: getattr(io, name) for name, _ in io._fields_}}


def counter_delta(before, after):
    if before is None or after is None:
        return None
    delta = {key: after[key] - before[key] for key in before}
    if any(value < 0 for value in delta.values()):
        raise ValueError('Non-monotonic own-process counters')
    return delta


@contextmanager
def installed(*, counters=None, capacity=32768):
    """Reversible diagnostic-only hooks. SQL/payloads/paths are never exported.

    Native-call wall boundaries include wrapper/trace instrumentation. I/O is shared
    across this process and cannot prove per-request filesystem latency or fsync.
    """
    import m33_request_trace as tracing
    if type(capacity) is not int or not 1 <= capacity <= 65536:
        raise ValueError('Invalid diagnostic capacity')
    counter = counters or OwnProcessCounters()
    report = {'native_calls': [], 'event_loop_lateness': [], 'overflow': False,
              'counter_scope': 'OWN_PROCESS_IO_SHARED_AND_OWN_THREAD_CYCLES',
              'context_switches': None, 'fsync_syscall_latency': None,
              'lock_wait_exclusive': None, 'cycle_time_to_ms_conversion': 'PROHIBITED'}
    lock = threading.Lock()
    original_span, original_call = tracing.sql_span, TraceMiddleware.__call__

    def append(key, row):
        with lock:
            if len(report[key]) < capacity:
                report[key].append(row)
            else:
                report['overflow'] = True

    @contextmanager
    def observed_sql(connection, label):
        request_id = current_request_id()
        if request_id is None:
            with original_span(connection, label):
                yield
            return
        before = counter.snapshot()
        start = time.perf_counter_ns()
        failed = False
        in_transaction = connection.in_transaction
        try:
            with original_span(connection, label):
                yield
        except (StopIteration, StopAsyncIteration):
            raise
        except BaseException:
            failed = True
            raise
        finally:
            end = time.perf_counter_ns()
            after = counter.snapshot()
            try:
                transaction_after = connection.in_transaction
            except Exception:
                transaction_after = None  # Closed connection, no fabricated state.
            append('native_calls', {'request_id': request_id, 'connection_id': connection.diagnostic_id,
                   'resource': connection.diagnostic_resource, 'thread_id': threading.get_native_id(),
                   'stage': label, 'start_ns': start, 'end_ns': end, 'failed': failed,
                   'transaction_before': in_transaction, 'transaction_after': transaction_after,
                   'counter_delta': counter_delta(before, after)})

    async def observed_call(self, scope, receive, send):
        if scope['type'] != 'http':
            return await original_call(self, scope, receive, send)
        # Instrument the already-created request context via send, and use only a
        # bounded final list. A heartbeat's own lateness is not additive CPU work.
        observed_ids = set()
        async def observed_send(message):
            request_id = current_request_id()
            if request_id:
                observed_ids.add(request_id)
            await send(message)
        delays = []
        first_deadline = time.perf_counter_ns() + 2_000_000
        async def heartbeat():
            expected = first_deadline
            while True:
                await asyncio.sleep(max(0, (expected-time.perf_counter_ns())/1e9))
                actual = time.perf_counter_ns()
                if len(delays) < 1024:
                    delays.append({'expected_ns': expected, 'actual_ns': actual})
                else:
                    report['overflow'] = True
                expected = actual + 2_000_000
        task = asyncio.create_task(heartbeat())
        try:
            return await original_call(self, scope, receive, observed_send)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            for request_id in observed_ids:
                for row in delays:
                    append('event_loop_lateness', {'request_id': request_id, **row})

    tracing.sql_span = observed_sql
    TraceMiddleware.__call__ = observed_call
    try:
        yield report
    finally:
        tracing.sql_span, TraceMiddleware.__call__ = original_span, original_call
