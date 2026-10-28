"""Diagnostic hooks installed only by the synthetic M33 P0 benchmark process."""
from contextlib import contextmanager, ExitStack
import sqlite3
import time
import gc
from itertools import count
from pathlib import Path

from app.services.request_tracing import span, stage, current_request_id
import profile_m31_baseline as old

_connection_ids = count()


def sql_span(connection, label):
    return span(label, resource=connection.diagnostic_resource, connection_id=connection.diagnostic_id)


def classify(sql):
    # SQL is inspected transiently, NEVER exported (nor its parameters).
    text = sql.strip().upper()
    if text.startswith('BEGIN'): return 'SQLITE_BEGIN_LOCK_INCLUSIVE'
    if text.startswith('INSERT INTO SECURITY_EVENTS'): return 'INSERT_INCLUDING_FTS'
    if text.startswith('DELETE FROM SECURITY_EVENTS'): return 'RETENTION_DELETE_INCLUDING_FTS'
    if text.startswith('SELECT EVENT_ID, DEDUPLICATION_ID'): return 'IDEMPOTENCY_LOOKUP'
    if text.startswith('PRAGMA'): return 'SQLITE_CONNECTION_PRAGMA'
    if text.startswith('INSERT') or text.startswith('UPDATE') or text.startswith('DELETE'): return 'SQLITE_OTHER_WRITE'
    return 'SQLITE_OTHER_READ'


class TraceCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        label = classify(sql)
        start = time.perf_counter()
        try:
            with sql_span(self.connection, label):
                return super().execute(sql, parameters)
        except sqlite3.Error as exc:
            with old.LOCK: old.ERRORS[getattr(exc, 'sqlite_errorname', type(exc).__name__)] += 1
            raise
        finally:
            with old.LOCK: old.STAGES[label].append((time.perf_counter()-start)*1000)

    def executemany(self, sql, seq):
        with sql_span(self.connection, classify(sql)):
            return super().executemany(sql, seq)

    def fetchone(self):
        with sql_span(self.connection, 'SQLITE_FETCH_ONE'):
            return super().fetchone()

    def fetchall(self):
        with sql_span(self.connection, 'SQLITE_FETCH_ALL'):
            return super().fetchall()

    def __next__(self):
        with sql_span(self.connection, 'SQLITE_FETCH_NEXT'):
            return super().__next__()


class TraceConnection(sqlite3.Connection):
    def __init__(self, database, *args, **kwargs):
        self.diagnostic_id = next(_connection_ids)
        self.diagnostic_resource = 'SIDECAR' if 'history' in Path(str(database)).name else 'SOURCE'
        super().__init__(database, *args, **kwargs)

    def cursor(self, factory=TraceCursor):
        return super().cursor(factory)

    def execute(self, sql, parameters=()):
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql, parameters):
        return self.cursor().executemany(sql, parameters)

    def commit(self):
        with sql_span(self, 'SQLITE_EXPLICIT_COMMIT'):
            return self._commit_native()

    def _commit_native(self):
        return super().commit()

    def rollback(self):
        with sql_span(self, 'SQLITE_EXPLICIT_ROLLBACK'):
            return super().rollback()

    def __exit__(self, *args):
        label=('SQLITE_CONTEXT_ROLLBACK' if args[0] is not None else 'SQLITE_CONTEXT_COMMIT') if self.in_transaction else 'SQLITE_CONTEXT_NO_TRANSACTION'
        with sql_span(self, label):
            return super().__exit__(*args)

    def close(self):
        with sql_span(self, 'SQLITE_CLOSE_CHECKPOINT_INCLUSIVE'):
            return super().close()


@contextmanager
def installed():
    """Reversible process-local hooks; never change production connection policy."""
    from app.db.events import EventRepository
    from app.db.shadow_history import ShadowHistoryRepository
    from app.services.identity_resolution import IdentityResolver
    from app.db.cqql import CQQLSearchRepository
    from app.services.shadow_history import ShadowHistoryService
    from app.services.shadow_scheduling import ShadowScheduler
    import fastapi.dependencies.utils as dependencies
    import fastapi.routing as routing
    connect = sqlite3.connect
    def traced_connect(*args, **kwargs):
        kwargs.setdefault('factory', TraceConnection)
        with span('SQLITE_OPEN'):
            return connect(*args, **kwargs)
    wrapped = []
    for owner, name, label in (
        (EventRepository, '_connect', 'INGEST_CONNECTION'),
        (EventRepository, 'ingest', 'INGEST_REPOSITORY'),
        (EventRepository, '_insert_event_row', 'EVENT_INSERT_WITH_FTS'),
        (EventRepository, '_enforce_retention', 'RETENTION'),
        (EventRepository, '_select_retention_candidates', 'RETENTION_CANDIDATES'),
        (ShadowHistoryRepository, '_connect', 'SIDECAR_CONNECTION'),
        (ShadowHistoryRepository, 'complete', 'SIDECAR_FINDING_TRANSACTION'),
        (ShadowHistoryRepository, 'seal', 'SIDECAR_SNAPSHOT_TRANSACTION'),
        (IdentityResolver, 'assess', 'IDENTITY_RESOLUTION'),
        (CQQLSearchRepository, '_acquire_slot', 'CQQL_SLOT_ADMISSION'),
        (CQQLSearchRepository, '_connect', 'CQQL_CONNECTION'),
        (CQQLSearchRepository, 'search', 'CQQL_REPOSITORY'),
        (CQQLSearchRepository, 'analytics', 'ANALYTICS_REPOSITORY'),
        (ShadowHistoryService, 'evaluate', 'DURABLE_SHADOW_WORKER'),
        (routing, 'solve_dependencies', 'AUTH_AND_DEPENDENCY_VALIDATION'),
        (routing, 'serialize_response', 'RESPONSE_SERIALIZATION'),
        (routing._IncludedRouter, 'effective_candidates', 'ROUTING_EFFECTIVE_CANDIDATES'),
        (routing._IncludedRouter, '_build_effective_context', 'ROUTING_COLD_CONTEXT_BUILD'),
    ):
        original = getattr(owner, name)
        wrapped.append((owner, name, original))
        setattr(owner, name, stage(label)(original))
    dependency_pool = dependencies.run_in_threadpool
    async def dependency_dispatch(function, *args, **kwargs):
        queued = time.perf_counter_ns()
        def work():
            with span('DEPENDENCY_WORKER_QUEUE', start_ns=queued):
                pass
            with span('DEPENDENCY_WORKER'):
                return function(*args, **kwargs)
        return await dependency_pool(work)
    dependencies.run_in_threadpool = dependency_dispatch
    admission = ShadowScheduler.admit
    @contextmanager
    def admitted(self, *args, **kwargs):
        with ExitStack() as stack:
            with span('SHADOW_ADMISSION'):
                value=stack.enter_context(admission(self, *args, **kwargs))
            yield value
    ShadowScheduler.admit=admitted
    diagnostic={'gc_events':[],'gc_overflow':False}
    gc_started=None
    def observed_gc(phase, info):
        # Do not acquire trace locks or create spans inside a GC callback: GC
        # may have begun while the invoking thread already owns that lock.
        nonlocal gc_started
        if phase=='start':
            gc_started=(time.perf_counter_ns(),current_request_id(),info['generation'])
        elif phase=='stop' and gc_started is not None:
            if len(diagnostic['gc_events'])<1024:
                diagnostic['gc_events'].append({'start_ns':gc_started[0],'end_ns':time.perf_counter_ns(),
                    'invoking_request_id':gc_started[1],'generation':gc_started[2],
                    'collected':info['collected'],'uncollectable':info['uncollectable']})
            else:diagnostic['gc_overflow']=True
            gc_started=None
    gc.callbacks.append(observed_gc)
    sqlite3.connect = traced_connect
    try:
        yield diagnostic
    finally:
        gc.callbacks.remove(observed_gc)
        sqlite3.connect = connect
        dependencies.run_in_threadpool = dependency_pool
        ShadowScheduler.admit=admission
        for owner, name, original in reversed(wrapped): setattr(owner, name, original)


@contextmanager
def legacy_profile_installed():
    """Unchanged M31 global profiler, for an untraced observer-effect control."""
    from app.db.events import EventRepository
    from app.db.shadow_history import ShadowHistoryRepository
    from app.services.identity_resolution import IdentityResolver
    connect=sqlite3.connect
    def profiled_connect(*args,**kwargs):
        kwargs.setdefault('factory',old.ProfileConnection)
        return connect(*args,**kwargs)
    originals=[]
    for owner,name,label in ((EventRepository,'ingest','INGEST_REPOSITORY'),
                             (ShadowHistoryRepository,'complete','FINDING_TRANSACTION'),
                             (ShadowHistoryRepository,'seal','SNAPSHOT_TRANSACTION'),
                             (IdentityResolver,'assess','IDENTITY_RESOLUTION')):
        originals.append((owner,name,getattr(owner,name)));old.timed(owner,name,label)
    sqlite3.connect=profiled_connect
    try:yield
    finally:
        sqlite3.connect=connect
        for owner,name,function in reversed(originals):setattr(owner,name,function)
