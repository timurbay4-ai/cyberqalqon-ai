"""Instrument the unchanged M30 disposable workload; never accepts a live DB path."""
import contextvars
import functools
import json
import sqlite3
import sys
import threading
import time
from collections import Counter,defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
import benchmark_m30_detection as benchmark
from app.db.audit import AuditRepository
from app.db.auth import AuthRepository
from app.db.cqql import CQQLSearchRepository
from app.db.events import EventRepository
from app.services import shadow_detection
from app.services.advanced_detection import AdvancedDetectionEngine

TRACE=contextvars.ContextVar('m31_synthetic_trace',default='FOREGROUND_REPOSITORY')
LOCK=threading.Lock()
STAGES=defaultdict(list)
OUTCOMES=[]
ERRORS=Counter()


def record(name,began):
    with LOCK: STAGES[name].append((time.perf_counter()-began)*1000)


def timed(owner,name,label):
    original=getattr(owner,name)
    @functools.wraps(original)
    def wrapper(*args,**kwargs):
        began=time.perf_counter()
        try:return original(*args,**kwargs)
        except Exception as exc:
            with LOCK: ERRORS[label+':'+getattr(exc,'sqlite_errorname',type(exc).__name__)]+=1
            raise
        finally:record(label,began)
    setattr(owner,name,wrapper)


class ProfileConnection(sqlite3.Connection):
    def execute(self,sql,parameters=()):
        upper=sql.strip().upper()
        label=('SQLITE_WRITE_LOCK_ACQUIRE' if upper.startswith('BEGIN IMMEDIATE') else
               'INSERT_INCLUDING_FTS' if upper.startswith('INSERT INTO SECURITY_EVENTS') else
               'RETENTION_DELETE_INCLUDING_FTS' if upper.startswith('DELETE FROM SECURITY_EVENTS') else
               'AUDIT_INSERT' if upper.startswith('INSERT INTO SECURITY_AUDIT_EVENTS') else 'SQL_OTHER')
        began=time.perf_counter()
        try:return super().execute(sql,parameters)
        except sqlite3.Error as exc:
            with LOCK:ERRORS[label+':'+getattr(exc,'sqlite_errorname',type(exc).__name__)]+=1
            raise
        finally:record(label,began)

    def __exit__(self,*args):
        began=time.perf_counter()
        try:return super().__exit__(*args)
        finally:record('CONTEXT_COMMIT_OR_ROLLBACK',began)


def main():
    original_connect=sqlite3.connect
    def connect(*args,**kwargs):
        kwargs.setdefault('factory',ProfileConnection)
        return original_connect(*args,**kwargs)
    sqlite3.connect=connect
    for owner,name,label in ((AuditRepository,'append','AUDIT_TOTAL'),(AuthRepository,'resolve_session','AUTHENTICATION'),
        (EventRepository,'ingest','INGEST_REPOSITORY'),(CQQLSearchRepository,'_connect','SQLITE_READ_OPEN'),
        (CQQLSearchRepository,'_acquire_slot','QUERY_ADMISSION'),(CQQLSearchRepository,'search','CQQL_SEARCH'),
        (CQQLSearchRepository,'analytics','ANALYTICS'),(AdvancedDetectionEngine,'simulate_contract','SHADOW_TOTAL'),
        (shadow_detection,'evaluate_records','RULE_EVALUATION')):timed(owner,name,label)
    create=benchmark.create_app
    def create_profiled(*args,**kwargs):
        app=create(*args,**kwargs)
        @app.middleware('http')
        async def trace(request,call_next):
            if not request.url.path.endswith('/shadow-v2/simulate'):return await call_next(request)
            began=time.perf_counter()
            with LOCK:index=len(OUTCOMES)+1
            token=TRACE.set(f'SYNTHETIC-M31-{index:04d}')
            try:
                response=await call_next(request)
                # Response streaming is intentionally consumed/rebuilt ONLY in this profiler.
                body=b''.join([part async for part in response.body_iterator])
                detail=json.loads(body).get('detail',{}) if response.status_code!=200 else {}
                with LOCK:OUTCOMES.append({'request_id':TRACE.get(),'status':response.status_code,
                    'code':detail.get('code','OK'),'wall_ms':round((time.perf_counter()-began)*1000,4)})
                from starlette.responses import Response
                return Response(body,status_code=response.status_code,headers=dict(response.headers),media_type='application/json')
            finally:TRACE.reset(token);record('HTTP_SHADOW_TOTAL',began)
        return app
    benchmark.create_app=create_profiled
    measurements=ROOT/'docs/siem/M31_BASELINE_PERFORMANCE.json'
    sys.argv=[__file__,'--output',str(measurements)]
    started=time.perf_counter()
    try:benchmark.main()
    finally:
        report={'scope':'UNCHANGED_M30_DISPOSABLE_WORKLOAD_INSTRUMENTED','wall_seconds':time.perf_counter()-started,
            'logical_outcomes':OUTCOMES,'statuses':dict(Counter(str(row['status']) for row in OUTCOMES)),
            'codes':dict(Counter(row['code'] for row in OUTCOMES)),
            'stage_metrics':{key:benchmark.stats(value) for key,value in STAGES.items()},'internal_errors':dict(ERRORS),
            'limitations':['Timing-dependent request count; original 161-count is not reproducible scheduling.',
                'Original four responses lacked reason codes and cannot be retrospectively proven.',
                'SQL INSERT/DELETE includes FTS triggers; lock acquire is observed wall time, not a busy-handler trace.',
                'Instrumentation adds overhead; compare instrumented M31 with like scope, not unlike raw timings.']}
        (ROOT/'docs/siem/M31_503_BASELINE.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
