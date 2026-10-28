"""Controlled M29 API/contention probes; called only on harness-created databases."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import timedelta
import secrets
import gc
import json
import sqlite3
import threading
import time

from fastapi.testclient import TestClient
from app.core.config import Settings
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from app.services.cqql import compile_cqql
from benchmark_cqql import process_memory
import app.api.routes.events as event_route


class MeteredSlots:
    def __init__(self):
        self.inner = threading.BoundedSemaphore(4)
        self.lock = threading.Lock()
        self.active = self.peak = 0

    def acquire(self, *args, **kwargs):
        acquired = self.inner.acquire(*args, **kwargs)
        if acquired:
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
        return acquired

    def release(self):
        with self.lock: self.active -= 1
        self.inner.release()


def api_probe(path, repository, query_repo, factory, stats):
    key, password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    settings = Settings(database_url=f'sqlite:///{path.as_posix()}', wazuh_ingest_api_key=key,
                        allow_m14_schema_migration=False)
    normalization, validation, inserts, duplicates, payload_sizes = [], [], [], [], []
    padded = False
    original_normalize, original_read = event_route.normalize_wazuh_event, event_route._read_json_object
    def normalize(*args, **kwargs):
        started = time.perf_counter()
        try: return original_normalize(*args, **kwargs)
        finally: normalization.append((time.perf_counter()-started)*1000)
    async def read(*args, **kwargs):
        started = time.perf_counter()
        try: return await original_read(*args, **kwargs)
        finally: validation.append((time.perf_counter()-started)*1000)
    event_route.normalize_wazuh_event, event_route._read_json_object = normalize, read
    try:
        with TestClient(create_app(settings)) as client:
            client.app.state.event_repository = repository
            client.app.state.cqql_search_repository = query_repo
            client.app.state.auth_repository.bootstrap_first_admin(AnalystCreate(
                username='SYNTHETIC-M29-admin', display_name='SYNTHETIC M29 benchmark',
                password=password, role=AnalystRole.ADMIN))
            login = client.post('/api/v1/auth/login', headers={'Origin':'http://localhost:5173'},
                json={'username':'SYNTHETIC-M29-admin','password':password})
            if login.status_code != 200: raise RuntimeError('disposable benchmark login failed')
            client.headers.update({'Origin':'http://localhost:5173','X-CSRF-Token':login.json()['csrf_token']})
            accepted = []
            for index in range(30):
                raw = factory(40_000_000+index).raw_payload
                if not padded and raw.get('decoder',{}).get('name') == 'windows_eventchannel':
                    raw['full_log'] = str(raw.get('full_log','')) + ' SYNTHETIC M29 large API payload '*1800
                    padded = True
                payload_sizes.append(len(json.dumps(raw,ensure_ascii=False).encode()))
                for expected, samples in ((201,inserts),(200,duplicates)):
                    started = time.perf_counter()
                    response = client.post('/api/v1/events/ingest', headers={'X-API-Key':key}, json=raw)
                    samples.append((time.perf_counter()-started)*1000)
                    if response.status_code != expected: raise RuntimeError('API acknowledgement contract mismatch')
                    if expected == 201: accepted.append(response.json()['event']['event_id'])
            raw = {'timestamp':factory(1).timestamp.isoformat(), 'id':'SYNTHETIC-M29-UNSUPPORTED',
                'decoder':{'name':'SYNTHETIC-UNKNOWN'}, 'full_log':'SYNTHETIC unsupported source',
                '_cuse':{'provenance_status':'VERIFIED','source_generation':'SYNTHETIC-false-binding'}}
            response = client.post('/api/v1/events/ingest', headers={'X-API-Key':key}, json=raw)
            if response.status_code != 201: raise RuntimeError('unsupported-source evidence was lost')
            accepted.append(response.json()['event']['event_id'])
            detail = client.get('/api/v1/events/'+accepted[-1]).json()['cuse']
            if detail['endpoint_identity_verified'] or detail.get('source_generation') is not None or detail['provenance_status'] != 'PARTIAL':
                raise RuntimeError('untrusted provenance became authoritative')
            malformed = dict(raw)
            malformed.pop('timestamp')
            if client.post('/api/v1/events/ingest', headers={'X-API-Key':key}, json=malformed).status_code != 422:
                raise RuntimeError('malformed event was acknowledged')
            if client.post('/api/v1/events/ingest', json=raw).status_code != 401:
                raise RuntimeError('analyst session bypassed machine authentication')
            saved = repository.ingest
            def unavailable(*args, **kwargs): raise sqlite3.OperationalError('SYNTHETIC-private-outage')
            repository.ingest = unavailable
            retry_raw = factory(40_000_100).raw_payload
            try:
                response = client.post('/api/v1/events/ingest', headers={'X-API-Key':key}, json=retry_raw)
                if response.status_code != 503 or 'SYNTHETIC-private-outage' in response.text:
                    raise RuntimeError('storage failure was not safely retryable')
            finally: repository.ingest = saved
            for expected in (201,200):
                response = client.post('/api/v1/events/ingest', headers={'X-API-Key':key}, json=retry_raw)
                if response.status_code != expected: raise RuntimeError('outage recovery acknowledgement mismatch')
                if expected == 201: accepted.append(response.json()['event']['event_id'])
            metrics = client.app.state.ingestion_metrics.snapshot()
            if metrics['inserted'] != 32 or metrics['duplicates'] != 31:
                raise RuntimeError('durable API accounting mismatch')
            analytics_started = time.perf_counter()
            analytics = client.post('/api/v1/siem/search/analytics', json={
                'query':'event.severity >= 0', 'start_time':(factory(1).timestamp-timedelta(days=3)).isoformat(),
                'end_time':(factory(1).timestamp+timedelta(minutes=1)).isoformat(),
                'group_by':['event.category','event.severity','event.source_type'], 'interval':'day'})
            analytics_wall_ms = round((time.perf_counter()-analytics_started)*1000,3)
            if analytics.status_code not in (200,408):
                raise RuntimeError('unexpected analytics HTTP classification')
            if analytics.status_code == 200:
                body = analytics.json()
                if body['completeness'] != 'EXACT_WITHIN_BOUNDED_RANGE' or sum(row['count'] for row in body['time_series']) != body['matching_events']:
                    raise RuntimeError('analytics completeness mismatch')
            with closing(sqlite3.connect(path)) as connection:
                present = sum(connection.execute('SELECT 1 FROM security_events WHERE event_id=?', (event_id,)).fetchone() is not None for event_id in accepted)
            if present != len(accepted): raise RuntimeError('recent acknowledged fixture event missing')
            return {'insert_http':stats(inserts), 'duplicate_http':stats(duplicates),
                'json_validation':stats(validation), 'normalization':stats(normalization),
                'durable_inserts':metrics['inserted'], 'durable_duplicates':metrics['duplicates'],
                'retryable_failures':metrics['retryable_failures'], 'normalization_counts':metrics['normalization_counts'],
                'recent_accepted_verified':present, 'machine_boundary':'PASS', 'spoofed_provenance':'NOT_VERIFIED',
                'payload_bytes_min':min(payload_sizes), 'payload_bytes_max':max(payload_sizes),
                'large_synthetic_payload_included':padded,
                'analytics_http':analytics.status_code,
                'analytics_http_wall_ms':analytics_wall_ms}
    finally:
        event_route.normalize_wazuh_event, event_route._read_json_object = original_normalize, original_read
        gc.collect()


def contention(path, repository, query_repo, factory, base, stats):
    slots = MeteredSlots()
    query_repo._slots = slots
    start, end = base-timedelta(days=3), base+timedelta(minutes=1)
    queries = {'indexed':'event.code = "4625"', 'provider':'event.provider = "Microsoft-Windows-Sysmon"',
               'fts':'text CONTAINS "synthetic"', 'analytics':'event.severity >= 0'}
    scenarios = {'A':[], 'B':['indexed'], 'C':['provider'], 'D':['fts'], 'E':['analytics'],
                 'F':['indexed','provider','fts','analytics'],
                 'G':['indexed','provider','fts','analytics']*2}
    result, next_id = {}, 50_000_000
    for scenario, kinds in scenarios.items():
        sample_start = len(repository.sql_samples)
        barrier = threading.Barrier(len(kinds)+1)
        wall_started, cpu_started = time.perf_counter(), time.process_time()
        def writer():
            barrier.wait()
            times, wal = [], 0
            for index in range(8):
                event = factory(next_id+index)
                began = time.perf_counter()
                stored = repository.ingest(event, now=base)
                if stored.duplicate: raise RuntimeError('unexpected contention duplicate')
                times.append((time.perf_counter()-began)*1000)
                file = path.with_name(path.name+'-wal')
                wal = max(wal, file.stat().st_size if file.exists() else 0)
            return {'write':stats(times), 'wal_peak_observed_bytes':wal}
        def reader(kind):
            barrier.wait()
            times, outcomes = [], []
            for _ in range(3):
                began = time.perf_counter()
                try:
                    if kind == 'analytics':
                        query_repo.analytics(compile_cqql(queries[kind]), start_time=start,end_time=end,
                            group_by=['event.category','event.severity','event.source_type'], top_n=10,interval='day')
                    else:
                        query_repo.search(compile_cqql(queries[kind]),start_time=start,end_time=end,sort='newest',limit=100,cursor=None)
                    outcomes.append('COMPLETE')
                except Exception as exc:
                    name = type(exc).__name__
                    if name not in {'CQQLQueryBusyError','CQQLQueryTimeoutError'}: raise
                    outcomes.append('BUSY' if name == 'CQQLQueryBusyError' else 'TIMEOUT')
                times.append((time.perf_counter()-began)*1000)
            return {'kind':kind, **stats(times), 'outcomes':outcomes}
        with ThreadPoolExecutor(max_workers=len(kinds)+1) as executor:
            write = executor.submit(writer)
            reads = [executor.submit(reader,kind) for kind in kinds]
            observed = write.result()
            observed['readers'] = [future.result() for future in reads]
        next_id += 100
        if slots.active != 0 or slots.peak > 4: raise RuntimeError('query semaphore leak/limit violation')
        observed.update({'wall_ms':round((time.perf_counter()-wall_started)*1000,3),
                         'cpu_seconds':round(time.process_time()-cpu_started,3), 'query_peak_slots':slots.peak,
                         'writer_lock':stats([value for key,value in repository.sql_samples[sample_start:] if key == 'write_lock']),
                         **process_memory()})
        result[scenario] = observed
    cancel, entered = threading.Event(), threading.Event()
    original = query_repo._connect
    def connect():
        connection = original()
        entered.set()
        return connection
    query_repo._connect = connect
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(query_repo.search,compile_cqql(queries['fts']), start_time=start,end_time=end,
                sort='newest',limit=100,cursor=None,cancel_event=cancel)
            if not entered.wait(3): raise RuntimeError('cancellation worker did not start')
            time.sleep(.02)
            began = time.perf_counter()
            cancel.set()
            try:
                future.result(timeout=3)
                cancellation = 'ALREADY_COMPLETE'
            except Exception as exc:
                if type(exc).__name__ != 'CQQLQueryCancelledError': raise
                cancellation = 'CANCELLED'
            result['cancellation'] = {'status':cancellation,'release_ms':round((time.perf_counter()-began)*1000,3)}
    finally: query_repo._connect = original
    query_repo.search(compile_cqql(queries['indexed']),start_time=start,end_time=end,sort='newest',limit=10,cursor=None)
    result['post_overload_recovery'] = slots.active == 0 and slots.peak <= 4
    return result
