"""M29 reproducible source-only profiling; no live database argument exists."""
from __future__ import annotations

import argparse
import copy
import gc
import hashlib
import importlib.util
import json
import platform
import shutil
import sqlite3
import statistics
import sys
import tempfile
import threading
import time
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'backend'), str(ROOT / 'scripts')]
from app.db.alerts import AlertRepository
from app.db.events import EventRepository
from app.db.cqql import (CQQLSearchRepository, CQQLQueryTimeoutError, CQQLQueryBusyError,
                        CQQLQueryCancelledError, CQQLExecutionError)
from app.services.cqql import compile_cqql
from app.services.event_normalizer import normalize_wazuh_event
from app.services.wazuh_normalizer import canonical_json
from benchmark_cqql import process_memory
import m28_synthetic
import m29_synthetic
import m29_workloads

SNAPSHOT = ROOT / 'artifacts/runtime/m29-baseline-source'


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''):
            digest.update(block)
    return digest.hexdigest()


def load_snapshot(name):
    path = SNAPSHOT / (name + '.py')
    inventory = json.loads((ROOT / 'docs/siem/M29_BASELINE_INVENTORY.json').read_text())
    expected = next(row['sha256'] for row in inventory if row['path'] == f'backend/app/db/{name}.py')
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise RuntimeError('baseline source checksum mismatch')
    spec = importlib.util.spec_from_file_location('m29_baseline_' + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    if name == 'cqql':
        # Aliased modules otherwise create distinct exception classes, preventing
        # the unchanged API route from translating the same old timeout to 408.
        # Only class identity is bridged: SQL, deadlines and algorithms unchanged.
        for error in (CQQLQueryTimeoutError,CQQLQueryBusyError,CQQLQueryCancelledError,CQQLExecutionError):
            setattr(module,error.__name__,error)
    return module


def stats(values):
    if not values:
        return {'samples': 0}
    ordered = sorted(values)
    return {'samples': len(values), 'p50_ms': round(statistics.median(values), 4),
            'p95_ms': round(ordered[max(0, __import__('math').ceil(len(values)*.95)-1)], 4),
            'max_ms': round(max(values), 4)}


def stage(sql):
    sql = sql.strip().upper()
    if sql.startswith('BEGIN'): return 'write_lock'
    if sql.startswith('INSERT INTO SECURITY_EVENTS'): return 'insert_including_indexes_fts'
    if sql.startswith('DELETE FROM SECURITY_EVENTS'): return 'retention_delete_including_fts'
    if 'DEDUPLICATION_ID = ? OR EVENT_ID = ?' in sql: return 'idempotency_lookup'
    return 'other_sql'


class ProfileConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        started = time.perf_counter()
        try:
            return super().execute(sql, parameters)
        finally:
            self.samples.append((stage(sql), (time.perf_counter()-started)*1000))

    def commit(self):
        active = self.in_transaction
        started = time.perf_counter()
        try:
            return super().commit()
        finally:
            if active: self.samples.append(('commit', (time.perf_counter()-started)*1000))


def profiled(base):
    class Profiled(base):
        def _connect(self):
            connection = sqlite3.connect(self.path, timeout=5, factory=ProfileConnection)
            connection.samples = self.sql_samples
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA busy_timeout=5000')
            return connection

        def _enforce_retention(self, *args, **kwargs):
            result = super()._enforce_retention(*args, **kwargs)
            self.retention_samples.append(asdict(result))
            return result
    return Profiled


def fixture(index, base, templates):
    original = templates[index % len(templates)]
    raw = copy.deepcopy(original.raw_payload)
    raw['id'] = f'SYNTHETIC-M29-{index:012d}'
    digest = hashlib.sha256(canonical_json(raw).encode()).hexdigest()
    structured = copy.deepcopy(original.structured_payload)
    structured['_cuse']['content_fingerprint'] = digest
    if structured['_cuse']['source_family'] not in {'WINDOWS_EVENTCHANNEL', 'SYSMON'}:
        structured['_cuse']['original_event_identity'] = raw['id']
    return original.model_copy(update={'event_id': 'EVT-'+digest[:24].upper(),
        'deduplication_id': digest, 'source_event_id': raw['id'], 'raw_payload': raw,
        'structured_payload': structured, 'raw_size_bytes': len(canonical_json(raw).encode())})


def seed(path, count, base, templates):
    AlertRepository(f'sqlite:///{path.as_posix()}', migration_target_version=17).initialize()
    repository = EventRepository(path, retention_days=30, max_records=100_000)
    started = time.perf_counter()
    with closing(repository._connect()) as connection:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='security_events_fts_insert'").fetchone()[0]
        connection.execute('DROP TRIGGER security_events_fts_insert')
        for index in range(count):
            event = fixture(index, base, templates)
            repository._insert_event_row(connection, event, occurred_at=event.timestamp,
                                        ingested_at=base, related_alert_id=None)
            if index % 1000 == 999: connection.commit()
        connection.execute('INSERT INTO security_events_fts(event_id,search_text) SELECT event_id,search_text FROM security_events')
        connection.execute(trigger)
        connection.execute('UPDATE security_event_store_state SET retained_records=?, last_retention_at=? WHERE singleton=1',
                           (count, base.isoformat()))
        connection.commit()
        connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    return round((time.perf_counter()-started)*1000, 3)


def capture_running_fixture(source, output):
    source = source.resolve()
    if (source.name != 'seed-100000.db' or source.parent.parent != Path(tempfile.gettempdir()).resolve()
            or not source.parent.name.startswith('cyberqalqon-m29-')):
        raise ValueError('capture accepts only this harness temporary synthetic fixture')
    target = ROOT / 'artifacts/runtime/m29-seed.db'
    if target.exists(): raise ValueError('refusing to overwrite retained fixture')
    deadline = time.monotonic()+1800
    while time.monotonic() < deadline:
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True)) as connection:
            count = connection.execute('SELECT retained_records FROM security_event_store_state WHERE singleton=1').fetchone()[0]
            if count == 100_000:
                synthetic = connection.execute("SELECT COUNT(*) FROM security_events WHERE source_event_id LIKE 'SYNTHETIC-M29-%'").fetchone()[0]
                if synthetic != count: raise ValueError('fixture is not entirely synthetic')
                with closing(sqlite3.connect(target)) as destination: connection.backup(destination)
                output.write_text(json.dumps({'scope':'SYNTHETIC_DISPOSABLE_ONLY', 'count':count,
                    'sha256':file_sha(target)})+'\n')
                print('retained consistent synthetic fixture', flush=True)
                return
        time.sleep(5)
    raise TimeoutError('fixture population did not finish')


def integrity(path):
    with closing(sqlite3.connect(path)) as connection:
        from app.db.fts_locator_proposal import verify_fts_content
        locator_present = connection.execute("SELECT 1 FROM sqlite_master WHERE name='m29_fts_locator'").fetchone() is not None
        fts_verified = verify_fts_content(connection,locator=locator_present)
        connection.commit()
        rows = connection.execute('SELECT event_id, deduplication_id, raw_event_json, structured_json FROM security_events ORDER BY event_id')
        digest = hashlib.sha256()
        mismatches = 0
        for event_id, identity, raw, structured in rows:
            expected = hashlib.sha256(canonical_json(json.loads(raw)).encode()).hexdigest()
            mismatches += int(identity != expected or event_id != 'EVT-'+expected[:24].upper())
            digest.update(json.dumps([event_id,identity,raw,structured],ensure_ascii=False).encode())
        return {'quick_check': connection.execute('PRAGMA quick_check').fetchone()[0],
            'foreign_keys': len(connection.execute('PRAGMA foreign_key_check').fetchall()),
            'count': connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],
            'counter': connection.execute('SELECT retained_records FROM security_event_store_state WHERE singleton=1').fetchone()[0],
            'schema': connection.execute('PRAGMA user_version').fetchone()[0],
            'identity_mismatches': mismatches, 'evidence_sha256': digest.hexdigest(),
            'fts_count': fts_verified, 'fts_content_and_integrity':'PASS',
            'protected_records': connection.execute('SELECT COUNT(*) FROM case_events').fetchone()[0]}


def protected_hash(path):
    with closing(sqlite3.connect(path)) as connection:
        rows = connection.execute('SELECT e.event_id,e.raw_event_json,e.structured_json FROM security_events e '
            'JOIN case_events c ON c.event_id=e.event_id ORDER BY e.event_id').fetchall()
    return hashlib.sha256(json.dumps(rows,ensure_ascii=False).encode()).hexdigest()


def fts_cost(path, repository, event):
    """Paired rollbacks, including DDL: no measurements become accepted events."""
    result = {}
    with closing(sqlite3.connect(path)) as connection:
        connection.execute('PRAGMA foreign_keys=ON')
        event_id = connection.execute('SELECT e.event_id FROM security_events e WHERE NOT EXISTS('
            'SELECT 1 FROM case_events c WHERE c.event_id=e.event_id) LIMIT 1').fetchone()[0]
        for operation in ('insert','delete'):
            for enabled in (True, False):
                times = []
                for _ in range(3):
                    connection.execute('SAVEPOINT microprobe')
                    try:
                        if not enabled:
                            connection.execute('DROP TRIGGER security_events_fts_'+operation)
                        began = time.perf_counter()
                        if operation == 'delete':
                            connection.execute('DELETE FROM security_events WHERE event_id=?',(event_id,))
                        else:
                            repository._insert_event_row(connection,event,occurred_at=event.timestamp,
                                ingested_at=event.timestamp,related_alert_id=None)
                        times.append((time.perf_counter()-began)*1000)
                    finally:
                        connection.execute('ROLLBACK TO microprobe')
                        connection.execute('RELEASE microprobe')
                result[operation+('_with_fts_trigger' if enabled else '_without_fts_trigger')] = stats(times)
    return result


def observe(path, count, base, templates, event_class, query_class, samples):
    cpu_started, wall_started = time.process_time(), time.perf_counter()
    protected_before = protected_hash(path)
    repository = profiled(event_class)(path, retention_days=30, max_records=100_000)
    repository.sql_samples, repository.retention_samples = [], []
    # Match the historical M28 cap-pressure burst: 24 preceding API probe rows.
    with closing(repository._connect()) as connection:
        extras = 24 if count == 100_000 else 0
        for index in range(count, count+extras):
            event = fixture(index, base, templates)
            repository._insert_event_row(connection, event, occurred_at=event.timestamp, ingested_at=base, related_alert_id=None)
        connection.execute('UPDATE security_event_store_state SET retained_records=? WHERE singleton=1', (count+extras,))
        connection.commit()
    repository.sql_samples.clear()
    times, duplicates = [], []
    for index in range(count+100, count+100+samples):
        event = fixture(index, base, templates)
        started = time.perf_counter()
        result = repository.ingest(event, now=base)
        times.append((time.perf_counter()-started)*1000)
        if result.duplicate: raise RuntimeError('unexpected duplicate')
        started = time.perf_counter()
        if not repository.ingest(event, now=base).duplicate: raise RuntimeError('duplicate acknowledgement mismatch')
        duplicates.append((time.perf_counter()-started)*1000)
    queries = {
        'common_provider': 'event.provider = "Microsoft-Windows-Sysmon"',
        'provider_host': 'event.provider = "Microsoft-Windows-Sysmon" AND host.name = "SYNTH-M28-WINDOWS"',
        'provider_severity': 'event.provider = "Microsoft-Windows-Sysmon" AND event.severity >= 7',
        'no_match_provider': 'event.provider = "SYNTHETIC-NO-MATCH"',
        'indexed': 'event.code = "4625"',
        'fts_dense': 'text CONTAINS "synthetic"',
        'fts_sparse': 'text CONTAINS "m29nosuchtoken"',
        'fts_rare': 'text CONTAINS "m29rareuniquetoken"',
        'rare_provider': 'event.provider = "SYNTHETIC-Rare-Provider"',
        'common_provider_oldest': 'event.provider = "Microsoft-Windows-Sysmon"',
        'common_provider_recent': 'event.provider = "Microsoft-Windows-Sysmon"',
    }
    query_repo = query_class(path)
    start, end = base-timedelta(days=3), base+timedelta(minutes=1)
    query_results = {}
    actual_plans = {}
    for name, query in queries.items():
        query_start = base-timedelta(hours=1) if name.endswith('_recent') else start
        sort = 'oldest' if name.endswith('_oldest') else 'newest'
        direction = 'ASC' if sort == 'oldest' else 'DESC'
        elapsed, ids, timeouts = [], [], 0
        compiled = compile_cqql(query)
        with closing(sqlite3.connect(path)) as reference:
            reference_from = ('security_events e INDEXED BY idx_security_events_occurred_id'
                              if compiled.referenced_fields == ('text',) else 'security_events e')
            expected = [row[0] for row in reference.execute(
                f'SELECT e.event_id FROM {reference_from} WHERE e.occurred_at BETWEEN ? AND ? AND {compiled.sql} ORDER BY e.occurred_at {direction},e.event_id {direction} LIMIT 100',
                (query_start.isoformat(), end.isoformat(), *compiled.parameters))]
        for _ in range(5):
            traced = []
            original_connect = query_repo._connect
            if name == 'common_provider' and _ == 0:
                def trace_connect():
                    connection = original_connect()
                    connection.set_trace_callback(traced.append)
                    return connection
                query_repo._connect = trace_connect
            started = time.perf_counter()
            try:
                result = query_repo.search(compile_cqql(query), start_time=query_start, end_time=end,
                                          sort=sort, limit=100, cursor=None)
                ids = [row.event_id for row in result.items]
                if ids != expected: raise RuntimeError('query identity/order mismatch')
            except Exception as exc:
                if type(exc).__name__ != 'CQQLQueryTimeoutError': raise
                timeouts += 1
            finally:
                query_repo._connect = original_connect
            elapsed.append((time.perf_counter()-started)*1000)
            if traced:
                with closing(sqlite3.connect(path)) as reference:
                    actual_plans[name] = [[row[3] for row in reference.execute('EXPLAIN QUERY PLAN '+sql)]
                        for sql in traced if sql.lstrip().upper().startswith('SELECT') and 'WHERE' in sql.upper()]
        query_results[name] = {**stats(elapsed), 'timeouts': timeouts,
            'cold_connection_ms': elapsed[0], 'warm': stats(elapsed[1:]), 'elapsed_samples_ms': elapsed,
            'reference_rows': len(expected),
            'result_ids_sha256': hashlib.sha256(json.dumps(ids).encode()).hexdigest(), 'returned_rows': len(ids)}
    analytics = []
    for groups in [['event.category'], ['event.severity', 'event.source_type', 'host.name']]:
        started = time.perf_counter()
        try:
            result = query_repo.analytics(compile_cqql('event.severity >= 0'), start_time=start,
                end_time=end, group_by=groups, top_n=10, interval='day')
            analytics.append({'groups': groups, 'status': 'COMPLETE', 'matching_events': result.matching_events,
                              'bucket_sum': sum(row.count for row in result.time_series)})
        except Exception as exc:
            if type(exc).__name__ != 'CQQLQueryTimeoutError': raise
            analytics.append({'groups': groups, 'status': 'TIMEOUT'})
        analytics[-1]['wall_ms'] = round((time.perf_counter()-started)*1000, 3)
    stages = {name: stats([elapsed for key, elapsed in repository.sql_samples if key == name])
              for name in sorted({key for key, _ in repository.sql_samples})}
    maintenance_probe = fts_cost(path,repository,fixture(60_000_000,base,templates))
    api = m29_workloads.api_probe(path, repository, query_repo,
                                lambda index: fixture(index,base,templates), stats)
    mixed = m29_workloads.contention(path,repository,query_repo,
        lambda index: fixture(index,base,templates),base,stats) if count == 100_000 else None
    state = integrity(path)
    state['protected_hash_preserved'] = protected_before == protected_hash(path)
    with closing(sqlite3.connect(path)) as connection:
        plans = [row[3] for row in connection.execute('EXPLAIN QUERY PLAN SELECT e.event_id FROM security_events e WHERE e.event_provider=? COLLATE NOCASE ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 101', ('Microsoft-Windows-Sysmon',))]
        checkpoint = tuple(connection.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
    gc.collect()
    return {'insert': stats(times), 'first_insert_ms': times[0], 'steady_insert': stats(times[1:]),
        'duplicate': stats(duplicates), 'stages': stages,
        'retention_profiles': repository.retention_samples, 'search': query_results, 'analytics': analytics,
        'api':api, 'contention':mixed, 'actual_query_plans':actual_plans,
        'fts_rollback_microprobe':maintenance_probe,
        'integrity': state, 'provider_narrow_reference_plan': plans, 'db_bytes': path.stat().st_size,
        'cpu_seconds':round(time.process_time()-cpu_started,3),
        'wall_seconds':round(time.perf_counter()-wall_started,3),
        'wal_bytes': path.with_name(path.name+'-wal').stat().st_size if path.with_name(path.name+'-wal').exists() else 0,
        'passive_checkpoint': checkpoint, **process_memory()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snapshot', action='store_true')
    parser.add_argument('--capture-running-fixture', type=Path)
    parser.add_argument('--reuse-fixture', action='store_true')
    parser.add_argument('--cache-fixtures', action='store_true')
    parser.add_argument('--mode', choices=['baseline', 'comparison', 'optimized'], default='baseline')
    parser.add_argument('--sizes', nargs='+', type=int, default=[10_000, 50_000, 100_000])
    parser.add_argument('--samples', type=int, default=12)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.capture_running_fixture:
        capture_running_fixture(args.capture_running_fixture, args.output)
        return 0
    if any(not 1 <= size <= 100_000 for size in args.sizes) or not 1 <= args.samples <= 50:
        parser.error('disposable workload bounds exceeded')
    if args.snapshot:
        if SNAPSHOT.exists(): parser.error('baseline snapshot already exists; refusing overwrite')
        SNAPSHOT.mkdir(parents=True)
        for name in ('events', 'cqql'):
            shutil.copyfile(ROOT / f'backend/app/db/{name}.py', SNAPSHOT / (name+'.py'))
    old_event, old_query = load_snapshot('events').EventRepository, load_snapshot('cqql').CQQLSearchRepository
    base = datetime.now(timezone.utc).replace(microsecond=0)
    templates = [normalize_wazuh_event(raw) for _, raw, _ in m28_synthetic.cases(base)]
    report = {'scope': 'SYNTHETIC_DISPOSABLE_ONLY', 'live_access': False, 'generated_at': base.isoformat(),
        'python': platform.python_version(), 'sqlite': sqlite3.sqlite_version, 'platform': platform.platform(),
        'deadline_seconds': 1.5, 'query_slots': 4, 'population': 'cached-normalized M28 30-template mix; unique original envelope hashes',
        'timing_scope': 'repository; timeout samples INCLUDED; first query cold connection, not OS-cache eviction', 'populations': []}
    report['source_sha256'] = {name: file_sha(ROOT / name) for name in (
        'backend/app/db/events.py','backend/app/db/cqql.py',
        'backend/app/db/fts_locator_proposal.py','backend/app/db/analytics_index_proposal.py',
        'scripts/benchmark_m29_performance.py','scripts/m29_workloads.py','scripts/m29_synthetic.py')}
    cpu = time.process_time()
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m29-') as temporary:
        for size in args.sizes:
            path = Path(temporary) / f'seed-{size}.db'
            source_path = ROOT / ('artifacts/runtime/m29-seed.db' if size == 100_000
                                  else f'artifacts/runtime/m29-seed-{size}.db')
            manifest_path = source_path.with_name(source_path.stem+'-manifest.json')
            if args.reuse_fixture and source_path.exists():
                manifest = json.loads(manifest_path.read_text())
                if manifest.get('scope') != 'SYNTHETIC_DISPOSABLE_ONLY' or file_sha(source_path) != manifest['sha256']:
                    raise ValueError('retained synthetic fixture checksum mismatch')
                with closing(sqlite3.connect(source_path.as_uri()+'?mode=ro', uri=True)) as source, closing(sqlite3.connect(path)) as destination:
                    source.backup(destination)
                population_ms = None
            else:
                population_ms = seed(path, size, base, templates)
                if args.cache_fixtures and not source_path.exists():
                    with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(source_path)) as destination:
                        source.backup(destination)
                    manifest_path.write_text(json.dumps({'scope':'SYNTHETIC_DISPOSABLE_ONLY',
                        'count':size,'sha256':file_sha(source_path)})+'\n')
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('PRAGMA foreign_keys=ON')
                distribution = m29_synthetic.decorate(connection,
                    EventRepository(path, retention_days=30, max_records=100_000), base)
            row = {'size': size, 'population_ms': population_ms, 'distribution': distribution, 'variants': {}}
            report['populations'].append(row)
            for name, eclass, qclass in [('before', old_event, old_query),
                    ('source_only', EventRepository, CQQLSearchRepository),
                    ('source_plus_storage_v1', EventRepository, CQQLSearchRepository)]:
                if args.mode == 'baseline' and name != 'before': continue
                if args.mode == 'optimized' and name != 'source_plus_storage_v1': continue
                target = Path(temporary) / f'{size}-{name}.db'
                with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(target)) as destination:
                    source.backup(destination)
                migration = None
                if name == 'source_plus_storage_v1':
                    from app.db.fts_locator_proposal import install
                    from app.db.analytics_index_proposal import install as install_analytics
                    before_bytes = target.stat().st_size
                    with closing(sqlite3.connect(target)) as connection:
                        migration = install(connection, disposable_only=True)
                        migration['analytics_cover'] = install_analytics(connection, disposable_only=True)
                        wal = target.with_name(target.name+'-wal')
                        migration['wal_bytes_after_commit_before_close'] = wal.stat().st_size if wal.exists() else 0
                        migration['synchronous'] = connection.execute('PRAGMA synchronous').fetchone()[0]
                    migration['database_growth_bytes'] = target.stat().st_size-before_bytes
                row['variants'][name] = observe(target, size, base, templates, eclass, qclass, args.samples)
                row['variants'][name]['storage_migration'] = migration
                print(f'completed size={size} variant={name}', flush=True)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2)+'\n')
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2)+'\n')
            gc.collect()
    report['cpu_seconds'] = round(time.process_time()-cpu, 3)
    integrity_ok = all(
        value['integrity']['quick_check'] == 'ok'
        and value['integrity']['foreign_keys'] == 0
        and value['integrity']['schema'] == 17
        and value['integrity']['count'] == value['integrity']['counter'] == value['integrity']['fts_count']
        and value['integrity']['count'] <= 100_000
        and value['integrity']['identity_mismatches'] == 0
        and value['integrity']['protected_records'] == 4
        and value['integrity']['protected_hash_preserved']
        for population in report['populations'] for value in population['variants'].values())
    evidence_equal = all(len({value['integrity']['evidence_sha256'] for value in population['variants'].values()}) == 1
                         for population in report['populations'])
    report['acceptance'] = {'integrity':'PASS' if integrity_ok and evidence_equal else 'FAIL',
        'paired_evidence_equal':evidence_equal, 'production':'NOT_DEPLOYED',
        'requires_separate_storage_approval':True, 'timing_exit_code_is_not_acceptance':True}
    for population in report['populations']:
        if population['size'] == 100_000 and 'source_plus_storage_v1' in population['variants']:
            value = population['variants']['source_plus_storage_v1']
            report['acceptance'].update({
                'provider_primary': 'PASS' if value['search']['common_provider']['timeouts'] == 0 else 'PERFORMANCE_BLOCKED',
                'broad_analytics':'PASS' if all(row['status'] == 'COMPLETE' for row in value['analytics']) and value['api']['analytics_http'] == 200 else 'PERFORMANCE_BLOCKED',
                'steady_insert_subsecond':value['steady_insert']['p95_ms'] < 1000,
                'dense_fts_timeouts':value['search']['fts_dense']['timeouts']})
    if not integrity_ok or not evidence_equal:
        args.output.write_text(json.dumps(report,indent=2)+'\n')
        raise RuntimeError('M29 integrity/equivalent-evidence gate failed')
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
