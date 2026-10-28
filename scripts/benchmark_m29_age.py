"""Bounded age-sweep/provider probes using checksum-verified SYNTHETIC seeds only."""
import argparse
import gc
import json
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import datetime,timedelta,timezone
from pathlib import Path

from benchmark_m29_performance import (ROOT,EventRepository,CQQLSearchRepository,fixture,
    file_sha,load_snapshot,profiled,integrity,stats,protected_hash,compile_cqql,
    normalize_wazuh_event,m28_synthetic,m29_synthetic)
from app.db.fts_locator_proposal import install
from app.db.analytics_index_proposal import install as install_cover


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    base = datetime.now(timezone.utc).replace(microsecond=0)
    templates = [normalize_wazuh_event(raw) for _,raw,_ in m28_synthetic.cases(base)]
    old_templates = [normalize_wazuh_event(raw) for _,raw,_ in m28_synthetic.cases(base-timedelta(days=31))]
    old_class = load_snapshot('events').EventRepository
    report = {'scope':'SYNTHETIC_DISPOSABLE_ONLY','at':base.isoformat(),
        'samples_per_variant':3,'percentile_note':'exploratory n=3, p95 is maximum, not an SLA',
        'source_sha256':{name:file_sha(ROOT/name) for name in (
            'scripts/benchmark_m29_age.py','backend/app/db/events.py','backend/app/db/cqql.py',
            'backend/app/db/fts_locator_proposal.py','backend/app/db/analytics_index_proposal.py')},'populations':[]}
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m29-age-') as temporary:
        for size in (10000,50000,100000):
            source_path = ROOT/('artifacts/runtime/m29-seed.db' if size == 100000 else f'artifacts/runtime/m29-seed-{size}.db')
            manifest = json.loads(source_path.with_name(source_path.stem+'-manifest.json').read_text())
            if manifest['scope'] != 'SYNTHETIC_DISPOSABLE_ONLY' or file_sha(source_path) != manifest['sha256']:
                raise RuntimeError('synthetic seed checksum mismatch')
            population = {'size':size,'variants':{}}
            report['populations'].append(population)
            for name,eclass in (('before',old_class),('source_only',EventRepository),('storage',EventRepository)):
                path = Path(temporary)/f'{size}-{name}.db'
                with closing(sqlite3.connect(source_path.as_uri()+'?mode=ro',uri=True)) as source, closing(sqlite3.connect(path)) as connection:
                    source.backup(connection)
                    connection.execute('PRAGMA foreign_keys=ON')
                    repository = profiled(eclass)(path,retention_days=30,max_records=100000)
                    repository.sql_samples,repository.retention_samples = [],[]
                    m29_synthetic.decorate(connection,repository,base)
                    if name == 'storage':
                        install(connection,disposable_only=True)
                        install_cover(connection,disposable_only=True)
                times = []
                for episode in range(3):
                    with closing(sqlite3.connect(path)) as connection:
                        connection.execute('PRAGMA foreign_keys=ON')
                        for offset in (0,1):
                            event = fixture(70_000_000+episode*10+offset,base,old_templates)
                            repository._insert_event_row(connection,event,occurred_at=event.timestamp,
                                ingested_at=event.timestamp,related_alert_id=None)
                            if offset == 0:
                                connection.execute('INSERT INTO case_events(case_id,event_id,linked_at,linked_by_display) VALUES(?,?,?,?)',
                                    ('SYNTHETIC-M29-PROTECTED-CASE',event.event_id,base.isoformat(),'SYNTHETIC'))
                        connection.execute('UPDATE security_event_store_state SET retained_records=retained_records+2,last_retention_at=? WHERE singleton=1',
                            ((base-timedelta(minutes=6)).isoformat(),))
                        connection.commit()
                    protected_before = protected_hash(path)
                    current = fixture(80_000_000+episode,base,templates)
                    began = time.perf_counter()
                    assert not repository.ingest(current,now=base).duplicate
                    times.append((time.perf_counter()-began)*1000)
                    assert repository.ingest(current,now=base).duplicate
                    assert protected_hash(path) == protected_before
                state = integrity(path)
                assert state['count'] == state['counter'] == state['fts_count'] == min(size+6,100000)
                assert state['protected_records'] == 7 and state['foreign_keys'] == 0 and state['quick_check'] == 'ok'
                assert state['identity_mismatches'] == 0 and state['schema'] == 17
                value = {'age_insert':stats(times),'retention_profiles':repository.retention_samples,'integrity':state}
                if eclass is EventRepository:
                    began = time.perf_counter()
                    try:
                        result = CQQLSearchRepository(path).analytics(compile_cqql('event.severity >= 0'),
                            start_time=base-timedelta(days=30),end_time=base+timedelta(minutes=1),
                            group_by=['event.provider','event.severity','event.source_type'],top_n=20,interval='day')
                        elapsed = (time.perf_counter()-began)*1000
                        with closing(sqlite3.connect(path)) as connection:
                            reference = connection.execute('SELECT event_provider,COUNT(*) AS n FROM security_events WHERE event_provider IS NOT NULL AND occurred_at BETWEEN ? AND ? GROUP BY event_provider ORDER BY n DESC,event_provider LIMIT 20',
                                ((base-timedelta(days=30)).isoformat(),(base+timedelta(minutes=1)).isoformat())).fetchall()
                        assert [(row.name,row.count) for row in result.groups[0].buckets] == reference
                        assert result.matching_events == sum(row.count for row in result.time_series) == state['count']-3
                        value['provider_analytics'] = {'status':'COMPLETE','wall_ms':round(elapsed,3),'exact_reference':'PASS'}
                    except Exception as exc:
                        if type(exc).__name__ != 'CQQLQueryTimeoutError': raise
                        value['provider_analytics'] = {'status':'TIMEOUT','wall_ms':round((time.perf_counter()-began)*1000,3)}
                else: value['provider_analytics'] = {'status':'UNSUPPORTED_IN_BASELINE_CONTRACT'}
                population['variants'][name] = value
                gc.collect()
                print(f'age completed size={size} variant={name}',flush=True)
                args.output.write_text(json.dumps(report,indent=2)+'\n')
            assert len({value['integrity']['evidence_sha256'] for value in population['variants'].values()}) == 1
    report['integrity']='PASS'
    args.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__': main()
