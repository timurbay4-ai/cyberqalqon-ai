"""Checksum-verified synthetic M31 seeds -> own temporary FTS strategy matrix."""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime,timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from app.db.fts_rowid import install,verify,file_sha
from app.db.cqql import CQQLSearchRepository
from app.services.cqql import compile_cqql
from benchmark_m29_performance import stats,process_memory


def run(size,root):
    source=ROOT/('artifacts/runtime/m29-seed.db' if size==100000 else f'artifacts/runtime/m29-seed-{size}.db')
    manifest=json.loads(source.with_name(source.stem+'-manifest.json').read_text())
    if manifest['scope']!='SYNTHETIC_DISPOSABLE_ONLY' or file_sha(source)!=manifest['sha256']:raise ValueError('SYNTHETIC_SEED_CHECKSUM_MISMATCH')
    path=root/f'fts-{size}.db'
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(path)) as c:original.backup(c)
    with closing(sqlite3.connect(path)) as c:
        ids=[r[0] for r in c.execute('SELECT event_id FROM security_events ORDER BY occurred_at DESC,event_id DESC')]
        for event,word in ((ids[0],'m32rarecent'),(ids[-1],'m32rarehistorical')):
            c.execute('UPDATE security_events SET search_text=search_text || ? WHERE event_id=?',(' '+word,event))
        c.commit();end=datetime.fromisoformat(c.execute('SELECT MAX(occurred_at) FROM security_events').fetchone()[0])+timedelta(hours=1)
        start=datetime.fromisoformat(c.execute('SELECT MIN(occurred_at) FROM security_events').fetchone()[0])-timedelta(hours=1)
    migration=install(path,root/f'backup-{size}.db',disposable_only=True)
    match={'dense':'"synthetic"','rare_recent':'"m32rarecent"','rare_old':'"m32rarehistorical"',
        'multi':'"synthetic" AND "m32rarehistorical"','none':'"m32nomatch"'}
    result={'events':size,'seed_sha256':manifest['sha256'],'migration':migration,'post_build_bytes':path.stat().st_size,'queries':{},'deadline_ms':1500,'scope':'DISPOSABLE_ONLY'}
    for name,term in match.items():
        strategies={
            'legacy':"e.event_id IN (SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ?)",
            'rowid_in':"e.rowid IN (SELECT rowid FROM m32_events_fts WHERE m32_events_fts MATCH ?)",
            'time_correlated':"EXISTS(SELECT 1 FROM m32_events_fts f WHERE f.rowid=e.rowid AND m32_events_fts MATCH ?)",
            'time_intersection':"e.rowid IN (SELECT rowid FROM m32_events_fts WHERE m32_events_fts MATCH ?)"}
        outcomes={};reference=None
        # Independent SQL reference: complete legacy FTS IDs, sorted by Python.
        with closing(sqlite3.connect(path)) as c:
            expected_set={r[0] for r in c.execute('SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ?',(term,))}
            ordered=[r[0] for r in c.execute('SELECT event_id FROM security_events WHERE occurred_at BETWEEN ? AND ? ORDER BY occurred_at DESC,event_id DESC',(start.isoformat(),end.isoformat()))]
            reference=[value for value in ordered if value in expected_set][:101]
        for strategy,predicate in strategies.items():
            index=' INDEXED BY idx_security_events_occurred_id' if strategy.startswith('time_') else ''
            sql=f'SELECT e.event_id FROM security_events e{index} WHERE e.occurred_at BETWEEN ? AND ? AND {predicate} ORDER BY e.occurred_at DESC,e.event_id DESC LIMIT 101'
            parameters=(start.isoformat(),end.isoformat(),term);samples=[];statuses=[];correct=[]
            cpu_start=time.process_time()
            with closing(sqlite3.connect(path)) as c:
                plan=[r[3] for r in c.execute('EXPLAIN QUERY PLAN '+sql,parameters)]
                for attempt in range(3):
                    began=time.perf_counter();c.set_progress_handler(lambda:int(time.perf_counter()-began>=1.5),1000)
                    try:
                        actual=[r[0] for r in c.execute(sql,parameters)];statuses.append('COMPLETE');correct.append(actual==reference)
                    except sqlite3.OperationalError as exc:
                        if 'interrupt' not in str(exc).lower():raise
                        statuses.append('TIMEOUT');correct.append(None)
                    finally:c.set_progress_handler(None,0);samples.append((time.perf_counter()-began)*1000)
            outcomes[strategy]={'statuses':statuses,'equivalent':correct,'samples_ms':samples,
                'first_sample_scope':'NEW_CONNECTION_OS_CACHE_UNCONTROLLED','sql':sql,'parameters':list(parameters),
                'cpu_seconds':time.process_time()-cpu_start,'latency_including_failures':stats(samples),'plan':plan}
        result['queries'][name]={'exact_candidate_count':len(expected_set),'reference_ids_sha256':hashlib.sha256(json.dumps(reference).encode()).hexdigest(),'strategies':outcomes}
    # Actual repository candidate/search/export and deterministic paginated IDs.
    repository=CQQLSearchRepository(path,fts_strategy='m32_rowid');pages={}
    for name,text in [('dense','SYNTHETIC'),('rare_old','m32rarehistorical'),('none','m32nomatch')]:
        compiled=compile_cqql('text CONTAINS "'+text+'"');began=time.perf_counter()
        found=repository.search(compiled,start_time=start,end_time=end,sort='newest',limit=100,cursor=None)
        pages[name]={'elapsed_ms':round((time.perf_counter()-began)*1000,4),'count':len(found.items),'has_next':bool(found.next_cursor)}
    with closing(sqlite3.connect(path)) as c:
        verify(c,integrity=True);result['integrity']={'quick_check':c.execute('PRAGMA quick_check').fetchone()[0],
            'fk':len(c.execute('PRAGMA foreign_key_check').fetchall()),'schema':c.execute('PRAGMA user_version').fetchone()[0]}
    result['repository']=pages;result.update(process_memory());return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--sizes',type=int,nargs='+',default=[10000,50000,100000]);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError('OUTPUT_MUST_BE_NEW')
    report={'scope':'M32_SYNTHETIC_DISPOSABLE_FTS','runtime':sqlite3.sqlite_version,'source_id':sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0],'populations':[],
        'source_sha256':{name:file_sha(ROOT/name) for name in ('backend/app/db/cqql.py','backend/app/db/fts_rowid.py','scripts/benchmark_m32_fts.py')}}
    with tempfile.TemporaryDirectory(prefix='cq-m32-fts-',ignore_cleanup_errors=True) as raw:
        for size in args.sizes:
            if size not in (10000,50000,100000):raise ValueError('invalid size')
            report['populations'].append(run(size,Path(raw)));args.output.write_text(json.dumps(report,indent=2)+'\n');print('completed '+str(size),flush=True)


if __name__=='__main__':main()
