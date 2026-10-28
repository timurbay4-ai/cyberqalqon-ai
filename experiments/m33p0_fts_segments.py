"""Read-only FTS structure observations around owned diagnostic writes.

NEVER an acceptance workload: extra reads can warm pages and perturb timing.
Only the original fixed synthetic seeds are accepted by the delegated harness.
No FTS commands, checkpoint calls, DDL, configuration or data changes are added.
"""
from __future__ import annotations
import argparse
from contextvars import ContextVar
from contextlib import closing
from functools import wraps
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
import benchmark_m33p0 as benchmark
import m33_request_trace as tracing
from app.db.events import EventRepository
from app.db.fts_rowid import verify
from app.services.request_tracing import current_request_id

_ingest=ContextVar('segment_probe_ingest',default=False)
_insert=ContextVar('segment_probe_insert',default=False)


def varint(data,offset):
    value=0
    for index in range(9):
        if offset>=len(data):raise ValueError('TRUNCATED_FTS_VARINT')
        byte=data[offset];offset+=1
        value=(value<<8)|byte if index==8 else (value<<7)|(byte&127)
        if index==8 or byte<128:return value,offset
    raise ValueError('INVALID_FTS_VARINT')


def structure_header(data):
    if not isinstance(data,bytes) or not 7<=len(data)<=65536:raise ValueError('UNSUPPORTED_FTS_STRUCTURE')
    levels,offset=varint(data,4)
    segments,offset=varint(data,offset)
    leaves,offset=varint(data,offset)
    if levels>64 or segments>65535:raise ValueError('UNSUPPORTED_FTS_STRUCTURE')
    detail=[];seen=0
    for _ in range(levels):
        inputs,offset=varint(data,offset);count,offset=varint(data,offset)
        if count>segments:raise ValueError('UNSUPPORTED_FTS_STRUCTURE')
        pages=0
        for _ in range(count):
            segid,offset=varint(data,offset);first,offset=varint(data,offset);last,offset=varint(data,offset)
            if not 0<segid<=65535 or not 0<first<=last:raise ValueError('UNSUPPORTED_FTS_STRUCTURE')
            pages+=last-first+1
        seen+=count;detail.append({'merging_inputs':inputs,'segments':count,'leaf_pages':pages})
    if seen!=segments or offset!=len(data):raise ValueError('UNSUPPORTED_FTS_STRUCTURE')
    return {'levels':levels,'segments':segments,'level0_leaves_written':leaves,'per_level':detail}


def snapshot(connection):
    result={}
    queries=(('security_events_fts','SELECT block FROM security_events_fts_data WHERE id=10',
              'SELECT COUNT(DISTINCT segid) FROM security_events_fts_idx'),
             ('m32_events_fts','SELECT block FROM m32_events_fts_data WHERE id=10',
              'SELECT COUNT(DISTINCT segid) FROM m32_events_fts_idx'))
    for prefix,structure_sql,count_sql in queries:
        # Fixed developer-owned table names, not SQL/payload supplied by input.
        exists=sqlite3.Connection.execute(connection,'SELECT 1 FROM sqlite_master WHERE name=?',(prefix,)).fetchone()
        if not exists:
            result['legacy' if prefix=='security_events_fts' else 'candidate']=None;continue
        blob=sqlite3.Connection.execute(connection,structure_sql).fetchone()
        header=structure_header(blob[0])
        header['idx_distinct_segments']=sqlite3.Connection.execute(connection,count_sql).fetchone()[0]
        if header['segments']!=header['idx_distinct_segments']:raise ValueError('FTS_SEGMENT_COUNT_DISAGREEMENT')
        result['legacy' if prefix=='security_events_fts' else 'candidate']=header
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--snapshots-output',required=True,type=Path)
    parser.add_argument('--precompact-new-index',action='store_true')
    args,remaining=parser.parse_known_args()
    if args.snapshots_output.exists():parser.error('New snapshot path required')
    if sqlite3.sqlite_version!='3.54.1':parser.error('Verified 3.54.1 process required')
    if '--trace-off' in remaining:parser.error('Segment probe requires request tracing')
    rows=[]
    probe_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    original_ingest=EventRepository.ingest
    original_commit=tracing.TraceConnection._commit_native
    original_execute=tracing.TraceCursor.execute
    original_install=benchmark.install_rowid
    def prepared_install(path,backup,**kwargs):
        manifest=original_install(path,backup,**kwargs)
        # This intervention is only called by the verified synthetic harness's
        # B setup, before its application starts. Never repair existing/live DBs.
        with closing(sqlite3.connect(path)) as c,c:
            assert c.execute('PRAGMA user_version').fetchone()[0]==17
            c.execute('BEGIN IMMEDIATE')
            c.execute("INSERT INTO m32_events_fts(m32_events_fts) VALUES('optimize')")
            verify(c,integrity=True);c.commit()
        return manifest
    @wraps(original_ingest)
    def ingest(*a,**kw):
        token,new=_ingest.set(True),_insert.set(False)
        try:return original_ingest(*a,**kw)
        finally:_ingest.reset(token);_insert.reset(new)
    def observe(connection,operation,function):
        if not _ingest.get() or current_request_id() is None:return function()
        if len(rows)>=1024:raise RuntimeError('SEGMENT_PROBE_BUDGET')
        before=snapshot(connection);changes=connection.total_changes;started=time.perf_counter_ns()
        try:return function()
        finally:
            elapsed=time.perf_counter_ns()-started
            rows.append({'request_id':current_request_id(),'operation':operation,'is_new':_insert.get(),
                         'native_call_ns':elapsed,'before':before,'after':snapshot(connection),
                         'changes_during_call':connection.total_changes-changes})
    def commit(connection):return observe(connection,'COMMIT',lambda:original_commit(connection))
    def execute(cursor,sql,parameters=()):
        if tracing.classify(sql)=='INSERT_INCLUDING_FTS' and _ingest.get():
            _insert.set(True)
            return observe(cursor.connection,'INSERT_INCLUDING_FTS',lambda:original_execute(cursor,sql,parameters))
        return original_execute(cursor,sql,parameters)
    EventRepository.ingest=ingest
    tracing.TraceConnection._commit_native=commit
    tracing.TraceCursor.execute=execute
    if args.precompact_new_index:benchmark.install_rowid=prepared_install
    sys.argv=[str(ROOT/'scripts/benchmark_m33p0.py'),*remaining]
    try:benchmark.main()
    finally:
        EventRepository.ingest=original_ingest
        tracing.TraceConnection._commit_native=original_commit
        tracing.TraceCursor.execute=original_execute
        benchmark.install_rowid=original_install
        report={'scope':'DISPOSABLE_DIAGNOSTIC_EXTRA_READS_NOT_ACCEPTANCE','sqlite':sqlite3.sqlite_version,
                'probe_sha256':probe_sha,'precompact_new_index':args.precompact_new_index,
                'note':'Native-call timing excludes snapshots; HTTP/outer commit includes probe overhead. No syscall fsync attribution.',
                'records':rows}
        args.snapshots_output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'status':'FAILED','error_type':type(exc).__name__}),flush=True)
        raise SystemExit(1) from None
