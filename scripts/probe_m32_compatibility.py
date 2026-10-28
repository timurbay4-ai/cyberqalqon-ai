"""Same immutable disposable source+sidecar read by original/candidate processes."""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize,ShadowHistoryRepository
from app.db.cqql import CQQLSearchRepository
from app.services.cqql import compile_cqql
from app.db.fts_rowid import file_sha


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--history',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    if args.output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    before=[file_sha(args.source),file_sha(args.history)];store=ShadowHistoryRepository(args.history,args.source)
    start=datetime(2026,10,1,tzinfo=timezone.utc);end=start+timedelta(days=31);queries={}
    definitions=['text CONTAINS "synthetic"','text CONTAINS "rareword"','text CONTAINS "CAFÉ"','text CONTAINS "absent"',
        'event.severity >= 7 AND NOT event.provider = "absent"','event.provider = "Microsoft-Windows-Security-Auditing"',
        'source.port >= 49152 AND (event.code = "4625" OR event.code = "4624")']
    for strategy in ('legacy','m32_rowid'):
        repository=CQQLSearchRepository(args.source,fts_strategy=strategy)
        for query in definitions:
            compiled=compile_cqql(query);ids=[];cursors=[];cursor=None
            while True:
                page=repository.search(compiled,start_time=start,end_time=end,sort='newest',limit=7,cursor=cursor)
                ids.extend(v.event_id for v in page.items);cursor=page.next_cursor
                if not cursor:break
                cursors.append(cursor)
            exported=repository.export(compiled,start_time=start,end_time=end,sort='newest',limit=1000)
            analytics=repository.analytics(compiled,start_time=start,end_time=end,group_by=['event.provider'],top_n=10,interval='day')
            assert ids==[v.event_id for v in exported.items] and len(ids)==analytics.matching_events
            queries[strategy+':'+query]={'ids':ids,'cursors':cursors,'matching_events':analytics.matching_events,
                'groups':[v.model_dump(mode='json') for v in analytics.groups],'series':[v.model_dump(mode='json') for v in analytics.time_series]}
    with tempfile.TemporaryDirectory(prefix='cq-m32-fresh-') as raw:
        path=Path(raw)/'fresh.db';AlertRepository(f'sqlite:///{path.as_posix()}',migration_target_version=17).initialize()
        history=Path(raw)/'fresh-history.db';initialize(history,path,disposable_only=True);ShadowHistoryRepository(history,path).verify()
        with closing(sqlite3.connect(path)) as c:
            schema=c.execute('PRAGMA user_version').fetchone()[0];c.execute('PRAGMA foreign_keys=ON');c.execute('CREATE TABLE sample(id INTEGER PRIMARY KEY,value TEXT)')
            c.execute('INSERT INTO sample VALUES(1,?)',('SYNTHETIC',));c.execute('SAVEPOINT check_savepoint');c.execute('INSERT INTO sample VALUES(2,?)',('rollback',));c.execute('ROLLBACK TO check_savepoint');c.execute('RELEASE check_savepoint');c.commit()
            savepoint=c.execute('SELECT * FROM sample').fetchall();json_value=c.execute("SELECT json_extract('{\"n\":7}','$.n')").fetchone()[0]
            with closing(sqlite3.connect(Path(raw)/'backup.db')) as target:c.backup(target)
        with closing(sqlite3.connect(Path(raw)/'backup.db')) as c:restored=c.execute('SELECT * FROM sample').fetchall();assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
    assert before==[file_sha(args.source),file_sha(args.history)]
    semantic={'queries':queries,'fresh_schema':schema,'existing_sidecar_schema':1,'savepoint':savepoint,'json':json_value,'backup_restore':restored,'input_sha256':before}
    report={'runtime':sqlite3.sqlite_version,'source_id':sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0],
        'semantic':semantic,'semantic_sha256':hashlib.sha256(json.dumps(semantic,sort_keys=True).encode()).hexdigest(),'inputs_unchanged':True}
    args.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
