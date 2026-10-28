"""Positive sparse FTS probe; synthetic derived search text only, never live data."""
import argparse
import gc
import json
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import datetime,timedelta,timezone
from pathlib import Path

from benchmark_m29_performance import ROOT,file_sha,load_snapshot,stats,integrity,CQQLSearchRepository,compile_cqql
from app.db.fts_locator_proposal import install


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    source_path = ROOT/'artifacts/runtime/m29-seed.db'
    manifest = json.loads((ROOT/'artifacts/runtime/m29-seed-manifest.json').read_text())
    if manifest['scope'] != 'SYNTHETIC_DISPOSABLE_ONLY' or file_sha(source_path) != manifest['sha256']:
        raise RuntimeError('synthetic fixture checksum mismatch')
    report = {'scope':'SYNTHETIC_DISPOSABLE_ONLY','setup':'one explicitly synthetic derived-index marker; restored before integrity',
        'note':'main matrix fts_rare returned zero; it is a no-match probe, not positive sparse evidence',
        'source_sha256':file_sha(Path(__file__)),'variants':{}}
    old_class = load_snapshot('cqql').CQQLSearchRepository
    with tempfile.TemporaryDirectory(prefix='cyberqalqon-m29-sparse-') as temporary:
        for name,qclass in (('before',old_class),('source_only',CQQLSearchRepository),('locator',CQQLSearchRepository)):
            path = Path(temporary)/(name+'.db')
            with closing(sqlite3.connect(source_path.as_uri()+'?mode=ro',uri=True)) as source, closing(sqlite3.connect(path)) as connection:
                source.backup(connection)
                event_id,text = connection.execute('SELECT event_id,search_text FROM security_events LIMIT 1').fetchone()
                connection.execute('UPDATE security_events SET search_text=search_text||? WHERE event_id=?',(' m29positivesparseuniquetoken',event_id))
                connection.commit()
                if name == 'locator': install(connection,disposable_only=True)
            query = compile_cqql('text CONTAINS "m29positivesparseuniquetoken"')
            repository = qclass(path)
            now = datetime.now(timezone.utc)
            elapsed = []
            for _ in range(5):
                began = time.perf_counter()
                result = repository.search(query,start_time=now-timedelta(days=3),end_time=now+timedelta(minutes=1),
                    sort='newest',limit=100,cursor=None)
                elapsed.append((time.perf_counter()-began)*1000)
                assert [row.event_id for row in result.items] == [event_id]
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('UPDATE security_events SET search_text=? WHERE event_id=?',(text,event_id))
                connection.commit()
            state = integrity(path)
            assert state['count'] == state['counter'] == state['fts_count'] == 100000
            assert state['identity_mismatches'] == state['foreign_keys'] == 0 and state['quick_check'] == 'ok'
            report['variants'][name] = {**stats(elapsed),'returned_rows':1,'timeouts':0,'reference':'PASS','integrity':state}
            gc.collect()
            args.output.write_text(json.dumps(report,indent=2)+'\n')
    assert len({value['integrity']['evidence_sha256'] for value in report['variants'].values()}) == 1
    report['integrity']='PASS'
    args.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__ == '__main__': main()
