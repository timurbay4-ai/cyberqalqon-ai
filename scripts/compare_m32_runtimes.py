"""Native-driver compatibility on exact same bytes, no production environment changes."""
from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
from app.db.alerts import AlertRepository
from app.db.shadow_history import initialize
from app.db.fts_rowid import install
from benchmark_cqql import INSERT_SQL,INSERT_COLUMNS,synthetic_row


def main():
    output=Path(sys.argv[1])
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    with tempfile.TemporaryDirectory(prefix='cq-m32-compare-') as raw:
        root=Path(raw);source=root/'source.db';history=root/'history.db';base=datetime(2026,10,22,8,tzinfo=timezone.utc)
        AlertRepository(f'sqlite:///{source.as_posix()}',migration_target_version=17).initialize()
        with closing(sqlite3.connect(source)) as c:
            for i in range(100):
                row=list(synthetic_row(i,base))
                if i%7==0:row[INSERT_COLUMNS.index('search_text')]+=' CAFÉ rareword'
                c.execute(INSERT_SQL,row)
            c.commit()
        initialize(history,source,disposable_only=True);install(source,root/'pre-index.db',disposable_only=True)
        results=[]
        for candidate in (False,True):
            result=root/('patched.json' if candidate else 'original.json')
            common=['--source',str(source),'--history',str(history),'--output',str(result)]
            command=[sys.executable,str(ROOT/'scripts/m32_candidate_runtime.py'),'--script',str(ROOT/'scripts/probe_m32_compatibility.py'),'--',*common] if candidate else [sys.executable,str(ROOT/'scripts/probe_m32_compatibility.py'),*common]
            subprocess.run(command,check=True,capture_output=True,timeout=60)
            results.append(json.loads(result.read_text()))
        if results[0]['semantic']!=results[1]['semantic']:raise AssertionError('RUNTIME_SEMANTIC_DIFFERENCE')
        output.write_text(json.dumps({'scope':'EXACT_SAME_DISPOSABLE_SCHEMA17_SIDECAR1_INPUT_BYTES','equivalent':True,'runtimes':results},indent=2)+'\n')
        print('exact compatibility PASS: '+results[0]['runtime']+' / '+results[1]['runtime'])


if __name__=='__main__':main()
