"""Exact M31 mixed HTTP workload, optional explicitly installed M32 index in clones."""
import argparse
import json
from pathlib import Path
import sys
import sqlite3
import hashlib
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'scripts')]
import benchmark_m31_reliability as previous
from app.db.fts_rowid import install
from app.db.cqql import CQQLSearchRepository
import app.main as application


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',action='store_true');parser.add_argument('--sizes',nargs='+',type=int,default=[10000,50000,100000]);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():raise ValueError('OUTPUT_MUST_BE_NEW')
    original=previous.harness.create_app
    def create(settings,**kwargs):
        if args.candidate:
            path=Path(settings.database_url.removeprefix('sqlite:///'))
            install(path,path.with_name(path.stem+'-m32-before.db'),disposable_only=True)
        if args.candidate:
            # Scope the factory injection to construction of this isolated test app.
            with patch.object(application,'CQQLSearchRepository',lambda path:CQQLSearchRepository(path,fts_strategy='m32_rowid')):
                app=original(settings,**kwargs)
        else:app=original(settings,**kwargs)
        return app
    previous.harness.create_app=create
    previous.harness.cpu_probe=lambda count,base:{'scope':'SEPARATE_CPU_PROBE_NOT_REPEATED_MIXED_CPU_IS_MEASURED'}
    sys.argv=[sys.argv[0],'--sizes',*[str(size) for size in args.sizes],'--output',str(args.output)]
    previous.main()
    report=json.loads(args.output.read_text());report['scope']='M32_M31_IDENTICAL_MIXED_HTTP_DISPOSABLE'
    report['fts_candidate']=args.candidate;report['ddl_activation']='EXPLICIT_TEMP_CLONES_ONLY'
    report['runtime']={'version':sqlite3.sqlite_version,'source_id':sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0]}
    report['m32_source_sha256']={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('backend/app/db/cqql.py','backend/app/db/fts_rowid.py','scripts/benchmark_m32_mixed.py')}
    args.output.write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
