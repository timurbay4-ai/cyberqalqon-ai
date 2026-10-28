"""M31 identical disposable HTTP workload using M33's supported app factory gate.

Both modes retain schema17, one single-event writer, 100k/30day retention and the
existing 1500ms/4-slot search budget. No real deployment or live path arguments.
"""
import argparse
import hashlib
import json
import sqlite3
import sys
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'backend'), str(ROOT/'scripts')]
import benchmark_m31_reliability as previous
from app.db.fts_rowid import install


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', action='store_true')
    parser.add_argument('--sizes', nargs='+', type=int, default=[10000, 50000, 100000])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must be new')
    original = previous.harness.create_app
    def create(settings, **kwargs):
        if args.candidate:
            source = Path(settings.database_url.removeprefix('sqlite:///'))
            install(source, source.with_name(source.stem+'-m33-before.db'), disposable_only=True)
            kwargs['disposable_fts_rowid'] = True
        return original(settings, **kwargs)
    previous.harness.create_app = create
    previous.harness.cpu_probe = lambda count, base: {'scope': 'SEPARATE_CPU_PROBE_NOT_REPEATED_MIXED_CPU_MEASURED'}
    sys.argv = [sys.argv[0], '--sizes', *map(str, args.sizes), '--output', str(args.output)]
    previous.main()
    result = json.loads(args.output.read_text())
    result['scope'] = 'M33_ACTUAL_FACTORY_M31_IDENTICAL_DISPOSABLE_HTTP'
    result['fts_candidate'] = args.candidate
    result['runtime'] = {'sqlite': sqlite3.sqlite_version,
        'source_id': sqlite3.connect(':memory:').execute('SELECT sqlite_source_id()').fetchone()[0],
        'fastapi': version('fastapi'), 'starlette': version('starlette'), 'pydantic': version('pydantic')}
    result['m33_source_sha256'] = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
        'backend/app/main.py','backend/app/db/cqql.py','backend/app/db/fts_rowid.py','scripts/benchmark_m33_release.py')}
    args.output.write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
