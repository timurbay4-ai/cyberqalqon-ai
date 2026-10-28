"""Read native runtime identity; exercises only memory/own temporary databases."""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from contextlib import closing


def probe():
    import _sqlite3
    origin=None
    if os.name=='nt':
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.GetModuleHandleW.argtypes=[ctypes.c_wchar_p];kernel.GetModuleHandleW.restype=ctypes.c_void_p
        kernel.GetModuleFileNameW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_uint];kernel.GetModuleFileNameW.restype=ctypes.c_uint
        handle=kernel.GetModuleHandleW('sqlite3.dll');buffer=ctypes.create_unicode_buffer(32768)
        if handle and kernel.GetModuleFileNameW(handle,buffer,len(buffer)):origin=buffer.value
    elif Path('/proc/self/maps').exists():
        found={line.split(maxsplit=5)[-1] for line in Path('/proc/self/maps').read_text().splitlines() if '/libsqlite3.so' in line}
        if len(found)==1:origin=found.pop()
    with closing(sqlite3.connect(':memory:')) as c:
        source=c.execute('select sqlite_source_id()').fetchone()[0]
        c.execute('create virtual table f using fts5(text)');c.execute("insert into f values('SYNTHETIC café')")
        fts=c.execute("select count(*) from f where f match 'cafe'").fetchone()[0]==1
        options=sorted(row[0] for row in c.execute('pragma compile_options'))
        json_ok=c.execute("select json_extract('{\"x\":7}','$.x')").fetchone()[0]==7
    with tempfile.TemporaryDirectory(prefix='cq-m32-probe-') as raw:
        p=Path(raw)/'probe.db'
        with closing(sqlite3.connect(p)) as c:
            wal=c.execute('pragma journal_mode=wal').fetchone()[0]
            c.execute('pragma busy_timeout=137');busy=c.execute('pragma busy_timeout').fetchone()[0]
            schema_cookie=c.execute('pragma schema_version').fetchone()[0]
            application_schema=c.execute('pragma user_version').fetchone()[0]
        header=p.read_bytes()[:16].hex()
        with closing(sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)) as c:uri=c.execute('pragma quick_check').fetchone()[0]=='ok'
    official_new='2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76'
    potentially_affected=tuple(map(int,sqlite3.sqlite_version.split('.'))) < (3,51,3)
    return {'scope':'FRESH_TEST_PROCESS_ONLY','python':sys.version,'executable':sys.executable,
        'sqlite_module':sqlite3.__file__,'sqlite_module_version':getattr(sqlite3,'version','NOT_EXPOSED_BY_THIS_PYTHON'),'sqlite_version':sqlite3.sqlite_version,
        'sqlite_source_id':source,'threadsafety':sqlite3.threadsafety,'compile_options':options,
        'extension_path':_sqlite3.__file__,'native_library':origin,
        'native_sha256':hashlib.sha256(Path(origin).read_bytes()).hexdigest() if origin else None,
        'fts5':fts,'json':json_ok,'uri_readonly':uri,'wal':wal,'busy_timeout_ms':busy,
        'probe_application_user_version':application_schema,'probe_schema_cookie':schema_cookie,
        'database_file_format':'SQLite format 3','database_header_hex':header,
        'advisory': 'PATCHED_VERIFIED' if source==official_new else 'POTENTIALLY_AFFECTED' if potentially_affected else 'UNKNOWN',
        'classification_basis':'Exact upstream source ID. Old vendor backport status is unverified; candidate archive provenance must also be verified. Stress/quick_check is not patch evidence.',
        'production_changed':False}


if __name__=='__main__':print(json.dumps(probe(),indent=2))
