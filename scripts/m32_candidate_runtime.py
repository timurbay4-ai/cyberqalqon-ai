"""Verified official SQLite candidate in a FRESH test process, never an installer."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]
DIRECTORY=ROOT/'artifacts/runtime/m32-sqlite-3540100'
URL='https://www.sqlite.org/2026/sqlite-dll-win-x64-3540100.zip'
SHA3='c2d09c8babb9399277055c057c97a53f1ffd7c5f11d0c1f2118ffdfa39f2daa4'
SOURCE='2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76'


def prepare():
    DIRECTORY.mkdir(parents=True,exist_ok=True)
    archive=DIRECTORY/'upstream.zip'
    if not archive.exists():
        with urllib.request.urlopen(URL,timeout=30) as r:body=r.read(4*1024*1024+1)
        if len(body)>4*1024*1024 or hashlib.sha3_256(body).hexdigest()!=SHA3:raise RuntimeError('upstream archive checksum mismatch')
        archive.write_bytes(body)
    body=archive.read_bytes()
    if hashlib.sha3_256(body).hexdigest()!=SHA3:raise RuntimeError('cached archive checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(body)) as zipped:
        matches=[entry for entry in zipped.infolist() if entry.filename=='sqlite3.dll']
        if len(matches)!=1 or matches[0].file_size>8*1024*1024:raise RuntimeError('unexpected upstream archive')
        dll=zipped.read(matches[0]);path=DIRECTORY/'sqlite3.dll'
        if path.exists() and path.read_bytes()!=dll:raise RuntimeError('candidate DLL substituted')
        if not path.exists():path.write_bytes(dll)
    return {'url':URL,'archive_sha3_256':SHA3,'dll_sha256':hashlib.sha256(dll).hexdigest(),'source_id':SOURCE,
        'verification':'Official HTTPS download-page SHA3 and release source ID, not an Authenticode claim.',
        'scope':'ISOLATED_TEST_PROCESS_ONLY_NOT_INSTALLED','dll_path':str(path)}


def load():
    if os.name!='nt' or 'sqlite3' in sys.modules or '_sqlite3' in sys.modules:raise RuntimeError('requires fresh Windows process before SQLite import')
    manifest=prepare();library=ctypes.WinDLL(str(DIRECTORY/'sqlite3.dll'))
    import sqlite3
    with sqlite3.connect(':memory:') as c:source=c.execute('select sqlite_source_id()').fetchone()[0]
    if source!=SOURCE:raise RuntimeError('linked SQLite source differs from verified candidate')
    # Keep the library handle alive until process exit. No PATH/sitecustomize/venv mutation.
    return library,manifest


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--prepare',action='store_true')
    parser.add_argument('--module');parser.add_argument('--script',type=Path);parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    if args.prepare:print(json.dumps(prepare(),indent=2));return
    library,manifest=load()
    arguments=args.arguments[1:] if args.arguments[:1]==['--'] else args.arguments
    sys.path[:0]=[str(ROOT/'backend'),str(ROOT/'wazuh'),str(ROOT/'scripts')]
    if args.module:sys.argv=[args.module,*arguments];runpy.run_module(args.module,run_name='__main__')
    elif args.script:sys.argv=[str(args.script),*arguments];runpy.run_path(str(args.script),run_name='__main__')
    else:
        from probe_m32_sqlite import probe
        print(json.dumps({'candidate':manifest,'probe':probe()},indent=2))


if __name__=='__main__':main()
