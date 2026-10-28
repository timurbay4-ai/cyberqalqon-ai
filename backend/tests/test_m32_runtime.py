from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
import pytest


@pytest.mark.parametrize('writers',['threads','processes'])
def test_wal_writers_checkpoint_and_reader_snapshot(tmp_path,writers):
    path=tmp_path/'SYNTHETIC-wal.db'
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('PRAGMA journal_mode=wal').fetchone()[0]=='wal'
        c.execute('CREATE TABLE rows(id INTEGER PRIMARY KEY,value TEXT NOT NULL)')
        c.executemany('INSERT INTO rows VALUES(?,?)',[(i,str(i)) for i in range(100)]);c.commit()
    reader=sqlite3.connect(path);reader.execute('BEGIN');assert reader.execute('SELECT COUNT(*) FROM rows').fetchone()[0]==100
    stops=threading.Event();checkpoints=[]
    def checkpoint():
        with closing(sqlite3.connect(path,timeout=.2)) as c:
            for _ in range(40):
                checkpoints.append(tuple(c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone()))
                if stops.is_set():break
    def write(offset):
        with closing(sqlite3.connect(path,timeout=2)) as c:
            for i in range(20):
                with c:c.execute('INSERT INTO rows VALUES(?,?)',(offset+i,str(offset+i)))
    with ThreadPoolExecutor(max_workers=3) as pool:
        check=pool.submit(checkpoint)
        if writers=='threads':
            futures=[pool.submit(write,offset) for offset in (1000,2000)]
            for future in futures:future.result(timeout=15)
        else:
            code="import sqlite3,sys; c=sqlite3.connect(sys.argv[1],timeout=2); n=int(sys.argv[2]); [(c.execute('INSERT INTO rows VALUES(?,?)',(n+i,str(n+i))),c.commit()) for i in range(20)];c.close()"
            workers=[subprocess.Popen([sys.executable,'-c',code,str(path),str(offset)],stdout=subprocess.PIPE,stderr=subprocess.PIPE) for offset in (1000,2000)]
            for worker in workers:
                output,error=worker.communicate(timeout=15);assert worker.returncode==0,error
        stops.set();check.result(timeout=5)
    assert checkpoints and reader.execute('SELECT COUNT(*) FROM rows').fetchone()[0]==100
    reader.rollback();reader.close()
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('SELECT COUNT(*) FROM rows').fetchone()[0]==140
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()==(0,0,0)
        rows=list(c.execute('SELECT id,value FROM rows ORDER BY id'))
    expected=[(i,str(i)) for i in range(100)]+[(n+i,str(n+i)) for n in (1000,2000) for i in range(20)]
    assert rows==expected


def test_terminated_writer_has_no_partial_commit(tmp_path):
    path=tmp_path/'SYNTHETIC-kill.db';ready=tmp_path/'ready'
    with closing(sqlite3.connect(path)) as c:
        c.execute('PRAGMA journal_mode=wal');c.execute('CREATE TABLE rows(id INTEGER PRIMARY KEY)');c.execute('INSERT INTO rows VALUES(1)');c.commit()
    code="import sqlite3,sys,pathlib,time; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); c.execute('INSERT INTO rows VALUES(2)');pathlib.Path(sys.argv[2]).write_text('ready');time.sleep(20)"
    worker=subprocess.Popen([sys.executable,'-c',code,str(path),str(ready)])
    try:
        deadline=time.perf_counter()+3
        while not ready.exists() and time.perf_counter()<deadline:time.sleep(.01)
        assert ready.exists();worker.kill();worker.wait(timeout=5)
    finally:
        if worker.poll() is None:worker.kill();worker.wait(timeout=5)
    with closing(sqlite3.connect(path)) as c:
        assert c.execute('SELECT id FROM rows').fetchall()==[(1,)]
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'


def test_backup_json_savepoint_and_existing_file_compatibility(tmp_path):
    path=tmp_path/'SYNTHETIC-compat.db';backup=tmp_path/'backup.db'
    with closing(sqlite3.connect(path)) as c:
        c.execute('PRAGMA foreign_keys=ON');c.execute('CREATE TABLE parent(id INTEGER PRIMARY KEY)');c.execute('CREATE TABLE child(id REFERENCES parent(id))')
        c.execute('INSERT INTO parent VALUES(1)');c.execute('SAVEPOINT sample');c.execute('INSERT INTO child VALUES(1)');c.execute('ROLLBACK TO sample');c.execute('RELEASE sample');c.commit()
        assert c.execute('SELECT COUNT(*) FROM child').fetchone()[0]==0
        assert c.execute("SELECT json_extract('{\"x\":7}','$.x')").fetchone()[0]==7
        with closing(sqlite3.connect(backup)) as target:c.backup(target)
    with closing(sqlite3.connect(backup.as_uri()+'?mode=ro',uri=True)) as c:
        assert c.execute('SELECT id FROM parent').fetchall()==[(1,)]
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_candidate_child_bootstrap_uses_same_source_id():
    parent=sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0]
    child=subprocess.check_output([sys.executable,'-c',"import sqlite3;print(sqlite3.connect(':memory:').execute('select sqlite_source_id()').fetchone()[0])"],text=True).strip()
    assert child==parent
