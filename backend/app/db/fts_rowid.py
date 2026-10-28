"""M32 explicit disposable external-content index. No startup/live migration."""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import time

TABLE='m32_events_fts'
DDL=(
 "CREATE VIRTUAL TABLE m32_events_fts USING fts5(search_text,content='security_events',content_rowid='rowid',tokenize='unicode61 remove_diacritics 2')",
 "CREATE TRIGGER m32_fts_insert AFTER INSERT ON security_events BEGIN INSERT INTO m32_events_fts(rowid,search_text) VALUES(new.rowid,new.search_text); END",
 "CREATE TRIGGER m32_fts_delete AFTER DELETE ON security_events BEGIN INSERT INTO m32_events_fts(m32_events_fts,rowid,search_text) VALUES('delete',old.rowid,old.search_text); END",
 "CREATE TRIGGER m32_fts_update AFTER UPDATE OF search_text ON security_events BEGIN INSERT INTO m32_events_fts(m32_events_fts,rowid,search_text) VALUES('delete',old.rowid,old.search_text); INSERT INTO m32_events_fts(rowid,search_text) VALUES(new.rowid,new.search_text); END",
 "CREATE TRIGGER m32_fts_rowid_guard BEFORE UPDATE ON security_events WHEN old.rowid!=new.rowid BEGIN SELECT RAISE(ABORT,'FTS rowid change requires explicit rebuild'); END",
 "CREATE TABLE m32_fts_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL CHECK(version=1),manifest TEXT NOT NULL)"
)
LEGACY='e.event_id IN (SELECT event_id FROM security_events_fts WHERE security_events_fts MATCH ?)'
OPTIMIZED='e.rowid IN (SELECT rowid FROM m32_events_fts WHERE m32_events_fts MATCH ?)'


def file_sha(path):
    value=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):value.update(block)
    return value.hexdigest()


def content_digest(c):
    value=hashlib.sha256()
    for row in c.execute('SELECT event_id,raw_event_json,search_text FROM security_events ORDER BY event_id'):
        value.update(json.dumps(tuple(row),ensure_ascii=False,separators=(',',':')).encode());value.update(b'\n')
    return value.hexdigest()


def verify(c,*,integrity=False):
    expected={s.split()[3 if s.startswith('CREATE VIRTUAL') else 2].split('(')[0]:s for s in DDL}
    rows={row[0]:row[1] for row in c.execute("SELECT name,sql FROM sqlite_master WHERE name IN ('m32_events_fts','m32_fts_insert','m32_fts_delete','m32_fts_update','m32_fts_rowid_guard','m32_fts_meta')")}
    if rows!=expected:raise ValueError('M32_FTS_SCHEMA_MISMATCH')
    row=c.execute('SELECT version,manifest FROM m32_fts_meta WHERE singleton=1').fetchone()
    if row is None or row[0]!=1:raise ValueError('M32_FTS_MANIFEST_MISSING')
    manifest=json.loads(row[1])
    if manifest.get('version')!='m32-fts-rowid-v1' or manifest.get('ddl_sha256')!=hashlib.sha256('\n'.join(DDL).encode()).hexdigest():
        raise ValueError('M32_FTS_MANIFEST_MISMATCH')
    if integrity:c.execute("INSERT INTO m32_events_fts(m32_events_fts,rank) VALUES('integrity-check',1)")
    return manifest


def rewrite(compiled):
    if not compiled.uses_fts:return compiled.sql
    if LEGACY not in compiled.sql:raise ValueError('M32_FTS_COMPILER_CONTRACT_MISMATCH')
    return compiled.sql.replace(LEGACY,OPTIMIZED)


def install(path:Path,backup:Path,*,disposable_only=False,fault_hook=None):
    if disposable_only is not True:raise ValueError('DISPOSABLE_MIGRATION_REQUIRED')
    path=Path(path).resolve(strict=True);backup=Path(backup)
    started=time.perf_counter();fault_hook=fault_hook or (lambda stage:None)
    with closing(sqlite3.connect(path)) as c:
        if c.execute('PRAGMA user_version').fetchone()[0]!=17:raise ValueError('SOURCE_SCHEMA_NOT_17')
        if c.execute("SELECT 1 FROM sqlite_master WHERE name='m32_fts_meta'").fetchone():return verify(c,integrity=True)
        if backup.exists() or backup.is_symlink() or backup.resolve()==path:raise ValueError('BACKUP_TARGET_MUST_BE_NEW')
        required=path.stat().st_size*2+10485760
        if shutil.disk_usage(path.parent).free<required:raise ValueError('INSUFFICIENT_BACKUP_INDEX_HEADROOM')
        before=content_digest(c)
        # Create only a new caller-owned disposable backup; never overwrite.
        with backup.open('xb'):pass
        with closing(sqlite3.connect(backup)) as target:
            c.backup(target)
            if target.execute('PRAGMA quick_check').fetchone()[0]!='ok' or content_digest(target)!=before:raise ValueError('BACKUP_VERIFY_FAILED')
        manifest={'version':'m32-fts-rowid-v1','source_schema':17,'backup_sha256':file_sha(backup),
            'initial_index_maintenance':'FTS5_OPTIMIZE_BEFORE_PUBLICATION',
            'source_digest':before,'ddl_sha256':hashlib.sha256('\n'.join(DDL).encode()).hexdigest(),
            'rows':c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],
            'disk_headroom_required_bytes':required,'source_identity':'UNCHANGED_EVENT_IDS_AND_ENVELOPES',
            'activation':'EXPLICIT_DISPOSABLE_ONLY','rollback':'DROP_ONLY_M32_DERIVED_STRUCTURES'}
        try:
            c.execute('BEGIN IMMEDIATE')
            if content_digest(c)!=before:raise ValueError('SOURCE_CHANGED_AFTER_BACKUP')
            for statement in DDL:c.execute(statement)
            fault_hook('AFTER_DDL')
            c.execute("INSERT INTO m32_events_fts(m32_events_fts) VALUES('rebuild')")
            # A large rebuild can leave incremental merge debt. Finish it before
            # publishing this new derived index, rather than charging first ACKs.
            # Same tokenizer/positions/triggers, FULL commits and merge policy.
            c.execute("INSERT INTO m32_events_fts(m32_events_fts) VALUES('optimize')")
            c.execute('INSERT INTO m32_fts_meta VALUES(1,1,?)',(json.dumps(manifest,sort_keys=True),))
            verify(c,integrity=True)
            if content_digest(c)!=before:raise ValueError('SOURCE_CONTENT_CHANGED')
            fault_hook('BEFORE_COMMIT');c.commit()
        except BaseException:c.rollback();raise
        manifest['build_wall_ms']=round((time.perf_counter()-started)*1000,3)
        manifest['database_bytes']=path.stat().st_size
        return manifest


def rollback(path:Path,*,disposable_only=False):
    if disposable_only is not True:raise ValueError('DISPOSABLE_MIGRATION_REQUIRED')
    with closing(sqlite3.connect(path)) as c:
        try:
            c.execute('BEGIN IMMEDIATE')
            verify(c,integrity=True);before=content_digest(c)
            for name in ('m32_fts_insert','m32_fts_delete','m32_fts_update','m32_fts_rowid_guard'):c.execute('DROP TRIGGER '+name)
            c.execute('DROP TABLE m32_events_fts');c.execute('DROP TABLE m32_fts_meta')
            if content_digest(c)!=before:raise ValueError('SOURCE_CONTENT_CHANGED')
            c.commit()
        except BaseException:c.rollback();raise
