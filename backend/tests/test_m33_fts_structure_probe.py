from contextlib import closing
import sqlite3

import pytest

from experiments.m33p0_fts_segments import structure_header,varint
from tests.test_m32_storage import fts


def test_private_fts_header_probe_crosschecks_actual_segments_before_after_merge():
    with closing(sqlite3.connect(':memory:')) as c:
        c.execute('CREATE VIRTUAL TABLE synthetic USING fts5(content)')
        for i in range(5):
            c.execute('INSERT INTO synthetic(content) VALUES(?)',(f'SYNTHETIC {i}',));c.commit()
        before=structure_header(c.execute('SELECT block FROM synthetic_data WHERE id=10').fetchone()[0])
        assert before['segments']==c.execute('SELECT COUNT(DISTINCT segid) FROM synthetic_idx').fetchone()[0]
        # Only an owned in-memory verification of the observer's parser.
        c.execute("INSERT INTO synthetic(synthetic) VALUES('optimize')");c.commit()
        after=structure_header(c.execute('SELECT block FROM synthetic_data WHERE id=10').fetchone()[0])
        assert after['segments']==1 and after['levels']>=1
        assert c.execute('SELECT COUNT(*) FROM synthetic').fetchone()[0]==5


def test_structure_probe_rejects_truncated_and_unbounded_metadata():
    for data in (b'',b'\0'*4,b'\0'*4+b'\x80\x80\x80',b'\0'*4+b'\x41\x00\x00'):
        with pytest.raises(ValueError):structure_header(data)
    with pytest.raises(ValueError):varint(b'\x80',0)
    assert varint(b'\x81\x00',0)==(128,2)


def test_large_derived_index_build_finishes_merge_debt_before_publication(tmp_path):
    from datetime import datetime,timezone
    from app.db.alerts import AlertRepository
    from app.db.fts_rowid import install,verify,content_digest
    from scripts.benchmark_cqql import INSERT_SQL,INSERT_COLUMNS,synthetic_row
    path=tmp_path/'SYNTHETIC-large-index.db';base=datetime.now(timezone.utc)
    AlertRepository(f'sqlite:///{path.as_posix()}',migration_target_version=17).initialize()
    text=' '.join(f'syntheticword{i}' for i in range(1000))
    def rows():
        for index in range(5000):
            row=list(synthetic_row(index,base));row[INSERT_COLUMNS.index('search_text')]=text+f' document{index}'
            yield row
    with closing(sqlite3.connect(path)) as c:
        c.executemany(INSERT_SQL,rows())
        c.execute('UPDATE security_event_store_state SET retained_records=5000');c.commit()
        before=content_digest(c)
    install(path,tmp_path/'backup.db',disposable_only=True)
    with closing(sqlite3.connect(path)) as c:
        state=structure_header(c.execute('SELECT block FROM m32_events_fts_data WHERE id=10').fetchone()[0])
        assert state['segments']==1 and all(level['merging_inputs']==0 for level in state['per_level'])
        verify(c,integrity=True)
        assert content_digest(c)==before
        assert c.execute('PRAGMA user_version').fetchone()[0]==17
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()


def test_compaction_failure_rolls_back_new_derived_schema_and_preserves_source(fts,tmp_path,monkeypatch):
    from app.db.fts_rowid import install,rollback,content_digest
    path,_,_,_=fts
    rollback(path,disposable_only=True)
    with closing(sqlite3.connect(path)) as c:before=content_digest(c)
    original=sqlite3.connect
    class Fault(sqlite3.Connection):
        def execute(self,sql,parameters=()):
            if sql=="INSERT INTO m32_events_fts(m32_events_fts) VALUES('optimize')":
                raise sqlite3.OperationalError('SYNTHETIC_compaction_failure')
            return super().execute(sql,parameters)
    def connect(*args,**kwargs):
        kwargs.setdefault('factory',Fault);return original(*args,**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3,'connect',connect)
        with pytest.raises(sqlite3.OperationalError,match='SYNTHETIC_compaction_failure'):
            install(path,tmp_path/'failed-compaction-backup.db',disposable_only=True)
    with closing(sqlite3.connect(path)) as c:
        assert content_digest(c)==before
        assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name LIKE 'm32_%'").fetchone()[0]==0
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()
