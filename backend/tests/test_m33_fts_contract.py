"""Punctuation can encode native token phrases: do not discard FTS positions."""
from contextlib import closing
from datetime import timedelta
import json
import sqlite3

import pytest

from app.db.cqql import CQQLSearchRepository
from app.db.fts_rowid import verify
from app.services.cqql import compile_cqql
from tests.test_m32_storage import fts


@pytest.mark.parametrize('literal,expected_count',[
    ('powershell.exe',1),('SYNTHETIC-M30',1),('/usr/bin/test',1),
    ('powershell exe',2),('no-match-token',0),
])
def test_fts_preserves_compound_token_phrase_and_paginated_reference(fts,literal,expected_count):
    path,base,_,_=fts
    with closing(sqlite3.connect(path)) as c:
        ids=[r[0] for r in c.execute('SELECT event_id FROM security_events ORDER BY event_id LIMIT 2')]
        c.execute('UPDATE security_events SET search_text=? WHERE event_id=?',
                  ('powershell.exe SYNTHETIC-M30 /usr/bin/test',ids[0]))
        c.execute('UPDATE security_events SET search_text=? WHERE event_id=?',
                  ('powershell interrupted exe SYNTHETIC other M30 /usr separate bin test',ids[1]))
        c.commit();verify(c,integrity=True)
    query=compile_cqql('text CONTAINS '+json.dumps(literal))
    results=[]
    for strategy in ('legacy','m32_rowid'):
        repo=CQQLSearchRepository(path,fts_strategy=strategy);cursor=None;found=[]
        while True:
            page=repo.search(query,start_time=base-timedelta(days=8),end_time=base+timedelta(hours=1),
                             sort='newest',limit=1,cursor=cursor)
            found.extend(row.event_id for row in page.items);cursor=page.next_cursor
            if cursor is None:break
        results.append(found)
    assert results[0]==results[1] and len(results[1])==expected_count
