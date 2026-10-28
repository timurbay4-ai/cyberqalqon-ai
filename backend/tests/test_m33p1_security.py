"""Behavioral provenance and exact shadow-audit rejection regression."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.alerts import AlertRepository
from app.db.fts_rowid import install
from app.main import create_app
from scripts.m30_synthetic import win, auth
from tests.conftest import bootstrap_and_login
from tests.test_m30_shadow import client, ingest, request, BASE, PREFIX


@pytest.mark.parametrize('candidate', [False, True])
def test_hostile_filter_values_stay_data_across_real_sql_paths(tmp_path, candidate):
    path = tmp_path/'SYNTHETIC-source.db'
    settings = Settings(database_url=f'sqlite:///{path.as_posix()}', ai_enabled=False,
                        correlation_enabled=False, allow_m14_schema_migration=False,
                        wazuh_ingest_api_key='SYNTHETIC-P1')
    AlertRepository(settings.database_url, migration_target_version=17).initialize()
    if candidate:
        install(path, tmp_path/'backup.db', disposable_only=True)
    app = create_app(settings, disposable_detection_simulation=True, disposable_fts_rowid=candidate)
    hostile = "SYNTHETIC' OR 1=1; DROP TABLE security_events; --"
    now = datetime.now(timezone.utc)
    with TestClient(app) as api:
        bootstrap_and_login(api)
        ids = []
        for index, hostname in enumerate([hostile, 'SYNTHETIC-benign']):
            raw = win(991000+index, now, '4688')
            raw['agent']['name'] = hostname
            raw['data']['win']['system']['computer'] = hostname
            response = api.post('/api/v1/events/ingest', headers={'X-API-Key':'SYNTHETIC-P1'}, json=raw)
            assert response.status_code == 201
            ids.append(response.json()['event']['event_id'])
        filtered = api.get('/api/v1/events', params={'hostname':hostile})
        assert filtered.status_code == 200 and filtered.json()['page']['total'] == 1
        query = {'query':'host.name = '+json.dumps(hostile),
                 'start_time':(now-timedelta(minutes=1)).isoformat(),
                 'end_time':(now+timedelta(minutes=1)).isoformat(), 'limit':100}
        result = api.post('/api/v1/siem/search', json=query)
        assert result.status_code == 200
        assert [r['event_id'] for r in result.json()['items']] == [ids[0]]
        # SQL-looking field names cannot become identifiers through analytics.
        rejected = api.post('/api/v1/siem/search/analytics', json={**query,
            'group_by':['host.name); DROP TABLE security_events; --'], 'top_n':10, 'interval':'day'})
        assert rejected.status_code == 422
        for endpoint in ('/api/v1/cases', '/api/v1/audit-events'):
            response = api.get(endpoint, params={'search':hostile})
            assert response.status_code == 200
        with closing(sqlite3.connect(path)) as connection:
            assert connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0] == 2
            assert connection.execute('PRAGMA user_version').fetchone()[0] == 17
            assert connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            assert not connection.execute('PRAGMA foreign_key_check').fetchall()


def test_shadow_audit_budget_rejection_is_typed_and_retry_is_stable(client, monkeypatch):
    for raw in auth(BASE):
        ingest(client, raw)
    good = client.post(PREFIX+'/simulate', json=request())
    assert good.status_code == 200
    expected = [r['finding_id'] for r in good.json()['findings']]
    repository = client.app.state.shadow_audit_repository
    original = repository.append
    completed = []
    engine = client.app.state.advanced_detection_engine
    evaluate = engine.simulate_contract
    def observed(*args, **kwargs):
        value = evaluate(*args, **kwargs)
        completed.append(value)
        return value
    def unavailable(**kwargs):
        failure = sqlite3.OperationalError('SYNTHETIC deadline')
        failure.sqlite_errorcode = sqlite3.SQLITE_INTERRUPT
        raise failure
    with monkeypatch.context() as patch:
        patch.setattr(repository, 'append', unavailable)
        patch.setattr(engine, 'simulate_contract', observed)
        failed = client.post(PREFIX+'/simulate', json=request())
    assert completed  # Evaluation completed; mandatory audit did not persist.
    assert failed.status_code == 503
    assert failed.json()['detail']['reason_code'] == 'AUDIT_BUDGET_EXPIRED'
    assert failed.headers['retry-after'] == '1' and 'findings' not in failed.json()
    after = client.post(PREFIX+'/simulate', json=request())
    assert after.status_code == 200 and [r['finding_id'] for r in after.json()['findings']] == expected
    slots = client.app.state.cqql_search_repository._slots
    assert all(slots.acquire(blocking=False) for _ in range(4))
    for _ in range(4): slots.release()
    assert repository.append == original
