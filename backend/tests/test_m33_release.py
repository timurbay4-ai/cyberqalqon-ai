"""Integrated synthetic acceptance plus independent-checkpoint failure injection."""
from contextlib import closing
import json
from datetime import timedelta
import hashlib
import sqlite3

import pytest
from pydantic import ValidationError

from app.cli.rc_demo import run_demo
from app.db.investigation_workbench import _cursor_binding
from app.db.shadow_history import ShadowStoreError
from app.schemas.investigation_workbench import WorkbenchRequest
from app.services.shadow_continuity import prepare, ShadowContinuityWorker, ShadowContinuityError
from app.services.shadow_rules import catalog
from app.main import create_app
from scripts.m30_synthetic import win, auth
from tests.test_m31_history import prepared, client, ingest, evaluate, BASE, PREFIX


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def schedule(client, prepared, **kwargs):
    ingest(client)
    service = client.app.state.shadow_history_service
    rule = next(rule for rule in catalog() if rule.rule_id == 'SHADOW-WINDOWS-AUTH')
    path = prepared[1].path.parent / 'independent-evaluation.db'
    prepare(path, service, rule, first_end=BASE+timedelta(seconds=60), ticks=3, disposable_only=True)
    return path, service, rule, ShadowContinuityWorker(path, service, rule, disposable_only=True, **kwargs)


def target(client):
    ingest(client)
    finding_id = evaluate(client)['result']['finding_ids'][0]
    return {'target_type': 'DURABLE_SHADOW_FINDING', 'target_id': finding_id, 'shadow_revision': 1,
            'relative_minutes': None, 'start_time': (BASE-timedelta(seconds=1)).isoformat(),
            'end_time': (BASE+timedelta(minutes=2)).isoformat()}


def test_full_application_mode_a():
    report = run_demo()
    assert report['accepted_201'] == report['duplicate_200'] == 8
    assert report['findings'] == 2 and report['backup_restore'] == 'OFFLINE_RESTORE_VALIDATED'
    assert report['source_schema'] == 17 and all(report['security'].values())
    assert report['contract']['case']['status'] == 'TRIAGING'
    assert report['fts_strategy'] == 'm32_rowid' and report['fts_complete_ids'] == 8


def test_fts_factory_opt_in_is_disposable_and_does_not_install_ddl(prepared):
    settings, store = prepared
    before = checksum(store.source)
    with pytest.raises(ValueError, match='disposable'):
        create_app(settings, disposable_fts_rowid=True)
    app = create_app(settings, disposable_detection_simulation=True, disposable_fts_rowid=True)
    assert checksum(store.source) == before
    # Actual FTS verification remains fail-closed until explicit index install.
    from fastapi.testclient import TestClient
    from tests.conftest import bootstrap_and_login
    with TestClient(app) as value:
        bootstrap_and_login(value)
        response = value.post('/api/v1/siem/search', json={'query': 'text CONTAINS "synthetic"',
            'start_time': BASE.isoformat(), 'end_time': (BASE+timedelta(minutes=1)).isoformat()})
        assert response.status_code == 503


@pytest.mark.parametrize('xml', [
    '<!DOCTYPE ossec_config [<!ENTITY x "unsafe">]><ossec_config>&x;</ossec_config>',
    '<!DOCTYPE ossec_config SYSTEM "file:///nonexistent-synthetic"><ossec_config/>',
    '<ossec_config><broken>',
])
def test_windows_diagnostic_xml_rejects_entities_dtd_and_invalid_input(tmp_path, xml):
    from app.services.windows_agent_diagnostics import _config
    path = tmp_path/'SYNTHETIC-ossec.xml'
    path.write_text(xml)
    assert _config(path) == {}


def test_windows_diagnostic_xml_valid_synthetic_config_remains_supported(tmp_path):
    from app.services.windows_agent_diagnostics import _config
    path = tmp_path/'SYNTHETIC-ossec.xml'
    path.write_text('<ossec_config><client><server><address>192.0.2.33</address><port>1514</port></server></client></ossec_config>')
    result = _config(path)
    assert result['address'] == '192.0.2.33' and result['port'] == 1514


def test_durable_investigation_keeps_rule_revision_and_exact_evidence(client):
    body = target(client)
    response = client.post('/api/v1/investigations/workbench', json=body)
    assert response.status_code == 200
    value = response.json()
    context = value['durable_shadow_context']
    assert context == client.get(PREFIX+'/findings/'+body['target_id']).json()
    assert value['target_type'] == body['target_type']
    assert context['finding_id'] == body['target_id'] and context['revision'] == 1
    assert context['matching_evidence']['mitre']
    assert len(context['matching_evidence']['evidence']) == 4
    assert value['primary_event']['event_id'] in context['current_evidence_availability']


@pytest.mark.parametrize('mode', ['missing', 'changed'])
def test_durable_investigation_does_not_hide_retention_or_content_gap(client, prepared, mode):
    body = target(client)
    with closing(sqlite3.connect(prepared[1].source)) as connection:
        if mode == 'missing':
            connection.execute('DELETE FROM security_events')
        else:
            connection.execute("UPDATE security_events SET structured_json='{}'")
        connection.commit()
    response = client.post('/api/v1/investigations/workbench', json=body)
    assert response.status_code == 409
    assert response.json()['detail']['code'] == 'durable_evidence_unavailable'
    assert client.get(PREFIX+'/findings/'+body['target_id']).status_code == 200


def test_durable_investigation_unknown_evidence_is_not_available(client, monkeypatch):
    body = target(client)
    service = client.app.state.shadow_history_service
    original = service.detail
    def unknown(*args, **kwargs):
        value = original(*args, **kwargs)
        value['current_evidence_availability'] = dict.fromkeys(value['current_evidence_availability'], 'UNKNOWN')
        return value
    monkeypatch.setattr(service, 'detail', unknown)
    assert client.post('/api/v1/investigations/workbench', json=body).status_code == 409


@pytest.mark.parametrize('revision', [0, 8193, 'bad'])
def test_invalid_investigation_revision(client, revision):
    assert client.post('/api/v1/investigations/workbench', json={
        'target_type': 'DURABLE_SHADOW_FINDING', 'target_id': 'DSF-'+'a'*64, 'shadow_revision': revision}).status_code == 422


def test_revision_and_target_are_bound_to_related_cursor():
    request = WorkbenchRequest(target_type='DURABLE_SHADOW_FINDING', target_id='DSF-'+'a'*64, shadow_revision=1)
    other = request.model_copy(update={'shadow_revision': 2})
    assert _cursor_binding(request, 's', 'e') != _cursor_binding(other, 's', 'e')
    with pytest.raises(ValidationError):
        WorkbenchRequest(target_type='EVENT', target_id='e', shadow_revision=1)


def test_missing_revision_and_invalid_identity_are_explicit(client):
    body = target(client)
    assert client.post('/api/v1/investigations/workbench', json={**body, 'shadow_revision': 2}).status_code == 404
    assert client.post('/api/v1/investigations/workbench', json={**body, 'target_id': 'not-a-durable-id'}).status_code == 422


def test_latest_revision_cursor_cannot_cross_a_new_evidence_revision(client, prepared):
    body = {**target(client), 'shadow_revision': None, 'related_limit': 1}
    first = client.post('/api/v1/investigations/workbench', json=body).json()
    cursor = first['query']['related_next_cursor']
    assert cursor
    with closing(sqlite3.connect(prepared[1].source)) as connection:
        connection.execute('DELETE FROM security_events')
        connection.commit()
    raws = auth(BASE)
    for raw in raws:
        raw['id'] = 'SYNTHETIC-M33-NEW-PHYSICAL-'+raw['id']
    ingest(client, raws)
    finding = evaluate(client)['result']['finding_ids'][0]
    assert finding == body['target_id']
    assert client.get(PREFIX+'/findings/'+finding).json()['revision'] == 2
    result = client.post('/api/v1/investigations/workbench', json={**body, 'related_cursor': cursor})
    assert result.status_code == 422
    assert result.json()['detail']['code'] == 'invalid_cursor'


def test_independent_schedule_restart_dedup_and_complete(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    assert worker.tick()['next_tick'] == 1
    worker = ShadowContinuityWorker(path, service, rule, disposable_only=True)
    assert worker.tick()['next_tick'] == 2
    assert worker.tick()['status'] == 'COMPLETE'
    assert worker.tick()['next_tick'] == 3
    with closing(sqlite3.connect(prepared[1].path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0] == 3
        assert connection.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0] == 1


@pytest.mark.parametrize('stage', ['AFTER_HISTORY_COMMIT', 'BEFORE_CHECKPOINT_COMMIT'])
def test_history_commit_checkpoint_crash_retries_without_duplicate_findings(client, prepared, stage):
    def crash(at):
        if at == stage:
            raise RuntimeError('synthetic process failure')
    path, service, rule, worker = schedule(client, prepared, fault_hook=crash)
    with pytest.raises(RuntimeError):
        worker.tick()
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT next_tick FROM schedule').fetchone()[0] == 0
    recovered = ShadowContinuityWorker(path, service, rule, disposable_only=True)
    assert recovered.tick()['next_tick'] == 1
    with closing(sqlite3.connect(prepared[1].path)) as connection:
        assert connection.execute('SELECT COUNT(*) FROM shadow_runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0] == 1


@pytest.mark.parametrize('sealed', [True, False])
def test_existing_m31_recovery_boundary_is_preserved(client, prepared, sealed):
    path, service, rule, worker = schedule(client, prepared)
    def crash(at):
        if at == ('AFTER_SNAPSHOT_COMMIT' if sealed else 'AFTER_RUN_BEGIN'):
            raise RuntimeError('synthetic evaluator failure')
    service._fault = crash
    with pytest.raises(ShadowStoreError):
        worker.tick()
    service._fault = lambda stage: None
    if sealed:
        assert worker.tick()['next_tick'] == 1
    else:
        # Preserve the legacy no-witness boundary. M35 witnessed runs have
        # separate recovery acceptance; this fixture models an actual M31 row.
        with closing(sqlite3.connect(prepared[1].path)) as connection:
            row=connection.execute('SELECT run_id,request_json FROM shadow_runs').fetchone()
            body=json.loads(row[1]);body.pop('recovery_intent')
            connection.execute('UPDATE shadow_runs SET request_json=? WHERE run_id=?',
                               (json.dumps(body,separators=(',',':'),sort_keys=True),row[0]))
            connection.commit()
        with pytest.raises(ShadowStoreError, match='UNSEALED'):
            worker.tick()


@pytest.mark.parametrize('mode', ['rule', 'source-binding', 'checkpoint-sequence', 'checksum'])
def test_schedule_binding_and_partial_checkpoint_edits_fail_closed(client, prepared, mode):
    path, service, rule, worker = schedule(client, prepared)
    if mode == 'rule':
        worker.rule = rule.model_copy(update={'title': 'Different rule semantics'})
    elif mode == 'source-binding':
        other = path.with_name('other.db'); other.write_bytes(b'synthetic identity')
        service.store.source = other
    else:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('UPDATE schedule SET '+('next_tick=1' if mode == 'checkpoint-sequence' else "definition_sha='invalid'"))
            connection.commit()
    before = checksum(path)
    with pytest.raises((ShadowContinuityError, ShadowStoreError)):
        worker.tick()
    assert checksum(path) == before


@pytest.mark.parametrize('mode', ['missing', 'changed'])
def test_schedule_observed_source_gap_is_never_skipped(client, prepared, mode):
    path, service, rule, worker = schedule(client, prepared)
    worker.tick()
    with closing(sqlite3.connect(prepared[1].source)) as connection:
        connection.execute('DELETE FROM security_events' if mode == 'missing' else "UPDATE security_events SET structured_json='{}'")
        connection.commit()
    with pytest.raises(ShadowContinuityError, match='SOURCE_'):
        worker.tick()
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute('SELECT next_tick FROM schedule').fetchone()[0] == 1


def test_late_arrival_accounted_without_historical_replay(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    worker.tick()
    ingest(client, [win(9876, BASE-timedelta(minutes=5))])
    result = worker.tick()
    assert result['late_new'] == result['late_total'] == 1
    assert result['historical_continuity'] == 'UNPROVEN'
    assert result['late_outside_overlap'] == 'ACCOUNTED_NOT_REPLAYED'


def test_checkpoint_lock_does_not_block_ingest_acknowledgement(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute('BEGIN IMMEDIATE')
        with pytest.raises(ShadowContinuityError):
            worker.tick()
        assert ingest(client, [win(9877, BASE)])[0]
        connection.rollback()
    assert worker.tick()['next_tick'] == 1


def test_source_byte_capacity_fails_before_evaluation(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    with closing(sqlite3.connect(prepared[1].source)) as connection:
        connection.execute('UPDATE security_events SET raw_event_json=? WHERE event_id=(SELECT event_id FROM security_events LIMIT 1)', ('x'*(9*1024*1024),))
        connection.commit()
    with pytest.raises(ShadowContinuityError, match='BYTES_EXCEEDED'):
        worker.tick()


def test_corrupt_checkpoint_fails_closed(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    path.write_bytes(b'corrupt disposable checkpoint')
    with pytest.raises(ShadowContinuityError):
        worker.tick()


@pytest.mark.parametrize('which', ['source', 'checkpoint'])
def test_schedule_rejects_changed_schema_versions(client, prepared, which):
    path, service, rule, worker = schedule(client, prepared)
    with closing(sqlite3.connect(service.store.source if which == 'source' else path)) as connection:
        connection.execute('PRAGMA user_version='+('18' if which == 'source' else '2'))
    with pytest.raises(ShadowContinuityError, match='SCHEMA_MISMATCH'):
        worker.tick()


def test_schedule_observation_checksum_detects_partial_edit(client, prepared):
    path, service, rule, worker = schedule(client, prepared)
    worker.tick()
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE observed SET row_sha='tampered'")
        connection.commit()
    with pytest.raises(ShadowContinuityError, match='BINDING_MISMATCH'):
        worker.tick()


def test_schedule_row_admission_is_bounded(client, prepared, monkeypatch):
    path, service, rule, worker = schedule(client, prepared)
    monkeypatch.setattr('app.services.shadow_continuity.MAX_EVENTS', 3)
    with pytest.raises(ShadowContinuityError, match='SOURCE_OBSERVATION_CAPACITY_EXCEEDED'):
        worker.tick()


@pytest.mark.parametrize('kind', ['approval', 'overwrite', 'outside'])
def test_no_implicit_or_overwriting_schedule_initialization(client, prepared, kind):
    path, service, rule, worker = schedule(client, prepared)
    expected = ShadowContinuityError
    selected = path.parent/'new.db' if kind != 'outside' else path.parent.parent/'outside.db'
    with pytest.raises(expected):
        prepare(path if kind == 'overwrite' else selected, service, rule, first_end=BASE,
                ticks=1, disposable_only=kind != 'approval')
