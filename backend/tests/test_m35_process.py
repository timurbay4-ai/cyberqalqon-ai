from contextlib import closing
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.db.shadow_history import ShadowHistoryRepository
from app.services.continuous_shadow import prepare,ContinuousShadowWorker
from app.services.shadow_rules import catalog
from tests.test_m31_history import prepared,ingest,login,payload,BASE,PREFIX
from tests.conftest import bootstrap_and_login

CHILD = '''import sys,json,os
from pathlib import Path
from app.db.shadow_history import ShadowHistoryRepository
from app.db.cqql import CQQLSearchRepository
from app.services.shadow_history import ShadowHistoryService
from app.services.continuous_shadow import ContinuousShadowWorker
from app.services.shadow_rules import catalog
mode,history,source,checkpoint,stage=sys.argv[1:]
def fault(value):
    if value==stage:os._exit(27)
store=ShadowHistoryRepository(Path(history),Path(source))
service=ShadowHistoryService(store,CQQLSearchRepository(store.source),fault_hook=fault if mode=='resume' else None)
service.open()
if mode=='resume':
    row=store.recovery_headers()[0];service.resume(row['run_id'],'SYNTHETIC process recovery')
else:
    rule=next(r for r in catalog() if r.rule_id=='SHADOW-WINDOWS-AUTH')
    with ContinuousShadowWorker(Path(checkpoint),service,rule,disposable_only=True,fault_hook=fault) as worker:worker.tick()
service.close()
'''


@pytest.mark.parametrize('stage',['BEFORE_UNSEALED_RECONCILE','AFTER_UNSEALED_READ','BEFORE_UNSEALED_CLAIM','AFTER_UNSEALED_CLAIM'])
def test_m35_real_process_exit_during_unsealed_recovery(prepared,stage):
    settings,store=prepared
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as client:
        bootstrap_and_login(client);ingest(client)
        def fail(value):
            if value=='AFTER_RUN_BEGIN':raise RuntimeError('SYNTHETIC prepare unsealed intent')
        client.app.state.shadow_history_service._fault=fail
        assert client.post(PREFIX+'/runs',json=payload()).status_code==503
    result=subprocess.run([sys.executable,'-c',CHILD,'resume',str(store.path),str(store.source),'unused',stage],capture_output=True,timeout=30)
    assert result.returncode==27,result.stderr.decode(errors='replace')[:500]
    reopened=ShadowHistoryRepository(store.path,store.source)
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=reopened)) as client:
        login(client);run_id=reopened.recovery_headers()[0]['run_id']
        response=client.post(PREFIX+'/runs/'+run_id+'/resume')
        assert response.status_code==200,response.text
        assert len(response.json()['result']['finding_ids'])==1
        with closing(sqlite3.connect(store.path)) as c:
            assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1
            assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
            assert not c.execute('PRAGMA foreign_key_check').fetchall()


@pytest.mark.parametrize('stage',['AFTER_PENDING_COMMIT','AFTER_HISTORY_COMMIT','BEFORE_CHECKPOINT_COMMIT','AFTER_CHECKPOINT_COMMIT'])
def test_m35_real_process_exit_preserves_monotonic_checkpoint(prepared,stage):
    settings,store=prepared;path=store.path.parent/'m35-process-checkpoint.db'
    rule=next(r for r in catalog() if r.rule_id=='SHADOW-WINDOWS-AUTH')
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=store)) as client:
        bootstrap_and_login(client);ingest(client)
        prepare(path,client.app.state.shadow_history_service,rule,first_end=BASE+timedelta(seconds=60),disposable_only=True)
    result=subprocess.run([sys.executable,'-c',CHILD,'tick',str(store.path),str(store.source),str(path),stage],capture_output=True,timeout=30)
    assert result.returncode==27,result.stderr.decode(errors='replace')[:500]
    with closing(sqlite3.connect(path)) as c:
        state=json.loads(c.execute('SELECT data FROM checkpoint').fetchone()[0])
        before=int(stage=='AFTER_CHECKPOINT_COMMIT')
        assert state['sequence']==before and (state['pending'] is None)==bool(before)
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
    reopened=ShadowHistoryRepository(store.path,store.source)
    with TestClient(create_app(settings,disposable_detection_simulation=True,shadow_history=reopened)) as client:
        login(client)
        with ContinuousShadowWorker(path,client.app.state.shadow_history_service,rule,disposable_only=True) as worker:
            completed=worker.tick()
            assert completed['ticks_committed']==before+1 and len(completed['last_finding_ids'])==1
        with closing(sqlite3.connect(store.path)) as c:
            assert c.execute('SELECT COUNT(*) FROM shadow_findings').fetchone()[0]==1
            assert c.execute('SELECT COUNT(*) FROM shadow_revisions').fetchone()[0]==1
