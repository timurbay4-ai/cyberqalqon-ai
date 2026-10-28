"""Owned disposable socket server: a 201 must survive unexpected termination."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from scripts.m30_synthetic import win


SERVER = '''
import socket,sys
from pathlib import Path
import uvicorn
from app.core.config import Settings
from app.main import create_app
sock=socket.socket();sock.bind(('127.0.0.1',0));sock.listen(32)
Path(sys.argv[2]).write_text(str(sock.getsockname()[1]),encoding='utf-8')
app=create_app(Settings(database_url='sqlite:///'+Path(sys.argv[1]).as_posix(),
    allow_m14_schema_migration=False,ai_enabled=False,correlation_enabled=False,
    event_batch_ingest_enabled=False,wazuh_ingest_api_key='SYNTHETIC-OWNED-RECOVERY'))
uvicorn.Server(uvicorn.Config(app,log_level='critical',access_log=False)).run(sockets=[sock])
'''


def test_acknowledged_event_survives_owned_http_server_kill_and_retry(tmp_path):
    database=tmp_path/'SYNTHETIC-source.db'
    raw=win(8830001,datetime.now(timezone.utc),'4688')
    event_id=None
    for attempt in range(2):
        portfile=tmp_path/f'port-{attempt}.txt'
        with (tmp_path/f'server-{attempt}.log').open('wb') as log:
            process=subprocess.Popen([sys.executable,'-c',SERVER,str(database),str(portfile)],stdout=log,stderr=log)
            try:
                deadline=time.monotonic()+20
                while time.monotonic()<deadline:
                    assert process.poll() is None,'Owned server failed; see disposable server log'
                    try:
                        port=int(portfile.read_text(encoding='utf-8'))
                        with urlopen(f'http://127.0.0.1:{port}/health',timeout=.5) as response:
                            if response.status==200:break
                    except (OSError,ValueError,URLError):pass
                    time.sleep(.02)
                else:raise AssertionError('Owned server startup deadline')
                request=Request(f'http://127.0.0.1:{port}/api/v1/events/ingest',
                    data=json.dumps(raw).encode(),headers={'Content-Type':'application/json','X-API-Key':'SYNTHETIC-OWNED-RECOVERY'})
                with urlopen(request,timeout=10) as response:
                    assert response.status==(201 if attempt==0 else 200)
                    result=json.loads(response.read())
                    if event_id is None:event_id=result['event']['event_id']
                    assert result['event']['event_id']==event_id
            finally:
                if process.poll() is None:process.kill()
                process.wait(timeout=10)
    with closing(sqlite3.connect(database)) as c:
        assert c.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()
        assert c.execute('PRAGMA user_version').fetchone()[0]==17
        assert c.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]==1
        assert c.execute('SELECT COUNT(*) FROM security_events_fts').fetchone()[0]==1
