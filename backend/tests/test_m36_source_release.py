"""Source-release boundary tests use owned temporary trees, never the Git index."""
import copy
import hashlib
import json
import os
from pathlib import Path
import zipfile

import pytest

from scripts import source_release as release


def tree(tmp_path):
    root=tmp_path/'source';root.mkdir()
    (root/'main.py').write_text('import json\n',encoding='utf-8')
    return root


@pytest.mark.parametrize('name', ['../escape','/absolute','a/../b','a//b','a/./b',
    'C:/escape','a\\b','a:stream','NUL.py','aux/file','a.','a ','a\n.py',''])
def test_release_rejects_nonportable_paths(name):
    with pytest.raises(release.ReleaseError):release.relative_name(name)


@pytest.mark.parametrize('name', ['SECRETS/password.txt','.env','backend/data/app.db',
    'artifacts/runtime/tool.exe','frontend/node_modules/pkg/index.js','x/private.KEY',
    'frontend/dist/index.html','docs/release/M36_SOURCE_INVENTORY.json'])
def test_private_and_self_referential_paths_are_excluded(name):
    assert release.excluded(name)


def test_release_reconstructs_and_zip_is_deterministic(tmp_path):
    root=tree(tmp_path)
    manifest=release.build_manifest(root,['main.py'])
    release.validate_manifest(manifest)
    target=tmp_path/'reconstruction'
    release.materialize(root,manifest,target)
    assert (target/'main.py').read_bytes()==(root/'main.py').read_bytes()
    first=release.archive(root,manifest,tmp_path/'first.zip')
    second=release.archive(root,manifest,tmp_path/'second.zip')
    assert first==second
    with zipfile.ZipFile(tmp_path/'first.zip') as zipped:
        assert zipped.namelist()==['main.py','SOURCE-RELEASE-MANIFEST.json']
        embedded=json.loads(zipped.read('SOURCE-RELEASE-MANIFEST.json'))
        release.validate_manifest(embedded)
        assert embedded==manifest
        assert zipped.read('main.py')==(root/'main.py').read_bytes()
        assert zipped.getinfo('main.py').date_time==(1980,1,1,0,0,0)


def test_release_refuses_source_drift_and_existing_outputs(tmp_path):
    root=tree(tmp_path);manifest=release.build_manifest(root,['main.py'])
    (root/'main.py').write_text('import sys\n')
    with pytest.raises(release.ReleaseError,match='SOURCE_CHANGED'):
        release.materialize(root,manifest,tmp_path/'changed')
    target=tmp_path/'existing';target.mkdir()
    with pytest.raises(release.ReleaseError,match='NEW_RECONSTRUCTION'):
        release.materialize(root,manifest,target)
    output=tmp_path/'existing.zip';output.write_bytes(b'preserve')
    with pytest.raises(release.ReleaseError,match='NEW_ARCHIVE'):
        release.archive(root,manifest,output)
    assert output.read_bytes()==b'preserve'


def test_release_rejects_hardlinked_source(tmp_path):
    root=tree(tmp_path);os.link(root/'main.py',root/'alias.py')
    with pytest.raises(release.ReleaseError,match='UNALIASED'):
        release.build_manifest(root,['main.py'])


def test_release_redacts_synthetic_secret_pattern(tmp_path):
    root=tree(tmp_path)
    synthetic='gh'+'p_'+'X'*35
    (root/'main.py').write_text('TOKEN='+repr(synthetic))
    with pytest.raises(release.ReleaseError) as caught:
        release.build_manifest(root,['main.py'])
    assert synthetic not in str(caught.value)
    findings=release.secret_findings('main.py',(root/'main.py').read_bytes())
    assert findings and synthetic not in json.dumps(findings)


@pytest.mark.parametrize('mutation', ['duplicate','hash','path','mode','bytes','malformed'])
def test_release_rejects_invalid_manifest(tmp_path,mutation):
    manifest=release.build_manifest(tree(tmp_path),['main.py'])
    if mutation=='duplicate':manifest['files']*=2
    elif mutation=='hash':manifest['files'][0]['sha256']='f'*64
    elif mutation=='path':manifest['files'][0]['path']='../escape'
    elif mutation=='mode':manifest['files'][0]['mode']=0o777
    elif mutation=='bytes':manifest['files'][0]['bytes']=True
    else:manifest['files'][0]={}
    with pytest.raises(release.ReleaseError):release.validate_manifest(manifest)


def test_release_rejects_case_aliases(tmp_path):
    root=tree(tmp_path)
    with pytest.raises(release.ReleaseError,match='CASE_ALIAS'):
        release.build_manifest(root,['main.py','MAIN.py'])


def test_release_proves_local_dependency_closure(tmp_path):
    root=tmp_path/'source';root.mkdir()
    files={'backend/app/main.py':'from app import absent\nfrom app.absent import x\n',
        'backend/app/__init__.py':'',
        'frontend/src/main.ts':"import {x} from './missing'\n",
        'shared/schema.json':json.dumps({'$ref':'missing.json'}),
        'collector/main.go':'package main\nimport "cyberqalqon.local/collector/internal/absent"\n'}
    for name,content in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
    result=release.build_manifest(root,list(files))['dependency_graph']
    assert len(result['missing_required_local_modules'])>=4
    assert any(row['target']=='backend/app/__init__.py' for row in result['edges'])
