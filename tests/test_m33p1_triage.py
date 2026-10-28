"""Evidence-gate failures must survive Python optimization and source drift."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import review_m33p1_sast as review


def test_empty_triage_fails_even_with_python_optimization(tmp_path):
    release = tmp_path/'docs/release';release.mkdir(parents=True)
    (release/'M33_SAST_RESULTS.json').write_text(json.dumps({'findings':[]}), encoding='utf-8')
    program = 'from pathlib import Path;from scripts import review_m33p1_sast as r;r.ROOT=Path(__import__("sys").argv[1]);r.main()'
    result = subprocess.run([sys.executable, '-O', '-c', program, str(tmp_path)], capture_output=True, text=True)
    assert result.returncode != 0 and 'Incomplete finding inventory' in result.stderr
    assert not (release/'M33P1_SAST_TRIAGE.json').exists()


def test_triage_stops_on_changed_reviewed_source(tmp_path, monkeypatch):
    release = tmp_path/'docs/release';release.mkdir(parents=True)
    (tmp_path/'synthetic.py').write_text('def example(): return 1\n', encoding='utf-8')
    old = {'path':'synthetic.py','line':1,'test_id':'B608','source_sha256':'0'*64}
    (release/'M33_SAST_RESULTS.json').write_text(json.dumps({'findings':[old]}), encoding='utf-8')
    monkeypatch.setattr(review, 'ROOT', tmp_path)
    with pytest.raises(RuntimeError, match='source drift'):
        review.main()
    assert not (release/'M33P1_SAST_TRIAGE.json').exists()


def test_benchmark_wrapper_never_changes_existing_evidence(tmp_path, monkeypatch):
    from scripts import benchmark_m33p1 as benchmark
    output = tmp_path/'existing.json'
    original = b'{"scope":"IMMUTABLE_OLD_EVIDENCE"}\n'
    output.write_bytes(original)
    monkeypatch.setattr(sys, 'argv', ['benchmark_m33p1.py', '--output', str(output)])
    with pytest.raises(ValueError, match='New evidence'):
        benchmark.main()
    assert output.read_bytes() == original


def test_benchmark_wrapper_rejects_reuse_outside_writer_only(tmp_path, monkeypatch):
    from scripts import benchmark_m33p1 as benchmark
    output = tmp_path/'new.json'
    monkeypatch.setattr(sys, 'argv', ['benchmark_m33p1.py', '--reuse-e1', '--experiments', 'E7', '--output', str(output)])
    with pytest.raises(ValueError, match='restricted to diagnostic E1'):
        benchmark.main()
    assert not output.exists()
