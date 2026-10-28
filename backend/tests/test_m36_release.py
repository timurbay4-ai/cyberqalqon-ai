"""Release tooling must work independently of the original developer workstation."""
from pathlib import Path
import json
import subprocess
import sys

import pytest

from scripts import m35_go_synthetic


def test_go_discovery_prefers_explicit_toolchain(monkeypatch, tmp_path):
    assert m35_go_synthetic.ROOT==Path(__file__).resolve().parents[2]
    executable = tmp_path/'approved-go.exe'
    executable.write_bytes(b'SYNTHETIC path-only fixture, never executed')
    monkeypatch.setenv('CYBERQALQON_GO', str(executable))
    monkeypatch.setattr(m35_go_synthetic.shutil, 'which', lambda _: None)
    assert m35_go_synthetic.go_executable()==executable.resolve()


def test_go_discovery_uses_runner_path(monkeypatch, tmp_path):
    executable = tmp_path/'go'
    executable.write_bytes(b'SYNTHETIC path-only fixture, never executed')
    monkeypatch.delenv('CYBERQALQON_GO', raising=False)
    monkeypatch.setattr(m35_go_synthetic.shutil, 'which', lambda _: str(executable))
    assert m35_go_synthetic.go_executable()==executable.resolve()


def test_go_discovery_missing_tool_is_explicit_and_redacted(monkeypatch):
    monkeypatch.delenv('CYBERQALQON_GO', raising=False)
    monkeypatch.setattr(m35_go_synthetic.shutil, 'which', lambda _: None)
    with pytest.raises(RuntimeError, match='Go toolchain required'):
        m35_go_synthetic.go_executable()


def test_go_discovery_invalid_override_does_not_silently_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv('CYBERQALQON_GO', str(tmp_path/'SYNTHETIC_PRIVATE_PATH'))
    monkeypatch.setattr(m35_go_synthetic.shutil, 'which', lambda _: 'go')
    with pytest.raises(RuntimeError) as exc:
        m35_go_synthetic.go_executable()
    assert 'SYNTHETIC_PRIVATE_PATH' not in str(exc.value)


@pytest.mark.parametrize('program', [
    'from app.schemas.detection_engineering import BoundedTimeWindow;BoundedTimeWindow.model_construct(relative_minutes=None).resolved()',
    'from app.services.cqql import _validate_value,FIELD_CATALOG;_validate_value(FIELD_CATALOG["event.severity"],"7",0)',
    'from app.services.cqql import _compile_expression,Comparison;_compile_expression(Comparison("text","CONTAINS",7,0))',
])
def test_reviewed_invariants_survive_python_optimization(program):
    wrapper = ('import json\ntry:\n ' + program +
               '\nexcept RuntimeError as exc:\n print(json.dumps({"rejected":True,"kind":type(exc).__name__}))\n'
               'else:\n raise SystemExit("Invariant was omitted")\n')
    result = subprocess.run([sys.executable, '-O', '-c', wrapper], capture_output=True, text=True, timeout=20)
    assert result.returncode==0, result.stderr
    assert json.loads(result.stdout)=={'rejected':True,'kind':'RuntimeError'}
