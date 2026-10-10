from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY_ROOT / "scripts" / "validate_local_lab.py"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_local_lab", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_validator_accepts_only_literal_loopback_targets() -> None:
    validator = _load_validator()

    assert validator.is_loopback_target("localhost")
    assert validator.is_loopback_target("127.0.0.1")
    assert validator.is_loopback_target("::1")
    assert not validator.is_loopback_target("192.168.1.10")
    assert not validator.is_loopback_target("example.com")


def test_active_rule_set_remains_bounded() -> None:
    validator = _load_validator()

    assert validator.ACTIVE_RULE_IDS == ("100101", "100111", "100120")


def test_validator_includes_siem_event_store_and_event_shipper() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    assert "cyberqalqon-event-shipper.service" in source
    assert '"backend_relay_path"' in source
    assert "http://127.0.0.1:18000/health" in source
    assert "SELECT COUNT(*) FROM security_events" in source
    assert "schema_version == 14" in source
    assert "seq 1 12" in source
    assert source.index('"sensitive_path_loopback"') < source.index('"gobuster_loopback"')


def test_active_validator_honors_wazuh_correlation_cooldown(tmp_path: Path) -> None:
    validator = _load_validator()
    database = tmp_path / "validator.db"
    now = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE alerts (rule_id TEXT, ingested_at TEXT)")
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?)",
            ("100111", (now - timedelta(seconds=10)).isoformat()),
        )

    assert validator.active_correlation_cooldown(database, now=now) == 51
    assert validator.active_correlation_cooldown(
        database, now=now + timedelta(seconds=61)
    ) == 0
