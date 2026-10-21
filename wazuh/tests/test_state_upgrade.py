from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberqalqon_sender import durable_state
from cyberqalqon_sender.state_upgrade import (
    StateUpgradeError,
    apply_v2_upgrade,
    plan_v2_upgrade,
    rollback_upgrade,
)


def _v2_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    archive = tmp_path / "archives.json"
    archive.write_bytes(b'{"rule":{"id":"100111"}}\n')
    stat = archive.stat()
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "version": 2,
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "offset": archive.stat().st_size,
                "accepted": 17,
                "filtered_events": 8,
                "malformed_json": 2,
                "retry_attempts": 3,
                "updated_at": 123.0,
            }
        ),
        encoding="utf-8",
    )
    return archive, state, tmp_path / "backups"


def test_v2_upgrade_preserves_identity_cursor_and_unknown_history(tmp_path: Path) -> None:
    archive, state, backups = _v2_fixture(tmp_path)
    plan = plan_v2_upgrade(state, archive, backups)
    result = apply_v2_upgrade(plan, operator_approved=True, now=500.0)
    converted = json.loads(state.read_text(encoding="utf-8"))

    assert converted["version"] == 3
    assert converted["device"] == plan.archive_device
    assert converted["inode"] == plan.archive_inode
    assert converted["offset"] == plan.acknowledged_cursor
    assert converted["accepted"] == 0
    assert converted["duplicate_attempts"] == 0
    assert converted["legacy_successful_acknowledgements"] == 17
    assert plan.as_dict()["historic_unique_insertions"] is None
    assert plan.as_dict()["historic_duplicate_acknowledgements"] is None
    assert Path(result["backup_path"]).read_bytes()


def test_upgrade_rollback_only_before_new_v3_write(tmp_path: Path) -> None:
    archive, state, backups = _v2_fixture(tmp_path)
    original = state.read_bytes()
    result = apply_v2_upgrade(
        plan_v2_upgrade(state, archive, backups),
        operator_approved=True,
        now=500.0,
    )
    rolled_back = rollback_upgrade(
        Path(result["manifest_path"]), operator_approved=True
    )
    assert rolled_back["status"] == "ROLLED_BACK"
    assert state.read_bytes() == original

    second = apply_v2_upgrade(
        plan_v2_upgrade(state, archive, tmp_path / "backups-second"),
        operator_approved=True,
        now=501.0,
    )
    value = json.loads(state.read_text(encoding="utf-8"))
    value["updated_at"] = 999.0
    state.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(StateUpgradeError, match="changed since conversion"):
        rollback_upgrade(Path(second["manifest_path"]), operator_approved=True)


def test_upgrade_refuses_changed_state_after_plan(tmp_path: Path) -> None:
    archive, state, backups = _v2_fixture(tmp_path)
    plan = plan_v2_upgrade(state, archive, backups)
    value = json.loads(state.read_text(encoding="utf-8"))
    value["accepted"] = 18
    state.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(StateUpgradeError, match="changed after planning"):
        apply_v2_upgrade(plan, operator_approved=True)


def test_interrupted_atomic_replace_preserves_existing_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "state.json"
    target.write_bytes(b'{"version":2}')

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated interruption")

    monkeypatch.setattr(durable_state.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated interruption"):
        durable_state.durable_atomic_write(target, b'{"version":3}')
    assert target.read_bytes() == b'{"version":2}'
    assert not (tmp_path / ".state.json.tmp").exists()


def test_forward_version_fails_closed(tmp_path: Path) -> None:
    archive, state, backups = _v2_fixture(tmp_path)
    value = json.loads(state.read_text(encoding="utf-8"))
    value["version"] = 4
    state.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(StateUpgradeError, match="expected state version 2"):
        plan_v2_upgrade(state, archive, backups)
