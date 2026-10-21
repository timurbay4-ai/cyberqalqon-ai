from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from threading import Event

import pytest

from cyberqalqon_sender.config import SenderConfig
from cyberqalqon_sender.cli import main as cli_main
from cyberqalqon_sender.durable_state import durable_atomic_json
from cyberqalqon_sender.event_shipper import select_archive_event
from cyberqalqon_sender.forward_ingestion import (
    ForwardCheckpointLock,
    ForwardIngestionError,
    ForwardIngestionWorker,
    dry_run_forward_records,
    initialize_forward_generation,
    load_forward_state,
    validate_forward_checkpoint,
)
from cyberqalqon_sender.forward_service import (
    build_approval_template,
    run_forward_service,
    validate_live_approval,
)


def _row(identifier: str) -> bytes:
    return json.dumps(
        {"id": identifier, "rule": {"id": "100111"}}, separators=(",", ":")
    ).encode() + b"\n"


class SequenceDelivery:
    def __init__(self, outcomes: list[str]) -> None:
        self.outcomes = outcomes
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return self.outcomes.pop(0)


def _prepared(tmp_path: Path, rows: bytes | None = None) -> tuple[Path, Path, Path]:
    source = (tmp_path / "archives.json").resolve()
    source.write_bytes(rows if rows is not None else _row("one"))
    legacy = (tmp_path / "legacy" / "state.json").resolve()
    legacy.parent.mkdir()
    legacy.write_text(
        json.dumps({"version": 3, "device": 1, "inode": 2, "offset": 123}),
        encoding="utf-8",
    )
    state_path = initialize_forward_generation(
        source,
        (tmp_path / "forward").resolve(),
        namespace="m22-forward",
        start_offset=0,
        legacy_state_path=legacy,
    )
    return source, legacy, state_path


def _approval(state_path: Path, output: Path, *, now: float | None = None) -> Path:
    timestamp = time.time() if now is None else now
    payload = build_approval_template(state_path, expires_at_epoch=timestamp + 3600)
    payload.update(
        {
            "decision": "APPROVED",
            "issued_at_epoch": timestamp,
            "accepts_unproven_history": True,
        }
    )
    durable_atomic_json(output.resolve(), payload)
    if os.name == "posix":
        os.chmod(output, 0o600)
    return output.resolve()


def test_deep_checkpoint_validation_proves_prefix_chain_and_legacy(tmp_path: Path) -> None:
    source, _legacy, state_path = _prepared(tmp_path, _row("one") + _row("two"))
    worker = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted", "duplicate"]),
        max_line_bytes=4096,
    )
    worker.run_batch(limit=2)
    result = validate_forward_checkpoint(state_path, deep=True, max_line_bytes=4096)
    assert result["status"] == "VALID"
    assert result["chain_verified"] is True
    assert result["verified_records"] == 2
    assert result["byte_lag"] == 0
    assert source.stat().st_size == result["offset"]


def test_generation_id_is_stable_while_same_inode_appends(tmp_path: Path) -> None:
    source, legacy, state_path = _prepared(tmp_path)
    source.write_bytes(source.read_bytes() + _row("two"))
    repeated = initialize_forward_generation(
        source,
        (tmp_path / "forward").resolve(),
        namespace="m22-forward",
        start_offset=0,
        legacy_state_path=legacy,
    )
    assert repeated == state_path
    assert load_forward_state(repeated).generation_id == load_forward_state(
        state_path
    ).generation_id


def test_checkpoint_counter_tampering_is_rejected(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["accepted"] = 1
    durable_atomic_json(state_path, raw)
    with pytest.raises(ForwardIngestionError, match="record counters"):
        load_forward_state(state_path)


@pytest.mark.parametrize("field", ["generation_id", "start_prefix_sha256", "record_chain_sha256"])
def test_checkpoint_bad_digests_are_rejected(tmp_path: Path, field: str) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw[field] = "not-a-digest"
    durable_atomic_json(state_path, raw)
    with pytest.raises(ForwardIngestionError, match="digest"):
        load_forward_state(state_path)


def test_checkpoint_requires_absolute_source(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["source_path"] = "relative.json"
    durable_atomic_json(state_path, raw)
    with pytest.raises(ForwardIngestionError, match="absolute"):
        load_forward_state(state_path)


def test_legacy_state_change_blocks_before_delivery(tmp_path: Path) -> None:
    _source, legacy, state_path = _prepared(tmp_path)
    legacy.write_text(
        json.dumps({"version": 3, "device": 1, "inode": 2, "offset": 124}),
        encoding="utf-8",
    )
    delivery = SequenceDelivery(["accepted"])
    with pytest.raises(ForwardIngestionError, match="legacy state changed"):
        ForwardIngestionWorker(
            state_path,
            selector=select_archive_event,
            delivery=delivery,
            max_line_bytes=4096,
        ).run_batch()
    assert delivery.payloads == []
    assert load_forward_state(state_path).offset == 0


def test_dry_run_is_payload_free_and_does_not_write_checkpoint(tmp_path: Path) -> None:
    rows = _row("eligible") + b'{"location":"journald"}\n' + b"bad-json\n"
    _source, _legacy, state_path = _prepared(tmp_path, rows)
    before = hashlib.sha256(state_path.read_bytes()).hexdigest()
    result = dry_run_forward_records(state_path, limit=10, max_line_bytes=4096)
    after = hashlib.sha256(state_path.read_bytes()).hexdigest()
    assert result["counts"] == {
        "records": 3,
        "eligible": 1,
        "filtered": 1,
        "malformed": 1,
        "oversized": 0,
    }
    assert result["delivery_attempted"] is False
    assert result["checkpoint_modified"] is False
    assert before == after
    assert '"id":"eligible"' not in json.dumps(result)


def test_oversized_record_is_streamed_and_accounted_without_delivery(tmp_path: Path) -> None:
    huge = b'{"rule":{"id":"100111"},"padding":"' + (b"x" * 2_000_000) + b'"}\n'
    _source, _legacy, state_path = _prepared(tmp_path, huge + _row("after"))
    delivery = SequenceDelivery(["accepted"])
    state = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=delivery,
        max_line_bytes=4096,
    ).run_batch(limit=2)
    assert state.records == 2
    assert state.oversized == 1
    assert state.malformed == 1
    assert state.accepted == 1
    assert delivery.payloads == [_row("after").rstrip(b"\n")]


def test_partial_tail_does_not_advance(tmp_path: Path) -> None:
    complete = _row("one")
    _source, _legacy, state_path = _prepared(tmp_path, complete + b'{"id":"partial"')
    state = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
    ).run_batch(limit=10)
    assert state.offset == len(complete)
    assert state.records == 1
    assert state.status == "WAITING"


def test_filtered_records_use_one_bounded_checkpoint_write(tmp_path: Path) -> None:
    rows = b'{"location":"journald"}\n' + b"bad-json\n" * 4
    _source, _legacy, state_path = _prepared(tmp_path, rows)
    writes: list[dict[str, object]] = []

    def observed_writer(path: Path, payload: dict[str, object]) -> None:
        writes.append(dict(payload))
        durable_atomic_json(path, payload)

    state = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery([]),
        max_line_bytes=4096,
        state_writer=observed_writer,
    ).run_batch(limit=5)
    assert state.records == 5
    assert state.filtered == 1
    assert state.malformed == 4
    assert len(writes) == 1
    assert writes[0]["offset"] == len(rows)


def test_filtered_checkpoint_failure_replays_without_cursor_loss(tmp_path: Path) -> None:
    rows = b'{"location":"journald"}\n' + b"bad-json\n"
    _source, _legacy, state_path = _prepared(tmp_path, rows)

    def crash_before_checkpoint(_path: Path, _payload: dict[str, object]) -> None:
        raise OSError("simulated fsync failure")

    worker = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery([]),
        max_line_bytes=4096,
        state_writer=crash_before_checkpoint,
    )
    with pytest.raises(OSError, match="simulated fsync failure"):
        worker.run_batch(limit=2)
    state = load_forward_state(state_path)
    assert state.offset == 0
    assert state.records == 0
    assert validate_forward_checkpoint(state_path, deep=True, max_line_bytes=4096)[
        "status"
    ] == "VALID"


def test_acknowledged_event_is_checkpointed_before_later_filtering(tmp_path: Path) -> None:
    accepted = _row("accepted")
    filtered = b'{"location":"journald"}\n'
    _source, _legacy, state_path = _prepared(tmp_path, accepted + filtered)
    writes: list[dict[str, object]] = []

    def observed_writer(path: Path, payload: dict[str, object]) -> None:
        writes.append(dict(payload))
        durable_atomic_json(path, payload)

    state = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
        state_writer=observed_writer,
    ).run_batch(limit=2)
    assert state.accepted == 1
    assert state.filtered == 1
    assert len(writes) == 2
    assert writes[0]["offset"] == len(accepted)
    assert writes[0]["accepted"] == 1
    assert writes[0]["filtered"] == 0
    assert writes[1]["offset"] == len(accepted + filtered)


def test_checkpoint_lock_excludes_second_owner(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    with ForwardCheckpointLock(state_path):
        with pytest.raises(ForwardIngestionError, match="already owned"):
            with ForwardCheckpointLock(state_path):
                pass


def test_pending_approval_template_never_authorizes_live_run(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    template = build_approval_template(state_path, expires_at_epoch=time.time() + 3600)
    approval = (tmp_path / "approval.json").resolve()
    durable_atomic_json(approval, template)
    with pytest.raises(ForwardIngestionError, match="decision"):
        validate_live_approval(approval, state_path, require_root_owner=False)


def test_approval_is_bound_to_exact_source_generation_and_boundary(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    approval = _approval(state_path, tmp_path / "approval.json")
    raw = json.loads(approval.read_text(encoding="utf-8"))
    raw["source_inode"] += 1
    durable_atomic_json(approval, raw)
    with pytest.raises(ForwardIngestionError, match="source_inode"):
        validate_live_approval(approval, state_path, require_root_owner=False)


def test_approval_rejects_replay_or_legacy_mutation_scope(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    approval = _approval(state_path, tmp_path / "approval.json")
    for field in ("historical_replay_approved", "legacy_checkpoint_mutation_approved"):
        raw = json.loads(approval.read_text(encoding="utf-8"))
        raw[field] = True
        durable_atomic_json(approval, raw)
        with pytest.raises(ForwardIngestionError, match=field):
            validate_live_approval(approval, state_path, require_root_owner=False)
        raw[field] = False
        durable_atomic_json(approval, raw)


def test_expired_approval_is_rejected(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    approval = _approval(state_path, tmp_path / "approval.json", now=1000)
    with pytest.raises(ForwardIngestionError, match="expired"):
        validate_live_approval(
            approval, state_path, now=5000, require_root_owner=False
        )


def test_valid_approval_reports_unproven_history_without_claiming_replay(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    approval = _approval(state_path, tmp_path / "approval.json")
    result = validate_live_approval(approval, state_path, require_root_owner=False)
    assert result["status"] == "APPROVED"
    assert result["historical_continuity"] == "UNPROVEN"
    assert result["historical_replay_approved"] is False
    assert result["legacy_checkpoint_mutation_approved"] is False


def test_evolved_checkpoint_requires_valid_processed_chain(tmp_path: Path) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    approval = _approval(state_path, tmp_path / "approval.json")
    ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
    ).run_batch()
    validate_live_approval(approval, state_path, require_root_owner=False)
    raw = json.loads(state_path.read_text(encoding="utf-8"))
    raw["record_chain_sha256"] = "0" * 64
    durable_atomic_json(state_path, raw)
    with pytest.raises(ForwardIngestionError, match="chain"):
        validate_live_approval(approval, state_path, require_root_owner=False)


def test_service_uses_single_event_delivery_and_stops_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    monkeypatch.setenv("CYBERQALQON_EVENT_ARCHIVE", str((tmp_path / "archives.json").resolve()))
    monkeypatch.setenv("CYBERQALQON_EVENT_STATE", str((tmp_path / "legacy" / "state.json").resolve()))
    approval = _approval(state_path, tmp_path / "approval.json")
    stop = Event()

    class FakeClient:
        def __init__(self, _config: object) -> None:
            self.closed = False

        def deliver(self, _payload: bytes) -> str:
            stop.set()
            return "accepted"

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(
        "cyberqalqon_sender.forward_service.EventDeliveryClient", FakeClient
    )
    sender = SenderConfig(
        backend_url="http://127.0.0.1:8000",
        api_key="x" * 32,
        database_path=(tmp_path / "sender.db").resolve(),
        allow_insecure_http=True,
    )
    result = run_forward_service(
        sender,
        state_path=state_path,
        approval_path=approval,
        audit_path=(tmp_path / "audit.jsonl").resolve(),
        batch_limit=1,
        records_per_second=25,
        poll_seconds=0.1,
        stop_event=stop,
    )
    state = load_forward_state(state_path)
    assert result == 0
    assert state.accepted == 1
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "service_start" in audit_text
    assert "batch_complete" in audit_text
    assert "service_stop" in audit_text
    assert "rule" not in audit_text


def test_offline_cli_validate_and_dry_run_need_no_sender_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    monkeypatch.delenv("CYBERQALQON_URL", raising=False)
    monkeypatch.delenv("CYBERQALQON_INGEST_API_KEY", raising=False)
    assert cli_main(["forward", "validate", "--state", str(state_path)]) == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["status"] == "VALID"
    assert cli_main(["forward", "status", "--state", str(state_path)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["status"] == "VALID"
    assert cli_main(
        ["forward", "dry-run", "--state", str(state_path), "--limit", "1"]
    ) == 0
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run["delivery_attempted"] is False
    assert dry_run["checkpoint_modified"] is False


def test_cli_writes_only_a_non_authorizing_approval_template(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _source, _legacy, state_path = _prepared(tmp_path)
    output = (tmp_path / "pending-approval.json").resolve()
    assert cli_main(
        [
            "forward",
            "approval-template",
            "--state",
            str(state_path),
            "--output",
            str(output),
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "TEMPLATE_ONLY_NOT_APPROVED"
    template = json.loads(output.read_text(encoding="utf-8"))
    assert template["decision"] == "PENDING_EXPLICIT_USER_APPROVAL"
    assert template["accepts_unproven_history"] is False
    with pytest.raises(ForwardIngestionError, match="decision"):
        validate_live_approval(output, state_path, require_root_owner=False)
