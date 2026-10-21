from __future__ import annotations

import gzip
import json
import os
from pathlib import Path

import pytest

from cyberqalqon_sender.archive_recovery import (
    ArchiveGenerationManifest,
    ArchiveRecoveryError,
    HistoricalArchiveReplayer,
    audit_active_malformed_records,
    audit_malformed_records,
)
from cyberqalqon_sender.event_shipper import select_archive_event


class SequenceDelivery:
    def __init__(self, results: list[str]) -> None:
        self.results = results
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return self.results.pop(0)


def _manifest(tmp_path: Path) -> ArchiveGenerationManifest:
    return ArchiveGenerationManifest(tmp_path / "state" / "generations.json")


def test_generation_registration_is_idempotent_and_detects_mutation(tmp_path: Path) -> None:
    archive = tmp_path / "archive.json"
    archive.write_text('{"rule":{"id":"100111"}}\n', encoding="utf-8")
    manifest = _manifest(tmp_path)
    first = manifest.register(archive)
    second = manifest.register(archive)
    assert first == second
    assert manifest.get(first.generation_id) == first
    assert len(json.loads(manifest.path.read_text(encoding="utf-8"))["generations"]) == 1

    archive.write_text('{"rule":{"id":"100120"}}\n', encoding="utf-8")
    with pytest.raises(ArchiveRecoveryError, match="different immutable identity"):
        manifest.register(archive)


def test_missing_generation_and_corrupt_replay_state_fail_closed(tmp_path: Path) -> None:
    archive = tmp_path / "archive.json"
    archive.write_text('{"id":"one","rule":{"id":"100111"}}\n', encoding="utf-8")
    manifest = _manifest(tmp_path)
    generation = manifest.register(archive)
    with pytest.raises(ArchiveRecoveryError, match="not registered"):
        manifest.get("0" * 64)

    delivery = SequenceDelivery(["accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    replayer.state_path.parent.mkdir(parents=True)
    replayer.state_path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ArchiveRecoveryError, match="state is unreadable"):
        replayer.run_batch(operator_approved=True)
    assert delivery.payloads == []

    replayer.state_path.unlink()
    archive.unlink()
    with pytest.raises(ArchiveRecoveryError, match="archive is unavailable"):
        replayer.run_batch(operator_approved=True)
    assert not replayer.state_path.exists()


def test_truncated_gzip_replay_fails_closed_without_checkpoint(tmp_path: Path) -> None:
    archive = tmp_path / "truncated.json.gz"
    with gzip.open(archive, "wb") as handle:
        handle.write(b'{"id":"one","rule":{"id":"100111"}}\n')
    archive.write_bytes(archive.read_bytes()[:-4])
    generation = _manifest(tmp_path).register(archive)
    delivery = SequenceDelivery(["accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    with pytest.raises(ArchiveRecoveryError, match="cannot be decoded safely"):
        replayer.run_batch(operator_approved=True)
    assert not replayer.state_path.exists()


def test_historical_replay_is_approved_bounded_durable_and_idempotent(tmp_path: Path) -> None:
    archive = tmp_path / "archive.json"
    rows = [
        json.dumps({"id": "accepted", "rule": {"id": "100111"}}).encode() + b"\n",
        json.dumps({"id": "duplicate", "rule": {"id": "100111"}}).encode() + b"\n",
        json.dumps({"id": "filtered", "location": "journald"}).encode() + b"\n",
        b"not-json\n",
        b"x" * 5000 + b"\n",
    ]
    archive.write_bytes(b"".join(rows))
    generation = _manifest(tmp_path).register(archive)
    delivery = SequenceDelivery(["accepted", "duplicate"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    with pytest.raises(ArchiveRecoveryError, match="explicit operator approval"):
        replayer.run_batch(operator_approved=False)
    assert not replayer.state_path.exists()

    state = replayer.run_batch(
        operator_approved=True,
        limit=10,
        records_per_second=1000,
    )
    assert state.status == "COMPLETE"
    assert state.accepted == 1
    assert state.duplicates == 1
    assert state.filtered == 1
    assert state.malformed == 2
    assert state.oversized == 1
    assert state.offset == sum(len(row) for row in rows)
    before = replayer.state_path.read_bytes()
    resumed = replayer.run_batch(operator_approved=True)
    assert resumed.status == "COMPLETE"
    assert replayer.state_path.read_bytes() == before
    assert len(delivery.payloads) == 2


def test_disposable_rotated_generation_resumes_verified_checkpoint_once(
    tmp_path: Path,
) -> None:
    rows = [
        b'{"id":"already-acknowledged","rule":{"id":"100111"}}\n',
        b'{"id":"new","rule":{"id":"100111"}}\n',
        b'{"id":"duplicate","rule":{"id":"100111"}}\n',
        b'{"id":"filtered","location":"journald"}\n',
        b"malformed\n",
        b'{"id":"last","rule":{"id":"100120"}}\n',
    ]
    archive = tmp_path / "ossec-archive-15.json.gz"
    with gzip.open(archive, "wb") as handle:
        handle.write(b"".join(rows))
    generation = _manifest(tmp_path).register(archive)
    state_directory = tmp_path / "replay"
    state_directory.mkdir()
    state_path = state_directory / f"{generation.generation_id}.json"
    checkpoint = len(rows[0])
    state_path.write_text(
        json.dumps(
            {
                "version": 2,
                "generation_id": generation.generation_id,
                "offset": checkpoint,
                "status": "PAUSED",
            }
        ),
        encoding="utf-8",
    )

    first_delivery = SequenceDelivery(["accepted", "duplicate"])
    first = HistoricalArchiveReplayer(
        generation,
        state_directory,
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=first_delivery,
    ).run_batch(operator_approved=True, limit=2, records_per_second=1000)
    assert first.status == "PAUSED"
    assert first.accepted == 1
    assert first.duplicates == 1
    assert all(b"already-acknowledged" not in payload for payload in first_delivery.payloads)

    second_delivery = SequenceDelivery(["accepted"])
    restarted = HistoricalArchiveReplayer(
        generation,
        state_directory,
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=second_delivery,
    )
    complete = restarted.run_batch(
        operator_approved=True,
        limit=100,
        records_per_second=1000,
    )
    assert complete.status == "COMPLETE"
    assert complete.accepted == 2
    assert complete.duplicates == 1
    assert complete.filtered == 1
    assert complete.malformed == 1
    assert complete.offset == sum(len(row) for row in rows)
    before = state_path.read_bytes()
    assert restarted.run_batch(operator_approved=True).status == "COMPLETE"
    assert state_path.read_bytes() == before
    assert second_delivery.payloads == [rows[-1].rstrip(b"\n")]


@pytest.mark.parametrize(
    ("offset", "message"),
    [
        (10_000, "beyond the archive"),
        (2, "not on a record boundary"),
        (-1, "checkpoint is negative"),
    ],
)
def test_corrupt_historical_checkpoint_fails_closed_without_delivery(
    tmp_path: Path,
    offset: int,
    message: str,
) -> None:
    archive = tmp_path / "archive.json.gz"
    with gzip.open(archive, "wb") as handle:
        handle.write(b'{"id":"one","rule":{"id":"100111"}}\n')
    generation = _manifest(tmp_path).register(archive)
    state_directory = tmp_path / "replay"
    state_directory.mkdir()
    state_path = state_directory / f"{generation.generation_id}.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 2,
                "generation_id": generation.generation_id,
                "offset": offset,
                "status": "PAUSED",
            }
        ),
        encoding="utf-8",
    )
    delivery = SequenceDelivery(["accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        state_directory,
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    with pytest.raises(ArchiveRecoveryError, match=message):
        replayer.run_batch(operator_approved=True)
    assert delivery.payloads == []
    assert json.loads(state_path.read_text(encoding="utf-8"))["offset"] == offset


def test_same_identity_content_mutation_is_detected_before_delivery(tmp_path: Path) -> None:
    archive = tmp_path / "archive.json"
    archive.write_bytes(b'{"id":"one","rule":{"id":"100111"}}\n')
    generation = _manifest(tmp_path).register(archive)
    original_stat = archive.stat()
    mutated = archive.read_bytes().replace(b'"one"', b'"two"')
    assert len(mutated) == original_stat.st_size
    archive.write_bytes(mutated)
    os.utime(archive, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    delivery = SequenceDelivery(["accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    with pytest.raises(ArchiveRecoveryError, match="digest changed"):
        replayer.run_batch(operator_approved=True)
    assert delivery.payloads == []


def test_historical_retry_pauses_without_advancing_then_resumes(tmp_path: Path) -> None:
    archive = tmp_path / "retry.json"
    archive.write_text('{"id":"retry","rule":{"id":"5710"}}\n', encoding="utf-8")
    generation = _manifest(tmp_path).register(archive)
    delivery = SequenceDelivery(["retry", "accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    blocked = replayer.run_batch(operator_approved=True, records_per_second=1000)
    assert blocked.status == "PAUSED"
    assert blocked.offset == 0
    assert blocked.retry_attempts == 1
    completed = replayer.run_batch(operator_approved=True, records_per_second=1000)
    assert completed.status == "COMPLETE"
    assert completed.accepted == 1
    assert completed.offset == archive.stat().st_size


def test_historical_protocol_error_pauses_without_advancing(tmp_path: Path) -> None:
    archive = tmp_path / "protocol.json"
    archive.write_text('{"id":"protocol","rule":{"id":"5710"}}\n', encoding="utf-8")
    generation = _manifest(tmp_path).register(archive)
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=SequenceDelivery(["protocol_error"]),
    )
    state = replayer.run_batch(operator_approved=True, records_per_second=1000)
    assert state.status == "PAUSED"
    assert state.offset == 0
    assert state.protocol_errors == 1
    assert state.retry_attempts == 1


def test_historical_permanent_rejection_blocks_without_advancing(tmp_path: Path) -> None:
    archive = tmp_path / "rejected.json"
    archive.write_text('{"id":"rejected","rule":{"id":"5710"}}\n', encoding="utf-8")
    generation = _manifest(tmp_path).register(archive)
    delivery = SequenceDelivery(["rejected", "accepted"])
    replayer = HistoricalArchiveReplayer(
        generation,
        tmp_path / "replay",
        max_line_bytes=4096,
        selector=select_archive_event,
        delivery=delivery,
    )
    blocked = replayer.run_batch(operator_approved=True, records_per_second=1000)
    assert blocked.status == "BLOCKED"
    assert blocked.terminal_blocked is True
    assert blocked.offset == 0
    assert blocked.delivery_rejected == 1
    repeated = replayer.run_batch(operator_approved=True, records_per_second=1000)
    assert repeated.status == "BLOCKED"
    assert len(delivery.payloads) == 1


def test_gzip_malformed_audit_records_only_hashes_offsets_and_categories(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "rotated.json.gz"
    evidence = (
        b'{"id":"valid","rule":{"id":"100111"}}\n'
        + b"not-json secret-marker\n"
        + b"\xff\xfe\n"
        + b"x" * 5000
        + b"\n"
        + b'{"partial":true}'
    )
    with gzip.open(archive, "wb") as handle:
        handle.write(evidence)
    generation = _manifest(tmp_path).register(archive)
    output = tmp_path / "audit" / "malformed.json"
    result = audit_malformed_records(
        generation,
        start_offset=0,
        max_line_bytes=4096,
        output_path=output,
    )
    assert result["counts"] == {
        "invalid_utf8": 1,
        "invalid_json": 1,
        "oversized": 1,
        "partial_line": 1,
        "total": 4,
    }
    assert {item["category"] for item in result["records"]} == {
        "invalid_utf8",
        "invalid_json",
        "oversized",
        "partial_line",
    }
    serialized = output.read_text(encoding="utf-8")
    assert "secret-marker" not in serialized
    assert '"contains_raw_payload":false' in serialized
    assert all(len(item["line_sha256"]) == 64 for item in result["records"])


def test_active_malformed_audit_stops_at_acknowledged_cursor(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    acknowledged = b"bad-json\n" + b'{"id":"valid"}\n'
    archive.write_bytes(acknowledged + b"future-bad-json\n")
    stat = archive.stat()
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "version": 3,
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "offset": len(acknowledged),
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "active-audit.json"
    result = audit_active_malformed_records(
        archive,
        state,
        max_line_bytes=4096,
        output_path=output,
    )
    assert result["counts"]["total"] == 1
    assert result["counts"]["invalid_json"] == 1
    assert result["source_identity"]["snapshot_end_offset"] == len(acknowledged)
    assert "future-bad-json" not in output.read_text(encoding="utf-8")
