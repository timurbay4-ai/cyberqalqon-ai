from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path

import pytest

from cyberqalqon_sender.durable_state import durable_atomic_json
from cyberqalqon_sender.event_shipper import select_archive_event
from cyberqalqon_sender.forward_ingestion import (
    ForwardIngestionError,
    ForwardIngestionWorker,
    initialize_forward_generation,
    load_forward_state,
    rebind_rotated_candidate,
    verify_rotated_candidate,
)
from cyberqalqon_sender.reconciliation import (
    ArchiveReconciler,
    ReconciliationError,
    ReconciliationSource,
    RetainedIdentityInventory,
    canonical_event_fingerprint,
    decoded_prefix_sha256,
    state_report,
    validate_decoded_boundary,
)


def _row(identifier: str, *, timestamp: str | None = None) -> bytes:
    payload: dict[str, object] = {"id": identifier, "rule": {"id": "100111"}}
    if timestamp is not None:
        payload["timestamp"] = timestamp
    return json.dumps(payload, separators=(",", ":")).encode() + b"\n"


def _fingerprint(row: bytes) -> str:
    return canonical_event_fingerprint(json.loads(row))


class SequenceDelivery:
    def __init__(self, outcomes: list[str]) -> None:
        self.outcomes = outcomes
        self.payloads: list[bytes] = []

    def deliver(self, payload: bytes) -> str:
        self.payloads.append(payload)
        return self.outcomes.pop(0)


def _reconciler(
    archive: Path,
    tmp_path: Path,
    inventory: RetainedIdentityInventory,
) -> ArchiveReconciler:
    return ArchiveReconciler(
        ReconciliationSource.capture(archive),
        inventory,
        tmp_path / "reconciliation" / "state.json",
        selector=select_archive_event,
        max_line_bytes=4096,
    )


def test_payload_free_backend_identity_export_is_loaded(tmp_path: Path) -> None:
    export = tmp_path / "identities.tsv.gz"
    fingerprint = "a" * 64
    with gzip.open(export, "wt", encoding="utf-8", newline="") as handle:
        handle.write('{"version":1,"row_count":1}\n')
        handle.write(f"F\t{fingerprint}\n")
        handle.write("S\t1790000000.1\n")
    inventory = RetainedIdentityInventory.from_payload_free_export(export.resolve())
    assert inventory.fingerprints == frozenset({fingerprint})
    assert inventory.source_ids == frozenset({"1790000000.1"})
    assert inventory.retention_capped is True


def test_matching_prefix_does_not_prove_a_mismatching_suffix(tmp_path: Path) -> None:
    prefix = _row("prefix")
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(prefix + _row("suffix-a"))
    second.write_bytes(prefix + _row("suffix-b"))
    assert decoded_prefix_sha256(first, len(prefix)) == decoded_prefix_sha256(
        second, len(prefix)
    )
    assert hashlib.sha256(first.read_bytes()).digest() != hashlib.sha256(
        second.read_bytes()
    ).digest()


def test_missing_original_inode_and_unavailable_generation_fail_closed(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "archive.json"
    archive.write_bytes(_row("one"))
    source = ReconciliationSource.capture(archive)
    reconciler = ArchiveReconciler(
        source,
        RetainedIdentityInventory.unavailable(),
        tmp_path / "state.json",
        selector=select_archive_event,
        max_line_bytes=4096,
    )
    archive.unlink()
    with pytest.raises(ReconciliationError, match="unavailable"):
        reconciler.run_batch()


def test_valid_and_invalid_cursor_boundaries(tmp_path: Path) -> None:
    first = _row("one")
    archive = tmp_path / "archive.json"
    archive.write_bytes(first + _row("two"))
    source = ReconciliationSource.capture(archive)
    assert validate_decoded_boundary(source, len(first)) is False
    with pytest.raises(ReconciliationError, match="record boundary"):
        validate_decoded_boundary(source, 2)


def test_equal_ledger_count_with_different_payload_is_not_same_generation(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_bytes(_row("one") + _row("two"))
    second.write_bytes(_row("one") + _row("changed"))
    assert first.read_bytes().count(b"\n") == second.read_bytes().count(b"\n")
    assert ReconciliationSource.capture(first).generation_id != ReconciliationSource.capture(
        second
    ).generation_id


def test_timestamp_gap_does_not_claim_continuity(tmp_path: Path) -> None:
    rows = (
        _row("one", timestamp="2026-10-15T00:00:00Z")
        + _row("two", timestamp="2026-10-17T00:00:00Z")
    )
    archive = tmp_path / "gap.json"
    archive.write_bytes(rows)
    inventory = RetainedIdentityInventory(
        frozenset(_fingerprint(line + b"\n") for line in rows.splitlines()),
        frozenset({"one", "two"}),
    )
    state = _reconciler(archive, tmp_path, inventory).run_batch()
    assert state.counts.proven_already_ingested == 2
    report = state_report(ReconciliationSource.capture(archive), state, inventory)
    assert "continuity" not in json.dumps(report)


def test_reconciliation_classifies_exact_probable_absent_duplicate_and_filtered(
    tmp_path: Path,
) -> None:
    exact = _row("exact")
    probable = _row("probable")
    absent = _row("absent")
    filtered = b'{"id":"filtered","location":"journald"}\n'
    archive = tmp_path / "classification.json"
    archive.write_bytes(exact + probable + absent + exact + filtered)
    inventory = RetainedIdentityInventory(
        frozenset({_fingerprint(exact)}),
        frozenset({"exact", "probable"}),
    )
    state = _reconciler(archive, tmp_path, inventory).run_batch()
    assert state.status == "COMPLETE"
    assert state.counts.proven_already_ingested == 2
    assert state.counts.probable_duplicate_not_proven == 1
    assert state.counts.present_archive_absent_retained_database == 1
    assert state.counts.exact_archive_duplicates == 1
    assert state.counts.filtered == 1


def test_retention_absence_is_not_reported_as_never_ingested(tmp_path: Path) -> None:
    archive = tmp_path / "retained-away.json"
    archive.write_bytes(_row("old"))
    inventory = RetainedIdentityInventory(frozenset(), frozenset(), retention_capped=True)
    reconciler = _reconciler(archive, tmp_path, inventory)
    state = reconciler.run_batch()
    report = state_report(reconciler.source, state, inventory)
    assert state.counts.present_archive_absent_retained_database == 1
    assert report["retained_identity_inventory"]["absence_is_proof_of_never_ingested"] is False


def test_unknown_inventory_is_unable_to_classify(tmp_path: Path) -> None:
    archive = tmp_path / "unknown.json"
    archive.write_bytes(_row("unknown"))
    state = _reconciler(
        archive, tmp_path, RetainedIdentityInventory.unavailable()
    ).run_batch()
    assert state.counts.unable_to_classify == 1


@pytest.mark.parametrize(
    ("tail", "field"),
    [
        (b"\x00" * 305, "partial_tail"),
        (b'{"id":"truncated"', "partial_tail"),
        (b"\xff\xfe\n", "invalid_utf8"),
        (b"not-json\n", "invalid_json"),
    ],
)
def test_reconciliation_accounts_for_malformed_and_incomplete_records(
    tmp_path: Path,
    tail: bytes,
    field: str,
) -> None:
    archive = tmp_path / f"{field}-{len(tail)}.json"
    archive.write_bytes(_row("valid") + tail)
    state = _reconciler(
        archive, tmp_path, RetainedIdentityInventory.unavailable()
    ).run_batch()
    assert state.counts.malformed_or_incomplete == 1
    assert getattr(state.counts, field) == 1


def test_interrupted_reconciliation_scan_resumes_without_counting_prefix_twice(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "resume.json"
    archive.write_bytes(_row("one") + _row("two") + _row("three"))
    inventory = RetainedIdentityInventory.unavailable()
    first = _reconciler(archive, tmp_path, inventory)
    paused = first.run_batch(limit=1)
    assert paused.status == "PAUSED"
    assert paused.counts.records == 1
    complete = _reconciler(archive, tmp_path, inventory).run_batch(limit=10)
    assert complete.status == "COMPLETE"
    assert complete.counts.records == 3
    assert complete.counts.unable_to_classify == 3


def test_forward_cursor_restarts_in_an_independent_namespace(tmp_path: Path) -> None:
    archive = tmp_path / "active.json"
    rows = [_row("one"), _row("two")]
    archive.write_bytes(b"".join(rows))
    state_path = initialize_forward_generation(
        archive,
        tmp_path / "forward",
        namespace="m21-forward",
        start_offset=0,
    )
    first_delivery = SequenceDelivery(["accepted"])
    first = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=first_delivery,
        max_line_bytes=4096,
    ).run_batch(limit=1)
    assert first.offset == len(rows[0])
    second_delivery = SequenceDelivery(["accepted"])
    resumed = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=second_delivery,
        max_line_bytes=4096,
    ).run_batch(limit=10)
    assert resumed.offset == sum(map(len, rows))
    assert resumed.accepted == 2
    assert second_delivery.payloads == [rows[1].rstrip(b"\n")]


def test_forward_source_identity_mismatch_fails_without_delivery(tmp_path: Path) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(_row("one"))
    state_path = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(_row("replacement"))
    os.replace(replacement, archive)
    delivery = SequenceDelivery(["accepted"])
    with pytest.raises(ForwardIngestionError, match="identity changed"):
        ForwardIngestionWorker(
            state_path,
            selector=select_archive_event,
            delivery=delivery,
            max_line_bytes=4096,
        ).run_batch()
    assert delivery.payloads == []
    assert load_forward_state(state_path).offset == 0


def test_forward_backend_unavailable_and_protocol_error_do_not_advance(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(_row("one"))
    state_path = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    delivery = SequenceDelivery(["retry", "protocol_error"])
    worker = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=delivery,
        max_line_bytes=4096,
    )
    assert worker.run_batch().offset == 0
    state = worker.run_batch()
    assert state.offset == 0
    assert state.retry_attempts == 2
    assert state.protocol_errors == 1


def test_duplicate_http_acknowledgement_advances_once(tmp_path: Path) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(_row("duplicate"))
    state_path = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    state = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["duplicate"]),
        max_line_bytes=4096,
    ).run_batch()
    assert state.duplicates == 1
    assert state.accepted == 0
    assert state.offset == archive.stat().st_size


def test_commit_succeeded_response_lost_retries_as_duplicate(tmp_path: Path) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(_row("uncertain-ack"))
    state_path = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )

    def fail_after_acknowledgement(path: Path, payload: dict[str, object]) -> None:
        if int(payload["accepted"]) == 1:
            raise OSError("simulated crash before cursor commit")
        durable_atomic_json(path, payload)

    with pytest.raises(OSError, match="simulated crash"):
        ForwardIngestionWorker(
            state_path,
            selector=select_archive_event,
            delivery=SequenceDelivery(["accepted"]),
            max_line_bytes=4096,
            state_writer=fail_after_acknowledgement,
        ).run_batch()
    assert load_forward_state(state_path).offset == 0
    recovered = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["duplicate"]),
        max_line_bytes=4096,
    ).run_batch()
    assert recovered.offset == archive.stat().st_size
    assert recovered.duplicates == 1


def test_crash_during_independent_checkpoint_save_keeps_previous_cursor(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(b'{"id":"filtered","location":"journald"}\n')
    state_path = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )

    def fail_write(path: Path, payload: dict[str, object]) -> None:
        raise OSError("simulated checkpoint failure")

    with pytest.raises(OSError, match="checkpoint failure"):
        ForwardIngestionWorker(
            state_path,
            selector=select_archive_event,
            delivery=SequenceDelivery([]),
            max_line_bytes=4096,
            state_writer=fail_write,
        ).run_batch()
    assert load_forward_state(state_path).offset == 0
    recovered = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery([]),
        max_line_bytes=4096,
    ).run_batch()
    assert recovered.filtered == 1
    assert recovered.offset == archive.stat().st_size


def test_legacy_cursor_is_never_modified(tmp_path: Path) -> None:
    archive = tmp_path / "active.json"
    archive.write_bytes(_row("one"))
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps({"version": 3, "device": 1, "inode": 2, "offset": 93438552}),
        encoding="utf-8",
    )
    before = hashlib.sha256(legacy.read_bytes()).hexdigest()
    state_path = initialize_forward_generation(
        archive,
        tmp_path / "forward",
        namespace="m21-forward",
        start_offset=0,
        legacy_state_path=legacy,
    )
    ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
    ).run_batch()
    assert hashlib.sha256(legacy.read_bytes()).hexdigest() == before
    state = load_forward_state(state_path)
    assert state.legacy_cursor_at_registration == 93438552
    assert state.legacy_state_sha256 == before


def test_two_generations_with_identical_filenames_get_distinct_ids(tmp_path: Path) -> None:
    archive = tmp_path / "archives.json"
    archive.write_bytes(_row("first"))
    first = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    archive.unlink()
    archive.write_bytes(_row("second"))
    second = initialize_forward_generation(
        archive, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    assert load_forward_state(first).generation_id != load_forward_state(
        second
    ).generation_id


def test_rotation_and_gzip_conversion_require_verified_rebind(tmp_path: Path) -> None:
    active = tmp_path / "archives.json"
    rows = [_row("one"), _row("two")]
    active.write_bytes(b"".join(rows))
    state_path = initialize_forward_generation(
        active, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    first = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
    ).run_batch(limit=1)
    assert first.offset == len(rows[0])
    rotated = tmp_path / "ossec-archive.json.gz"
    with gzip.open(rotated, "wb") as handle:
        handle.write(b"".join(rows))
    active.unlink()
    binding = verify_rotated_candidate(state_path, rotated)
    assert binding["verified_through_offset"] == len(rows[0])
    with pytest.raises(ForwardIngestionError, match="explicit operator approval"):
        rebind_rotated_candidate(state_path, rotated, operator_approved=False)
    rebound = rebind_rotated_candidate(state_path, rotated, operator_approved=True)
    assert rebound.generation_id == first.generation_id
    finished = ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted"]),
        max_line_bytes=4096,
    ).run_batch(limit=10)
    assert finished.accepted == 2
    assert finished.offset == sum(map(len, rows))


def test_rotated_candidate_with_same_prefix_but_changed_processed_suffix_is_rejected(
    tmp_path: Path,
) -> None:
    active = tmp_path / "archives.json"
    rows = [_row("one"), _row("two")]
    active.write_bytes(b"".join(rows))
    state_path = initialize_forward_generation(
        active, tmp_path / "forward", namespace="m21-forward", start_offset=0
    )
    ForwardIngestionWorker(
        state_path,
        selector=select_archive_event,
        delivery=SequenceDelivery(["accepted", "accepted"]),
        max_line_bytes=4096,
    ).run_batch(limit=2)
    candidate = tmp_path / "candidate.json.gz"
    with gzip.open(candidate, "wb") as handle:
        handle.write(rows[0] + _row("xxx"))
    with pytest.raises(ForwardIngestionError, match="chain does not match"):
        verify_rotated_candidate(state_path, candidate)
