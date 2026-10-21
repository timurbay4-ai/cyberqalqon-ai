from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from cyberqalqon_sender.cli import main as cli_main
from cyberqalqon_sender.durable_state import durable_atomic_json
from cyberqalqon_sender.forward_ingestion import (
    ForwardIngestionError,
    initialize_forward_generation,
)
from cyberqalqon_sender.forward_service import (
    build_approval_renewal_proposal,
    build_approval_template,
    validate_live_approval,
)


def _row(identifier: str) -> bytes:
    return json.dumps(
        {"id": identifier, "rule": {"id": "100111"}}, separators=(",", ":")
    ).encode() + b"\n"


def _fixture(
    tmp_path: Path, *, issued: float, expires: float, start_offset: int = 0
) -> tuple[Path, Path]:
    source = (tmp_path / "archives.json").resolve()
    source.write_bytes(_row("one") + _row("two"))
    legacy = (tmp_path / "legacy-state.json").resolve()
    legacy.write_text(
        json.dumps({"version": 3, "device": 1, "inode": 2, "offset": 93438552}),
        encoding="utf-8",
    )
    state = initialize_forward_generation(
        source,
        (tmp_path / "forward").resolve(),
        namespace="m23-lifecycle",
        start_offset=start_offset,
        legacy_state_path=legacy,
    )
    approval = (tmp_path / "approval.json").resolve()
    payload = build_approval_template(state, expires_at_epoch=expires)
    payload.update(
        {
            "decision": "APPROVED",
            "issued_at_epoch": issued,
            "accepts_unproven_history": True,
        }
    )
    durable_atomic_json(approval, payload)
    return state, approval


def test_active_authority_builds_pending_generation_bound_renewal(tmp_path: Path) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=4_000)
    result = build_approval_renewal_proposal(
        approval,
        state,
        requested_expires_at_epoch=5_000,
        now=2_000,
        require_root_owner=False,
    )

    assert result["status"] == "RENEWAL_PROPOSAL_READY"
    assert result["action_required"] == "EXPLICIT_OPERATOR_APPROVAL"
    assert result["proposal"]["decision"] == "PENDING_EXPLICIT_USER_APPROVAL"
    assert result["proposal"]["proposal_kind"] == "RENEWAL"
    assert result["proposal"]["generation_id"] == result["generation_id"]
    assert result["proposal"]["prepared_state_sha256"] == result["checkpoint_sha256"]
    assert result["proposal"]["historical_continuity"] == "UNPROVEN"
    assert result["proposal"]["historical_replay_approved"] is False
    assert result["proposal"]["legacy_checkpoint_mutation_approved"] is False
    assert result["proposal"]["accepts_unproven_history"] is False


def test_duplicate_or_shorter_renewal_is_idempotent(tmp_path: Path) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=4_000)
    for requested in (4_000, 3_500):
        result = build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=requested,
            now=2_000,
            require_root_owner=False,
        )
        assert result["status"] == "ALREADY_APPROVED"
        assert result["proposal"] is None
        assert result["action_required"] == "NONE"


def test_expired_authority_never_becomes_an_automatic_renewal(tmp_path: Path) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=2_000)
    result = build_approval_renewal_proposal(
        approval,
        state,
        requested_expires_at_epoch=5_000,
        now=3_000,
        require_root_owner=False,
    )

    assert result["status"] == "ACTIVATION_PROPOSAL_REQUIRED"
    assert result["reason_codes"] == ["EXPIRED_APPROVAL"]
    assert result["proposal"]["proposal_kind"] == "FRESH_ACTIVATION"
    assert result["proposal"]["decision"] == "PENDING_EXPLICIT_USER_APPROVAL"
    with pytest.raises(ForwardIngestionError, match="decision"):
        pending = (tmp_path / "pending.json").resolve()
        durable_atomic_json(pending, result["proposal"])
        validate_live_approval(pending, state, now=3_000, require_root_owner=False)


@pytest.mark.parametrize("requested", [2_050, 88_401, float("inf"), float("nan")])
def test_proposal_window_is_finite_and_bounded(tmp_path: Path, requested: float) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=4_000)
    with pytest.raises(ForwardIngestionError, match="60 to 86400"):
        build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=requested,
            now=2_000,
            require_root_owner=False,
        )


@pytest.mark.parametrize("field", ["generation_id", "source_inode", "legacy_cursor"])
def test_proposal_fails_closed_on_scope_mismatch(tmp_path: Path, field: str) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=4_000)
    raw = json.loads(approval.read_text(encoding="utf-8"))
    raw[field] = "0" * 64 if field == "generation_id" else int(raw[field]) + 1
    durable_atomic_json(approval, raw)

    with pytest.raises(ForwardIngestionError, match=field):
        build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=5_000,
            now=2_000,
            require_root_owner=False,
        )


def test_clock_regression_fails_closed(tmp_path: Path) -> None:
    state, approval = _fixture(tmp_path, issued=2_000, expires=4_000)
    with pytest.raises(ForwardIngestionError, match="clock regression"):
        build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=5_000,
            now=1_000,
            require_root_owner=False,
        )


def test_invalid_prepared_state_checksum_blocks_proposal(tmp_path: Path) -> None:
    state, approval = _fixture(tmp_path, issued=1_000, expires=4_000)
    raw = json.loads(approval.read_text(encoding="utf-8"))
    raw["prepared_state_sha256"] = "not-a-digest"
    durable_atomic_json(approval, raw)

    with pytest.raises(ForwardIngestionError, match="prepared-state digest"):
        build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=5_000,
            now=2_000,
            require_root_owner=False,
        )


def test_source_prefix_change_blocks_proposal(tmp_path: Path) -> None:
    state, approval = _fixture(
        tmp_path,
        issued=1_000,
        expires=4_000,
        start_offset=len(_row("one")),
    )
    raw = json.loads(state.read_text(encoding="utf-8"))
    source = Path(raw["source_path"])
    encoded = source.read_bytes()
    source.write_bytes(b"X" + encoded[1:])

    with pytest.raises(ForwardIngestionError, match="prefix"):
        build_approval_renewal_proposal(
            approval,
            state,
            requested_expires_at_epoch=5_000,
            now=2_000,
            require_root_owner=False,
        )


def test_cli_writes_proposal_envelope_not_live_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    state, approval = _fixture(tmp_path, issued=now - 10, expires=now + 600)
    output = (tmp_path / "proposal-envelope.json").resolve()
    requested = now + 1_200
    from cyberqalqon_sender import cli

    build_proposal = cli.build_approval_renewal_proposal
    monkeypatch.setattr(
        cli,
        "build_approval_renewal_proposal",
        lambda approval_path, checkpoint_path, **kwargs: build_proposal(
            approval_path,
            checkpoint_path,
            require_root_owner=False,
            **kwargs,
        ),
    )

    assert cli_main(
        [
            "forward",
            "approval-proposal",
            "--state",
            str(state),
            "--approval",
            str(approval),
            "--output",
            str(output),
            "--requested-expires-at-epoch",
            str(requested),
        ]
    ) == 0
    envelope = json.loads(output.read_text(encoding="utf-8"))
    assert envelope["status"] == "RENEWAL_PROPOSAL_READY"
    assert envelope["proposal"]["decision"] == "PENDING_EXPLICIT_USER_APPROVAL"
    assert envelope["contains_raw_payload"] is False
    canonical = json.dumps(
        envelope["proposal"], sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == envelope["proposal_sha256"]
    with pytest.raises(ForwardIngestionError, match="version|decision"):
        validate_live_approval(output, state, require_root_owner=False)


def test_cli_refuses_to_overwrite_existing_proposal(tmp_path: Path) -> None:
    now = time.time()
    state, approval = _fixture(tmp_path, issued=now - 10, expires=now + 600)
    output = (tmp_path / "existing.json").resolve()
    output.write_text("preserve-me", encoding="utf-8")

    assert cli_main(
        [
            "forward",
            "approval-proposal",
            "--state",
            str(state),
            "--approval",
            str(approval),
            "--output",
            str(output),
            "--requested-expires-at-epoch",
            str(now + 1_200),
        ]
    ) == 2
    assert output.read_text(encoding="utf-8") == "preserve-me"
