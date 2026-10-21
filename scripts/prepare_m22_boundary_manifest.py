"""Write a payload-free M22 start-boundary and historical-gap manifest."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from cyberqalqon_sender.durable_state import durable_atomic_json
from cyberqalqon_sender.forward_ingestion import (
    load_forward_state,
    validate_forward_checkpoint,
)


APPROVAL_QUESTION = (
    "Yangi archive generation uchun independent forward ingestion'ni belgilangan "
    "boundary'dan live ishga tushirishga, eski tarixiy uzluksizlik UNPROVEN bo‘lib "
    "qolishini va eski loglar alohida recovery jarayoniga qoldirilishini tushungan "
    "holda ruxsat berasizmi?"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    state_path = args.state.resolve()
    output = args.output.resolve()
    if output.exists():
        raise ValueError("refusing to overwrite an existing boundary manifest")
    validation = validate_forward_checkpoint(state_path, deep=True)
    state = load_forward_state(state_path)
    legacy = json.loads(Path(str(state.legacy_state_path)).read_text(encoding="utf-8"))
    planned_state = (
        f"/var/lib/cyberqalqon-forward/{state.namespace}/{state.generation_id}.json"
    )
    payload = {
        "version": 1,
        "milestone": "M22",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "contains_raw_payload": False,
        "live_forward_ingestion_started": False,
        "live_approval_status": "PENDING_SEPARATE_EXPLICIT_APPROVAL",
        "source": {
            "path": state.source_path,
            "device": state.source_device,
            "inode": state.source_inode,
            "generation_id": state.generation_id,
            "size_at_validation": validation["source_size"],
            "source_hash_scope": "PREFIX_THROUGH_EXPLICIT_BOUNDARY",
            "verified_prefix_length": state.start_offset,
            "verified_prefix_sha256": state.start_prefix_sha256,
            "full_file_sha256": None,
            "full_file_hash_reason": "ACTIVE_APPEND_ONLY_FILE",
        },
        "forward_boundary": {
            "offset": state.start_offset,
            "record_boundary": "NEWLINE_VERIFIED",
            "next_record_prefix": "JSON_OBJECT_START_VERIFIED",
            "checkpoint_offset": state.offset,
            "checkpoint_chain_verified": validation["chain_verified"],
            "records_processed": validation["verified_records"],
        },
        "legacy_checkpoint": {
            "path": state.legacy_state_path,
            "sha256": state.legacy_state_sha256,
            "cursor": state.legacy_cursor_at_registration,
            "mutation_authorized": False,
            "unchanged_during_validation": validation["legacy_state_unchanged"],
            "continuity": "UNPROVEN",
        },
        "checkpoint": {
            "staging_path": str(state_path),
            "staging_sha256": validation["state_sha256"],
            "planned_live_path": planned_state,
            "namespace_isolated_from_legacy": True,
            "activation_state": "NOT_DEPLOYED",
        },
        "excluded_from_immediate_forward_delivery": [
            {
                "scope": "LEGACY_GENERATION_UNREAD_SUFFIX",
                "stored_legacy_source_device": int(legacy["device"]),
                "stored_legacy_source_inode": int(legacy["inode"]),
                "legacy_cursor": state.legacy_cursor_at_registration,
                "delivery_status": "UNKNOWN",
                "classification": "UNPROVEN_REQUIRES_SEPARATE_RECONCILIATION",
            },
            {
                "scope": "RETAINED_DAYS_15_TO_19",
                "observed_eligible_records": 465121,
                "delivery_status": "UNKNOWN",
                "classification": "PRESERVED_FOR_SEPARATE_RECONCILIATION_OR_REPLAY",
            },
            {
                "scope": "ACTIVE_DAY20_PREFIX",
                "byte_range": [0, state.start_offset],
                "delivery_status": "UNKNOWN",
                "classification": "INTENTIONALLY_EXCLUDED_BY_FORWARD_BOUNDARY",
            },
            {
                "scope": "SOURCE_OFFLINE_INTERVALS",
                "delivery_status": "NO_ARCHIVE_EVIDENCE",
                "classification": "NOT_REPLAYABLE_FROM_WAZUH_ARCHIVES",
            },
        ],
        "historical_replay": {
            "state": "NOT_STARTED",
            "authorized": False,
        },
        "safety_gates": {
            "single_event_ingestion_only": True,
            "batch_protocol_enabled": False,
            "legacy_checkpoint_mutation_authorized": False,
            "historical_replay_authorized": False,
            "schema_migration_authorized": False,
            "service_install_or_enable_authorized": False,
        },
        "approval_question": APPROVAL_QUESTION,
    }
    output.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    durable_atomic_json(output, payload)
    print(json.dumps({"output": str(output), "generation_id": state.generation_id}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
