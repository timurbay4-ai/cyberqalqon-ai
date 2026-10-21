#!/usr/bin/env python3
"""Run bounded read-only M21 archive reconciliation and emit a payload-free report."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cyberqalqon_sender.event_shipper import select_archive_event
from cyberqalqon_sender.reconciliation import (
    ArchiveReconciler,
    ReconciliationSource,
    RetainedIdentityInventory,
    state_report,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--identity-export", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--batch-records", type=int, default=100_000)
    arguments = parser.parse_args()
    archive = arguments.archive.resolve()
    identity_export = arguments.identity_export.resolve()
    state_path = arguments.state.resolve()
    report_path = arguments.report.resolve()
    if state_path.exists() or report_path.exists():
        raise SystemExit("refusing to overwrite an existing reconciliation artifact")
    source = ReconciliationSource.capture(archive)
    inventory = RetainedIdentityInventory.from_payload_free_export(identity_export)
    reconciler = ArchiveReconciler(
        source,
        inventory,
        state_path,
        selector=select_archive_event,
    )
    while True:
        state = reconciler.run_batch(limit=arguments.batch_records)
        print(f"status={state.status} records={state.counts.records} offset={state.offset}")
        if state.status == "COMPLETE":
            break
    payload = state_report(source, state, inventory)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_name(f".{report_path.name}.tmp-{os.getpid()}")
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, report_path)
    print(report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
