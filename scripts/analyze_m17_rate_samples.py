"""Aggregate bounded M17 point samples without inventing record counts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("samples", nargs="*", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "runtime" / "m17-rate-summary.json",
    )
    args = parser.parse_args()
    paths = args.samples or sorted(
        (ROOT / "artifacts" / "runtime").glob("m17-live-rate-sample*.json")
    )
    if len(paths) < 2:
        parser.error("at least two bounded samples are required")
    samples = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    samples.sort(key=lambda item: float(item["start"]["shipper"]["captured_at_epoch"]))
    first = samples[0]["start"]
    last = samples[-1]["end"]
    first_shipper = first["shipper"]
    last_shipper = last["shipper"]
    identities = {
        (int(item[side]["shipper"]["archive_device"]), int(item[side]["shipper"]["archive_inode"]))
        for item in samples
        for side in ("start", "end")
    }
    if len(identities) != 1:
        parser.error("samples span multiple active archive generations")
    duration = float(last_shipper["captured_at_epoch"]) - float(
        first_shipper["captured_at_epoch"]
    )
    if duration <= 0:
        parser.error("sample time window is invalid")
    archive_delta = int(last_shipper["archive_size_bytes"]) - int(
        first_shipper["archive_size_bytes"]
    )
    cursor_delta = int(last_shipper["cursor_bytes"]) - int(first_shipper["cursor_bytes"])
    lag_delta = archive_delta - cursor_delta
    net_rate = lag_delta / duration
    trend = "GROWING" if net_rate > 0 else "DRAINING" if net_rate < 0 else "STABLE"
    ending_lag = int(last_shipper["archive_size_bytes"]) - int(last_shipper["cursor_bytes"])
    drain_seconds = ending_lag / -net_rate if net_rate < 0 else None
    report = {
        "version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "sample_count": len(samples),
        "source_files": [str(path) for path in paths],
        "archive_device": next(iter(identities))[0],
        "archive_inode": next(iter(identities))[1],
        "window_seconds": round(duration, 3),
        "deltas": {
            "archive_size_bytes": archive_delta,
            "cursor_bytes": cursor_delta,
            "archive_lag_bytes": lag_delta,
            "successful_acknowledgements_v2_mixed": (
                int(last_shipper["accepted"]) - int(first_shipper["accepted"])
            ),
            "filtered_records": int(last_shipper["filtered"]) - int(first_shipper["filtered"]),
            "malformed_records": int(last_shipper["malformed"]) - int(first_shipper["malformed"]),
            "retry_attempts": int(last_shipper["retry_attempts"])
            - int(first_shipper["retry_attempts"]),
            "retention_insert_proxy": int(last["database"]["retention_deleted_by_limit"])
            - int(first["database"]["retention_deleted_by_limit"]),
        },
        "rates_per_second": {
            "archive_growth_bytes": round(archive_delta / duration, 3),
            "cursor_progress_bytes": round(cursor_delta / duration, 3),
            "net_archive_lag_bytes": round(net_rate, 3),
            "successful_acknowledgements_v2_mixed": round(
                (int(last_shipper["accepted"]) - int(first_shipper["accepted"])) / duration,
                6,
            ),
            "filtered_records": round(
                (int(last_shipper["filtered"]) - int(first_shipper["filtered"])) / duration,
                6,
            ),
            "retention_insert_proxy": round(
                (
                    int(last["database"]["retention_deleted_by_limit"])
                    - int(first["database"]["retention_deleted_by_limit"])
                )
                / duration,
                6,
            ),
        },
        "ending_archive_lag_bytes": ending_lag,
        "backlog_trend": trend,
        "estimated_drain_seconds": round(drain_seconds, 3) if drain_seconds is not None else None,
        "accounting": {
            "state_version": int(last_shipper["state_version"]),
            "historic_unique_insertions": None,
            "historic_duplicate_acknowledgements": None,
            "accepted_semantics": "V2_MIXED_INSERT_AND_DUPLICATE_ACKNOWLEDGEMENT",
            "retention_insert_proxy_is_not_a_durable_v3_counter": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, args.output)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
