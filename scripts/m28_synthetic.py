"""Shared deterministic SYNTHETIC fixtures for M28 tests and disposable benchmarks."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "backend/tests/fixtures/m28_sources.json"


def envelope(index: int, at: datetime) -> dict:
    return {
        "timestamp": at.isoformat(), "id": f"SYNTHETIC-M28-{index:012d}",
        "agent": {"id": "928", "name": "SYNTH-M28-ENDPOINT"},
        "manager": {"name": "SYNTH-M28-MANAGER"},
        "rule": {"id": "992800", "level": 7, "description": "SYNTHETIC M28 telemetry", "groups": ["synthetic"]},
    }


def windows(index: int, at: datetime, code: str = "4625", *, sysmon: bool = False) -> dict:
    raw = envelope(index, at)
    raw["decoder"] = {"name": "windows_eventchannel"}
    provider = "Microsoft-Windows-Sysmon" if sysmon else "Microsoft-Windows-Security-Auditing"
    channel = "Microsoft-Windows-Sysmon/Operational" if sysmon else "Security"
    if code == "4104" and not sysmon:
        provider, channel = "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational"
    raw["data"] = {"win": {
        "system": {"eventID": code, "providerName": provider, "channel": channel,
                   "computer": "SYNTH-M28-WINDOWS", "systemTime": at.isoformat(),
                   "eventRecordID": str(index), "version": "1"},
        "eventdata": {"image": r"C:\Synthetic\example.exe", "processId": "928",
                      "commandLine": "example.exe --synthetic", "parentImage": r"C:\Synthetic\parent.exe",
                      "parentProcessId": "927", "processGuid": "{00000000-0000-0000-0000-000000000928}",
                      "parentProcessGuid": "{00000000-0000-0000-0000-000000000927}",
                      "sourceIp": "192.0.2.28", "destinationIp": "198.51.100.28",
                      "sourcePort": "50280", "destinationPort": "443",
                      "user": "SYNTHETIC\\analyst", "queryName": "synthetic.example.invalid",
                      "hashes": "SHA256=" + "a" * 64,
                      "targetObject": r"HKCU\Synthetic\Example", "eventType": "SetValue"},
    }}
    return raw


def cases(at: datetime | None = None) -> list[tuple[str, dict, dict]]:
    at = at or datetime(2026, 10, 22, 8, tzinfo=timezone.utc)
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    output = []
    index = 0
    for code, action, outcome in golden["windows"]:
        output.append((f"windows-{code}", windows(index, at, code),
                       {"event_code": code, "event_action": action, "outcome": outcome}))
        index += 1
    for code, action in golden["sysmon"]:
        output.append((f"sysmon-{code}", windows(index, at, code, sysmon=True),
                       {"event_code": code, "event_action": action, "outcome": "observed"}))
        index += 1
    for item in golden["linux"]:
        raw = envelope(index, at)
        raw.update(decoder={"name": item["program"]}, predecoder={"program_name": item["program"]},
                   location="/var/log/secure", full_log=item["message"])
        output.append((item["name"], raw, item["expected"]))
        index += 1
    for item in golden["syslog"]:
        raw = envelope(index, at)
        raw.update(decoder={"name": "syslog"}, full_log=item["message"].replace("2026-10-22T08:00:00Z", at.isoformat()))
        output.append((item["name"], raw, item["expected"]))
        index += 1
    raw = envelope(index, at)
    raw["data"] = {"journald": {"__REALTIME_TIMESTAMP": str(int(at.timestamp() * 1_000_000)),
        "_HOSTNAME": "SYNTH-M28-JOURNAL", "_COMM": "synthetic-app", "_PID": "928",
        "PRIORITY": "6", "SYSLOG_FACILITY": "3", "MESSAGE": "SYNTHETIC journal message",
        "_BOOT_ID": "a" * 32, "__CURSOR": "s=synthetic-record"}}
    output.append(("journald", raw, {"hostname": "SYNTH-M28-JOURNAL", "process_id": "928"}))
    return output
