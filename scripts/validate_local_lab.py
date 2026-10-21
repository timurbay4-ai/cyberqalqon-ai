"""Validate the authorized local CyberQalqon lab and emit a JSON report.

Active probes are opt-in and are hard-limited to a loopback target.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import urlopen


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = REPOSITORY_ROOT / "backend" / "data" / "cyberqalqon-local-lab.db"
DEFAULT_OUTPUT = REPOSITORY_ROOT / "artifacts" / "lab-validation" / "latest.json"
ACTIVE_RULE_IDS = ("100101", "100111", "100120")
CORRELATION_RULE_IDS = ("100101", "100111")
CORRELATION_COOLDOWN_SECONDS = 61
MINIMUM_RUNTIME_SCHEMA = 15
LATEST_APPLICATION_SCHEMA = 18
# M14 schema is prepared and rehearsed, but the live approval gate remains 17.
RELEASE_TARGET_SCHEMA = 17


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def is_loopback_target(value: str) -> bool:
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def run(arguments: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
    )


def wsl(distro: str, command: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return run(["wsl.exe", "-d", distro, "-u", "root", "--", "bash", "-lc", command], timeout=timeout)


def http_status(url: str, *, expected: int = 200) -> tuple[bool, str]:
    started = time.perf_counter()
    try:
        with urlopen(url, timeout=5) as response:  # noqa: S310 - URL is fixed to loopback below.
            status = response.status
    except HTTPError as error:
        status = error.code
    except (URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", str(error))
        return False, f"unreachable: {reason}"
    elapsed_ms = (time.perf_counter() - started) * 1000
    return status == expected, f"HTTP {status} in {elapsed_ms:.1f} ms"


def query_alerts_since(database: Path, started_at: datetime) -> dict[str, dict[str, Any]]:
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        rows = connection.execute(
            """
            SELECT alert_id, rule_id, rule_level, agent_name, occurred_at, ingested_at
            FROM alerts
            WHERE rule_id IN (?, ?, ?) AND ingested_at >= ?
            ORDER BY ingested_at ASC
            """,
            (*ACTIVE_RULE_IDS, started_at.isoformat()),
        ).fetchall()
    return {
        row[1]: {
            "alert_id": row[0],
            "rule_level": row[2],
            "agent_name": row[3],
            "occurred_at": row[4],
            "ingested_at": row[5],
        }
        for row in rows
    }


def active_correlation_cooldown(
    database: Path,
    *,
    now: datetime | None = None,
) -> float:
    """Return the remaining Wazuh ignore window for repeatable active probes."""

    if not database.exists():
        return 0.0
    reference = now or utc_now()
    try:
        with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
            row = connection.execute(
                "SELECT MAX(ingested_at) FROM alerts WHERE rule_id IN (?, ?)",
                CORRELATION_RULE_IDS,
            ).fetchone()
    except sqlite3.Error:
        return 0.0
    if not row or not row[0]:
        return 0.0
    try:
        last_ingested = datetime.fromisoformat(str(row[0]))
    except ValueError:
        return 0.0
    if last_ingested.tzinfo is None or last_ingested.utcoffset() is None:
        return 0.0
    elapsed = (reference - last_ingested.astimezone(timezone.utc)).total_seconds()
    return max(0.0, CORRELATION_COOLDOWN_SECONDS - elapsed)


def add_check(report: dict[str, Any], name: str, passed: bool, detail: str) -> None:
    report["checks"].append({"name": name, "status": "PASS" if passed else "FAIL", "detail": detail})


def add_status(report: dict[str, Any], name: str, status: str, detail: str) -> None:
    if status not in {
        "PASS", "WARNING", "PARTIAL", "FAIL", "BLOCKED", "UNKNOWN",
        "DEFERRED_BY_USER",
    }:
        raise ValueError("unsupported validator status")
    report["checks"].append({"name": name, "status": status, "detail": detail})


def configured_flag(name: str, *, default: bool) -> bool:
    env_path = REPOSITORY_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == name:
                normalized = value.strip().casefold()
                if normalized in {"1", "true", "yes", "on"}:
                    return True
                if normalized in {"0", "false", "no", "off"}:
                    return False
    return default


def assess_database(
    *, integrity: str, foreign_key_errors: int, schema_version: int
) -> tuple[bool, dict[str, Any]]:
    """Classify integrity separately from runtime and release-target compatibility."""

    if schema_version < MINIMUM_RUNTIME_SCHEMA:
        compatibility = "UNSUPPORTED_OLDER"
    elif schema_version > LATEST_APPLICATION_SCHEMA:
        compatibility = "UNSUPPORTED_FUTURE"
    elif schema_version < RELEASE_TARGET_SCHEMA:
        compatibility = "SUPPORTED_OLDER"
    elif schema_version > RELEASE_TARGET_SCHEMA:
        compatibility = "PREPARED_NEWER_NOT_RELEASE_TARGET"
    else:
        compatibility = "TARGET"
    integrity_ok = integrity == "ok" and foreign_key_errors == 0
    target_ready = schema_version == RELEASE_TARGET_SCHEMA
    return integrity_ok and target_ready, {
        "integrity": "PASS" if integrity_ok else "FAIL",
        "runtime_compatibility": compatibility,
        "target_ready": target_ready,
        "minimum_runtime_schema": MINIMUM_RUNTIME_SCHEMA,
        "latest_application_schema": LATEST_APPLICATION_SCHEMA,
        "release_target_schema": RELEASE_TARGET_SCHEMA,
    }


def passive_checks(args: argparse.Namespace, report: dict[str, Any]) -> None:
    for name, url in (
        ("backend_health", "http://127.0.0.1:8000/health"),
        ("frontend_health_proxy", "http://127.0.0.1:5173/health"),
    ):
        passed, detail = http_status(url)
        add_check(report, name, passed, detail)

    kali_services = wsl(
        args.kali_distro,
        "systemctl is-active nginx wazuh-agent cyberqalqon-wazuh-agent-relay.service "
        "cyberqalqon-nftables-monitor.service",
    )
    active_lines = [line.strip() for line in kali_services.stdout.splitlines() if line.strip()]
    add_check(
        report,
        "kali_services",
        kali_services.returncode == 0 and active_lines == ["active"] * 4,
        ", ".join(active_lines) or kali_services.stderr.strip() or "no output",
    )

    manager_services = wsl(
        args.manager_distro,
        "systemctl is-active wazuh-manager cyberqalqon-sender cyberqalqon-backend-relay.service "
        "cyberqalqon-wazuh-manager-relay@1514.service cyberqalqon-event-shipper.service",
    )
    active_lines = [line.strip() for line in manager_services.stdout.splitlines() if line.strip()]
    add_check(
        report,
        "manager_services",
        manager_services.returncode == 0 and active_lines == ["active"] * 5,
        ", ".join(active_lines) or manager_services.stderr.strip() or "no output",
    )

    relay_health = wsl(
        args.manager_distro,
        "python3 -c 'import urllib.request; "
        "r=urllib.request.urlopen(\"http://127.0.0.1:18000/health\",timeout=3); "
        "print(r.status)'",
    )
    relay_status = relay_health.stdout.strip()
    add_check(
        report,
        "backend_relay_path",
        relay_health.returncode == 0 and relay_status == "200",
        f"HTTP {relay_status}"
        if relay_status
        else "WSL relay HTTP health check timed out or failed",
    )

    agents = wsl(args.manager_distro, "/var/ossec/bin/agent_control -lc")
    agent_ok = "cyberqalqon-test-web" in agents.stdout and "Active" in agents.stdout
    add_check(report, "wazuh_agent_enrollment", agent_ok, "cyberqalqon-test-web active" if agent_ok else "agent not active")

    sender = wsl(
        args.manager_distro,
        "set -a; . /etc/cyberqalqon/sender.env; set +a; "
        "/opt/cyberqalqon-sender/.venv/bin/cyberqalqon-sender status",
    )
    sender_summary = " ".join(sender.stdout.splitlines())
    sender_ok = sender.returncode == 0 and "queue=0" in sender_summary and "dead_letters=0" in sender_summary
    add_check(report, "sender_queue", sender_ok, sender_summary or sender.stderr.strip() or "no output")

    shipper = wsl(
        args.manager_distro,
        "python3 -c 'import json,os,time; "
        "p=\"/var/lib/cyberqalqon-sender/event-shipper-state.json\"; "
        "a=\"/var/ossec/logs/archives/archives.json\"; d=json.load(open(p)); s=os.stat(a); "
        "print(json.dumps({\"offset\":int(d[\"offset\"]),\"archive_size\":s.st_size,"
        "\"archive_device\":s.st_dev,\"archive_inode\":s.st_ino,"
        "\"cursor_device\":int(d[\"device\"]),\"cursor_inode\":int(d[\"inode\"]),"
        "\"updated_age\":max(0,time.time()-float(d[\"updated_at\"])),"
        "\"malformed_json\":int(d.get(\"malformed_json\",0)),"
        "\"delivery_rejected\":int(d.get(\"delivery_rejected\",0))}))'",
    )
    try:
        shipper_state = json.loads(shipper.stdout)
        shipper_lag = max(0, int(shipper_state["archive_size"]) - int(shipper_state["offset"]))
        shipper_age = max(0.0, float(shipper_state["updated_age"]))
        identity_matches = (
            int(shipper_state["archive_device"]) == int(shipper_state["cursor_device"])
            and int(shipper_state["archive_inode"]) == int(shipper_state["cursor_inode"])
        )
        shipper_ok = (
            shipper.returncode == 0
            and identity_matches
            and shipper_age <= 30
            and int(shipper_state["delivery_rejected"]) == 0
        )
        shipper_detail = (
            f"cursor={shipper_state['offset']}; archive={shipper_state['archive_size']}; "
            f"lag={shipper_lag}; updated_age={shipper_age:.1f}s; "
            f"identity_matches={identity_matches}; "
            f"malformed={shipper_state['malformed_json']}; "
            f"delivery_rejected={shipper_state['delivery_rejected']}"
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        shipper_ok = False
        shipper_detail = shipper.stderr.strip() or "durable shipper state unavailable"
    shipper_status = (
        "FAIL" if not shipper_ok else "WARNING" if shipper_lag > 1_048_576 else "PASS"
    )
    add_status(report, "event_shipper_cursor", shipper_status, shipper_detail)

    archive_audit = wsl(
        args.manager_distro,
        "python3 -c 'import json; from pathlib import Path; "
        "p=Path(\"/var/lib/cyberqalqon-sender/m16\"); "
        "a=json.load(open(p/\"malformed-active-acknowledged.json\")); "
        "r=json.load(open(p/\"malformed-rotated-13.json\")); "
        "print(json.dumps({\"active\":a[\"counts\"][\"total\"],"
        "\"rotated\":r[\"counts\"][\"total\"],"
        "\"raw\":bool(a[\"contains_raw_payload\"] or r[\"contains_raw_payload\"])}))'",
    )
    try:
        archive_audit_state = json.loads(archive_audit.stdout)
        malformed_total = int(archive_audit_state["active"]) + int(
            archive_audit_state["rotated"]
        )
        archive_audit_ok = (
            archive_audit.returncode == 0
            and malformed_total == 162
            and archive_audit_state["raw"] is False
        )
        archive_audit_detail = (
            f"active={archive_audit_state['active']}; "
            f"rotated={archive_audit_state['rotated']}; total={malformed_total}; raw_payload=false"
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        archive_audit_ok = False
        archive_audit_detail = archive_audit.stderr.strip() or "malformed audit unavailable"
    add_check(report, "archive_malformed_audit", archive_audit_ok, archive_audit_detail)

    if args.database.exists():
        try:
            with sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True) as connection:
                integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
                foreign_key_errors = len(connection.execute("PRAGMA foreign_key_check").fetchall())
                alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                event_count = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
                schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
                retention_state = connection.execute(
                    "SELECT last_retention_at,last_deleted_count,retained_records "
                    "FROM security_event_store_state WHERE singleton=1"
                ).fetchone()
                protected_records = connection.execute(
                    """
                    SELECT COUNT(*) FROM security_events e JOIN (
                        SELECT event_id AS protected_event_id FROM case_events
                        UNION SELECT evidence_id FROM incident_evidence_pins
                              WHERE evidence_type='EVENT'
                        UNION SELECT reference_id FROM case_evidence_refs
                              WHERE reference_type='EVENT'
                        UNION SELECT e2.event_id FROM security_events e2
                              JOIN alerts a ON a.alert_id=
                                  COALESCE(e2.related_alert_id,e2.source_event_id)
                    ) p ON p.protected_event_id=e.event_id
                    """
                ).fetchone()[0]
            database_ok, database_status = assess_database(
                integrity=str(integrity),
                foreign_key_errors=foreign_key_errors,
                schema_version=int(schema_version),
            )
            report["database"] = {
                "quick_check": str(integrity),
                "foreign_key_errors": foreign_key_errors,
                "schema_version": schema_version,
                "alerts": alert_count,
                "events": event_count,
                **database_status,
            }
            add_check(
                report,
                "database_integrity",
                database_ok,
                f"quick_check={integrity}; foreign_keys={foreign_key_errors}; "
                f"schema={schema_version}; compatibility={database_status['runtime_compatibility']}; "
                f"target={RELEASE_TARGET_SCHEMA}; alerts={alert_count}; events={event_count}",
            )
            retention_max = 100_000
            retained = int(retention_state[2] if retention_state else event_count)
            retention_status = "WARNING" if retained >= retention_max else "PASS"
            add_status(
                report,
                "retention_capacity",
                retention_status,
                f"retained={retained}; max={retention_max}; protected={protected_records}; "
                f"last_deleted={int(retention_state[1] or 0) if retention_state else 0}; "
                f"last_run={retention_state[0] if retention_state else None}",
            )
            ai_enabled = configured_flag("AI_ENABLED", default=False)
            schema18_allowed = configured_flag("ALLOW_M14_SCHEMA_MIGRATION", default=False)
            policy_ok = (
                schema_version == RELEASE_TARGET_SCHEMA
                and not ai_enabled
                and not schema18_allowed
            )
            add_check(
                report,
                "release_safety_gates",
                policy_ok,
                f"schema={schema_version}; schema18_allowed={schema18_allowed}; "
                f"ai_enabled={ai_enabled}; DET-001..DET-009=DISABLED_BY_POLICY/SHADOW_ONLY",
            )
        except sqlite3.Error as error:
            add_check(report, "database_integrity", False, f"SQLite error: {error}")
    else:
        add_check(report, "database_integrity", False, f"missing database: {args.database}")

    portproxy = run(["netsh.exe", "interface", "portproxy", "show", "v4tov4"])
    compact_proxy = " ".join(portproxy.stdout.split())
    mapping_present = (
        portproxy.returncode == 0
        and "16000" in compact_proxy
        and "127.0.0.1" in compact_proxy
        and "8000" in compact_proxy
    )
    mapping = re.search(
        r"(?m)^\s*(\d+\.\d+\.\d+\.\d+)\s+16000\s+127\.0\.0\.1\s+8000\s*$",
        portproxy.stdout,
    )
    listener_reachable = False
    listener_error = "mapping unavailable"
    if mapping_present and mapping:
        try:
            with socket.create_connection((mapping.group(1), 16000), timeout=2):
                listener_reachable = True
                listener_error = ""
        except OSError as error:
            listener_error = type(error).__name__
    proxy_ok = mapping_present and listener_reachable
    add_check(
        report,
        "wsl_portproxy_16000",
        proxy_ok,
        "TCP 16000 mapping is present, scoped to the WSL gateway, and accepting connections"
        if proxy_ok
        else (
            f"mapping_present={mapping_present}; listener_reachable={listener_reachable}; "
            f"error={listener_error}"
        ),
    )
    add_status(
        report,
        "browser_uat",
        "DEFERRED_BY_USER",
        "DEFERRED_BY_USER: Chrome/Edge UAT was explicitly excluded from M16 execution",
    )


def active_checks(args: argparse.Namespace, report: dict[str, Any]) -> None:
    cooldown = active_correlation_cooldown(args.database)
    report["active_cooldown_seconds"] = round(cooldown, 3)
    cooldown_deadline = time.monotonic() + cooldown
    while time.monotonic() < cooldown_deadline:
        time.sleep(min(2.0, cooldown_deadline - time.monotonic()))
    started_at = utc_now()
    probes = (
        # Run the single-event rule before the two correlation bursts. Wazuh
        # selects one terminal child rule per event, so a still-open web
        # enumeration correlation can otherwise mask rule 100120.
        (
            "sensitive_path_loopback",
            "test \"$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1/.env)\" = 404",
        ),
        (
            "nmap_loopback",
            "timeout 20s nmap -sT -Pn -p22,23,25,53,80,110,443,445 127.0.0.1 >/dev/null",
        ),
        (
            "gobuster_loopback",
            "set -e; trap 'rm -f /tmp/cyberqalqon-validator-gobuster.txt' EXIT; "
            "seq 1 12 | sed 's#^#cq-validator-gobuster-#' "
            "> /tmp/cyberqalqon-validator-gobuster.txt; "
            "timeout 20s gobuster dir --url http://127.0.0.1/ "
            "--wordlist /tmp/cyberqalqon-validator-gobuster.txt --threads 1 --timeout 2s "
            "--no-error --no-progress >/dev/null",
        ),
    )
    for name, command in probes:
        result = wsl(args.kali_distro, command, timeout=25)
        add_check(report, name, result.returncode == 0, "bounded loopback probe completed" if result.returncode == 0 else result.stderr.strip())

    deadline = time.monotonic() + args.wait_seconds
    evidence: dict[str, dict[str, Any]] = {}
    while time.monotonic() < deadline:
        evidence = query_alerts_since(args.database, started_at)
        if all(rule_id in evidence for rule_id in ACTIVE_RULE_IDS):
            break
        time.sleep(2)
    report["active_evidence"] = evidence
    for rule_id in ACTIVE_RULE_IDS:
        row = evidence.get(rule_id)
        valid = bool(row and row["agent_name"] == "cyberqalqon-test-web")
        add_check(
            report,
            f"cyberqalqon_rule_{rule_id}",
            valid,
            f"alert_id={row['alert_id']}; agent={row['agent_name']}" if row else "new alert not observed before timeout",
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="127.0.0.1", help="Must resolve literally to a loopback address")
    parser.add_argument("--active", action="store_true", help="Run the bounded local Nmap/Gobuster/HTTP probes")
    parser.add_argument("--wait-seconds", type=int, default=30)
    parser.add_argument("--kali-distro", default="kali-linux")
    parser.add_argument("--manager-distro", default="Ubuntu-24.04")
    parser.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if sys.platform != "win32":
        raise SystemExit("This validator must run from the Windows lab host")
    if not is_loopback_target(args.target):
        raise SystemExit("Refusing non-loopback target; only localhost lab validation is permitted")
    if not 5 <= args.wait_seconds <= 120:
        raise SystemExit("--wait-seconds must be between 5 and 120")

    report: dict[str, Any] = {
        "generated_at": utc_now().isoformat(),
        "target": args.target,
        "mode": "active" if args.active else "passive",
        "checks": [],
    }
    passive_checks(args, report)
    if args.active:
        active_checks(args, report)
    statuses = {check["status"] for check in report["checks"]}
    report["summary"] = {
        status: sum(check["status"] == status for check in report["checks"])
        for status in (
            "PASS", "WARNING", "PARTIAL", "FAIL", "BLOCKED", "UNKNOWN",
            "DEFERRED_BY_USER",
        )
    }
    report["overall"] = (
        "FAIL"
        if "FAIL" in statuses
        else "BLOCKED"
        if "BLOCKED" in statuses
        else "PARTIAL"
        if "PARTIAL" in statuses or "UNKNOWN" in statuses
        else "WARNING"
        if "WARNING" in statuses
        else "PASS"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{report['overall']}: {len(report['checks'])} checks; report={args.output}")
    return {"PASS": 0, "WARNING": 0, "PARTIAL": 0, "FAIL": 1, "BLOCKED": 2}[
        report["overall"]
    ]


if __name__ == "__main__":
    raise SystemExit(main())
