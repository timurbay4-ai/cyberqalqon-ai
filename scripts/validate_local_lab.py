"""Validate the authorized local CyberQalqon lab and emit a JSON report.

Active probes are opt-in and are hard-limited to a loopback target.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
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
    except URLError as error:
        return False, f"unreachable: {error.reason}"
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
        f"HTTP {relay_status}" if relay_status else relay_health.stderr.strip() or "relay unavailable",
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
        "\"updated_age\":max(0,time.time()-float(d[\"updated_at\"])),"
        "\"malformed_json\":int(d.get(\"malformed_json\",0)),"
        "\"delivery_rejected\":int(d.get(\"delivery_rejected\",0))}))'",
    )
    try:
        shipper_state = json.loads(shipper.stdout)
        shipper_lag = max(0, int(shipper_state["archive_size"]) - int(shipper_state["offset"]))
        shipper_age = max(0.0, float(shipper_state["updated_age"]))
        shipper_ok = shipper.returncode == 0 and shipper_lag <= 1_048_576 and shipper_age <= 30
        shipper_detail = (
            f"cursor={shipper_state['offset']}; archive={shipper_state['archive_size']}; "
            f"lag={shipper_lag}; updated_age={shipper_age:.1f}s; "
            f"malformed={shipper_state['malformed_json']}; "
            f"delivery_rejected={shipper_state['delivery_rejected']}"
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        shipper_ok = False
        shipper_detail = shipper.stderr.strip() or "durable shipper state unavailable"
    add_check(report, "event_shipper_cursor", shipper_ok, shipper_detail)

    if args.database.exists():
        try:
            with sqlite3.connect(f"file:{args.database.as_posix()}?mode=ro", uri=True) as connection:
                integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
                alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                event_count = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
                schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            add_check(
                report,
                "database_integrity",
                integrity == "ok" and schema_version == 14,
                f"quick_check={integrity}; schema={schema_version}; alerts={alert_count}; events={event_count}",
            )
        except sqlite3.Error as error:
            add_check(report, "database_integrity", False, f"SQLite error: {error}")
    else:
        add_check(report, "database_integrity", False, f"missing database: {args.database}")


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
    report["overall"] = "PASS" if all(check["status"] == "PASS" for check in report["checks"]) else "FAIL"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{report['overall']}: {len(report['checks'])} checks; report={args.output}")
    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
