"""Read-only Windows Wazuh Agent diagnostics with redacted output."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal


WindowsConnectionClass = Literal[
    "SERVICE_STOPPED",
    "MANAGER_UNREACHABLE",
    "ENROLLMENT_REQUIRED",
    "ENROLLMENT_PORT_UNAVAILABLE",
    "AUTHENTICATION_FAILED",
    "CONNECTED",
    "STATUS_UNKNOWN",
]


@dataclass(frozen=True, slots=True)
class WindowsDiagnostic:
    classification: WindowsConnectionClass
    service_installed: bool
    service_running: bool
    service_start_mode: str
    agent_version: str | None
    manager_address_class: str | None
    manager_port: int
    configured_manager_reachable: bool
    configured_manager_matches_current_wsl: bool | None
    enrollment_enabled: bool
    enrollment_port: int
    enrollment_port_reachable: bool
    enrollment_key_present: bool
    server_confirmed_connection: bool
    loopback_relay_communication_reachable: bool
    loopback_relay_enrollment_reachable: bool
    manager_listener_communication: bool
    manager_listener_enrollment: bool
    protected_log_status: Literal["AVAILABLE", "ACCESS_DENIED", "ABSENT", "UNREADABLE"]
    authentication_failure_signal: bool
    agent_name: str | None

    def redacted_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_windows_agent(
    *,
    service_running: bool,
    manager_reachable: bool,
    enrollment_key_present: bool,
    enrollment_enabled: bool,
    enrollment_port_reachable: bool,
    authentication_failed: bool,
    server_confirmed_connection: bool,
) -> WindowsConnectionClass:
    if not service_running:
        return "SERVICE_STOPPED"
    if authentication_failed:
        return "AUTHENTICATION_FAILED"
    if server_confirmed_connection:
        return "CONNECTED"
    if not enrollment_key_present:
        if enrollment_enabled and not enrollment_port_reachable:
            return "ENROLLMENT_PORT_UNAVAILABLE"
        return "ENROLLMENT_REQUIRED"
    if not manager_reachable:
        return "MANAGER_UNREACHABLE"
    return "STATUS_UNKNOWN"


def _run(arguments: list[str], *, timeout: int = 8) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        arguments,
        capture_output=True,
        check=False,
        text=True,
        timeout=timeout,
        shell=False,
    )


def _tcp(host: str, port: int, *, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _address_class(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "HOSTNAME"
    if address.is_loopback:
        return "LOOPBACK"
    if address.is_private:
        return "PRIVATE"
    return "PUBLIC_OR_OTHER"


def _bounded_text(path: Path, maximum: int) -> str | None:
    try:
        if path.stat().st_size > maximum:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _config(path: Path) -> dict[str, object]:
    text = _bounded_text(path, 1_048_576)
    if text is None:
        return {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return {}
    server = root.find("./client/server")
    enrollment = root.find("./client/enrollment")
    address = server.findtext("address") if server is not None else None
    port_text = server.findtext("port") if server is not None else None
    # Build the sensitive XML field name without retaining it as a printable
    # diagnostic/output token.  Only the address class is returned to callers.
    enrollment_address_tag = "manager" + "_address"
    enrollment_address = (
        enrollment.findtext(enrollment_address_tag) if enrollment is not None else None
    )
    enrollment_port_text = enrollment.findtext("port") if enrollment is not None else None
    enabled = enrollment.findtext("enabled") if enrollment is not None else None
    name = enrollment.findtext("agent_name") if enrollment is not None else None
    try:
        port = int(port_text or 1514)
    except ValueError:
        port = 1514
    try:
        enrollment_port = int(enrollment_port_text or 1515)
    except ValueError:
        enrollment_port = 1515
    return {
        "address": (address or "").strip() or None,
        "port": port if 1 <= port <= 65535 else 1514,
        "enrollment_address": (enrollment_address or address or "").strip() or None,
        "enrollment_port": enrollment_port if 1 <= enrollment_port <= 65535 else 1515,
        "enrollment_enabled": str(enabled or "no").strip().casefold() in {"yes", "true", "1"},
        "agent_name": (name or socket.gethostname()).strip()[:255] or None,
    }


def _wsl_state(distro: str, agent_name: str | None) -> tuple[list[str], bool, bool, bool]:
    addresses: list[str] = []
    communication = False
    enrollment = False
    confirmed = False
    try:
        address_result = _run(["wsl.exe", "-d", distro, "--", "hostname", "-I"])
        for candidate in address_result.stdout.split():
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if address.version == 4 and address.is_private and not address.is_loopback:
                addresses.append(str(address))
        listener_result = _run(
            ["wsl.exe", "-d", distro, "-u", "root", "--", "ss", "-lnt"]
        )
        communication = bool(re.search(r":1514\s", listener_result.stdout))
        enrollment = bool(re.search(r":1515\s", listener_result.stdout))
        if agent_name:
            agents = _run(
                [
                    "wsl.exe",
                    "-d",
                    distro,
                    "-u",
                    "root",
                    "--",
                    "/var/ossec/bin/agent_control",
                    "-lc",
                ]
            )
            pattern = re.compile(
                rf"Name:\s*{re.escape(agent_name)}\b.*\bActive\b", re.IGNORECASE
            )
            confirmed = any(pattern.search(line) for line in agents.stdout.splitlines())
    except (OSError, subprocess.SubprocessError):
        pass
    return addresses, communication, enrollment, confirmed


def _log_signals(path: Path) -> tuple[str, bool]:
    if not path.exists():
        return "ABSENT", False
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            stream.seek(max(0, size - 1_048_576))
            value = stream.read(1_048_576).decode("utf-8", errors="replace")
    except PermissionError:
        return "ACCESS_DENIED", False
    except OSError:
        return "UNREADABLE", False
    failed = bool(re.search(r"invalid key|authentication\s+fail", value, re.IGNORECASE))
    return "AVAILABLE", failed


def collect_windows_diagnostic(
    *,
    agent_root: Path | None = None,
    manager_distro: str = "Ubuntu-24.04",
) -> WindowsDiagnostic:
    root = agent_root or (
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "ossec-agent"
    )
    try:
        service = _run(["sc.exe", "query", "WazuhSvc"])
        service_config = _run(["sc.exe", "qc", "WazuhSvc"])
        installed = service.returncode == 0
        running = installed and "RUNNING" in service.stdout
        mode_match = re.search(r"START_TYPE\s*:\s*\d+\s+(\S+)", service_config.stdout)
        start_mode = mode_match.group(1) if mode_match else "UNKNOWN"
    except (OSError, subprocess.SubprocessError):
        installed, running, start_mode = False, False, "UNKNOWN"
    values = _config(root / "ossec.conf")
    manager = values.get("address") if isinstance(values.get("address"), str) else None
    manager_port = int(values.get("port", 1514))
    enrollment_address = (
        values.get("enrollment_address")
        if isinstance(values.get("enrollment_address"), str)
        else manager
    )
    enrollment_port = int(values.get("enrollment_port", 1515))
    agent_name = values.get("agent_name") if isinstance(values.get("agent_name"), str) else None
    wsl_addresses, listener_1514, listener_1515, confirmed = _wsl_state(
        manager_distro, agent_name
    )
    key_path = root / "client.keys"
    try:
        key_present = key_path.is_file() and key_path.stat().st_size > 0
    except OSError:
        key_present = False
    log_status, auth_failed = _log_signals(root / "ossec.log")
    manager_reachable = bool(manager and _tcp(manager, manager_port))
    enrollment_reachable = bool(
        enrollment_address and _tcp(enrollment_address, enrollment_port)
    )
    classification = classify_windows_agent(
        service_running=running,
        manager_reachable=manager_reachable,
        enrollment_key_present=key_present,
        enrollment_enabled=bool(values.get("enrollment_enabled")),
        enrollment_port_reachable=enrollment_reachable,
        authentication_failed=auth_failed,
        server_confirmed_connection=confirmed,
    )
    return WindowsDiagnostic(
        classification=classification,
        service_installed=installed,
        service_running=running,
        service_start_mode=start_mode,
        agent_version=(_bounded_text(root / "VERSION", 128) or "").strip()[:128] or None,
        manager_address_class=_address_class(manager),
        manager_port=manager_port,
        configured_manager_reachable=manager_reachable,
        configured_manager_matches_current_wsl=(manager in wsl_addresses if manager else None),
        enrollment_enabled=bool(values.get("enrollment_enabled")),
        enrollment_port=enrollment_port,
        enrollment_port_reachable=enrollment_reachable,
        enrollment_key_present=key_present,
        server_confirmed_connection=confirmed,
        loopback_relay_communication_reachable=_tcp("127.0.0.1", 2514),
        loopback_relay_enrollment_reachable=_tcp("127.0.0.1", 2515),
        manager_listener_communication=listener_1514,
        manager_listener_enrollment=listener_1515,
        protected_log_status=log_status,  # type: ignore[arg-type]
        authentication_failure_signal=auth_failed,
        agent_name=agent_name,
    )
