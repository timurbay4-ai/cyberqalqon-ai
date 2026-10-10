from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


ROOT = Path(__file__).resolve().parents[2]
RELAY_PATH = ROOT / "scripts" / "windows_wazuh_loopback_relay.py"


def _relay_module():
    spec = importlib.util.spec_from_file_location("windows_wazuh_loopback_relay", RELAY_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_loopback_relay_selects_only_private_wsl_ipv4() -> None:
    relay = _relay_module()
    assert relay.choose_wsl_address("127.0.0.1 172.16.0.2 fe80::1") == "172.16.0.2"
    with pytest.raises(RuntimeError):
        relay.choose_wsl_address("127.0.0.1 203.0.113.5 ::1")


def test_loopback_relay_has_no_shell_or_public_default() -> None:
    source = RELAY_PATH.read_text(encoding="utf-8")
    assert 'default="127.0.0.1"' in source
    assert "shell=True" not in source
    assert "os.system" not in source
    assert "eval(" not in source


def test_windows_eventchannel_configuration_is_narrow_and_well_formed() -> None:
    fragment = (ROOT / "wazuh" / "configs" / "windows-eventchannels.xml").read_text(encoding="utf-8")
    root = ET.fromstring(f"<ossec_config>{fragment}</ossec_config>")
    definitions = {node.findtext("location"): node.findtext("query") for node in root.findall("localfile")}
    assert set(definitions) == {
        "Security",
        "System",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
    }
    for event_id in ("4624", "4625", "4720", "4726", "4732", "1102"):
        assert f"EventID={event_id}" in definitions["Security"]
    assert "EventID=7045" in definitions["System"]
    assert definitions["Microsoft-Windows-PowerShell/Operational"] == "Event/System[EventID=4104]"
    assert "EventID=1116" in definitions["Microsoft-Windows-Windows Defender/Operational"]
    assert "EventID=1117" in definitions["Microsoft-Windows-Windows Defender/Operational"]


def test_windows_synthetic_fixtures_have_expected_provider_and_channel() -> None:
    expected = {
        "security-4625.json": ("Microsoft-Windows-Security-Auditing", "Security", "4625"),
        "security-4720.json": ("Microsoft-Windows-Security-Auditing", "Security", "4720"),
        "system-7045.json": ("Service Control Manager", "System", "7045"),
        "powershell-4104.json": (
            "Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational", "4104"
        ),
        "defender-1116.json": (
            "Microsoft-Windows-Windows Defender",
            "Microsoft-Windows-Windows Defender/Operational",
            "1116",
        ),
    }
    fixture_root = ROOT / "wazuh" / "fixtures" / "windows-eventchannel"
    for name, values in expected.items():
        system = json.loads((fixture_root / name).read_text(encoding="utf-8"))["win"]["system"]
        assert (system["providerName"], system["channel"], system["eventID"]) == values


def test_windows_installer_refuses_non_admin_and_public_manager() -> None:
    source = (ROOT / "scripts" / "Install-WindowsWazuhMonitoring.ps1").read_text(encoding="utf-8")
    assert "WindowsBuiltInRole]::Administrator" in source
    assert "loopback or RFC1918" in source
    assert "Restart-Service -Name WazuhSvc" in source
    assert "agent-auth.exe" in source
