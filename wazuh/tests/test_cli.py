from __future__ import annotations

import json
from pathlib import Path

from cyberqalqon_sender import cli, wazuh_entry
from cyberqalqon_sender.config import SenderConfig
from cyberqalqon_sender.models import DeliveryClassification, ProcessOutcome


def test_status_json_contains_no_api_key(
    sender_env: dict[str, str], monkeypatch, capsys
) -> None:
    for name, value in sender_env.items():
        monkeypatch.setenv(name, value)
    exit_code = cli.main(["status", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    parsed = json.loads(captured.out)
    assert parsed["queue"]["depth"] == 0
    assert sender_env["CYBERQALQON_INGEST_API_KEY"] not in captured.out
    assert sender_env["CYBERQALQON_INGEST_API_KEY"] not in captured.err


def test_wazuh_entry_uses_official_file_key_hook_arguments(
    sender_env: dict[str, str], monkeypatch, tmp_path: Path
) -> None:
    alert_path = tmp_path / "alert.json"
    alert_path.write_text("{}", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_submit(config: SenderConfig, path: str, *, logger) -> int:
        captured["url"] = config.backend_url
        captured["key"] = config.api_key
        captured["path"] = path
        return 0

    monkeypatch.setattr(wazuh_entry, "submit_file", fake_submit)
    monkeypatch.setenv("CYBERQALQON_SENDER_DB", sender_env["CYBERQALQON_SENDER_DB"])
    monkeypatch.setenv("CYBERQALQON_ALLOW_INSECURE_HTTP", "true")
    exit_code = wazuh_entry.main(
        [
            "custom-cyberqalqon",
            str(alert_path),
            "wazuh-argument-key-000000",
            "http://127.0.0.1:8000",
        ]
    )
    assert exit_code == 0
    assert captured == {
        "url": "http://127.0.0.1:8000",
        "key": "wazuh-argument-key-000000",
        "path": str(alert_path),
    }


def test_wazuh_entry_rejects_missing_alert_path(capsys) -> None:
    assert wazuh_entry.main(["custom-cyberqalqon"]) == 2
    output = capsys.readouterr().err
    assert "Wazuh did not provide an alert file path" in output


def test_cli_configuration_error_does_not_echo_secret(monkeypatch, capsys) -> None:
    secret = "secret-value-that-must-not-appear"
    monkeypatch.delenv("CYBERQALQON_URL", raising=False)
    monkeypatch.setenv("CYBERQALQON_INGEST_API_KEY", secret)
    exit_code = cli.main(["status"])
    output = capsys.readouterr()
    assert exit_code == 2
    assert secret not in output.out
    assert secret not in output.err


def test_dead_lettered_transient_returns_nonzero() -> None:
    outcome = ProcessOutcome(
        queue_id=1,
        alert_id="one",
        classification=DeliveryClassification.TRANSIENT_FAILURE,
        attempt_count=1,
        dead_letter_id=7,
    )
    assert cli._outcome_exit(outcome) == 4
