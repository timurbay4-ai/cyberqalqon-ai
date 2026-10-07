from __future__ import annotations

from pathlib import Path

import pytest

from cyberqalqon_sender.config import ConfigurationError, SenderConfig


def test_valid_config_normalizes_url_and_builds_ingest_url(sender_env: dict[str, str]) -> None:
    sender_env["CYBERQALQON_URL"] = "https://SOC.EXAMPLE:8443/"
    sender_env.pop("CYBERQALQON_ALLOW_INSECURE_HTTP")
    config = SenderConfig.from_env(sender_env)

    assert config.backend_url == "https://soc.example:8443"
    assert config.ingest_url == "https://soc.example:8443/api/v1/alerts/ingest"
    assert config.max_attempts == 8
    assert config.backoff_jitter_ratio == 0.20


@pytest.mark.parametrize("missing", ["CYBERQALQON_URL", "CYBERQALQON_INGEST_API_KEY"])
def test_required_configuration_is_enforced(
    sender_env: dict[str, str], missing: str
) -> None:
    sender_env.pop(missing)
    with pytest.raises(ConfigurationError, match=missing):
        SenderConfig.from_env(sender_env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CYBERQALQON_CONNECT_TIMEOUT_SECONDS", "0"),
        ("CYBERQALQON_REQUEST_TIMEOUT_SECONDS", "-1"),
        ("CYBERQALQON_MAX_ATTEMPTS", "0"),
        ("CYBERQALQON_QUEUE_MAX_ITEMS", "-5"),
        ("CYBERQALQON_QUEUE_MAX_BYTES", "0"),
        ("CYBERQALQON_DEAD_LETTER_MAX_ITEMS", "0"),
        ("CYBERQALQON_BACKOFF_JITTER_RATIO", "0.75"),
    ],
)
def test_invalid_numeric_configuration_is_rejected(
    sender_env: dict[str, str], name: str, value: str
) -> None:
    sender_env[name] = value
    with pytest.raises(ConfigurationError, match=name):
        SenderConfig.from_env(sender_env)


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "ftp://soc.example",
        "https://user:password@soc.example",
        "https://soc.example/api/v1/alerts/ingest",
        "https://soc.example?debug=1",
        "https://soc.example/#fragment",
    ],
)
def test_malformed_or_ambiguous_url_is_rejected(
    sender_env: dict[str, str], url: str
) -> None:
    sender_env["CYBERQALQON_URL"] = url
    sender_env.pop("CYBERQALQON_ALLOW_INSECURE_HTTP", None)
    with pytest.raises(ConfigurationError, match="CYBERQALQON_URL"):
        SenderConfig.from_env(sender_env)


def test_plain_http_requires_explicit_loopback_exception(sender_env: dict[str, str]) -> None:
    sender_env.pop("CYBERQALQON_ALLOW_INSECURE_HTTP")
    with pytest.raises(ConfigurationError, match="plain HTTP"):
        SenderConfig.from_env(sender_env)

    sender_env["CYBERQALQON_ALLOW_INSECURE_HTTP"] = "true"
    sender_env["CYBERQALQON_URL"] = "http://10.0.0.8:8000"
    with pytest.raises(ConfigurationError, match="plain HTTP"):
        SenderConfig.from_env(sender_env)


def test_secret_is_not_present_in_repr(sender_env: dict[str, str]) -> None:
    secret = sender_env["CYBERQALQON_INGEST_API_KEY"]
    config = SenderConfig.from_env(sender_env)
    assert secret not in repr(config)


def test_queue_and_dead_letter_bytes_must_hold_one_payload(
    sender_env: dict[str, str]
) -> None:
    sender_env["CYBERQALQON_MAX_PAYLOAD_BYTES"] = "8192"
    sender_env["CYBERQALQON_QUEUE_MAX_BYTES"] = "4096"
    with pytest.raises(ConfigurationError, match="QUEUE_MAX_BYTES"):
        SenderConfig.from_env(sender_env)

    sender_env["CYBERQALQON_QUEUE_MAX_BYTES"] = "16384"
    sender_env["CYBERQALQON_DEAD_LETTER_MAX_BYTES"] = "4096"
    with pytest.raises(ConfigurationError, match="DEAD_LETTER_MAX_BYTES"):
        SenderConfig.from_env(sender_env)


def test_lease_must_outlive_request(sender_env: dict[str, str]) -> None:
    sender_env["CYBERQALQON_REQUEST_TIMEOUT_SECONDS"] = "20"
    sender_env["CYBERQALQON_LEASE_SECONDS"] = "30"
    with pytest.raises(ConfigurationError, match="LEASE_SECONDS"):
        SenderConfig.from_env(sender_env)


def test_ca_bundle_must_be_existing_absolute_file(
    sender_env: dict[str, str], tmp_path: Path
) -> None:
    sender_env["CYBERQALQON_CA_BUNDLE"] = str(tmp_path / "missing.pem")
    with pytest.raises(ConfigurationError, match="CA_BUNDLE"):
        SenderConfig.from_env(sender_env)


def test_programmatic_config_cannot_bypass_url_or_key_safety(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="plain HTTP"):
        SenderConfig(
            backend_url="http://example.com",
            api_key="programmatic-test-key-0001",
            database_path=(tmp_path / "sender.db").resolve(),
        )
    with pytest.raises(ConfigurationError, match="INGEST_API_KEY"):
        SenderConfig(
            backend_url="https://example.com",
            api_key="short",
            database_path=(tmp_path / "sender.db").resolve(),
        )
    with pytest.raises(ConfigurationError, match="finite"):
        SenderConfig(
            backend_url="https://example.com",
            api_key="programmatic-test-key-0001",
            database_path=(tmp_path / "sender.db").resolve(),
            request_timeout_seconds=float("nan"),
        )
