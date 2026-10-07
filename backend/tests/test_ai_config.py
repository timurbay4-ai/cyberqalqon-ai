from __future__ import annotations

import pytest

from app.core.config import Settings


def test_ai_is_disabled_by_default_and_requires_a_model_when_enabled() -> None:
    assert Settings().ai_enabled is False
    assert Settings(ai_enabled=True).ai_configuration_error == "OLLAMA_MODEL must be configured when AI_ENABLED is true"


@pytest.mark.parametrize(
    "url",
    [
        "https://public.example",
        "ftp://127.0.0.1:11434",
        "http://user:password@127.0.0.1:11434",
        "http://127.0.0.1:11434/api",
        "http://127.0.0.1:11434?secret=value",
    ],
)
def test_ai_rejects_public_credentialed_or_ambiguous_provider_urls(url: str) -> None:
    assert Settings(ai_enabled=True, ollama_model="model", ollama_base_url=url).ai_configuration_error is not None


def test_ai_accepts_loopback_and_requires_explicit_private_network_opt_in() -> None:
    assert Settings(ai_enabled=True, ollama_model="model", ollama_base_url="http://127.0.0.1:11434").ai_configuration_error is None
    assert Settings(ai_enabled=True, ollama_model="model", ollama_base_url="http://10.10.10.4:11434").ai_configuration_error is not None
    assert Settings(ai_enabled=True, ollama_model="model", ollama_base_url="http://10.10.10.4:11434", ollama_allow_private_network=True).ai_configuration_error is None


def test_ai_container_hostname_requires_private_opt_in_and_exact_allowlist() -> None:
    base = {
        "ai_enabled": True,
        "ollama_model": "model",
        "ollama_base_url": "http://ollama:11434",
    }
    assert Settings(**base).ai_configuration_error is not None
    assert Settings(**base, ollama_allow_private_network=True).ai_configuration_error is not None
    assert Settings(
        **base,
        ollama_allow_private_network=True,
        ollama_allowed_hosts=("ollama",),
    ).ai_configuration_error is None


def test_ai_numeric_limits_fail_fast() -> None:
    with pytest.raises(ValueError, match="ai_max_context_bytes"):
        Settings(ai_max_context_bytes=0)
    with pytest.raises(ValueError, match="ollama_request_timeout_seconds"):
        Settings(ollama_request_timeout_seconds=0)
    with pytest.raises(ValueError, match="ai_user_cooldown_seconds"):
        Settings(ai_user_cooldown_seconds=-1)
