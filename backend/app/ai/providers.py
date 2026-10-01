"""Provider abstraction and local Ollama adapter."""
import json
from typing import Protocol
import httpx
from pydantic import ValidationError
from app.core.config import Settings
from app.schemas.analysis import AnalysisResult

class ProviderError(Exception):
    def __init__(self, category: str, message: str): self.category = category; super().__init__(message)

class AIAnalyzer(Protocol):
    provider: str
    model: str | None
    def analyze(self, prompt: str) -> AnalysisResult: ...

class NoOpAIAnalyzer:
    provider = "noop"; model = None
    @property
    def status(self) -> str: return "not_configured"
    def analyze(self, prompt: str) -> AnalysisResult: raise ProviderError("not_configured", "AI provider is not configured")

class OllamaAIAnalyzer:
    provider = "ollama"
    def __init__(self, settings: Settings):
        self.model = settings.ai_model; self.base_url = settings.ai_base_url; self.timeout = settings.ai_timeout_seconds; self.temperature = settings.ai_temperature
    def analyze(self, prompt: str) -> AnalysisResult:
        try:
            response = httpx.post(f"{self.base_url}/api/generate", json={"model": self.model, "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": self.temperature}}, timeout=self.timeout)
            response.raise_for_status(); content = response.json().get("response", "")
            if not isinstance(content, str) or not content.strip(): raise ProviderError("empty_response", "AI provider returned an empty response")
            return AnalysisResult.model_validate(json.loads(content))
        except ProviderError: raise
        except httpx.TimeoutException as exc: raise ProviderError("timeout", "AI provider timed out") from exc
        except httpx.ConnectError as exc: raise ProviderError("connection", "AI provider is unavailable") from exc
        except httpx.HTTPStatusError as exc: raise ProviderError("provider_http", f"AI provider returned HTTP {exc.response.status_code}") from exc
        except (json.JSONDecodeError, ValidationError, TypeError, ValueError) as exc: raise ProviderError("invalid_output", "AI provider returned invalid structured output") from exc
        except httpx.HTTPError as exc: raise ProviderError("provider_error", "AI provider request failed") from exc
        except Exception as exc: raise ProviderError("provider_error", "AI provider returned an unexpected error") from exc

def create_analyzer(settings: Settings) -> AIAnalyzer:
    return OllamaAIAnalyzer(settings) if settings.ai_provider == "ollama" else NoOpAIAnalyzer()
