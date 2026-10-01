"""AI interface placeholder. Phase 2 never performs inference."""

from typing import Protocol


class AIAnalyzer(Protocol):
    @property
    def status(self) -> str: ...


class NoOpAIAnalyzer:
    @property
    def status(self) -> str:
        return "not_configured"
