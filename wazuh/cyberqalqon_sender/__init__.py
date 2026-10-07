"""Reliable Wazuh-to-CyberQalqon alert delivery."""

from .config import SenderConfig
from .models import DeliveryClassification, DeliveryResult, FailureCategory

__all__ = [
    "DeliveryClassification",
    "DeliveryResult",
    "FailureCategory",
    "SenderConfig",
]

__version__ = "0.1.0"
