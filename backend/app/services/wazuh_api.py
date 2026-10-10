"""Least-privilege, read-only Wazuh API inventory client."""

from __future__ import annotations

import base64
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from app.core.config import Settings


@dataclass(frozen=True, slots=True)
class WazuhAgentRecord:
    agent_id: str
    name: str
    status: str
    ip: str | None
    os_name: str | None
    os_platform: str | None
    os_version: str | None
    manager: str | None
    last_keepalive: str | None


@dataclass(frozen=True, slots=True)
class WazuhInventoryResult:
    available: bool
    reason: str
    manager_identity: str | None = None
    agents: tuple[WazuhAgentRecord, ...] = ()


class WazuhApiClient:
    """Fetch inventory only; this client has no mutation methods."""

    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.wazuh_api_url.rstrip("/")
        self.username = settings.wazuh_api_username
        self.password = settings.wazuh_api_password
        self.timeout = settings.wazuh_api_timeout_seconds
        self.ca_bundle = settings.wazuh_api_ca_bundle

    def _client(self) -> httpx.Client:
        if self.ca_bundle:
            ca_path = Path(self.ca_bundle)
            if not ca_path.is_file():
                raise ValueError("Configured Wazuh API CA bundle is unavailable")
            context = ssl.create_default_context(cafile=str(ca_path))
        else:
            context = ssl.create_default_context()
        return httpx.Client(
            base_url=self.base_url,
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(self.timeout, connect=self.timeout),
        )

    @staticmethod
    def _items(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        if not isinstance(data, dict):
            return []
        items = data.get("affected_items")
        return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []

    def fetch_inventory(self) -> WazuhInventoryResult:
        if not self.username or not self.password:
            return WazuhInventoryResult(
                available=False,
                reason="Read-only Wazuh API credentials are not configured.",
            )
        basic = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        try:
            with self._client() as client:
                auth = client.get(
                    "/security/user/authenticate",
                    params={"raw": "true"},
                    headers={"Authorization": f"Basic {basic}"},
                )
                if auth.status_code != 200:
                    return WazuhInventoryResult(
                        available=False,
                        reason=f"Wazuh API authentication returned HTTP {auth.status_code}.",
                    )
                token = auth.text.strip().strip('"')
                if not token or len(token) > 16_384:
                    return WazuhInventoryResult(
                        available=False,
                        reason="Wazuh API returned an invalid authentication token.",
                    )
                bearer = {"Authorization": f"Bearer {token}"}
                agents_response = client.get(
                    "/agents",
                    params={
                        "limit": "500",
                        "select": "id,name,ip,status,lastKeepAlive,manager,os.name,os.platform,os.version",
                        "sort": "+id",
                    },
                    headers=bearer,
                )
                if agents_response.status_code != 200:
                    return WazuhInventoryResult(
                        available=False,
                        reason=f"Wazuh agent inventory returned HTTP {agents_response.status_code}.",
                    )
                manager_response = client.get("/manager/info", headers=bearer)
                manager_items = (
                    self._items(manager_response.json()) if manager_response.status_code == 200 else []
                )
                manager_identity = None
                if manager_items:
                    manager_identity = str(
                        manager_items[0].get("name")
                        or manager_items[0].get("node_name")
                        or ""
                    ).strip() or None
                agents: list[WazuhAgentRecord] = []
                for row in self._items(agents_response.json()):
                    os_data = row.get("os") if isinstance(row.get("os"), dict) else {}
                    agent_id = str(row.get("id") or "").strip()
                    name = str(row.get("name") or "").strip()
                    if not agent_id or not name:
                        continue
                    agents.append(
                        WazuhAgentRecord(
                            agent_id=agent_id[:128],
                            name=name[:255],
                            status=str(row.get("status") or "unknown").upper()[:32],
                            ip=_optional(row.get("ip"), 64),
                            os_name=_optional(os_data.get("name"), 128),
                            os_platform=_optional(os_data.get("platform"), 128),
                            os_version=_optional(os_data.get("version"), 128),
                            manager=_optional(row.get("manager"), 255),
                            last_keepalive=_optional(row.get("lastKeepAlive"), 64),
                        )
                    )
                return WazuhInventoryResult(
                    available=True,
                    reason="Read-only Wazuh API inventory retrieved successfully.",
                    manager_identity=manager_identity,
                    agents=tuple(agents),
                )
        except (httpx.HTTPError, ssl.SSLError, OSError, ValueError):
            return WazuhInventoryResult(
                available=False,
                reason="Wazuh API is unreachable or its TLS certificate is not trusted.",
            )


def _optional(value: object, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    return str(value)[:maximum]
