"""Least-privilege, read-only Wazuh API inventory client."""

from __future__ import annotations

import base64
import json
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from app.core.config import Settings


AGENT_ID_PATTERN = re.compile(r"^[0-9]{3,12}$")
TRANSIENT_STATUS = {429, 502, 503, 504}


class WazuhResponseTooLarge(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class WazuhAgentRecord:
    agent_id: str
    name: str
    status: str
    ip: str | None
    os_name: str | None
    os_platform: str | None
    os_version: str | None
    agent_version: str | None
    groups: tuple[str, ...]
    manager: str | None
    last_keepalive: str | None
    disconnected_at: str | None
    enrolled_at: str | None


@dataclass(frozen=True, slots=True)
class WazuhInventoryResult:
    available: bool
    reason: str
    observed_at: datetime
    manager_identity: str | None = None
    manager_version: str | None = None
    manager_health: str | None = None
    agents: tuple[WazuhAgentRecord, ...] = ()
    rejected_agent_count: int = 0


class WazuhApiClient:
    """Fetch inventory only; this client deliberately has no mutation methods."""

    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.wazuh_api_url.rstrip("/")
        self.username = settings.wazuh_api_username
        self.password = settings.wazuh_api_password
        self.timeout = settings.wazuh_api_timeout_seconds
        self.ca_bundle = settings.wazuh_api_ca_bundle
        self.max_response_bytes = settings.wazuh_api_max_response_bytes
        self.page_size = settings.wazuh_api_page_size
        self.max_pages = settings.wazuh_api_max_pages
        self.retry_attempts = settings.wazuh_api_retry_attempts

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

    def _get(
        self,
        client: httpx.Client,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        maximum: int | None = None,
    ) -> tuple[int, bytes]:
        """Read one bounded GET response with a bounded transient retry count."""

        limit = maximum or self.max_response_bytes
        last_error: httpx.HTTPError | None = None
        for attempt in range(self.retry_attempts + 1):
            try:
                with client.stream("GET", path, headers=headers, params=params) as response:
                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise WazuhResponseTooLarge("Wazuh API response exceeded the configured limit")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > limit:
                            raise WazuhResponseTooLarge(
                                "Wazuh API response exceeded the configured limit"
                            )
                    if response.status_code not in TRANSIENT_STATUS or attempt >= self.retry_attempts:
                        return response.status_code, bytes(body)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.retry_attempts:
                    raise
        if last_error is not None:
            raise last_error
        raise RuntimeError("bounded Wazuh request did not produce a response")

    def _authenticate(
        self,
        client: httpx.Client,
        *,
        headers: dict[str, str],
    ) -> tuple[int, bytes]:
        """Use Wazuh's non-mutating POST authentication endpoint only."""

        limit = 16_384
        last_error: httpx.HTTPError | None = None
        for attempt in range(self.retry_attempts + 1):
            try:
                with client.stream(
                    "POST",
                    "/security/user/authenticate",
                    headers=headers,
                    params={"raw": "true"},
                ) as response:
                    declared = response.headers.get("content-length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise WazuhResponseTooLarge(
                            "Wazuh API response exceeded the configured limit"
                        )
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) > limit:
                            raise WazuhResponseTooLarge(
                                "Wazuh API response exceeded the configured limit"
                            )
                    if response.status_code not in TRANSIENT_STATUS or attempt >= self.retry_attempts:
                        return response.status_code, bytes(body)
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt >= self.retry_attempts:
                    raise
        if last_error is not None:
            raise last_error
        raise RuntimeError("bounded Wazuh authentication did not produce a response")

    @staticmethod
    def _json(body: bytes) -> dict[str, Any]:
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Wazuh API returned malformed JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("Wazuh API returned an unexpected JSON shape")
        return value

    @staticmethod
    def _items(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        data = payload.get("data")
        if not isinstance(data, dict):
            return []
        items = data.get("affected_items")
        return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []

    @staticmethod
    def _total(payload: dict[str, Any]) -> int | None:
        data = payload.get("data")
        value = data.get("total_affected_items") if isinstance(data, dict) else None
        return value if isinstance(value, int) and value >= 0 else None

    def fetch_inventory(self) -> WazuhInventoryResult:
        observed_at = datetime.now(timezone.utc)
        if not self.username or not self.password:
            return WazuhInventoryResult(
                available=False,
                reason="Read-only Wazuh API credentials are not configured.",
                observed_at=observed_at,
            )
        basic = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        try:
            with self._client() as client:
                status, auth_body = self._authenticate(
                    client,
                    headers={"Authorization": f"Basic {basic}"},
                )
                if status != 200:
                    return WazuhInventoryResult(
                        available=False,
                        reason=f"Wazuh API authentication returned HTTP {status}.",
                        observed_at=observed_at,
                    )
                token = auth_body.decode("utf-8", errors="strict").strip().strip('"')
                if not token or len(token) > 16_384 or any(ord(char) < 32 for char in token):
                    return WazuhInventoryResult(
                        available=False,
                        reason="Wazuh API returned an invalid authentication token.",
                        observed_at=observed_at,
                    )
                bearer = {"Authorization": f"Bearer {token}"}

                agent_rows: list[dict[str, Any]] = []
                total: int | None = None
                for page in range(self.max_pages):
                    agent_status, agent_body = self._get(
                        client,
                        "/agents",
                        params={
                            "limit": str(self.page_size),
                            "offset": str(page * self.page_size),
                            "select": (
                                "id,name,ip,status,lastKeepAlive,manager,node_name,version,group,"
                                "dateAdd,disconnection_time,os.name,os.platform,os.version"
                            ),
                            "sort": "+id",
                        },
                        headers=bearer,
                    )
                    if agent_status != 200:
                        return WazuhInventoryResult(
                            available=False,
                            reason=f"Wazuh agent inventory returned HTTP {agent_status}.",
                            observed_at=observed_at,
                        )
                    payload = self._json(agent_body)
                    page_rows = self._items(payload)
                    agent_rows.extend(page_rows)
                    total = self._total(payload) if total is None else total
                    if len(page_rows) < self.page_size or (
                        total is not None and len(agent_rows) >= total
                    ):
                        break
                else:
                    if total is None or len(agent_rows) < total:
                        return WazuhInventoryResult(
                            available=False,
                            reason="Wazuh agent inventory exceeded the configured page limit.",
                            observed_at=observed_at,
                        )

                manager_status, manager_body = self._get(client, "/manager/info", headers=bearer)
                manager_items = (
                    self._items(self._json(manager_body)) if manager_status == 200 else []
                )
                manager = manager_items[0] if manager_items else {}
                manager_identity = _optional(
                    manager.get("name") or manager.get("node_name"), 255
                )
                manager_version = _optional(manager.get("version"), 128)
                health_status, health_body = self._get(client, "/manager/status", headers=bearer)
                manager_health = "UNKNOWN"
                if health_status == 200:
                    health_items = self._items(self._json(health_body))
                    daemon_values: list[str] = []
                    for item in health_items:
                        daemon_values.extend(
                            str(value).casefold()
                            for value in item.values()
                            if isinstance(value, str)
                        )
                    if daemon_values:
                        manager_health = (
                            "HEALTHY"
                            if all(value in {"running", "active"} for value in daemon_values)
                            else "DEGRADED"
                        )

                agents: list[WazuhAgentRecord] = []
                rejected = 0
                for row in agent_rows:
                    os_data = row.get("os") if isinstance(row.get("os"), dict) else {}
                    agent_id = str(row.get("id") or "").strip()
                    name = str(row.get("name") or "").strip()
                    if not AGENT_ID_PATTERN.fullmatch(agent_id) or not name or len(name) > 255:
                        rejected += 1
                        continue
                    groups_raw = row.get("group")
                    if isinstance(groups_raw, list):
                        groups = tuple(
                            value
                            for value in (_optional(item, 128) for item in groups_raw[:128])
                            if value
                        )
                    elif groups_raw not in (None, ""):
                        groups = tuple(
                            item.strip()[:128]
                            for item in str(groups_raw).split(",")[:128]
                            if item.strip()
                        )
                    else:
                        groups = ()
                    agents.append(
                        WazuhAgentRecord(
                            agent_id=agent_id,
                            name=name,
                            status=str(row.get("status") or "unknown").upper()[:32],
                            ip=_optional(row.get("ip"), 64),
                            os_name=_optional(os_data.get("name"), 128),
                            os_platform=_optional(os_data.get("platform"), 128),
                            os_version=_optional(os_data.get("version"), 128),
                            agent_version=_optional(row.get("version"), 128),
                            groups=groups,
                            manager=_optional(row.get("manager") or row.get("node_name"), 255),
                            last_keepalive=_optional(row.get("lastKeepAlive"), 64),
                            disconnected_at=_optional(
                                row.get("disconnection_time") or row.get("disconnectionTime"), 64
                            ),
                            enrolled_at=_optional(row.get("dateAdd"), 64),
                        )
                    )
                return WazuhInventoryResult(
                    available=True,
                    reason="Read-only Wazuh API inventory retrieved successfully.",
                    observed_at=observed_at,
                    manager_identity=manager_identity,
                    manager_version=manager_version,
                    manager_health=manager_health,
                    agents=tuple(agents),
                    rejected_agent_count=rejected,
                )
        except WazuhResponseTooLarge:
            return WazuhInventoryResult(
                available=False,
                reason="Wazuh API response exceeded the configured size limit.",
                observed_at=observed_at,
            )
        except (httpx.HTTPError, ssl.SSLError, OSError, ValueError, UnicodeDecodeError):
            return WazuhInventoryResult(
                available=False,
                reason="Wazuh API is unreachable, malformed, or its TLS certificate is not trusted.",
                observed_at=observed_at,
            )


def _optional(value: object, maximum: int) -> str | None:
    if value in (None, ""):
        return None
    result = str(value).strip()
    return result[:maximum] if result else None
