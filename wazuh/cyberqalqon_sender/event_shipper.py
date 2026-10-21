"""Bounded incremental shipper for selected Wazuh archives.json security events."""

from __future__ import annotations

import json
import hashlib
import logging
import os
import signal
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any

import httpx

from .config import SenderConfig
from .durable_state import durable_atomic_json
from .logging import log_event


DEFAULT_ARCHIVE_PATH = Path("/var/ossec/logs/archives/archives.json")
DEFAULT_STATE_PATH = Path("/var/lib/cyberqalqon-sender/event-shipper-state.json")
SELECTED_WINDOWS_EVENT_IDS = {
    "1102",
    "1116",
    "1117",
    "1118",
    "1119",
    "4103",
    "4104",
    "4624",
    "4625",
    "4634",
    "4648",
    "4672",
    "4688",
    "4720",
    "4726",
    "4732",
    "5000",
    "5001",
    "5004",
    "5007",
    "7045",
}
LAB_APPLICATION_EVENTS = {("application", "cyberqalqon-v091", "100")}


class ArchiveCursorStateError(RuntimeError):
    """Raised when continuing from the durable cursor could lose archive evidence."""


@dataclass(frozen=True, slots=True)
class EventShipperConfig:
    archive_path: Path
    state_path: Path
    endpoint: str
    api_key: str
    poll_seconds: float
    batch_size: int
    bootstrap_bytes: int
    max_line_bytes: int
    connect_timeout_seconds: float
    request_timeout_seconds: float
    ca_bundle: Path | None
    batch_protocol_enabled: bool = False
    network_batch_size: int = 25
    max_batch_request_bytes: int = 2_097_152
    adaptive_enabled: bool = False
    adaptive_min_batch_size: int = 10
    adaptive_max_batch_size: int = 25
    adaptive_low_latency_ms: float = 150.0
    adaptive_high_latency_ms: float = 750.0
    retry_backoff_max_seconds: float = 60.0

    @classmethod
    def from_sender(cls, sender: SenderConfig) -> "EventShipperConfig":
        env = os.environ
        archive = Path(env.get("CYBERQALQON_EVENT_ARCHIVE", str(DEFAULT_ARCHIVE_PATH)))
        state = Path(env.get("CYBERQALQON_EVENT_STATE", str(DEFAULT_STATE_PATH)))
        poll = float(env.get("CYBERQALQON_EVENT_POLL_SECONDS", "5"))
        batch = int(env.get("CYBERQALQON_EVENT_BATCH_SIZE", "200"))
        bootstrap = int(env.get("CYBERQALQON_EVENT_BOOTSTRAP_BYTES", str(16 * 1024 * 1024)))
        maximum = int(env.get("CYBERQALQON_EVENT_MAX_BYTES", "262144"))
        adaptive = env.get("CYBERQALQON_EVENT_ADAPTIVE_ENABLED", "false").casefold() == "true"
        adaptive_minimum = int(
            env.get("CYBERQALQON_EVENT_ADAPTIVE_MIN_BATCH", str(min(10, batch)))
        )
        adaptive_maximum = int(
            env.get("CYBERQALQON_EVENT_ADAPTIVE_MAX_BATCH", str(min(25, batch)))
        )
        low_latency = float(env.get("CYBERQALQON_EVENT_ADAPTIVE_LOW_LATENCY_MS", "150"))
        high_latency = float(env.get("CYBERQALQON_EVENT_ADAPTIVE_HIGH_LATENCY_MS", "750"))
        maximum_backoff = float(env.get("CYBERQALQON_EVENT_RETRY_BACKOFF_MAX_SECONDS", "60"))
        batch_protocol_enabled = (
            env.get("CYBERQALQON_EVENT_BATCH_PROTOCOL_ENABLED", "false").casefold()
            == "true"
        )
        network_batch_size = int(
            env.get("CYBERQALQON_EVENT_NETWORK_BATCH_SIZE", "25")
        )
        max_batch_request_bytes = int(
            env.get("CYBERQALQON_EVENT_BATCH_MAX_BYTES", str(2 * 1024 * 1024))
        )
        if not archive.is_absolute() or not state.is_absolute():
            raise ValueError("event archive and state paths must be absolute")
        if not 0.25 <= poll <= 300:
            raise ValueError("CYBERQALQON_EVENT_POLL_SECONDS must be between 0.25 and 300")
        if not 1 <= batch <= 1000:
            raise ValueError("CYBERQALQON_EVENT_BATCH_SIZE must be between 1 and 1000")
        if not 0 <= bootstrap <= 134_217_728:
            raise ValueError("CYBERQALQON_EVENT_BOOTSTRAP_BYTES must be between 0 and 134217728")
        if not 4096 <= maximum <= min(sender.max_payload_bytes, 1_048_576):
            raise ValueError("CYBERQALQON_EVENT_MAX_BYTES is outside the supported bound")
        if not 1 <= adaptive_minimum <= adaptive_maximum <= batch:
            raise ValueError("adaptive batch bounds must satisfy 1 <= min <= max <= batch size")
        if not 1 <= low_latency < high_latency <= 60_000:
            raise ValueError("adaptive latency bounds are invalid")
        if not poll <= maximum_backoff <= 900:
            raise ValueError("retry backoff maximum must be between poll interval and 900 seconds")
        if not 1 <= network_batch_size <= min(100, batch):
            raise ValueError(
                "network batch size must satisfy 1 <= size <= min(100, local batch size)"
            )
        if not maximum <= max_batch_request_bytes <= 8_388_608:
            raise ValueError(
                "batch request bytes must be at least the event limit and at most 8388608"
            )
        if (
            batch_protocol_enabled
            and adaptive
            and adaptive_maximum > network_batch_size
        ):
            raise ValueError(
                "adaptive batch maximum cannot exceed the network batch size"
            )
        return cls(
            archive_path=archive,
            state_path=state,
            endpoint=f"{sender.backend_url}/api/v1/events/ingest",
            api_key=sender.api_key,
            poll_seconds=poll,
            batch_size=batch,
            bootstrap_bytes=bootstrap,
            max_line_bytes=maximum,
            connect_timeout_seconds=sender.connect_timeout_seconds,
            request_timeout_seconds=sender.request_timeout_seconds,
            ca_bundle=sender.ca_bundle,
            batch_protocol_enabled=batch_protocol_enabled,
            network_batch_size=network_batch_size,
            max_batch_request_bytes=max_batch_request_bytes,
            adaptive_enabled=adaptive,
            adaptive_min_batch_size=adaptive_minimum,
            adaptive_max_batch_size=adaptive_maximum,
            adaptive_low_latency_ms=low_latency,
            adaptive_high_latency_ms=high_latency,
            retry_backoff_max_seconds=maximum_backoff,
        )


@dataclass(slots=True)
class CursorState:
    device: int
    inode: int
    offset: int
    accepted: int = 0
    skipped: int = 0
    rejected: int = 0
    filtered_events: int = 0
    malformed_json: int = 0
    oversized_lines: int = 0
    delivery_rejected: int = 0
    retry_attempts: int = 0
    duplicate_attempts: int = 0
    legacy_successful_acknowledgements: int | None = None
    protocol_errors: int = 0
    consecutive_retries: int = 0
    recovery_transitions: int = 0
    last_success_at: float | None = None
    last_failure_at: float | None = None
    last_recovery_at: float | None = None
    delivery_window_started_at: float | None = None
    accounting_started_at: float | None = None
    last_request_latency_ms: float | None = None
    current_batch_size: int | None = None
    single_http_requests: int = 0
    batch_http_requests: int = 0
    batch_events_acknowledged: int = 0
    last_batch_size: int | None = None
    ingress_protocol: str = "single-v1"
    terminal_blocked: bool = False
    last_failure_category: str | None = None
    updated_at: float = 0.0

    def as_dict(self) -> dict[str, int | float | bool | str | None]:
        successful = self.accepted + self.duplicate_attempts
        duration = (
            self.last_success_at - self.delivery_window_started_at
            if self.last_success_at is not None and self.delivery_window_started_at is not None
            else 0
        )
        return {
            "version": 3,
            "device": self.device,
            "inode": self.inode,
            "offset": self.offset,
            "accepted": self.accepted,
            "skipped": self.skipped,
            "rejected": self.rejected,
            "filtered_events": self.filtered_events,
            "malformed_json": self.malformed_json,
            "oversized_lines": self.oversized_lines,
            "delivery_rejected": self.delivery_rejected,
            "retry_attempts": self.retry_attempts,
            "duplicate_attempts": self.duplicate_attempts,
            "legacy_successful_acknowledgements": self.legacy_successful_acknowledgements,
            "protocol_errors": self.protocol_errors,
            "consecutive_retries": self.consecutive_retries,
            "recovery_transitions": self.recovery_transitions,
            "last_success_at": self.last_success_at,
            "last_failure_at": self.last_failure_at,
            "last_recovery_at": self.last_recovery_at,
            "delivery_window_started_at": self.delivery_window_started_at,
            "accounting_started_at": self.accounting_started_at,
            "last_request_latency_ms": self.last_request_latency_ms,
            "current_batch_size": self.current_batch_size,
            "single_http_requests": self.single_http_requests,
            "batch_http_requests": self.batch_http_requests,
            "batch_events_acknowledged": self.batch_events_acknowledged,
            "last_batch_size": self.last_batch_size,
            "ingress_protocol": self.ingress_protocol,
            "terminal_blocked": self.terminal_blocked,
            "last_failure_category": self.last_failure_category,
            "delivery_rate_per_second": (
                round(successful / duration, 6) if successful and duration > 0 else None
            ),
            "updated_at": self.updated_at,
        }


def select_archive_event(payload: dict[str, Any]) -> bool:
    """Allow only explicit security sources; never mirror the full archive uncontrolled."""

    if isinstance(payload.get("rule"), dict) and payload["rule"].get("id") is not None:
        return True
    location = str(payload.get("location", "")).casefold()
    decoder = payload.get("decoder") if isinstance(payload.get("decoder"), dict) else {}
    decoder_name = str(decoder.get("name", "")).casefold()
    full_log = str(payload.get("full_log", ""))
    if "/nginx/" in location or location.endswith("nginx/access.log") or location.endswith("nginx/error.log"):
        return True
    if "syscheck" in location or "syscheck" in decoder_name:
        return True
    if "CQ-NETSCAN" in full_log:
        return True
    if decoder_name in {"pam", "sshd"}:
        return True
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}
    event_id = str(system.get("eventID", system.get("eventId", "")))
    if event_id in SELECTED_WINDOWS_EVENT_IDS:
        return True
    channel = str(system.get("channel", "")).casefold()
    provider = str(system.get("providerName", system.get("provider", ""))).casefold()
    return (channel, provider, event_id) in LAB_APPLICATION_EVENTS


@dataclass(frozen=True, slots=True)
class BatchDeliveryResult:
    status: str
    outcomes: tuple[str, ...] = ()


class EventDeliveryClient:
    def __init__(self, config: EventShipperConfig) -> None:
        context = ssl.create_default_context(
            cafile=str(config.ca_bundle) if config.ca_bundle is not None else None
        )
        self.endpoint = config.endpoint
        self.batch_endpoint = f"{config.endpoint.removesuffix('/ingest')}/ingest-batch"
        self.api_key = config.api_key
        self.max_batch_request_bytes = config.max_batch_request_bytes
        self.client = httpx.Client(
            verify=context,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                config.request_timeout_seconds,
                connect=config.connect_timeout_seconds,
            ),
        )
        self.last_latency_ms: float | None = None
        self.last_status_code: int | None = None

    def close(self) -> None:
        self.client.close()

    def deliver(self, payload: bytes) -> str:
        started = time.monotonic()
        try:
            response = self.client.post(
                self.endpoint,
                headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
                content=payload,
            )
        except httpx.HTTPError:
            self.last_latency_ms = round((time.monotonic() - started) * 1000, 3)
            self.last_status_code = None
            return "retry"
        self.last_latency_ms = round((time.monotonic() - started) * 1000, 3)
        self.last_status_code = response.status_code
        if response.status_code in {200, 201}:
            try:
                result = response.json()
            except (TypeError, ValueError):
                return "protocol_error"
            if not isinstance(result, dict):
                return "protocol_error"
            if (
                response.status_code == 201
                and result.get("status") == "created"
                and result.get("duplicate") is False
            ):
                return "accepted"
            if (
                response.status_code == 200
                and result.get("status") == "duplicate"
                and result.get("duplicate") is True
            ):
                return "duplicate"
            return "protocol_error"
        if response.status_code in {400, 409, 413, 415, 422}:
            return "rejected"
        return "retry"

    def deliver_batch(
        self,
        payloads: list[dict[str, Any]],
        *,
        batch_id: str,
    ) -> BatchDeliveryResult:
        envelope = {
            "protocol_version": "m18-batch-v1",
            "batch_id": batch_id,
            "events": payloads,
        }
        encoded = json.dumps(
            envelope,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > self.max_batch_request_bytes:
            return BatchDeliveryResult("rejected")
        started = time.monotonic()
        try:
            response = self.client.post(
                self.batch_endpoint,
                headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
                content=encoded,
            )
        except httpx.HTTPError:
            self.last_latency_ms = round((time.monotonic() - started) * 1000, 3)
            self.last_status_code = None
            return BatchDeliveryResult("retry")
        self.last_latency_ms = round((time.monotonic() - started) * 1000, 3)
        self.last_status_code = response.status_code
        if response.status_code in {200, 201}:
            try:
                result = response.json()
            except (TypeError, ValueError):
                return BatchDeliveryResult("protocol_error")
            if (
                not isinstance(result, dict)
                or result.get("protocol_version") != "m18-batch-v1"
                or result.get("batch_id") != batch_id
                or result.get("status") != "COMMITTED"
                or result.get("atomic") is not True
                or not isinstance(result.get("results"), list)
                or len(result["results"]) != len(payloads)
            ):
                return BatchDeliveryResult("protocol_error")
            outcomes: list[str] = []
            for index, item in enumerate(result["results"]):
                if (
                    not isinstance(item, dict)
                    or item.get("index") != index
                    or item.get("outcome") not in {"INSERTED", "DUPLICATE"}
                ):
                    return BatchDeliveryResult("protocol_error")
                outcomes.append(
                    "accepted" if item["outcome"] == "INSERTED" else "duplicate"
                )
            inserted = outcomes.count("accepted")
            duplicates = outcomes.count("duplicate")
            if (
                result.get("inserted") != inserted
                or result.get("duplicates") != duplicates
                or (response.status_code == 200 and inserted != 0)
                or (response.status_code == 201 and inserted == 0)
            ):
                return BatchDeliveryResult("protocol_error")
            return BatchDeliveryResult("accepted", tuple(outcomes))
        if response.status_code in {400, 409, 413, 415, 422}:
            return BatchDeliveryResult("rejected")
        return BatchDeliveryResult("retry")


@dataclass(slots=True)
class AdaptiveBatchController:
    minimum: int
    maximum: int
    low_latency_ms: float
    high_latency_ms: float
    current: int

    def observe(self, *, request_latencies_ms: list[float], blocked: bool) -> int:
        if blocked:
            self.current = max(self.minimum, self.current // 2)
            return self.current
        if not request_latencies_ms:
            return self.current
        average = sum(request_latencies_ms) / len(request_latencies_ms)
        if average >= self.high_latency_ms:
            self.current = max(self.minimum, self.current // 2)
        elif average <= self.low_latency_ms:
            self.current = min(self.maximum, self.current + max(1, self.current // 10))
        return self.current


class ArchiveEventShipper:
    def __init__(self, config: EventShipperConfig, *, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.delivery = EventDeliveryClient(config)
        self.adaptive = AdaptiveBatchController(
            minimum=config.adaptive_min_batch_size,
            maximum=config.adaptive_max_batch_size,
            low_latency_ms=config.adaptive_low_latency_ms,
            high_latency_ms=config.adaptive_high_latency_ms,
            current=(config.adaptive_min_batch_size if config.adaptive_enabled else config.batch_size),
        )

    def close(self) -> None:
        self.delivery.close()

    def _load_state(self, stat: os.stat_result) -> CursorState:
        if not self.config.state_path.exists():
            return CursorState(
                device=stat.st_dev,
                inode=stat.st_ino,
                offset=max(0, stat.st_size - self.config.bootstrap_bytes),
            )
        try:
            raw = json.loads(self.config.state_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ArchiveCursorStateError("durable cursor has an unsupported format")
            version = int(raw.get("version", -1))
            if version != 3:
                if version in {1, 2}:
                    raise ArchiveCursorStateError(
                        "legacy cursor requires an explicit, operator-approved v2 to v3 upgrade"
                    )
                raise ArchiveCursorStateError("durable cursor has an unsupported forward version")
            device = int(raw["device"])
            inode = int(raw["inode"])
            offset = int(raw["offset"])
            if device != stat.st_dev or inode != stat.st_ino:
                raise ArchiveCursorStateError(
                    "archive identity changed; preserve rotated evidence and reconcile the cursor"
                )
            if not 0 <= offset <= stat.st_size:
                raise ArchiveCursorStateError(
                    "archive was truncated behind the durable cursor; refusing to skip evidence"
                )
            return CursorState(
                device=stat.st_dev,
                inode=stat.st_ino,
                offset=offset,
                accepted=max(0, int(raw.get("accepted", 0))),
                skipped=max(0, int(raw.get("skipped", 0))),
                rejected=max(0, int(raw.get("rejected", 0))),
                filtered_events=max(0, int(raw.get("filtered_events", raw.get("skipped", 0)))),
                malformed_json=max(0, int(raw.get("malformed_json", 0))),
                oversized_lines=max(0, int(raw.get("oversized_lines", 0))),
                delivery_rejected=max(0, int(raw.get("delivery_rejected", 0))),
                retry_attempts=max(0, int(raw.get("retry_attempts", 0))),
                duplicate_attempts=max(0, int(raw.get("duplicate_attempts", 0))),
                legacy_successful_acknowledgements=(
                    max(0, int(raw["legacy_successful_acknowledgements"]))
                    if raw.get("legacy_successful_acknowledgements") is not None else None
                ),
                protocol_errors=max(0, int(raw.get("protocol_errors", 0))),
                consecutive_retries=max(0, int(raw.get("consecutive_retries", 0))),
                recovery_transitions=max(0, int(raw.get("recovery_transitions", 0))),
                last_success_at=(
                    float(raw["last_success_at"])
                    if raw.get("last_success_at") is not None else None
                ),
                last_failure_at=(
                    float(raw["last_failure_at"])
                    if raw.get("last_failure_at") is not None else None
                ),
                last_recovery_at=(
                    float(raw["last_recovery_at"])
                    if raw.get("last_recovery_at") is not None else None
                ),
                delivery_window_started_at=(
                    float(raw["delivery_window_started_at"])
                    if raw.get("delivery_window_started_at") is not None else None
                ),
                accounting_started_at=(
                    float(raw["accounting_started_at"])
                    if raw.get("accounting_started_at") is not None else None
                ),
                last_request_latency_ms=(
                    float(raw["last_request_latency_ms"])
                    if raw.get("last_request_latency_ms") is not None else None
                ),
                current_batch_size=(
                    max(1, int(raw["current_batch_size"]))
                    if raw.get("current_batch_size") is not None else None
                ),
                single_http_requests=max(0, int(raw.get("single_http_requests", 0))),
                batch_http_requests=max(0, int(raw.get("batch_http_requests", 0))),
                batch_events_acknowledged=max(
                    0, int(raw.get("batch_events_acknowledged", 0))
                ),
                last_batch_size=(
                    max(1, int(raw["last_batch_size"]))
                    if raw.get("last_batch_size") is not None
                    else None
                ),
                ingress_protocol=str(raw.get("ingress_protocol", "single-v1")),
                terminal_blocked=bool(raw.get("terminal_blocked", False)),
                last_failure_category=(
                    str(raw["last_failure_category"])
                    if raw.get("last_failure_category") is not None else None
                ),
                updated_at=float(raw.get("updated_at", 0)),
            )
        except ArchiveCursorStateError:
            raise
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ArchiveCursorStateError(
                "durable cursor is unreadable; refusing to bootstrap over existing state"
            ) from exc

    def _save_state(self, state: CursorState) -> None:
        durable_atomic_json(self.config.state_path, state.as_dict())

    @staticmethod
    def _discard_line_remainder(handle: Any, chunk: bytes) -> None:
        while chunk and not chunk.endswith(b"\n"):
            chunk = handle.readline(65_536)

    def _encoded_batch_size(self, payloads: list[dict[str, Any]]) -> int:
        return len(
            json.dumps(
                {
                    "protocol_version": "m18-batch-v1",
                    "batch_id": f"m18-{'0' * 32}",
                    "events": payloads,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )

    def _run_protocol_batch(self, state: CursorState) -> dict[str, int | bool]:
        if state.terminal_blocked:
            return {
                "processed": 0,
                "retry_blocked": False,
                "terminal_blocked": True,
                "offset": state.offset,
                "wait_seconds": self.config.retry_backoff_max_seconds,
            }
        initial_offset = state.offset
        final_offset = state.offset
        processed = 0
        filtered = 0
        malformed = 0
        oversized = 0
        payloads: list[dict[str, Any]] = []
        batch_limit = self.adaptive.current if self.config.adaptive_enabled else self.config.batch_size
        state.current_batch_size = min(batch_limit, self.config.network_batch_size)
        state.ingress_protocol = "m18-batch-v1"

        with self.config.archive_path.open("rb") as handle:
            handle.seek(state.offset)
            if state.offset > 0 and state.updated_at == 0:
                handle.readline()
                final_offset = handle.tell()
            while processed < batch_limit and len(payloads) < self.config.network_batch_size:
                line_start = handle.tell()
                line = handle.readline(self.config.max_line_bytes + 1)
                if not line:
                    break
                if len(line) > self.config.max_line_bytes:
                    self._discard_line_remainder(handle, line)
                    final_offset = handle.tell()
                    oversized += 1
                    processed += 1
                    continue
                if not line.endswith(b"\n"):
                    handle.seek(line_start)
                    break
                try:
                    payload = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    final_offset = handle.tell()
                    malformed += 1
                    processed += 1
                    continue
                if not isinstance(payload, dict) or not select_archive_event(payload):
                    final_offset = handle.tell()
                    filtered += 1
                    processed += 1
                    continue
                candidate = [*payloads, payload]
                if self._encoded_batch_size(candidate) > self.config.max_batch_request_bytes:
                    handle.seek(line_start)
                    if not payloads:
                        state.rejected += 1
                        state.delivery_rejected += 1
                        state.terminal_blocked = True
                        state.last_failure_at = time.time()
                        state.last_failure_category = "batch_payload_too_large"
                    break
                payloads.append(payload)
                final_offset = handle.tell()
                processed += 1

        if not payloads:
            state.offset = final_offset
            state.skipped += filtered
            state.filtered_events += filtered
            state.rejected += malformed + oversized
            state.malformed_json += malformed
            state.oversized_lines += oversized
            state.updated_at = time.time()
            self._save_state(state)
            return {
                "processed": processed,
                "retry_blocked": False,
                "terminal_blocked": state.terminal_blocked,
                "offset": state.offset,
                "wait_seconds": self.config.poll_seconds,
            }

        digest = hashlib.sha256(
            f"{state.device}:{state.inode}:{initial_offset}:{final_offset}:{len(payloads)}".encode()
        ).hexdigest()[:32]
        batch_id = f"m18-{digest}"
        state.batch_http_requests += 1
        state.last_batch_size = len(payloads)
        delivery = self.delivery.deliver_batch(payloads, batch_id=batch_id)
        latency = getattr(self.delivery, "last_latency_ms", None)
        if isinstance(latency, (int, float)) and latency >= 0:
            state.last_request_latency_ms = float(latency)

        retry_blocked = delivery.status in {"retry", "protocol_error"}
        terminal_blocked = delivery.status == "rejected"
        if retry_blocked:
            state.retry_attempts += 1
            if delivery.status == "protocol_error":
                state.protocol_errors += 1
            state.consecutive_retries += 1
            state.last_failure_at = time.time()
            state.last_failure_category = delivery.status
        elif terminal_blocked:
            state.rejected += 1
            state.delivery_rejected += 1
            state.terminal_blocked = True
            state.last_failure_at = time.time()
            state.last_failure_category = "delivery_rejected"
        else:
            delivered_at = time.time()
            state.offset = final_offset
            state.skipped += filtered
            state.filtered_events += filtered
            state.rejected += malformed + oversized
            state.malformed_json += malformed
            state.oversized_lines += oversized
            state.accepted += delivery.outcomes.count("accepted")
            state.duplicate_attempts += delivery.outcomes.count("duplicate")
            state.batch_events_acknowledged += len(delivery.outcomes)
            if state.delivery_window_started_at is None:
                state.delivery_window_started_at = delivered_at
            if state.accounting_started_at is None:
                state.accounting_started_at = delivered_at
            if state.consecutive_retries:
                state.recovery_transitions += 1
                state.last_recovery_at = delivered_at
            state.consecutive_retries = 0
            state.last_success_at = delivered_at
            state.last_failure_category = None

        if self.config.adaptive_enabled:
            latencies = [float(latency)] if isinstance(latency, (int, float)) else []
            state.current_batch_size = min(
                self.adaptive.observe(
                    request_latencies_ms=latencies,
                    blocked=retry_blocked or terminal_blocked,
                ),
                self.config.network_batch_size,
            )
        state.updated_at = time.time()
        self._save_state(state)
        wait_seconds = self.config.poll_seconds
        if retry_blocked:
            exponent = min(max(state.consecutive_retries - 1, 0), 10)
            wait_seconds = min(
                self.config.retry_backoff_max_seconds,
                self.config.poll_seconds * (2**exponent),
            )
        return {
            "processed": processed,
            "retry_blocked": retry_blocked,
            "terminal_blocked": terminal_blocked,
            "offset": state.offset,
            "wait_seconds": wait_seconds,
        }

    def run_batch(self) -> dict[str, int | bool]:
        stat = self.config.archive_path.stat()
        state = self._load_state(stat)
        if self.config.batch_protocol_enabled:
            return self._run_protocol_batch(state)
        processed = 0
        retry_blocked = False
        terminal_blocked = state.terminal_blocked
        request_latencies_ms: list[float] = []
        batch_limit = self.adaptive.current if self.config.adaptive_enabled else self.config.batch_size
        state.current_batch_size = batch_limit
        if terminal_blocked:
            return {
                "processed": 0,
                "retry_blocked": False,
                "terminal_blocked": True,
                "offset": state.offset,
                "wait_seconds": self.config.retry_backoff_max_seconds,
            }
        with self.config.archive_path.open("rb") as handle:
            handle.seek(state.offset)
            if state.offset > 0 and state.updated_at == 0:
                handle.readline()
                state.offset = handle.tell()
            while processed < batch_limit:
                line_start = handle.tell()
                line = handle.readline(self.config.max_line_bytes + 1)
                if not line:
                    break
                if len(line) > self.config.max_line_bytes:
                    self._discard_line_remainder(handle, line)
                    state.offset = handle.tell()
                    state.rejected += 1
                    state.oversized_lines += 1
                    processed += 1
                    continue
                if not line.endswith(b"\n"):
                    # Wazuh may still be appending the record. Preserve the last acknowledged
                    # offset and retry only after the line becomes complete.
                    handle.seek(line_start)
                    break
                try:
                    payload = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    state.offset = handle.tell()
                    state.rejected += 1
                    state.malformed_json += 1
                    processed += 1
                    continue
                if not isinstance(payload, dict) or not select_archive_event(payload):
                    state.offset = handle.tell()
                    state.skipped += 1
                    state.filtered_events += 1
                    processed += 1
                    continue
                state.ingress_protocol = "single-v1"
                state.single_http_requests += 1
                result = self.delivery.deliver(line.rstrip(b"\r\n"))
                latency = getattr(self.delivery, "last_latency_ms", None)
                if isinstance(latency, (int, float)) and latency >= 0:
                    request_latencies_ms.append(float(latency))
                    state.last_request_latency_ms = float(latency)
                if result in {"retry", "protocol_error"}:
                    handle.seek(line_start)
                    state.retry_attempts += 1
                    if result == "protocol_error":
                        state.protocol_errors += 1
                    state.consecutive_retries += 1
                    state.last_failure_at = time.time()
                    state.last_failure_category = result
                    retry_blocked = True
                    break
                if result in {"accepted", "duplicate"}:
                    state.offset = handle.tell()
                    delivered_at = time.time()
                    if state.delivery_window_started_at is None:
                        state.delivery_window_started_at = delivered_at
                    if state.accounting_started_at is None:
                        state.accounting_started_at = delivered_at
                    if state.consecutive_retries:
                        state.recovery_transitions += 1
                        state.last_recovery_at = delivered_at
                    state.consecutive_retries = 0
                    state.last_success_at = delivered_at
                    state.last_failure_category = None
                if result == "accepted":
                    state.accepted += 1
                elif result == "duplicate":
                    state.duplicate_attempts += 1
                else:
                    state.rejected += 1
                    state.delivery_rejected += 1
                    state.last_failure_at = time.time()
                    state.last_failure_category = "delivery_rejected"
                    state.terminal_blocked = True
                    terminal_blocked = True
                    handle.seek(line_start)
                    break
                processed += 1
        if self.config.adaptive_enabled:
            state.current_batch_size = self.adaptive.observe(
                request_latencies_ms=request_latencies_ms,
                blocked=retry_blocked or terminal_blocked,
            )
        state.updated_at = time.time()
        self._save_state(state)
        wait_seconds = self.config.poll_seconds
        if retry_blocked:
            exponent = min(max(state.consecutive_retries - 1, 0), 10)
            wait_seconds = min(
                self.config.retry_backoff_max_seconds,
                self.config.poll_seconds * (2**exponent),
            )
        return {
            "processed": processed,
            "retry_blocked": retry_blocked,
            "terminal_blocked": terminal_blocked,
            "offset": state.offset,
            "wait_seconds": wait_seconds,
        }

    def run(self, stop_event: Event) -> None:
        log_event(self.logger, logging.INFO, "event_shipper_started")
        while not stop_event.is_set():
            try:
                result = self.run_batch()
                if (
                    result["processed"] == 0
                    or result["retry_blocked"]
                    or result["terminal_blocked"]
                ):
                    stop_event.wait(float(result["wait_seconds"]))
            except OSError as exc:
                log_event(
                    self.logger,
                    logging.WARNING,
                    "event_shipper_source_unavailable",
                    error_type=type(exc).__name__,
                )
                stop_event.wait(self.config.poll_seconds)
            except Exception as exc:
                log_event(
                    self.logger,
                    logging.ERROR,
                    "event_shipper_batch_failed",
                    error_type=type(exc).__name__,
                )
                stop_event.wait(self.config.poll_seconds)
        log_event(self.logger, logging.INFO, "event_shipper_stopped")


def run_event_worker(config: SenderConfig, *, logger: logging.Logger) -> int:
    event_config = EventShipperConfig.from_sender(config)
    stop_event = Event()

    def stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    shipper = ArchiveEventShipper(event_config, logger=logger)
    try:
        shipper.run(stop_event)
    finally:
        shipper.close()
    return 0
