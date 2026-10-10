"""Bounded incremental shipper for selected Wazuh archives.json security events."""

from __future__ import annotations

import json
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
from .logging import log_event


DEFAULT_ARCHIVE_PATH = Path("/var/ossec/logs/archives/archives.json")
DEFAULT_STATE_PATH = Path("/var/lib/cyberqalqon-sender/event-shipper-state.json")
SELECTED_WINDOWS_EVENT_IDS = {"1102", "4104", "4624", "4625", "4720", "4726", "4732", "7045", "1116", "1117"}


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

    @classmethod
    def from_sender(cls, sender: SenderConfig) -> "EventShipperConfig":
        env = os.environ
        archive = Path(env.get("CYBERQALQON_EVENT_ARCHIVE", str(DEFAULT_ARCHIVE_PATH)))
        state = Path(env.get("CYBERQALQON_EVENT_STATE", str(DEFAULT_STATE_PATH)))
        poll = float(env.get("CYBERQALQON_EVENT_POLL_SECONDS", "5"))
        batch = int(env.get("CYBERQALQON_EVENT_BATCH_SIZE", "200"))
        bootstrap = int(env.get("CYBERQALQON_EVENT_BOOTSTRAP_BYTES", str(16 * 1024 * 1024)))
        maximum = int(env.get("CYBERQALQON_EVENT_MAX_BYTES", "262144"))
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
    updated_at: float = 0.0

    def as_dict(self) -> dict[str, int | float]:
        return {
            "version": 2,
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
    return str(system.get("eventID", system.get("eventId", ""))) in SELECTED_WINDOWS_EVENT_IDS


class EventDeliveryClient:
    def __init__(self, config: EventShipperConfig) -> None:
        context = ssl.create_default_context(
            cafile=str(config.ca_bundle) if config.ca_bundle is not None else None
        )
        self.endpoint = config.endpoint
        self.api_key = config.api_key
        self.client = httpx.Client(
            verify=context,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                config.request_timeout_seconds,
                connect=config.connect_timeout_seconds,
            ),
        )

    def close(self) -> None:
        self.client.close()

    def deliver(self, payload: bytes) -> str:
        try:
            response = self.client.post(
                self.endpoint,
                headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
                content=payload,
            )
        except httpx.HTTPError:
            return "retry"
        if response.status_code in {200, 201}:
            return "accepted"
        if response.status_code in {400, 409, 413, 415, 422}:
            return "rejected"
        return "retry"


class ArchiveEventShipper:
    def __init__(self, config: EventShipperConfig, *, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.delivery = EventDeliveryClient(config)

    def close(self) -> None:
        self.delivery.close()

    def _load_state(self, stat: os.stat_result) -> CursorState:
        try:
            raw = json.loads(self.config.state_path.read_text(encoding="utf-8"))
            if (
                raw.get("version") in {1, 2}
                and int(raw["device"]) == stat.st_dev
                and int(raw["inode"]) == stat.st_ino
                and 0 <= int(raw["offset"]) <= stat.st_size
            ):
                return CursorState(
                    device=stat.st_dev,
                    inode=stat.st_ino,
                    offset=int(raw["offset"]),
                    accepted=max(0, int(raw.get("accepted", 0))),
                    skipped=max(0, int(raw.get("skipped", 0))),
                    rejected=max(0, int(raw.get("rejected", 0))),
                    filtered_events=max(0, int(raw.get("filtered_events", raw.get("skipped", 0)))),
                    malformed_json=max(0, int(raw.get("malformed_json", 0))),
                    oversized_lines=max(0, int(raw.get("oversized_lines", 0))),
                    delivery_rejected=max(0, int(raw.get("delivery_rejected", 0))),
                    retry_attempts=max(0, int(raw.get("retry_attempts", 0))),
                    updated_at=float(raw.get("updated_at", 0)),
                )
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            pass
        return CursorState(
            device=stat.st_dev,
            inode=stat.st_ino,
            offset=max(0, stat.st_size - self.config.bootstrap_bytes),
        )

    def _save_state(self, state: CursorState) -> None:
        self.config.state_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        temporary = self.config.state_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(state.as_dict(), separators=(",", ":")),
            encoding="utf-8",
        )
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        os.replace(temporary, self.config.state_path)

    @staticmethod
    def _discard_line_remainder(handle: Any, chunk: bytes) -> None:
        while chunk and not chunk.endswith(b"\n"):
            chunk = handle.readline(65_536)

    def run_batch(self) -> dict[str, int | bool]:
        stat = self.config.archive_path.stat()
        state = self._load_state(stat)
        processed = 0
        retry_blocked = False
        with self.config.archive_path.open("rb") as handle:
            handle.seek(state.offset)
            if state.offset > 0 and state.updated_at == 0:
                handle.readline()
                state.offset = handle.tell()
            while processed < self.config.batch_size:
                line_start = handle.tell()
                line = handle.readline(self.config.max_line_bytes + 1)
                if not line:
                    break
                if len(line) > self.config.max_line_bytes or not line.endswith(b"\n"):
                    self._discard_line_remainder(handle, line)
                    state.offset = handle.tell()
                    state.rejected += 1
                    state.oversized_lines += 1
                    processed += 1
                    continue
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
                result = self.delivery.deliver(line.rstrip(b"\r\n"))
                if result == "retry":
                    handle.seek(line_start)
                    state.retry_attempts += 1
                    retry_blocked = True
                    break
                state.offset = handle.tell()
                if result == "accepted":
                    state.accepted += 1
                else:
                    state.rejected += 1
                    state.delivery_rejected += 1
                processed += 1
        state.updated_at = time.time()
        self._save_state(state)
        return {"processed": processed, "retry_blocked": retry_blocked, "offset": state.offset}

    def run(self, stop_event: Event) -> None:
        log_event(self.logger, logging.INFO, "event_shipper_started")
        while not stop_event.is_set():
            try:
                result = self.run_batch()
                if result["processed"] == 0 or result["retry_blocked"]:
                    stop_event.wait(self.config.poll_seconds)
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
