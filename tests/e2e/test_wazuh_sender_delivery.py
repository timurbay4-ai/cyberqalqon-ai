from __future__ import annotations

import io
import json
import logging
import socket
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import httpx
import uvicorn


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "backend"))
sys.path.insert(0, str(REPOSITORY_ROOT / "wazuh"))

from app.core.config import Settings  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from app.db.auth import AuthRepository  # noqa: E402
from app.main import create_app  # noqa: E402
from app.schemas.auth import AnalystCreate, AnalystRole  # noqa: E402
from cyberqalqon_sender.config import SenderConfig  # noqa: E402
from cyberqalqon_sender.http import HttpDeliveryClient  # noqa: E402
from cyberqalqon_sender.logging import configure_logging  # noqa: E402
from cyberqalqon_sender.models import DeliveryClassification  # noqa: E402
from cyberqalqon_sender.payloads import parse_payload_bytes  # noqa: E402
from cyberqalqon_sender.runtime import build_spool  # noqa: E402
from cyberqalqon_sender.service import SenderService  # noqa: E402


class Clock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


class LiveBackend:
    def __init__(self, app, port: int) -> None:
        self.port = port
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                log_level="warning",
                access_log=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and time.monotonic() < deadline:
            if not self.thread.is_alive():
                raise RuntimeError("test backend exited during startup")
            time.sleep(0.01)
        if not self.server.started:
            raise RuntimeError("test backend did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise RuntimeError("test backend did not stop")


def _sender_service(
    config: SenderConfig,
    clock: Clock,
    *,
    logger: logging.Logger | None = None,
):
    spool = build_spool(config)
    client = HttpDeliveryClient(config)
    service = SenderService(
        config,
        spool,
        client,
        clock=clock,
        random_source=lambda: 0.5,
        logger=logger,
    )
    return spool, client, service


def test_real_http_delivery_outage_restart_idempotency_conflict_and_auth(tmp_path: Path) -> None:
    backend_db = tmp_path / "backend.db"
    sender_db = tmp_path / "sender.db"
    machine_key = "temporary-e2e-machine-key-00000001"
    wrong_key = "temporary-e2e-wrong-key-0000000002"
    analyst_password = "Temporary-E2E-Analyst-Password-77"
    origin = "http://localhost:5173"
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    backend_settings = Settings(
        app_env="test",
        database_url=f"sqlite:///{backend_db.as_posix()}",
        cors_origins=(origin,),
        wazuh_ingest_api_key=machine_key,
        session_cookie_secure=False,
    )
    alert_repository = AlertRepository(backend_settings.database_url)
    alert_repository.initialize()
    AuthRepository(alert_repository.path, backend_settings).bootstrap_first_admin(
        AnalystCreate(
            username="e2e-admin",
            display_name="E2E Administrator",
            password=analyst_password,
            role=AnalystRole.ADMIN,
        )
    )
    backend_app = create_app(backend_settings)
    server = LiveBackend(backend_app, port)
    server.start()

    sender_config = SenderConfig(
        backend_url=base_url,
        api_key=machine_key,
        database_path=sender_db,
        connect_timeout_seconds=0.5,
        request_timeout_seconds=1.0,
        max_attempts=3,
        backoff_base_seconds=1.0,
        backoff_max_seconds=10.0,
        backoff_jitter_ratio=0.0,
        queue_max_items=20,
        queue_max_bytes=1_048_576,
        dead_letter_max_items=20,
        dead_letter_max_bytes=1_048_576,
        max_payload_bytes=64_000,
        lease_seconds=10.0,
        allow_insecure_http=True,
    )
    raw = json.loads(
        (REPOSITORY_ROOT / "wazuh" / "samples" / "authentication-failure.json").read_text(
            encoding="utf-8"
        )
    )
    raw["id"] = "e2e-normal-001"
    first_payload = parse_payload_bytes(
        json.dumps(raw, ensure_ascii=False).encode(), maximum_bytes=64_000
    )
    clock = Clock(1_800_000_000.0)

    try:
        spool, sender_client, sender = _sender_service(sender_config, clock)
        first = sender.submit(first_payload)
        sender_client.close()
        assert first.classification == DeliveryClassification.DELIVERED
        assert spool.status().queue_depth == 0

        analyst = httpx.Client(base_url=base_url, headers={"Origin": origin})
        login = analyst.post(
            "/api/v1/auth/login",
            json={"username": "e2e-admin", "password": analyst_password},
        )
        assert login.status_code == 200, login.text
        alert_read = analyst.get("/api/v1/alerts/e2e-normal-001")
        assert alert_read.status_code == 200, alert_read.text
        assert alert_read.json()["alert_id"] == "e2e-normal-001"

        assert httpx.get(
            f"{base_url}/api/v1/alerts",
            headers={"X-API-Key": machine_key},
        ).status_code == 401
        assert analyst.post(
            "/api/v1/alerts/ingest",
            json=raw,
        ).status_code == 401

        analyst.close()
        server.stop()
        outage_raw = dict(raw)
        outage_raw["id"] = "e2e-outage-002"
        outage_payload = parse_payload_bytes(
            json.dumps(outage_raw, ensure_ascii=False).encode(), maximum_bytes=64_000
        )
        outage_spool, outage_client, outage_sender = _sender_service(sender_config, clock)
        queued = outage_sender.submit(outage_payload)
        outage_client.close()
        assert queued.classification == DeliveryClassification.TRANSIENT_FAILURE
        assert queued.next_retry_at == clock.value + 1
        assert outage_spool.status().queue_depth == 1

        restarted_spool = build_spool(sender_config)
        assert restarted_spool.status().queue_depth == 1

        server = LiveBackend(create_app(backend_settings), port)
        server.start()
        analyst = httpx.Client(base_url=base_url, headers={"Origin": origin})
        relogin = analyst.post(
            "/api/v1/auth/login",
            json={"username": "e2e-admin", "password": analyst_password},
        )
        assert relogin.status_code == 200, relogin.text
        clock.value += 1
        recovered_spool, recovered_client, recovered_sender = _sender_service(
            sender_config, clock
        )
        recovery = recovered_sender.drain()
        recovered_client.close()
        assert recovery.delivered == 1
        assert recovered_spool.status().queue_depth == 0
        assert analyst.get("/api/v1/alerts/e2e-outage-002").status_code == 200

        duplicate_spool, duplicate_client, duplicate_sender = _sender_service(
            sender_config, clock
        )
        duplicate = duplicate_sender.submit(outage_payload)
        duplicate_client.close()
        assert duplicate.classification == DeliveryClassification.DUPLICATE
        listed = analyst.get("/api/v1/alerts", params={"limit": 100})
        assert listed.status_code == 200
        assert sum(
            item["alert_id"] == "e2e-outage-002" for item in listed.json()["items"]
        ) == 1

        conflict_raw = dict(outage_raw)
        conflict_raw["rule"] = dict(outage_raw["rule"])
        conflict_raw["rule"]["description"] = "different event with reused identifier"
        conflict_payload = parse_payload_bytes(
            json.dumps(conflict_raw, ensure_ascii=False).encode(), maximum_bytes=64_000
        )
        conflict_spool, conflict_client, conflict_sender = _sender_service(
            sender_config, clock
        )
        conflict = conflict_sender.submit(conflict_payload)
        conflict_client.close()
        assert conflict.classification == DeliveryClassification.CONFLICT
        assert conflict.dead_letter_id is not None
        conflict_record = conflict_spool.get_dead_letter(conflict.dead_letter_id)
        assert conflict_record is not None
        assert conflict_record["http_status"] == 409

        auth_raw = dict(raw)
        auth_raw["id"] = "e2e-auth-failure-003"
        auth_payload = parse_payload_bytes(
            json.dumps(auth_raw, ensure_ascii=False).encode(), maximum_bytes=64_000
        )
        log_stream = io.StringIO()
        logger = configure_logging("INFO")
        original_handlers = logger.handlers[:]
        logger.handlers.clear()
        logger.addHandler(logging.StreamHandler(log_stream))
        wrong_config = replace(sender_config, api_key=wrong_key)
        try:
            auth_spool, auth_client, auth_sender = _sender_service(
                wrong_config, clock, logger=logger
            )
            auth_failure = auth_sender.submit(auth_payload)
            auth_client.close()
        finally:
            logger.handlers.clear()
            logger.handlers.extend(original_handlers)
        assert auth_failure.classification == DeliveryClassification.PERMANENT_FAILURE
        assert auth_failure.http_status == 401
        assert auth_failure.dead_letter_id is not None
        assert auth_spool.status().queue_depth == 0
        assert wrong_key not in log_stream.getvalue()
        assert wrong_key.encode() not in sender_db.read_bytes()
        assert analyst.get("/api/v1/alerts/e2e-auth-failure-003").status_code == 404
        analyst.close()
    finally:
        if server.thread.is_alive():
            server.stop()

    assert backend_db.exists()
    assert sender_db.exists()
