#!/usr/bin/env python3
"""Validate authenticated CQQL cancellation over a real disposable TCP server."""

from __future__ import annotations

import argparse
import http.client
import json
import secrets
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))

import uvicorn  # noqa: E402

import benchmark_cqql as benchmark  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.db.alerts import AlertRepository  # noqa: E402
from app.db.auth import AuthRepository  # noqa: E402
from app.db.cqql import (  # noqa: E402
    CQQL_QUERY_DEADLINE_SECONDS,
    CQQLQueryCancelledError,
    CQQLSearchRepository,
)
from app.main import create_app  # noqa: E402
from app.schemas.auth import AnalystCreate, AnalystRole  # noqa: E402


class ObservedRepository:
    """Instrument the real repository without changing its cancellation path."""

    def __init__(self, repository: CQQLSearchRepository) -> None:
        self.repository = repository
        self.worker_started = threading.Event()
        self.worker_released = threading.Event()
        self.cancel_observed = threading.Event()
        self.lock = threading.Lock()
        self.active_workers = 0
        self.peak_workers = 0
        self.release_time: float | None = None
        self.slow_fixture_remaining = 0
        self.started_workers = 0
        self.released_workers = 0
        self.cancel_observed_count = 0

    def arm_slow_fixtures(self, count: int) -> None:
        with self.lock:
            self.slow_fixture_remaining += count

    def _bounded_slow_fixture(self, cancel_event: threading.Event):  # type: ignore[no-untyped-def]
        """Exercise the production semaphore/deadline/translation primitives."""

        acquired = False
        connection: sqlite3.Connection | None = None
        try:
            self.repository._acquire_slot(cancel_event)  # noqa: SLF001
            acquired = True
            connection = self.repository._connect()  # noqa: SLF001
            self.repository._install_deadline(  # noqa: SLF001
                connection,
                time.perf_counter() + CQQL_QUERY_DEADLINE_SECONDS,
                cancel_event,
            )
            connection.execute(
                "WITH RECURSIVE m27(value) AS (VALUES(0) UNION ALL "
                "SELECT value + 1 FROM m27 WHERE value < 100000000) "
                "SELECT SUM(value) FROM m27"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            raise self.repository._translate_sqlite(exc, cancel_event) from exc  # noqa: SLF001
        finally:
            if connection is not None:
                connection.set_progress_handler(None, 0)
                connection.close()
            if acquired:
                self.repository._slots.release()  # noqa: SLF001

    def search(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        with self.lock:
            self.active_workers += 1
            self.peak_workers = max(self.peak_workers, self.active_workers)
            self.started_workers += 1
        self.worker_started.set()
        try:
            with self.lock:
                use_slow_fixture = self.slow_fixture_remaining > 0
                if use_slow_fixture:
                    self.slow_fixture_remaining -= 1
            if use_slow_fixture:
                return self._bounded_slow_fixture(kwargs["cancel_event"])
            return self.repository.search(*args, **kwargs)
        except CQQLQueryCancelledError:
            with self.lock:
                self.cancel_observed_count += 1
            self.cancel_observed.set()
            raise
        finally:
            with self.lock:
                self.active_workers -= 1
                self.released_workers += 1
                self.release_time = time.perf_counter()
            self.worker_released.set()

    def analytics(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        return self.repository.analytics(*args, **kwargs)

    def export(self, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        return self.repository.export(*args, **kwargs)


def _cookie_header(headers: list[tuple[str, str]]) -> str:
    cookies = [value.split(";", 1)[0] for name, value in headers if name.casefold() == "set-cookie"]
    if not cookies:
        raise RuntimeError("login response did not set an authentication cookie")
    return "; ".join(cookies)


def _post_json(
    port: int,
    path: str,
    payload: dict[str, object],
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    timeout: float = 5,
) -> tuple[int, dict[str, object], list[tuple[str, str]]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Content-Type": "application/json", "Origin": "http://localhost:5173"}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    connection.request("POST", path, body=json.dumps(payload), headers=headers)
    response = connection.getresponse()
    body = response.read()
    response_headers = response.getheaders()
    connection.close()
    return response.status, json.loads(body) if body else {}, response_headers


def _raw_authenticated_request(
    port: int,
    payload: dict[str, object],
    cookie: str,
    csrf: str,
) -> socket.socket:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = (
        "POST /api/v1/siem/search HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Origin: http://localhost:5173\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: {cookie}\r\n"
        f"X-CSRF-Token: {csrf}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("ascii") + body
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(request)
    return client


def _close_socket(client: socket.socket, *, graceful: bool) -> None:
    if graceful:
        client.shutdown(socket.SHUT_RDWR)
    client.close()


def run(rows: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="cyberqalqon-m27-tcp-") as temporary:
        database = Path(temporary) / "tcp-cancellation.db"
        AlertRepository(
            f"sqlite:///{database.as_posix()}", migration_target_version=17
        ).initialize()
        base = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)
        with closing(sqlite3.connect(database, timeout=30)) as connection:
            for batch_start in range(0, rows, 1_000):
                connection.executemany(
                    benchmark.INSERT_SQL,
                    (
                        benchmark.synthetic_row(index, base)
                        for index in range(batch_start, min(rows, batch_start + 1_000))
                    ),
                )
                connection.commit()

        password = "M27-" + secrets.token_urlsafe(24)
        settings = Settings(
            database_url=f"sqlite:///{database.as_posix()}",
            wazuh_ingest_api_key="M27-" + secrets.token_urlsafe(32),
            allow_m14_schema_migration=False,
        )
        application = create_app(settings)
        AuthRepository(database, settings).bootstrap_first_admin(
            AnalystCreate(
                username="m27-tcp-analyst",
                display_name="M27 TCP Analyst",
                password=password,
                role=AnalystRole.ADMIN,
            )
        )
        real_repository = CQQLSearchRepository(database)
        observed = ObservedRepository(real_repository)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = int(listener.getsockname()[1])
        server = uvicorn.Server(
            uvicorn.Config(application, host="127.0.0.1", port=port, log_level="error")
        )
        thread = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            name="m27-disposable-uvicorn",
            daemon=True,
        )
        thread.start()
        deadline = time.perf_counter() + 10
        while not server.started and time.perf_counter() < deadline:
            time.sleep(0.01)
        if not server.started:
            raise RuntimeError("disposable loopback server did not start")
        application.state.cqql_search_repository = observed

        try:
            status, login, headers = _post_json(
                port,
                "/api/v1/auth/login",
                {"username": "m27-tcp-analyst", "password": password},
            )
            if status != 200:
                raise RuntimeError(f"authenticated test login failed with HTTP {status}")
            cookie = _cookie_header(headers)
            csrf = str(login["csrf_token"])
            request_payload: dict[str, object] = {
                "query": 'text CONTAINS "synthetic"',
                "start_time": (base - timedelta(days=7)).isoformat(),
                "end_time": (base + timedelta(minutes=1)).isoformat(),
                "sort": "newest",
                "limit": 100,
            }

            def wait_for_counter(name: str, target: int, timeout: float = 3) -> None:
                wait_deadline = time.perf_counter() + timeout
                while time.perf_counter() < wait_deadline:
                    with observed.lock:
                        value = int(getattr(observed, name))
                    if value >= target:
                        return
                    time.sleep(0.005)
                raise RuntimeError(f"{name} did not reach {target}")

            def disconnect_scenario(query: str, *, graceful: bool = True) -> dict[str, object]:
                payload = {**request_payload, "query": query}
                with observed.lock:
                    started_before = observed.started_workers
                    released_before = observed.released_workers
                    cancelled_before = observed.cancel_observed_count
                observed.arm_slow_fixtures(1)
                client = _raw_authenticated_request(port, payload, cookie, csrf)
                wait_for_counter("started_workers", started_before + 1)
                timed_out_before_close = False
                if not graceful:
                    client.settimeout(0.01)
                    try:
                        client.recv(1)
                    except (TimeoutError, socket.timeout):
                        timed_out_before_close = True
                disconnect_at = time.perf_counter()
                _close_socket(client, graceful=graceful)
                wait_for_counter("released_workers", released_before + 1)
                with observed.lock:
                    release_at = observed.release_time or time.perf_counter()
                    cancelled_after = observed.cancel_observed_count
                return {
                    "query": query,
                    "client_timeout_before_close": timed_out_before_close,
                    "cancel_observed": cancelled_after == cancelled_before + 1,
                    "worker_release_latency_ms": round((release_at - disconnect_at) * 1_000, 3),
                }

            scenarios: dict[str, object] = {}
            scenarios["fts_disconnect_during_execution"] = disconnect_scenario(
                'text CONTAINS "synthetic"'
            )
            scenarios["nested_boolean_disconnect_during_execution"] = disconnect_scenario(
                '(event.code = "4625" OR event.code = "4688") AND event.severity >= 8'
            )
            scenarios["client_timeout_then_ungraceful_close"] = disconnect_scenario(
                'source.ip = "192.0.2.10"', graceful=False
            )

            with observed.lock:
                released_before = observed.released_workers
            observed.arm_slow_fixtures(1)
            deadline_started = time.perf_counter()
            deadline_status, deadline_body, _ = _post_json(
                port,
                "/api/v1/siem/search",
                request_payload,
                cookie=cookie,
                csrf=csrf,
                timeout=3,
            )
            wait_for_counter("released_workers", released_before + 1)
            scenarios["server_deadline"] = {
                "http_status": deadline_status,
                "error_code": (
                    deadline_body.get("detail", {}).get("code")
                    if isinstance(deadline_body.get("detail"), dict) else None
                ),
                "wall_ms": round((time.perf_counter() - deadline_started) * 1_000, 3),
            }

            with observed.lock:
                started_before = observed.started_workers
                released_before = observed.released_workers
                cancelled_before = observed.cancel_observed_count
            observed.arm_slow_fixtures(4)
            clients = [
                _raw_authenticated_request(
                    port,
                    {**request_payload, "query": 'text CONTAINS "synthetic"'},
                    cookie,
                    csrf,
                )
                for _ in range(4)
            ]
            wait_for_counter("started_workers", started_before + 4)
            concurrent_disconnected_at = time.perf_counter()
            for client in clients:
                _close_socket(client, graceful=True)
            wait_for_counter("released_workers", released_before + 4)
            with observed.lock:
                concurrent_release_at = observed.release_time or time.perf_counter()
                concurrent_cancelled = observed.cancel_observed_count - cancelled_before
            scenarios["four_concurrent_disconnects"] = {
                "cancelled_workers": concurrent_cancelled,
                "worker_release_latency_ms": round(
                    (concurrent_release_at - concurrent_disconnected_at) * 1_000, 3
                ),
            }

            held_permits = 0
            for _ in range(4):
                if real_repository._slots.acquire(timeout=0.1):  # noqa: SLF001
                    held_permits += 1
            if held_permits != 4:
                raise RuntimeError("could not create the bounded queued-request fixture")
            try:
                with observed.lock:
                    started_before = observed.started_workers
                    released_before = observed.released_workers
                    cancelled_before = observed.cancel_observed_count
                observed.arm_slow_fixtures(1)
                queued_client = _raw_authenticated_request(port, request_payload, cookie, csrf)
                wait_for_counter("started_workers", started_before + 1)
                queued_disconnected_at = time.perf_counter()
                _close_socket(queued_client, graceful=True)
                wait_for_counter("released_workers", released_before + 1)
                with observed.lock:
                    queued_release_at = observed.release_time or time.perf_counter()
                    queued_cancelled = observed.cancel_observed_count - cancelled_before
                scenarios["queued_request_disconnect"] = {
                    "cancel_observed": queued_cancelled == 1,
                    "worker_release_latency_ms": round(
                        (queued_release_at - queued_disconnected_at) * 1_000, 3
                    ),
                }
            finally:
                for _ in range(held_permits):
                    real_repository._slots.release()  # noqa: SLF001

            cpu_started = time.process_time()
            time.sleep(0.1)
            idle_cpu_ms = (time.process_time() - cpu_started) * 1_000

            with observed.lock:
                active_after = observed.active_workers
            permits = 0
            for _ in range(4):
                if real_repository._slots.acquire(timeout=0.1):  # noqa: SLF001
                    permits += 1
            for _ in range(permits):
                real_repository._slots.release()  # noqa: SLF001

            observed.worker_started.clear()
            observed.worker_released.clear()
            fresh_payload = {
                **request_payload,
                "query": 'source.ip = "192.0.2.10"',
            }
            fresh_status, fresh_body, _ = _post_json(
                port,
                "/api/v1/siem/search",
                fresh_payload,
                cookie=cookie,
                csrf=csrf,
            )
            with closing(sqlite3.connect(database)) as connection:
                quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            result = {
                "isolated_loopback": True,
                "disposable_schema": 17,
                "synthetic_rows": rows,
                "tcp_port": port,
                "authenticated": True,
                "slow_query_fixture": "bounded recursive CTE through production CQQL cancellation primitives",
                "worker_started": True,
                "sqlite_cancel_observed": observed.cancel_observed.is_set(),
                "scenarios": scenarios,
                "active_workers_after_disconnect": active_after,
                "peak_workers": observed.peak_workers,
                "semaphore_permits_restored": permits,
                "idle_cpu_100ms_process_time_ms": round(idle_cpu_ms, 3),
                "fresh_query_http_status": fresh_status,
                "fresh_query_status": (
                    fresh_body.get("metadata", {}).get("query_status")
                    if isinstance(fresh_body.get("metadata"), dict) else None
                ),
                "quick_check": quick_check,
                "foreign_key_violations": foreign_keys,
            }
            scenario_pass = all(
                (
                    scenarios["fts_disconnect_during_execution"]["cancel_observed"],
                    scenarios["nested_boolean_disconnect_during_execution"]["cancel_observed"],
                    scenarios["client_timeout_then_ungraceful_close"]["cancel_observed"],
                    scenarios["client_timeout_then_ungraceful_close"]["client_timeout_before_close"],
                    scenarios["server_deadline"]["http_status"] == 408,
                    scenarios["server_deadline"]["error_code"] == "query_timeout",
                    scenarios["four_concurrent_disconnects"]["cancelled_workers"] == 4,
                    scenarios["queued_request_disconnect"]["cancel_observed"],
                )
            )
            if not observed.cancel_observed.is_set() or not scenario_pass:
                raise RuntimeError("TCP disconnect did not reach SQLite cancellation")
            if active_after != 0 or permits != 4 or fresh_status != 200:
                raise RuntimeError("worker, semaphore, or fresh-query recovery validation failed")
            return result
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            listener.close()
            if thread.is_alive():
                raise RuntimeError("disposable loopback server thread did not stop")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.rows < 10_000 or arguments.rows > 100_000:
        parser.error("rows must be between 10000 and 100000")
    result = run(arguments.rows)
    rendered = json.dumps(result, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
