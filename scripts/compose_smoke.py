"""Deterministic HTTPS smoke test for an isolated local Compose deployment.

This script deliberately permits a self-signed certificate only when
CYBERQALQON_SMOKE_ALLOW_SELF_SIGNED=true. It is not a production client.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


class Client:
    def __init__(self, base_url: str, *, allow_self_signed: bool) -> None:
        context = ssl.create_default_context()
        if allow_self_signed:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.base_url = base_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=context),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any | None = None,
        headers: dict[str, str] | None = None,
        expected: int = 200,
    ) -> tuple[Any, Any]:
        request_headers = {"Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=request_headers, method=method
        )
        try:
            response = self.opener.open(request, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        payload_bytes = response.read()
        if response.status != expected:
            raise AssertionError(
                f"{method} {path}: expected {expected}, got {response.status}: "
                f"{payload_bytes[:300]!r}"
            )
        content_type = response.headers.get("Content-Type", "")
        payload = (
            json.loads(payload_bytes.decode("utf-8"))
            if payload_bytes and "json" in content_type
            else payload_bytes.decode("utf-8", errors="replace")
        )
        return payload, response.headers


def _assert_security_headers(headers: Any) -> None:
    required = {
        "Strict-Transport-Security": "max-age=",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "frame-ancestors 'none'",
        "Permissions-Policy": "camera=()",
    }
    for name, expected in required.items():
        actual = headers.get(name, "")
        if expected not in actual:
            raise AssertionError(f"missing or invalid {name}: {actual!r}")


def main() -> int:
    base_url = os.getenv("CYBERQALQON_SMOKE_URL", "https://localhost:18443").rstrip("/")
    origin = os.getenv("CYBERQALQON_SMOKE_ORIGIN", base_url).rstrip("/")
    username = _required("CYBERQALQON_SMOKE_USERNAME")
    password = _required("CYBERQALQON_SMOKE_PASSWORD")
    ingest_key = _required("CYBERQALQON_SMOKE_INGEST_KEY")
    allow_self_signed = os.getenv("CYBERQALQON_SMOKE_ALLOW_SELF_SIGNED", "false").lower() == "true"
    client = Client(base_url, allow_self_signed=allow_self_signed)

    health, health_headers = client.request("GET", "/health")
    assert health["status"] == "ok"
    _assert_security_headers(health_headers)
    readiness, _ = client.request("GET", "/readiness")
    assert readiness == {"status": "ready"}
    for path in ("/", "/alerts", "/incidents"):
        _, headers = client.request("GET", path)
        _assert_security_headers(headers)

    sample = json.loads(
        (REPOSITORY_ROOT / "wazuh" / "samples" / "authentication-failure.json").read_text(
            encoding="utf-8-sig"
        )
    )
    ingested, _ = client.request(
        "POST",
        "/api/v1/alerts/ingest",
        body=sample,
        headers={"X-API-Key": ingest_key},
        expected=201,
    )
    alert_id = ingested["alert"]["alert_id"]

    session, login_headers = client.request(
        "POST",
        "/api/v1/auth/login",
        body={"username": username, "password": password},
        headers={"Origin": origin},
    )
    set_cookie = "; ".join(login_headers.get_all("Set-Cookie", []))
    for attribute in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
        if attribute.lower() not in set_cookie.lower():
            raise AssertionError(f"session cookie is missing {attribute}")
    csrf = session["csrf_token"]
    mutation_headers = {"Origin": origin, "X-CSRF-Token": csrf}

    client.request("GET", "/api/v1/auth/session")
    alerts, alert_headers = client.request("GET", "/api/v1/alerts?limit=10")
    assert any(item["alert_id"] == alert_id for item in alerts["items"])
    _assert_security_headers(alert_headers)
    assert "no-store" in alert_headers.get("Cache-Control", "")
    incident, _ = client.request(
        "POST",
        "/api/v1/incidents",
        body={"title": "Compose smoke incident", "severity": "HIGH", "alert_ids": [alert_id]},
        headers=mutation_headers,
        expected=201,
    )
    incident_id = incident["incident_id"]
    client.request(
        "PATCH",
        f"/api/v1/incidents/{incident_id}/status",
        body={"status": "TRIAGED"},
        headers=mutation_headers,
    )
    client.request(
        "POST",
        f"/api/v1/incidents/{incident_id}/notes",
        body={"body": "Synthetic deployment smoke note"},
        headers=mutation_headers,
        expected=201,
    )
    ai_status, _ = client.request("GET", "/api/v1/ai/status")
    assert ai_status["state"] in {"DISABLED", "AVAILABLE", "UNAVAILABLE", "MISCONFIGURED"}

    client.request(
        "POST",
        "/api/v1/alerts/ingest",
        body=sample,
        headers={"Origin": origin},
        expected=401,
    )
    client.request("POST", "/api/v1/auth/logout", headers=mutation_headers, expected=204)
    client.request(
        "GET", "/api/v1/alerts", headers={"X-API-Key": ingest_key}, expected=401
    )
    print("Compose HTTPS smoke test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, OSError, ValueError) as exc:
        print(f"Compose smoke test failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
