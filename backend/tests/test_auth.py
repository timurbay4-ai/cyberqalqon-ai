from __future__ import annotations

import hashlib
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.cli.bootstrap_analyst import main as bootstrap_main
from app.core.config import Settings, get_settings
from app.db.auth import BootstrapAlreadyCompletedError
from app.main import create_app
from app.schemas.auth import AnalystCreate, AnalystRole
from tests.conftest import TEST_ORIGIN, TEST_PASSWORD


def _bootstrap(client: TestClient, username: str = "admin", password: str = TEST_PASSWORD) -> dict:
    analyst = client.app.state.auth_repository.bootstrap_first_admin(
        AnalystCreate(
            username=username,
            display_name="Security Administrator",
            password=password,
            role=AnalystRole.ADMIN,
        )
    )
    return analyst.model_dump(mode="json")


def _login(client: TestClient, username: str = "admin", password: str = TEST_PASSWORD) -> dict:
    response = client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _csrf(session: dict) -> dict[str, str]:
    return {"Origin": TEST_ORIGIN, "X-CSRF-Token": session["csrf_token"]}


def test_fresh_database_bootstrap_hashes_password_and_is_one_time(
    unauthenticated_client: TestClient,
    database_path: Path,
) -> None:
    analyst = _bootstrap(unauthenticated_client)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT username_normalized, password_hash FROM analysts WHERE analyst_id = ?",
            (analyst["analyst_id"],),
        ).fetchone()
        tables = {
            item[0]
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert {"analysts", "analyst_sessions"}.issubset(tables)
    assert row is not None
    assert row[0] == "admin"
    assert row[1].startswith("$argon2id$")
    assert TEST_PASSWORD not in row[1]
    with pytest.raises(BootstrapAlreadyCompletedError):
        _bootstrap(unauthenticated_client, username="other-admin")


def test_bootstrap_cli_reads_password_from_stdin_and_refuses_repeat(
    database_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database_path.as_posix()}")
    get_settings.cache_clear()
    monkeypatch.setattr("sys.stdin", io.StringIO(TEST_PASSWORD + "\n"))
    assert bootstrap_main([
        "--username", "bootstrap-admin",
        "--display-name", "Bootstrap Administrator",
        "--password-stdin",
    ]) == 0
    assert "Created administrator bootstrap-admin" in capsys.readouterr().out

    monkeypatch.setattr("sys.stdin", io.StringIO("Another-Secure-Password-99\n"))
    assert bootstrap_main([
        "--username", "second-admin",
        "--display-name", "Second Administrator",
        "--password-stdin",
    ]) == 3
    assert "already exists" in capsys.readouterr().err
    get_settings.cache_clear()


def test_login_creates_digest_only_session_and_rejects_invalid_credentials(
    unauthenticated_client: TestClient,
    database_path: Path,
) -> None:
    _bootstrap(unauthenticated_client)
    invalid = unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "admin", "password": "incorrect-password"},
    )
    assert invalid.status_code == 401
    assert invalid.json()["detail"]["code"] == "invalid_credentials"

    response = unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "admin", "password": TEST_PASSWORD},
    )
    assert response.status_code == 200
    session = response.json()
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/" in set_cookie
    cookie = unauthenticated_client.cookies.get("cyberqalqon_session")
    assert cookie is not None
    with sqlite3.connect(database_path) as connection:
        stored = connection.execute(
            "SELECT token_digest, csrf_token FROM analyst_sessions"
        ).fetchone()
    assert stored is not None
    assert stored[0] == hashlib.sha256(cookie.encode()).hexdigest()
    assert stored[0] != cookie
    assert stored[1] == session["csrf_token"]
    assert "password" not in str(session).lower()


def test_production_session_uses_secure_host_cookie(database_path: Path) -> None:
    settings = Settings(
        app_env="production",
        database_url=f"sqlite:///{database_path.as_posix()}",
        cors_origins=("https://soc.example",),
        session_cookie_secure=True,
    )
    with TestClient(create_app(settings), base_url="https://api.example") as client:
        _bootstrap(client)
        response = client.post(
            "/api/v1/auth/login",
            headers={"Origin": "https://soc.example"},
            json={"username": "admin", "password": TEST_PASSWORD},
        )
    cookie = response.headers["set-cookie"].lower()
    assert response.status_code == 200
    assert "__host-cyberqalqon_session=" in cookie
    assert "secure" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie


def test_login_requires_trusted_origin_and_malformed_data_is_structured(
    unauthenticated_client: TestClient,
) -> None:
    _bootstrap(unauthenticated_client)
    missing_origin = unauthenticated_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": TEST_PASSWORD},
    )
    disallowed_origin = unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": "https://attacker.invalid"},
        json={"username": "admin", "password": TEST_PASSWORD},
    )
    malformed = unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "x", "password": TEST_PASSWORD},
    )
    assert missing_origin.status_code == 403
    assert disallowed_origin.status_code == 403
    assert disallowed_origin.json()["detail"]["code"] == "untrusted_origin"
    assert malformed.status_code == 422
    assert malformed.json()["detail"]["code"] == "invalid_request"


def test_session_expiration_logout_and_persistence_across_restart(database_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        wazuh_ingest_api_key="machine-secret",
    )
    with TestClient(create_app(settings)) as first:
        _bootstrap(first)
        session = _login(first)
        persisted_cookie = first.cookies.get("cyberqalqon_session")
        assert first.get("/api/v1/auth/session").status_code == 200

    with TestClient(create_app(settings)) as second:
        second.cookies.set("cyberqalqon_session", persisted_cookie)
        assert second.get("/api/v1/auth/session").status_code == 200
        logout = second.post("/api/v1/auth/logout", headers=_csrf(session))
        assert logout.status_code == 204
        assert second.get("/api/v1/auth/session").status_code == 401

        relogin = _login(second)
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                "UPDATE analyst_sessions SET expires_at = ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),),
            )
        expired = second.get("/api/v1/auth/session")
        assert expired.status_code == 401
        assert expired.json()["detail"]["code"] == "authentication_required"
        assert relogin["analyst"]["username"] == "admin"


def test_account_lockout_limits_repeated_password_attempts(
    unauthenticated_client: TestClient,
    database_path: Path,
) -> None:
    _bootstrap(unauthenticated_client)
    for _ in range(5):
        response = unauthenticated_client.post(
            "/api/v1/auth/login",
            headers={"Origin": TEST_ORIGIN},
            json={"username": "admin", "password": "wrong-password-value"},
        )
        assert response.status_code == 401
    assert unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "admin", "password": TEST_PASSWORD},
    ).status_code == 401
    with sqlite3.connect(database_path) as connection:
        locked_until = connection.execute(
            "SELECT locked_until FROM analysts WHERE username_normalized = 'admin'"
        ).fetchone()[0]
    assert locked_until is not None


def test_active_sessions_are_bounded_per_analyst(
    unauthenticated_client: TestClient,
    database_path: Path,
) -> None:
    _bootstrap(unauthenticated_client)
    repository = unauthenticated_client.app.state.auth_repository
    principal = repository.authenticate("admin", TEST_PASSWORD)
    assert principal is not None
    for _ in range(12):
        repository.create_session(principal)
    with sqlite3.connect(database_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM analyst_sessions WHERE analyst_id = ?",
            (principal.analyst_id,),
        ).fetchone()[0]
    assert count == 10


def test_soc_reads_require_human_session_and_machine_key_is_not_accepted(
    unauthenticated_client: TestClient,
    sample_alert: dict,
) -> None:
    _bootstrap(unauthenticated_client)
    unauthenticated = unauthenticated_client.get("/api/v1/alerts")
    machine_only = unauthenticated_client.get(
        "/api/v1/alerts", headers={"X-API-Key": "test-ingest-key"}
    )
    incident_read = unauthenticated_client.get("/api/v1/incidents")
    assert unauthenticated.status_code == 401
    assert machine_only.status_code == 401
    assert incident_read.status_code == 401

    ingested = unauthenticated_client.post(
        "/api/v1/alerts/ingest",
        headers={"X-API-Key": "test-ingest-key"},
        json=sample_alert,
    )
    assert ingested.status_code == 201
    _login(unauthenticated_client)
    assert unauthenticated_client.get("/api/v1/alerts").status_code == 200

    analyst_cookie_only = unauthenticated_client.post(
        "/api/v1/alerts/ingest", json=sample_alert
    )
    assert analyst_cookie_only.status_code == 401
    assert analyst_cookie_only.json()["detail"]["code"] == "invalid_api_key"


def test_csrf_and_authorization_protect_incident_mutations(
    unauthenticated_client: TestClient,
) -> None:
    admin = _bootstrap(unauthenticated_client)
    session = _login(unauthenticated_client)
    payload = {"title": "Protected incident", "severity": "HIGH"}
    missing = unauthenticated_client.post("/api/v1/incidents", json=payload)
    invalid = unauthenticated_client.post(
        "/api/v1/incidents",
        headers={"Origin": TEST_ORIGIN, "X-CSRF-Token": "wrong"},
        json=payload,
    )
    disallowed = unauthenticated_client.post(
        "/api/v1/incidents",
        headers={"Origin": "https://attacker.invalid", "X-CSRF-Token": session["csrf_token"]},
        json=payload,
    )
    assert missing.status_code == 403
    assert invalid.status_code == 403
    assert invalid.json()["detail"]["code"] == "invalid_csrf_token"
    assert disallowed.status_code == 403

    created = unauthenticated_client.post(
        "/api/v1/incidents", headers=_csrf(session), json=payload
    )
    assert created.status_code == 201
    history = created.json()["history"]
    assert history[0]["actor_id"] == admin["analyst_id"]
    assert history[0]["actor"] == "Security Administrator (admin)"

    impersonation = unauthenticated_client.post(
        "/api/v1/incidents",
        headers=_csrf(session),
        json={**payload, "actor": "another-user"},
    )
    assert impersonation.status_code == 422


def test_viewer_can_read_but_cannot_mutate_and_admin_can_manage_accounts(
    unauthenticated_client: TestClient,
) -> None:
    _bootstrap(unauthenticated_client)
    admin_session = _login(unauthenticated_client)
    created = unauthenticated_client.post(
        "/api/v1/auth/analysts",
        headers=_csrf(admin_session),
        json={
            "username": "viewer.one",
            "display_name": "Read Only",
            "password": "Viewer-Secure-Password-88",
            "role": "VIEWER",
        },
    )
    assert created.status_code == 201
    viewer = created.json()
    viewer_session = _login(
        unauthenticated_client,
        username="viewer.one",
        password="Viewer-Secure-Password-88",
    )
    assert unauthenticated_client.get("/api/v1/incidents").status_code == 200
    forbidden = unauthenticated_client.post(
        "/api/v1/incidents",
        headers=_csrf(viewer_session),
        json={"title": "Forbidden", "severity": "LOW"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["code"] == "permission_denied"
    assert unauthenticated_client.get("/api/v1/audit-events").status_code == 403

    settings = unauthenticated_client.app.state.settings
    with TestClient(create_app(settings)) as admin_client:
        restored_admin = _login(admin_client)
        disabled = admin_client.patch(
            f"/api/v1/auth/analysts/{viewer['analyst_id']}",
            headers=_csrf(restored_admin),
            json={"is_active": False},
        )
        assert disabled.status_code == 200
        assert disabled.json()["is_active"] is False
    assert unauthenticated_client.get("/api/v1/auth/session").status_code == 401


def test_password_change_preserves_current_session_revokes_others_and_is_audited(
    unauthenticated_client: TestClient,
) -> None:
    _bootstrap(unauthenticated_client)
    session = _login(unauthenticated_client)
    repository = unauthenticated_client.app.state.auth_repository
    principal = repository.authenticate("admin", TEST_PASSWORD)
    assert principal is not None
    repository.create_session(principal)
    repository.create_session(principal)

    before = unauthenticated_client.get("/api/v1/auth/sessions")
    assert before.status_code == 200
    assert before.json()["active_sessions"] == 3

    changed = unauthenticated_client.patch(
        "/api/v1/auth/password",
        headers=_csrf(session),
        json={
            "current_password": TEST_PASSWORD,
            "new_password": "New-Correct-Horse-Battery-88",
        },
    )
    assert changed.status_code == 204
    assert unauthenticated_client.get("/api/v1/auth/session").status_code == 200
    assert unauthenticated_client.get("/api/v1/auth/sessions").json()["active_sessions"] == 1

    unauthenticated_client.post("/api/v1/auth/logout", headers=_csrf(session))
    assert unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "admin", "password": TEST_PASSWORD},
    ).status_code == 401
    assert unauthenticated_client.post(
        "/api/v1/auth/login",
        headers={"Origin": TEST_ORIGIN},
        json={"username": "admin", "password": "New-Correct-Horse-Battery-88"},
    ).status_code == 200
    audit = unauthenticated_client.get("/api/v1/audit-events")
    assert audit.status_code == 200
    assert "PASSWORD_CHANGED" in {item["action"] for item in audit.json()["items"]}


def test_invalid_current_password_is_denied_without_changing_credential(
    unauthenticated_client: TestClient,
) -> None:
    _bootstrap(unauthenticated_client)
    session = _login(unauthenticated_client)
    response = unauthenticated_client.patch(
        "/api/v1/auth/password",
        headers=_csrf(session),
        json={"current_password": "wrong", "new_password": "New-Correct-Horse-Battery-88"},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "invalid_current_password"
    assert unauthenticated_client.app.state.auth_repository.authenticate("admin", TEST_PASSWORD) is not None


def test_credentialed_cors_is_explicit(unauthenticated_client: TestClient) -> None:
    allowed = unauthenticated_client.options(
        "/api/v1/incidents",
        headers={
            "Origin": TEST_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-csrf-token",
        },
    )
    denied = unauthenticated_client.options(
        "/api/v1/incidents",
        headers={
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == TEST_ORIGIN
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert "*" not in allowed.headers["access-control-allow-origin"]
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_production_refuses_insecure_session_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    with pytest.raises(ValueError, match="SESSION_COOKIE_SECURE"):
        Settings.from_env()


def test_settings_reject_wildcard_credentialed_cors() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        Settings(cors_origins=("*",))
