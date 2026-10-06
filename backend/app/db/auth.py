"""SQLite-backed analyst accounts and opaque server-side sessions."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from app.core.config import Settings
from app.schemas.auth import (
    ROLE_PERMISSIONS,
    AnalystCreate,
    AnalystPrincipal,
    AnalystPublic,
    AnalystRole,
    AnalystUpdate,
)
from app.security.passwords import hash_password, perform_dummy_verification, verify_password


class BootstrapAlreadyCompletedError(RuntimeError):
    pass


class DuplicateUsernameError(RuntimeError):
    pass


class AnalystNotFoundError(LookupError):
    pass


class SelfAdministrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SessionCredentials:
    token: str
    csrf_token: str
    expires_at: datetime
    principal: AnalystPrincipal


def normalize_username(username: str) -> str:
    return unicodedata.normalize("NFKC", username).casefold()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _principal_from_row(row: sqlite3.Row) -> AnalystPrincipal:
    role = AnalystRole(row["role"])
    return AnalystPrincipal(
        analyst_id=row["analyst_id"],
        username=row["username"],
        display_name=row["display_name"],
        role=role,
        permissions=list(ROLE_PERMISSIONS[role]),
    )


def _public_from_row(row: sqlite3.Row) -> AnalystPublic:
    return AnalystPublic(
        analyst_id=row["analyst_id"],
        username=row["username"],
        display_name=row["display_name"],
        role=AnalystRole(row["role"]),
        is_active=bool(row["is_active"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


class AuthRepository:
    def __init__(self, database_path: Path, settings: Settings) -> None:
        self.path = database_path
        self.settings = settings

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _insert_analyst(
        connection: sqlite3.Connection,
        request: AnalystCreate,
        now: datetime,
    ) -> AnalystPublic:
        analyst_id = f"USR-{uuid4().hex.upper()}"
        normalized = normalize_username(request.username)
        try:
            connection.execute(
                """
                INSERT INTO analysts (
                    analyst_id, username, username_normalized, display_name, role,
                    password_hash, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    analyst_id,
                    request.username,
                    normalized,
                    request.display_name,
                    request.role.value,
                    hash_password(request.password),
                    now.isoformat(),
                    now.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            if "username_normalized" in str(exc):
                raise DuplicateUsernameError(request.username) from exc
            raise
        row = connection.execute(
            "SELECT * FROM analysts WHERE analyst_id = ?", (analyst_id,)
        ).fetchone()
        if row is None:
            raise AnalystNotFoundError(analyst_id)
        return _public_from_row(row)

    def bootstrap_first_admin(self, request: AnalystCreate) -> AnalystPublic:
        if request.role is not AnalystRole.ADMIN:
            raise ValueError("The first analyst must use the ADMIN role")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM analysts LIMIT 1").fetchone() is not None:
                raise BootstrapAlreadyCompletedError("An analyst account already exists")
            return self._insert_analyst(connection, request, now)

    def create_analyst(self, request: AnalystCreate) -> AnalystPublic:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            return self._insert_analyst(connection, request, now)

    def list_analysts(self) -> list[AnalystPublic]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM analysts ORDER BY username_normalized"
            ).fetchall()
        return [_public_from_row(row) for row in rows]

    def update_analyst(
        self,
        analyst_id: str,
        request: AnalystUpdate,
        acting_analyst_id: str,
    ) -> AnalystPublic:
        if analyst_id == acting_analyst_id and (request.role is not None or request.is_active is not None):
            raise SelfAdministrationError("Administrators cannot change their own role or active state")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM analysts WHERE analyst_id = ?", (analyst_id,)
            ).fetchone()
            if row is None:
                raise AnalystNotFoundError(analyst_id)
            display_name = request.display_name if request.display_name is not None else row["display_name"]
            role = request.role.value if request.role is not None else row["role"]
            is_active = int(request.is_active) if request.is_active is not None else row["is_active"]
            connection.execute(
                """
                UPDATE analysts
                SET display_name = ?, role = ?, is_active = ?, updated_at = ?
                WHERE analyst_id = ?
                """,
                (display_name, role, is_active, now.isoformat(), analyst_id),
            )
            if not is_active:
                connection.execute(
                    "DELETE FROM analyst_sessions WHERE analyst_id = ?", (analyst_id,)
                )
            updated = connection.execute(
                "SELECT * FROM analysts WHERE analyst_id = ?", (analyst_id,)
            ).fetchone()
        if updated is None:
            raise AnalystNotFoundError(analyst_id)
        return _public_from_row(updated)

    def authenticate(self, username: str, password: str) -> AnalystPrincipal | None:
        normalized = normalize_username(username)
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM analysts WHERE username_normalized = ?", (normalized,)
            ).fetchone()
            if row is None:
                perform_dummy_verification(password)
                return None

            password_valid = verify_password(row["password_hash"], password)
            locked_until = (
                datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None
            )
            if not row["is_active"] or (locked_until is not None and locked_until > now):
                return None
            if not password_valid:
                failures = int(row["failed_login_count"]) + 1
                new_lock = None
                if failures >= self.settings.login_max_failures:
                    new_lock = now + timedelta(seconds=self.settings.login_lockout_seconds)
                    failures = 0
                connection.execute(
                    """
                    UPDATE analysts
                    SET failed_login_count = ?, locked_until = ?, updated_at = ?
                    WHERE analyst_id = ?
                    """,
                    (
                        failures,
                        new_lock.isoformat() if new_lock else None,
                        now.isoformat(),
                        row["analyst_id"],
                    ),
                )
                return None

            connection.execute(
                """
                UPDATE analysts
                SET failed_login_count = 0, locked_until = NULL, updated_at = ?
                WHERE analyst_id = ?
                """,
                (now.isoformat(), row["analyst_id"]),
            )
            return _principal_from_row(row)

    def create_session(self, principal: AnalystPrincipal) -> SessionCredentials:
        now = _utc_now()
        expires_at = now + timedelta(seconds=self.settings.analyst_session_ttl_seconds)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM analyst_sessions WHERE expires_at <= ?", (now.isoformat(),))
            connection.execute(
                """
                DELETE FROM analyst_sessions
                WHERE token_digest IN (
                    SELECT token_digest FROM analyst_sessions
                    WHERE analyst_id = ?
                    ORDER BY created_at DESC, token_digest DESC
                    LIMIT -1 OFFSET 9
                )
                """,
                (principal.analyst_id,),
            )
            connection.execute(
                """
                INSERT INTO analyst_sessions (
                    token_digest, analyst_id, csrf_token, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    _token_digest(token),
                    principal.analyst_id,
                    csrf_token,
                    now.isoformat(),
                    expires_at.isoformat(),
                ),
            )
        return SessionCredentials(token, csrf_token, expires_at, principal)

    def resolve_session(self, token: str) -> SessionCredentials | None:
        now = _utc_now()
        digest = _token_digest(token)
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT s.token_digest, s.csrf_token, s.created_at, s.expires_at, a.*
                FROM analyst_sessions s
                JOIN analysts a ON a.analyst_id = s.analyst_id
                WHERE s.token_digest = ?
                """,
                (digest,),
            ).fetchone()
            if row is None:
                return None
            expires_at = datetime.fromisoformat(row["expires_at"])
            if expires_at <= now or not row["is_active"]:
                connection.execute("DELETE FROM analyst_sessions WHERE token_digest = ?", (digest,))
                return None
            return SessionCredentials(token, row["csrf_token"], expires_at, _principal_from_row(row))

    def invalidate_session(self, token: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM analyst_sessions WHERE token_digest = ?", (_token_digest(token),)
            )
