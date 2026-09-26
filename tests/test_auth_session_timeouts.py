from __future__ import annotations

import threading
from datetime import timedelta, timezone

import pytest
from sqlalchemy import event, func, select, text

from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.models import AuditEvent, AuthSession, RevokedToken
from tests.conftest import register_and_login
from tests.test_auth_rotation_race import AUTH_SESSION_CLAIM_SQL
from tests.test_security_lifecycle import auth, pause_after_sql, run_request


def _session_for(db_session, user_id: str) -> AuthSession:
    return db_session.scalar(
        select(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.issued_at.desc())
    )


def test_idle_timeout_is_enforced_server_side(client, db_session):
    token = register_and_login(client, "idle-timeout-user")
    user_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()["id"]
    session = _session_for(db_session, user_id)
    session.last_activity_at = utcnow() - timedelta(minutes=31)
    db_session.commit()

    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert "hết hạn" in response.json()["detail"]


def test_refresh_cannot_keep_an_idle_session_alive(client, db_session):
    token = register_and_login(client, "idle-refresh-user")
    user_id = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()["id"]
    session = _session_for(db_session, user_id)
    old_activity = utcnow() - timedelta(minutes=5)
    session.last_activity_at = old_activity
    db_session.commit()

    response = client.post("/api/auth/refresh", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    new_token = response.json()["access_token"]
    db_session.expire_all()
    sessions = list(
        db_session.scalars(
            select(AuthSession).where(
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
        )
    )
    renewed = next(row for row in sessions if row.jti != session.jti)
    assert renewed.last_activity_at is not None
    renewed_activity = renewed.last_activity_at
    if renewed_activity.tzinfo is None:
        renewed_activity = renewed_activity.replace(tzinfo=old_activity.tzinfo)
    assert renewed_activity <= old_activity + timedelta(seconds=2)
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {new_token}"}).status_code == 200


def test_auth_session_metadata_exposes_idle_and_absolute_deadlines(client):
    token = register_and_login(client, "session-deadline-user")

    response = client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    row = response.json()[0]
    assert row["last_activity_at"]
    assert row["idle_expires_at"]
    assert row["absolute_expires_at"]


@pytest.mark.parametrize("path", ["/api/auth/me", "/api/auth/sessions", "/api/sessions"])
def test_absolute_deadline_rejects_requests_even_with_valid_jwt(client, app, db_session, path):
    token = register_and_login(client, "absolute-request-user")
    jti = app.state.token_service.decode(token)["jti"]
    session = db_session.get(AuthSession, jti)
    session.root_issued_at = utcnow() - timedelta(hours=9)
    db_session.commit()

    assert client.get(path, headers=auth(token)).status_code == 401
    db_session.expire_all()
    assert db_session.get(AuthSession, jti).revoked_at is not None
    assert db_session.get(RevokedToken, jti).reason == "absolute_lifetime_exceeded"


def test_database_expiry_is_enforced_independently_of_signed_token(client, app, db_session):
    token = register_and_login(client, "database-expired-user")
    jti = app.state.token_service.decode(token)["jti"]
    session = db_session.get(AuthSession, jti)
    session.expires_at = utcnow() - timedelta(seconds=1)
    db_session.commit()

    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    db_session.expire_all()
    assert db_session.get(RevokedToken, jti).reason == "token_lifetime_exceeded"


@pytest.mark.parametrize(
    ("field", "offset", "reason"),
    [("last_activity_at", timedelta(minutes=30), "idle_timeout"),
     ("root_issued_at", timedelta(hours=8), "absolute_lifetime_exceeded"),
     ("expires_at", timedelta(0), "token_lifetime_exceeded")],
)
def test_exact_session_deadline_is_already_expired(
    client, app, db_session, monkeypatch, field, offset, reason
):
    now = utcnow()
    token = register_and_login(client, "exact-deadline-user")
    jti = app.state.token_service.decode(token)["jti"]
    setattr(db_session.get(AuthSession, jti), field, now - offset)
    db_session.commit()
    monkeypatch.setattr("src.app.main.utcnow", lambda: now)

    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    db_session.expire_all()
    assert db_session.get(RevokedToken, jti).reason == reason


def test_metadata_does_not_advance_activity_but_protected_operation_does(
    client, app, db_session
):
    token = register_and_login(client, "polling-idle-user")
    jti = app.state.token_service.decode(token)["jti"]
    session = db_session.get(AuthSession, jti)
    old_activity = utcnow() - timedelta(minutes=10)
    original_root = session.root_issued_at
    original_step_up = session.last_step_up_at
    session.last_activity_at = old_activity
    db_session.commit()

    assert client.get("/api/auth/me", headers=auth(token)).status_code == 200
    assert client.get("/api/auth/sessions", headers=auth(token)).status_code == 200
    db_session.expire_all()
    assert session.last_activity_at.replace(tzinfo=timezone.utc) == old_activity
    assert client.get("/api/sessions", headers=auth(token)).status_code == 200
    db_session.expire_all()
    assert session.last_activity_at.replace(tzinfo=timezone.utc) > old_activity
    assert session.root_issued_at == original_root
    assert session.last_step_up_at == original_step_up


def test_session_list_omits_idle_devices_without_renewing_them(client, app, db_session):
    first = register_and_login(client, "idle-device-list")
    first_jti = app.state.token_service.decode(first)["jti"]
    second = client.post(
        "/api/auth/login",
        json={"username": "idle-device-list", "password": "Correct Horse Battery1"},
    ).json()["access_token"]
    stale = db_session.get(AuthSession, first_jti)
    old_activity = utcnow() - timedelta(minutes=31)
    stale.last_activity_at = old_activity
    db_session.commit()

    listed = client.get("/api/auth/sessions", headers=auth(second))

    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["id"] != first_jti
    db_session.expire_all()
    assert stale.last_activity_at.replace(tzinfo=timezone.utc) == old_activity


@pytest.mark.parametrize(
    ("field", "age", "reason"),
    [
        ("last_activity_at", timedelta(minutes=31), "idle_timeout"),
        ("root_issued_at", timedelta(hours=9), "absolute_lifetime_exceeded"),
        ("expires_at", timedelta(seconds=1), "token_lifetime_exceeded"),
    ],
)
def test_export_ticket_cannot_outlive_parent_session(
    client, app, db_session, field, age, reason
):
    token = register_and_login(client, "export-timeout-user")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Bounded export"}
    ).json()["id"]
    ticket = client.post(f"/api/sessions/{session_id}/export-ticket", headers=auth(token))
    assert ticket.status_code == 200
    jti = app.state.token_service.decode(token)["jti"]
    setattr(db_session.get(AuthSession, jti), field, utcnow() - age)
    db_session.commit()

    assert client.get(ticket.json()["download_url"]).status_code == 404
    db_session.expire_all()
    assert db_session.get(RevokedToken, jti).reason == reason


@pytest.mark.parametrize("path", ["/api/auth/refresh", "/api/sessions"])
def test_request_rechecks_idle_deadline_after_waiting_for_session_lock(
    client, app, db_session, monkeypatch, path
):
    import src.app.main as application

    token = register_and_login(client, "lock-deadline-user")
    jti = app.state.token_service.decode(token)["jti"]
    now = utcnow()
    db_session.get(AuthSession, jti).last_activity_at = now - timedelta(minutes=29)
    db_session.commit()
    clock = [now]
    monkeypatch.setattr(application, "utcnow", lambda: clock[0])

    def lock_took_time(_conn, _cursor, statement, _parameters, _context, _many):
        if AUTH_SESSION_CLAIM_SQL in " ".join(statement.lower().split()):
            clock[0] = now + timedelta(minutes=2)

    event.listen(app.state.database.engine, "after_cursor_execute", lock_took_time)
    try:
        response = (
            client.post(path, headers=auth(token))
            if path.endswith("refresh") else client.get(path, headers=auth(token))
        )
    finally:
        event.remove(app.state.database.engine, "after_cursor_execute", lock_took_time)

    assert response.status_code == 401
    db_session.expire_all()
    assert db_session.get(RevokedToken, jti).reason == "idle_timeout"
    assert db_session.scalar(select(func.count()).select_from(AuthSession)) == 1


def test_export_ticket_expiring_while_waiting_for_parent_lock_is_rejected(
    client, app, monkeypatch, db_session
):
    token = register_and_login(client, "export-lock-expiry-user")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Expiring ticket"}
    ).json()["id"]
    ticket = client.post(f"/api/sessions/{session_id}/export-ticket", headers=auth(token))
    assert ticket.status_code == 200
    now = utcnow()
    clock = [now]
    monkeypatch.setattr("src.app.main.utcnow", lambda: clock[0])

    def slow_lock(_conn, _cursor, statement, _parameters, _context, _many):
        if AUTH_SESSION_CLAIM_SQL in " ".join(statement.lower().split()):
            clock[0] = now + timedelta(minutes=2)

    event.listen(app.state.database.engine, "after_cursor_execute", slow_lock)
    try:
        response = client.get(ticket.json()["download_url"])
    finally:
        event.remove(app.state.database.engine, "after_cursor_execute", slow_lock)
    assert response.status_code == 404
    jti = app.state.token_service.decode(token)["jti"]
    assert db_session.get(AuthSession, jti).revoked_at is None


def test_two_expiry_requests_create_one_revocation_and_one_expiry_event(
    client, app, db_session
):
    token = register_and_login(client, "expiry-race-user")
    jti = app.state.token_service.decode(token)["jti"]
    db_session.get(AuthSession, jti).last_activity_at = utcnow() - timedelta(minutes=31)
    db_session.commit()
    results = {}
    with pause_after_sql(app.state.database.engine, AUTH_SESSION_CLAIM_SQL) as (
        claimed, release, errors
    ):
        first = threading.Thread(
            target=run_request,
            args=(results, "first", lambda: client.get("/api/auth/me", headers=auth(token))),
        )
        first.start()
        assert claimed.wait(timeout=5)
        second = threading.Thread(
            target=run_request,
            args=(results, "second", lambda: client.get("/api/auth/me", headers=auth(token))),
        )
        second.start()
        release.set()
        first.join(timeout=10)
        second.join(timeout=10)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert not isinstance(results["first"], BaseException)
    assert not isinstance(results["second"], BaseException)
    assert results["first"].status_code == results["second"].status_code == 401
    assert db_session.scalar(
        select(func.count()).select_from(RevokedToken).where(RevokedToken.jti == jti)
    ) == 1
    assert db_session.scalar(
        select(func.count()).select_from(AuditEvent).where(
            AuditEvent.event_type == "auth.session.expired", AuditEvent.target_id == jti
        )
    ) == 1


def test_logout_winning_account_lock_prevents_stale_activity_update(client, app, db_session):
    token = register_and_login(client, "activity-revocation-race")
    jti = app.state.token_service.decode(token)["jti"]
    session = db_session.get(AuthSession, jti)
    old_activity = utcnow() - timedelta(minutes=5)
    session.last_activity_at = old_activity
    db_session.commit()
    paused = threading.Event()
    release = threading.Event()
    results = {}
    activity_thread_id = []

    def before_account_lock(_conn, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.lower().split())
        if (
            threading.get_ident() in activity_thread_id
            and normalized.startswith("update users set token_version=users.token_version")
            and not paused.is_set()
        ):
            paused.set()
            assert release.wait(timeout=10)

    # FastAPI executes sync handlers in its worker thread, not the client thread.
    # Tag the handler using this request's SELECT before pausing its user lock.
    def mark_activity_request(_conn, _cursor, statement, _parameters, _context, _many):
        if "FROM auth_sessions" in statement and not paused.is_set():
            activity_thread_id.append(threading.get_ident())

    event.listen(app.state.database.engine, "before_cursor_execute", mark_activity_request)
    event.listen(app.state.database.engine, "before_cursor_execute", before_account_lock)
    worker = threading.Thread(
        target=run_request,
        args=(results, "activity", lambda: client.get("/api/sessions", headers=auth(token))),
    )
    try:
        worker.start()
        assert paused.wait(timeout=5)
        assert client.post("/api/auth/logout", headers=auth(token)).status_code == 204
    finally:
        release.set()
        worker.join(timeout=10)
        event.remove(app.state.database.engine, "before_cursor_execute", mark_activity_request)
        event.remove(app.state.database.engine, "before_cursor_execute", before_account_lock)
    assert not worker.is_alive()
    assert not isinstance(results["activity"], BaseException)
    assert results["activity"].status_code == 401
    db_session.expire_all()
    assert session.revoked_at is not None
    assert session.last_activity_at.replace(tzinfo=timezone.utc) == old_activity


def test_activity_migration_preserves_original_timestamp_and_is_idempotent(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'legacy-session.db'}")
    try:
        database.create_all()
        with database.engine.begin() as connection:
            connection.execute(text("ALTER TABLE auth_sessions DROP COLUMN last_activity_at"))
            connection.execute(text(
                "INSERT INTO users (id, username, password_hash, role, is_active, "
                "ai_data_consent, token_version, failed_login_attempts, mfa_enabled, "
                "secret_crypto_epoch, mfa_last_counter, created_at) VALUES "
                "('legacy-user', 'legacy-user', 'unused', 'user', 1, 0, 1, 0, 0, 0, 0, "
                "'2026-01-01 00:00:00')"
            ))
            connection.execute(text(
                "INSERT INTO auth_sessions (jti, user_id, session_family_id, issued_at, "
                "expires_at) VALUES ('legacy-jti', 'legacy-user', 'legacy-jti', "
                "'2026-01-01 00:00:00', '2026-01-01 00:30:00')"
            ))
        database.create_all()
        with database.engine.begin() as connection:
            assert connection.scalar(text(
                "SELECT last_activity_at = issued_at FROM auth_sessions WHERE jti='legacy-jti'"
            )) == 1
            connection.execute(text(
                "UPDATE auth_sessions SET last_activity_at='2026-01-01 00:10:00'"
            ))
        database.create_all()
        with database.engine.connect() as connection:
            assert connection.scalar(text(
                "SELECT last_activity_at FROM auth_sessions WHERE jti='legacy-jti'"
            )) == "2026-01-01 00:10:00"
    finally:
        database.engine.dispose()


@pytest.mark.parametrize(
    ("name", "value"),
    [("SESSION_IDLE_MINUTES", "0"), ("SESSION_IDLE_MINUTES", "1441"),
     ("SESSION_ABSOLUTE_HOURS", "0"), ("SESSION_ABSOLUTE_HOURS", "169"),
     ("SESSION_IDLE_MINUTES", "invalid")],
)
def test_session_timeout_configuration_rejects_invalid_bounds(monkeypatch, name, value):
    # Settings.from_env must not load the workspace's real .env during tests.
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("KEY_PROVIDER", "local")
    monkeypatch.setenv("SESSION_IDLE_MINUTES", "30")
    monkeypatch.setenv("SESSION_ABSOLUTE_HOURS", "8")
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match=name):
        Settings.from_env()
