from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from src.app.models import ChatSession, SecureMessage, User
from src.app.services import ChatService
from tests.conftest import register_and_login


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_login_and_encrypted_chat(client: TestClient, app):
    token = register_and_login(client, "alice")
    session = client.post("/api/sessions", headers=auth(token), json={"title": "Đồ án ATBM"})
    assert session.status_code == 201
    session_id = session.json()["id"]

    response = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "Phân tích mô hình đe dọa"},
    )
    assert response.status_code == 201
    assert response.json()["role"] == "assistant"

    decoded = client.get(f"/api/sessions/{session_id}/messages", headers=auth(token))
    assert decoded.status_code == 200
    assert len(decoded.json()) == 2
    assert decoded.json()[0]["content"] == "Phân tích mô hình đe dọa"

    raw = client.get(f"/api/sessions/{session_id}/ciphertexts", headers=auth(token))
    assert raw.status_code == 200
    payload = raw.json()
    assert len(payload) == 2
    assert "Phân tích mô hình đe dọa" not in str(payload)
    assert payload[0]["key_version"] == 1


def test_idor_is_blocked_with_resource_level_authorization(client: TestClient):
    alice = register_and_login(client, "alice")
    bob = register_and_login(client, "bob-user")

    created = client.post("/api/sessions", headers=auth(alice), json={"title": "Alice private"})
    session_id = created.json()["id"]

    forbidden_read = client.get(f"/api/sessions/{session_id}/messages", headers=auth(bob))
    forbidden_delete = client.delete(f"/api/sessions/{session_id}", headers=auth(bob))

    assert forbidden_read.status_code == 404
    assert forbidden_delete.status_code == 404


def test_generic_login_error_and_rate_limit(client: TestClient):
    register_and_login(client, "rate-user")

    wrong_user = client.post(
        "/api/auth/login", json={"username": "not-found", "password": "wrong-password"}
    )
    wrong_password = client.post(
        "/api/auth/login", json={"username": "rate-user", "password": "wrong-password"}
    )
    assert wrong_user.status_code == wrong_password.status_code == 401
    assert wrong_user.json()["detail"] == wrong_password.json()["detail"]

    # Same IP + username: after enough failed attempts, limiter returns 429.
    statuses = []
    for _ in range(6):
        statuses.append(
            client.post(
                "/api/auth/login", json={"username": "locked-user", "password": "wrong-password"}
            ).status_code
        )
    assert 429 in statuses


def test_admin_can_read_audit_log(client: TestClient, app):
    database = app.state.database
    password_service = app.state.password_service
    with database.session_factory() as db:
        admin = User(
            username="admin",
            password_hash=password_service.hash("AdminSecure123"),
            role="admin",
        )
        db.add(admin)
        db.commit()

    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "AdminSecure123"},
    )
    token = response.json()["access_token"]
    audit = client.get("/api/admin/audit", headers=auth(token))
    assert audit.status_code == 200
    assert any(item["event_type"] == "auth.login" for item in audit.json())


def test_normal_user_cannot_read_admin_audit(client: TestClient):
    token = register_and_login(client, "normal-user")
    response = client.get("/api/admin/audit", headers=auth(token))
    assert response.status_code == 403


def test_security_headers_and_invalid_token(client: TestClient):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers.get("x-request-id")

    invalid = client.get("/api/auth/me", headers=auth("not-a-valid-jwt"))
    assert invalid.status_code == 401


def test_body_size_limit(client: TestClient):
    response = client.post(
        "/api/auth/login",
        content=b"{}",
        headers={"content-type": "application/json", "content-length": str(1_048_577)},
    )
    assert response.status_code == 413


def test_password_change_invalidates_existing_tokens_and_logout_revokes_token(client: TestClient):
    token = register_and_login(client, "password-user")
    changed = client.patch(
        "/api/auth/password",
        headers=auth(token),
        json={
            "current_password": "Correct Horse Battery1",
            "new_password": "NewCorrect Horse Battery2",
        },
    )
    assert changed.status_code == 204
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401

    relogin = client.post(
        "/api/auth/login",
        json={"username": "password-user", "password": "NewCorrect Horse Battery2"},
    )
    new_token = relogin.json()["access_token"]
    assert client.post("/api/auth/logout", headers=auth(new_token)).status_code == 204
    assert client.get("/api/auth/me", headers=auth(new_token)).status_code == 401


def test_login_sessions_can_be_listed_revoked_and_revoked_globally(client: TestClient):
    first_token = register_and_login(client, "session-user")
    second_login = client.post(
        "/api/auth/login",
        json={"username": "session-user", "password": "Correct Horse Battery1"},
    )
    second_token = second_login.json()["access_token"]

    sessions = client.get("/api/auth/sessions", headers=auth(first_token))
    assert sessions.status_code == 200
    active_sessions = sessions.json()
    assert len(active_sessions) == 2
    other_session = next(session for session in active_sessions if not session["is_current"])

    revoked = client.delete(f"/api/auth/sessions/{other_session['id']}", headers=auth(first_token))
    assert revoked.status_code == 204
    assert client.get("/api/auth/me", headers=auth(second_token)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(first_token)).status_code == 200

    assert client.post("/api/auth/logout-all", headers=auth(first_token)).status_code == 204
    assert client.get("/api/auth/me", headers=auth(first_token)).status_code == 401


def test_existing_account_is_persistently_locked_after_failed_logins(client: TestClient, app):
    register_and_login(client, "lockout-user")
    for _ in range(5):
        assert (
            client.post(
                "/api/auth/login",
                json={"username": "lockout-user", "password": "incorrect password"},
            ).status_code
            == 401
        )

    with app.state.database.session_factory() as db:
        user = db.scalar(
            __import__("sqlalchemy").select(User).where(User.username == "lockout-user")
        )
        assert user is not None
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None


def test_admin_can_lock_account_and_view_security_alerts(client: TestClient, app):
    database = app.state.database
    password_service = app.state.password_service
    with database.session_factory() as db:
        admin = User(
            username="admin-lock",
            password_hash=password_service.hash("AdminSecure123"),
            role="admin",
        )
        db.add(admin)
        db.commit()

    admin_token = client.post(
        "/api/auth/login",
        json={"username": "admin-lock", "password": "AdminSecure123"},
    ).json()["access_token"]
    user_token = register_and_login(client, "lock-target")
    users = client.get("/api/admin/users", headers=auth(admin_token)).json()
    target = next(item for item in users if item["username"] == "lock-target")

    locked = client.patch(
        f"/api/admin/users/{target['id']}/status",
        headers=auth(admin_token),
        json={"is_active": False},
    )
    assert locked.status_code == 200
    assert locked.json()["is_active"] is False
    assert client.get("/api/auth/me", headers=auth(user_token)).status_code == 401

    for _ in range(3):
        client.post("/api/auth/login", json={"username": "not-real", "password": "wrong-password"})
    alerts = client.get(
        "/api/admin/security-alerts?window_minutes=60&threshold=2", headers=auth(admin_token)
    )
    assert alerts.status_code == 200
    assert any(alert["event_type"] == "auth.login" for alert in alerts.json())


def test_authorized_message_search_decrypts_only_owned_session(client: TestClient):
    token = register_and_login(client, "search-user")
    session_id = client.post("/api/sessions", headers=auth(token), json={"title": "Search"}).json()[
        "id"
    ]
    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "Needle in an encrypted haystack"},
    )
    result = client.get(f"/api/sessions/{session_id}/messages?query=needle", headers=auth(token))
    assert result.status_code == 200
    assert any("needle" in item["content"].lower() for item in result.json())


def test_rename_session(client: TestClient):
    token = register_and_login(client, "rename-user")
    session = client.post("/api/sessions", headers=auth(token), json={"title": "Old Title"})
    session_id = session.json()["id"]
    renamed = client.patch(
        f"/api/sessions/{session_id}",
        headers=auth(token),
        json={"title": "New Title"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["title"] == "New Title"


def test_admin_stats_endpoint(client: TestClient, app):
    database = app.state.database
    password_service = app.state.password_service
    with database.session_factory() as db:
        admin = User(
            username="stats-admin",
            password_hash=password_service.hash("AdminSecure123"),
            role="admin",
        )
        db.add(admin)
        db.commit()
    admin_token = client.post(
        "/api/auth/login",
        json={"username": "stats-admin", "password": "AdminSecure123"},
    ).json()["access_token"]
    stats = client.get("/api/admin/stats", headers=auth(admin_token))
    assert stats.status_code == 200
    data = stats.json()
    assert "total_users" in data
    assert "total_sessions" in data
    assert "total_messages" in data
    assert data["total_users"] >= 1


def test_passwords_below_minimum_length_are_rejected(client: TestClient):
    no_upper = client.post(
        "/api/auth/register", json={"username": "weak-user", "password": "alllowercase1"}
    )
    assert no_upper.status_code == 422
    no_digit = client.post(
        "/api/auth/register", json={"username": "weak-user", "password": "NoDigitsHereAA"}
    )
    assert no_digit.status_code == 422
    no_lower = client.post(
        "/api/auth/register", json={"username": "weak-user", "password": "ALLUPPERCASE1X"}
    )
    assert no_lower.status_code == 422


def test_duplicate_registration_returns_409(client: TestClient):
    register_and_login(client, "dup-user")
    dup = client.post(
        "/api/auth/register", json={"username": "dup-user", "password": "AnotherPass123x"}
    )
    assert dup.status_code == 409


def test_session_delete_cascades_messages(client: TestClient):
    token = register_and_login(client, "cascade-user")
    session = client.post("/api/sessions", headers=auth(token), json={"title": "Cascade Test"})
    session_id = session.json()["id"]
    client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "Test message here"},
    )
    msgs_before = client.get(f"/api/sessions/{session_id}/messages", headers=auth(token))
    assert len(msgs_before.json()) == 2
    client.delete(f"/api/sessions/{session_id}", headers=auth(token))
    get_deleted = client.get(f"/api/sessions/{session_id}", headers=auth(token))
    assert get_deleted.status_code == 404


# ---------- helper: create admin token ----------
def _admin_token(client, app, username="test-admin"):
    database = app.state.database
    password_service = app.state.password_service
    with database.session_factory() as db:
        from src.app.models import User

        existing = db.scalar(__import__("sqlalchemy").select(User).where(User.username == username))
        if existing is None:
            admin = User(
                username=username,
                password_hash=password_service.hash("Test Operator Passphrase 2026"),
                role="admin",
            )
            db.add(admin)
            db.commit()
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": "Test Operator Passphrase 2026"},
    ).json()["access_token"]


def test_moderator_cannot_access_other_users_chat_sessions(client: TestClient, app):
    # Create a user with a private session.
    user_token = register_and_login(client, "mod-test-user")
    session_id = client.post(
        "/api/sessions", headers=auth(user_token), json={"title": "User Session"}
    ).json()["id"]

    # Moderators may audit activity, but may not read, change, or delete chat content.
    admin_token = _admin_token(client, app, "mod-admin")
    client.post(
        "/api/admin/users",
        headers=auth(admin_token),
        json={"username": "test-mod", "password": "Moderator Passphrase 2026", "role": "moderator"},
    )
    mod_token = client.post(
        "/api/auth/login",
        json={"username": "test-mod", "password": "Moderator Passphrase 2026"},
    ).json()["access_token"]
    sessions = client.get("/api/sessions", headers=auth(mod_token))
    assert sessions.status_code == 200
    assert sessions.json() == []
    assert (
        client.get(f"/api/sessions/{session_id}/messages", headers=auth(mod_token)).status_code
        == 404
    )
    assert client.delete(f"/api/sessions/{session_id}", headers=auth(mod_token)).status_code == 404
    assert client.get("/api/admin/audit", headers=auth(mod_token)).status_code == 200


def test_moderator_cannot_access_admin_endpoints(client: TestClient, app):
    admin_token = _admin_token(client, app, "mod-admin2")
    client.post(
        "/api/admin/users",
        headers=auth(admin_token),
        json={
            "username": "test-mod2",
            "password": "Moderator Passphrase 2026",
            "role": "moderator",
        },
    )
    mod_token = client.post(
        "/api/auth/login",
        json={"username": "test-mod2", "password": "Moderator Passphrase 2026"},
    ).json()["access_token"]
    # Moderator CAN access audit
    assert client.get("/api/admin/audit", headers=auth(mod_token)).status_code == 200
    # Moderator CANNOT access admin-only endpoints
    assert client.get("/api/admin/users", headers=auth(mod_token)).status_code == 403
    assert client.get("/api/admin/stats", headers=auth(mod_token)).status_code == 403


def test_admin_create_user(client: TestClient, app):
    admin_token = _admin_token(client, app, "crud-admin")
    resp = client.post(
        "/api/admin/users",
        headers=auth(admin_token),
        json={
            "username": "created-user",
            "password": "Created User Passphrase 2026",
            "role": "user",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == "created-user"
    assert resp.json()["role"] == "user"


def test_admin_delete_user(client: TestClient, app):
    admin_token = _admin_token(client, app, "del-admin")
    client.post(
        "/api/admin/users",
        headers=auth(admin_token),
        json={"username": "to-delete", "password": "Delete User Passphrase 2026", "role": "user"},
    )
    users = client.get("/api/admin/users", headers=auth(admin_token)).json()
    uid = next(u["id"] for u in users if u["username"] == "to-delete")
    resp = client.delete(f"/api/admin/users/{uid}", headers=auth(admin_token))
    assert resp.status_code == 204


def test_admin_change_role(client: TestClient, app):
    admin_token = _admin_token(client, app, "role-admin")
    client.post(
        "/api/admin/users",
        headers=auth(admin_token),
        json={"username": "role-target", "password": "Role Target Passphrase 2026", "role": "user"},
    )
    users = client.get("/api/admin/users", headers=auth(admin_token)).json()
    uid = next(u["id"] for u in users if u["username"] == "role-target")
    resp = client.patch(
        f"/api/admin/users/{uid}/role", headers=auth(admin_token), json={"role": "moderator"}
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "moderator"


def test_export_session(client: TestClient):
    token = register_and_login(client, "export-user")
    session = client.post("/api/sessions", headers=auth(token), json={"title": "Export Test"})
    sid = session.json()["id"]
    client.post(
        f"/api/sessions/{sid}/messages", headers=auth(token), json={"content": "Hello export"}
    )
    resp = client.get(f"/api/sessions/{sid}/export", headers=auth(token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Export Test"
    assert len(data["messages"]) == 2


def test_failed_ai_generation_does_not_persist_half_a_chat_exchange(client: TestClient, app):
    class FailingAI:
        def generate(self, current_message, history, *, allow_external_ai):
            raise RuntimeError("AI provider unavailable")

    token = register_and_login(client, "atomic-chat-user")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Atomic chat"}
    ).json()["id"]
    chat_service = ChatService(app.state.crypto_service, FailingAI())

    with app.state.database.session_factory() as db:
        session = db.get(ChatSession, session_id)
        assert session is not None
        with pytest.raises(RuntimeError, match="provider unavailable"):
            chat_service.chat(
                db,
                session,
                "This must not be saved alone",
                allow_external_ai=False,
            )
        assert (
            db.scalar(
                select(func.count())
                .select_from(SecureMessage)
                .where(SecureMessage.session_id == session_id)
            )
            == 0
        )
