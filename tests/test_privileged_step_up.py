from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from src.app.db import utcnow
from src.app.ids import Detection
from src.app.models import AuthSession, ChatSession, User

ADMIN_PASSWORD = "Administrative Passphrase 2026"
USER_PASSWORD = "Ordinary User Passphrase 2026"


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_account(app, username: str, *, role: str = "user") -> str:
    with app.state.database.session_factory() as db:
        user = User(
            username=username,
            password_hash=app.state.password_service.hash(
                ADMIN_PASSWORD if role == "admin" else USER_PASSWORD
            ),
            role=role,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def expire_step_up(app, token: str) -> None:
    claims = app.state.token_service.decode(token)
    with app.state.database.session_factory() as db:
        auth_session = db.get(AuthSession, str(claims["jti"]))
        assert auth_session is not None
        auth_session.last_step_up_at = utcnow() - timedelta(
            minutes=app.state.settings.step_up_minutes + 1
        )
        db.commit()


def assert_step_up_required(response) -> None:
    assert response.status_code == 403, response.text
    assert response.headers.get("X-Step-Up-Required") == "true"


def block_test_source(app, source_ip: str) -> None:
    detection = Detection(
        rule_id="TEST-STEP-UP",
        severity="high",
        engine="test",
        description="step-up protected unblock target",
        source_ip=source_ip,
        path="/test",
        method="GET",
        evidence_sha256="0" * 64,
    )
    app.state.intrusion_state.record(detection)
    app.state.intrusion_state.record(detection)
    assert app.state.intrusion_state.is_blocked(source_ip)[0] is True


def test_stale_step_up_blocks_destructive_and_privileged_mutations(
    client: TestClient,
    app,
):
    admin_id = create_account(app, "stale-step-admin", role="admin")
    delete_target_id = create_account(app, "stale-delete-target")
    role_target_id = create_account(app, "stale-role-target")
    status_target_id = create_account(app, "stale-status-target")
    token = login(client, "stale-step-admin", ADMIN_PASSWORD)
    other_token = login(client, "stale-step-admin", ADMIN_PASSWORD)
    other_jti = str(app.state.token_service.decode(other_token)["jti"])
    blocked_source = "192.0.2.44"
    block_test_source(app, blocked_source)
    headers = auth(token)
    session_response = client.post(
        "/api/sessions",
        headers=headers,
        json={"title": "Must survive stale authorization"},
    )
    assert session_response.status_code == 201, session_response.text
    session_id = session_response.json()["id"]
    expire_step_up(app, token)

    responses = (
        client.delete(f"/api/sessions/{session_id}", headers=headers),
        client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "stale-persistence-admin",
                "password": ADMIN_PASSWORD,
                "role": "admin",
            },
        ),
        client.delete(f"/api/admin/users/{delete_target_id}", headers=headers),
        client.patch(
            f"/api/admin/users/{role_target_id}/role",
            headers=headers,
            json={"role": "moderator"},
        ),
        client.patch(
            f"/api/admin/users/{status_target_id}/status",
            headers=headers,
            json={"is_active": False},
        ),
        client.delete(f"/api/auth/sessions/{other_jti}", headers=headers),
        client.post("/api/auth/logout-all", headers=headers),
        client.delete(f"/api/admin/ids/blocklist/{blocked_source}", headers=headers),
    )
    for response in responses:
        assert_step_up_required(response)

    with app.state.database.session_factory() as db:
        assert db.get(ChatSession, session_id) is not None
        assert db.scalar(select(User).where(User.username == "stale-persistence-admin")) is None
        assert db.get(User, delete_target_id) is not None
        assert db.get(User, role_target_id).role == "user"
        assert db.get(User, status_target_id).is_active is True
        assert db.get(User, admin_id) is not None
        assert db.get(AuthSession, other_jti).revoked_at is None
    assert app.state.intrusion_state.is_blocked(blocked_source)[0] is True
    assert client.get("/api/auth/me", headers=auth(other_token)).status_code == 200


def test_fresh_step_up_allows_destructive_and_privileged_mutations(
    client: TestClient,
    app,
):
    create_account(app, "fresh-step-admin", role="admin")
    delete_target_id = create_account(app, "fresh-delete-target")
    role_target_id = create_account(app, "fresh-role-target")
    status_target_id = create_account(app, "fresh-status-target")
    token = login(client, "fresh-step-admin", ADMIN_PASSWORD)
    other_token = login(client, "fresh-step-admin", ADMIN_PASSWORD)
    other_jti = str(app.state.token_service.decode(other_token)["jti"])
    blocked_source = "192.0.2.45"
    block_test_source(app, blocked_source)
    headers = auth(token)
    session_response = client.post(
        "/api/sessions",
        headers=headers,
        json={"title": "Fresh authorization"},
    )
    assert session_response.status_code == 201, session_response.text
    session_id = session_response.json()["id"]
    expire_step_up(app, token)

    stepped_up = client.post(
        "/api/auth/step-up",
        headers=headers,
        json={"password": ADMIN_PASSWORD},
    )
    assert stepped_up.status_code == 200, stepped_up.text

    deleted_session = client.delete(f"/api/sessions/{session_id}", headers=headers)
    created_user = client.post(
        "/api/admin/users",
        headers=headers,
        json={
            "username": "fresh-created-user",
            "password": USER_PASSWORD,
            "role": "user",
        },
    )
    deleted_user = client.delete(f"/api/admin/users/{delete_target_id}", headers=headers)
    changed_role = client.patch(
        f"/api/admin/users/{role_target_id}/role",
        headers=headers,
        json={"role": "moderator"},
    )
    changed_status = client.patch(
        f"/api/admin/users/{status_target_id}/status",
        headers=headers,
        json={"is_active": False},
    )
    revoked_session = client.delete(f"/api/auth/sessions/{other_jti}", headers=headers)
    unblocked = client.delete(
        f"/api/admin/ids/blocklist/{blocked_source}", headers=headers
    )

    assert deleted_session.status_code == 204, deleted_session.text
    assert created_user.status_code == 201, created_user.text
    assert deleted_user.status_code == 204, deleted_user.text
    assert changed_role.status_code == 200, changed_role.text
    assert changed_role.json()["role"] == "moderator"
    assert changed_status.status_code == 200, changed_status.text
    assert changed_status.json()["is_active"] is False
    assert revoked_session.status_code == 204, revoked_session.text
    assert client.get("/api/auth/me", headers=auth(other_token)).status_code == 401
    assert unblocked.status_code == 204, unblocked.text
    assert app.state.intrusion_state.is_blocked(blocked_source)[0] is False

    logged_out_all = client.post("/api/auth/logout-all", headers=headers)
    assert logged_out_all.status_code == 204, logged_out_all.text
    assert client.get("/api/auth/me", headers=headers).status_code == 401
