from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from src.app.db import utcnow
from src.app.models import AuthSession
from tests.conftest import register_and_login


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
