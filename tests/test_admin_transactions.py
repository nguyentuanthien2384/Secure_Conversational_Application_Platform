"""Administrative authorization and audit must agree with the committed mutation."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.models import AuditEvent, AuthSession, User
from tests.test_privileged_step_up import ADMIN_PASSWORD, auth, create_account, login


@pytest.mark.parametrize("revocation", ["lock", "role", "logout", "logout_all", "session"])
def test_admin_create_rechecks_authority_after_password_work(client, app, monkeypatch, revocation):
    actor_id = create_account(app, "transaction-admin", role="admin")
    create_account(app, "transaction-controller", role="admin")
    token = login(client, "transaction-admin", ADMIN_PASSWORD)
    controller = login(client, "transaction-controller", ADMIN_PASSWORD)
    reached, release = threading.Event(), threading.Event()
    original_hash = app.state.password_service.hash

    def paused_hash(password):
        result = original_hash(password)
        reached.set()
        assert release.wait(10), "test did not release password work"
        return result

    monkeypatch.setattr(app.state.password_service, "hash", paused_hash)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client.post, "/api/admin/users", headers=auth(token), json={
            "username": "transaction-new-user", "password": ADMIN_PASSWORD, "role": "user",
        })
        try:
            assert reached.wait(10)
            if revocation == "lock":
                response = client.patch(f"/api/admin/users/{actor_id}/status",
                                        headers=auth(controller), json={"is_active": False})
            elif revocation == "role":
                response = client.patch(f"/api/admin/users/{actor_id}/role",
                                        headers=auth(controller), json={"role": "user"})
            elif revocation == "session":
                jti = app.state.token_service.decode(token)["jti"]
                response = client.delete(f"/api/auth/sessions/{jti}", headers=auth(token))
            else:
                path = "logout-all" if revocation == "logout_all" else "logout"
                response = client.post(f"/api/auth/{path}", headers=auth(token))
            assert response.status_code in (200, 204), response.text
        finally:
            release.set()
        result = pending.result(timeout=10)
    assert result.status_code == 401, result.text
    assert 'error="invalid_token"' in result.headers.get("WWW-Authenticate", "")
    with app.state.database.session_factory() as db:
        assert db.scalar(select(User).where(User.username == "transaction-new-user")) is None
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == "admin.user_create")) is None


@pytest.mark.parametrize("operation", ["create", "role", "status", "delete"])
def test_admin_mutation_rolls_back_when_audit_insert_fails(client, app, operation):
    create_account(app, "atomic-admin", role="admin")
    target_id = create_account(app, "atomic-target")
    token = login(client, "atomic-admin", ADMIN_PASSWORD)
    with app.state.database.session_factory() as db:
        old_version = db.get(User, target_id).token_version

    def fail_insert(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("audit unavailable", None, RuntimeError("test storage fault"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_insert)
    try:
        if operation == "create":
            result = client.post("/api/admin/users", headers=auth(token), json={
                "username": "atomic-created", "password": ADMIN_PASSWORD, "role": "user",
            })
        elif operation == "delete":
            result = client.delete(f"/api/admin/users/{target_id}", headers=auth(token))
        else:
            body = {"role": "moderator"} if operation == "role" else {"is_active": False}
            result = client.patch(f"/api/admin/users/{target_id}/{operation}",
                                  headers=auth(token), json=body)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_insert)
    assert result.status_code == 503, result.text
    with app.state.database.session_factory() as db:
        assert db.scalar(select(User).where(User.username == "atomic-created")) is None
        target = db.get(User, target_id)
        assert target is not None
        assert target.role == "user" and target.is_active
        assert target.token_version == old_version
        assert verify_chain(db, app.state.audit_key).intact


def test_successful_admin_mutation_has_sealed_audit_and_revokes_target_sessions(client, app):
    create_account(app, "sealed-admin", role="admin")
    target_id = create_account(app, "sealed-target", role="admin")
    token = login(client, "sealed-admin", ADMIN_PASSWORD)
    target_token = login(client, "sealed-target", ADMIN_PASSWORD)
    result = client.patch(f"/api/admin/users/{target_id}/role",
                          headers=auth(token), json={"role": "user"})
    assert result.status_code == 200, result.text
    assert client.get("/api/auth/me", headers=auth(target_token)).status_code == 401
    with app.state.database.session_factory() as db:
        audit = db.scalar(select(AuditEvent).where(AuditEvent.event_type == "admin.user_role_change"))
        assert audit is not None and audit.entry_hash and audit.target_id == target_id
        session = db.get(AuthSession, app.state.token_service.decode(target_token)["jti"])
        assert session.revoked_at is not None
        assert verify_chain(db, app.state.audit_key).intact
