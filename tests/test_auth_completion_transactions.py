"""A successful auth response and its persisted authorization state agree."""
from __future__ import annotations

import functools
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.models import AuthSession, RevokedToken, User
from tests.conftest import register_and_login
from tests.test_account_transactions import security_snapshot
from tests.test_mfa import enroll_and_enable
from tests.test_passkeys import PASSWORD, auth, register_passkey
from tests.webauthn_soft import SoftAuthenticator


def complete_snapshot(app):
    snapshot = security_snapshot(app)
    with app.state.database.session_factory() as db:
        snapshot["RevokedToken"] = sorted((row.jti, row.reason) for row in db.scalars(select(RevokedToken)))
        snapshot["UserPolicy"] = sorted(
            (row.id, row.ai_data_consent, row.ai_consent_at, row.ai_consent_version,
             row.failed_login_attempts, row.locked_until, row.mfa_failed_attempts)
            for row in db.scalars(select(User))
        )
    return snapshot


def test_self_registration_rolls_back_account_when_audit_fails(client, app):
    before = complete_snapshot(app)

    def fail_insert(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_insert)
    payload = {"username": "completion-register", "password": PASSWORD}
    try:
        response = client.post("/api/auth/register", json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_insert)
    assert response.status_code == 503, response.text
    assert complete_snapshot(app) == before
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


def test_mfa_challenge_login_rehash_rolls_back_when_audit_fails(client, app, monkeypatch):
    enroll_and_enable(client, "completion-challenge")
    monkeypatch.setattr(app.state.password_service, "needs_rehash", lambda _value: True)
    before = complete_snapshot(app)

    def fail_insert(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_insert)
    payload = {"username": "completion-challenge", "password": PASSWORD}
    try:
        response = client.post("/api/auth/login", json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_insert)
    assert response.status_code == 503, response.text
    assert complete_snapshot(app) == before
    retry = client.post("/api/auth/login", json=payload)
    assert retry.status_code == 200 and retry.json()["mfa_required"]


@pytest.mark.parametrize("operation", ["refresh", "logout", "consent_enable", "consent_disable"])
def test_session_and_consent_changes_roll_back_when_audit_fails(client, app, operation):
    token = register_and_login(client, "completion-state")
    consent = operation.startswith("consent")
    if operation == "consent_disable":
        assert client.patch("/api/auth/ai-consent", headers=auth(token), json={"ai_data_consent": True}).status_code == 200
    method = "PATCH" if consent else "POST"
    path = "/api/auth/ai-consent" if consent else f"/api/auth/{operation}"
    payload = {"ai_data_consent": operation == "consent_enable"} if consent else None
    before = complete_snapshot(app)

    def fail_insert(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_insert)
    try:
        response = client.request(method, path, headers=auth(token), json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_insert)
    assert response.status_code == 503, response.text
    assert complete_snapshot(app) == before
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 200
    retried = client.request(method, path, headers=auth(token), json=payload)
    assert retried.status_code == (204 if operation == "logout" else 200), retried.text
    if operation == "refresh":
        successor = retried.json()["access_token"]
        assert client.get("/api/auth/me", headers=auth(successor)).status_code == 200
        assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("method", ["password", "mfa_recovery", "passkey"])
@pytest.mark.parametrize("failing_event", ["primary", "new_device"])
def test_sign_in_rolls_back_proofs_session_and_every_required_audit(
    client, app, monkeypatch, method, failing_event,
):
    username = "completion-signin"
    if method == "mfa_recovery":
        _secret, _token, codes = enroll_and_enable(client, username)
        challenge = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()
        path, payload, primary = "/api/auth/mfa/verify", {"mfa_token": challenge["mfa_token"], "code": codes[0]}, "auth.mfa.verify"
    else:
        token = register_and_login(client, username)
        path, payload, primary = "/api/auth/login", {"username": username, "password": PASSWORD}, "auth.login"
        if method == "password":
            # Exercise the credential-upgrade write in the same login.
            monkeypatch.setattr(app.state.password_service, "needs_rehash", lambda _value: True)
        else:
            device = SoftAuthenticator()
            assert register_passkey(client, token, device).status_code == 201
            options = client.post("/api/auth/passkeys/authentication/options").json()
            path, primary = "/api/auth/passkeys/authentication/verify", "auth.passkey.login"
            payload = {"challenge_id": options["challenge_id"], "credential": device.assert_(options["public_key"])}
    # No recognition token is supplied, so a completed prior login means this
    # request must emit both its primary sign-in audit and a new-device event.
    target = "auth.login.new_device" if failing_event == "new_device" else primary
    before = complete_snapshot(app)
    injected = []

    def fail_target(_conn, _cursor, statement, _params, context, _many):
        if (statement.lstrip().lower().startswith("insert into audit_events")
                and any(item.get("event_type") == target for item in context.compiled_parameters)):
            injected.append(target)
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_target)
    try:
        response = client.post(path, json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_target)
    assert injected == [target]
    assert response.status_code == 503, response.text
    assert complete_snapshot(app) == before
    # A valid TOTP/recovery proof or passkey challenge is reusable after the
    # database transaction failed; no unseen bearer survives the failed call.
    retry = client.post(path, json=payload)
    assert retry.status_code == 200, retry.text
    assert client.get("/api/auth/me", headers=auth(retry.json()["access_token"])).status_code == 200
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("transition", ["logout", "logout-all", "refresh"])
def test_consent_cannot_be_enabled_by_an_inflight_revoked_bearer(client, app, transition):
    token = register_and_login(client, "completion-consent")
    route = next(item for item in app.routes if getattr(item, "path", "") == "/api/auth/ai-consent")
    dependency = next(item.call for item in route.dependant.dependencies if item.name == "user")
    reached, release = threading.Event(), threading.Event()

    @functools.wraps(dependency)
    def paused(*args, **kwargs):
        user = dependency(*args, **kwargs)
        if kwargs["request"].url.path == "/api/auth/ai-consent":
            reached.set()
            assert release.wait(10)
        return user

    app.dependency_overrides[dependency] = paused
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.patch, "/api/auth/ai-consent", headers=auth(token), json={"ai_data_consent": True})
            try:
                assert reached.wait(10)
                response = client.post(f"/api/auth/{transition}", headers=auth(token))
                assert response.status_code in {200, 204}, response.text
            finally:
                release.set()
            result = pending.result(timeout=10)
    finally:
        app.dependency_overrides.pop(dependency, None)
    assert result.status_code == 401, result.text
    assert 'error="invalid_token"' in result.headers.get("WWW-Authenticate", "")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "completion-consent"))
        assert user.ai_data_consent is False and user.ai_consent_at is None
        if transition == "logout":
            assert db.get(AuthSession, app.state.token_service.decode(token)["jti"]).revoked_at is not None
