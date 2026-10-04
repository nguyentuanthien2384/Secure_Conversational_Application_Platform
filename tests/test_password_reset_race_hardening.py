from __future__ import annotations

import functools
import threading
from datetime import timedelta

import pytest
from sqlalchemy import select

from src.app.db import utcnow
from src.app.models import AuthSession, User
from tests.conftest import register_and_login
from tests.test_account_recovery import (
    NEW_PASSWORD,
    PASSWORD,
    Recorder,
    add_verified_email,
    auth,
)
from tests.test_security_lifecycle import run_request


@pytest.fixture()
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


def request_reset(client, mail, username):
    response = client.post("/api/auth/password-reset/request", json={"identifier": username})
    assert response.status_code == 202, response.text
    return mail.code_for("reset-race@example.com")


@pytest.mark.parametrize("transition", ["reset", "logout", "refresh", "session_expiry"])
def test_password_change_rechecks_revocation_after_concurrent_session_change(client, app, mail,
                                                                           transition):
    username = f"change-race-{transition}"
    token = register_and_login(client, username)
    add_verified_email(client, mail, token, "reset-race@example.com")
    reset_code = request_reset(client, mail, username)
    route = next(route for route in app.routes if getattr(route, "path", None) == "/api/auth/password")
    current_user = next(item.call for item in route.dependant.dependencies if item.name == "user")
    authenticated, release = threading.Event(), threading.Event()
    results = {}

    @functools.wraps(current_user)
    def pause_after_authentication(*args, **kwargs):
        user = current_user(*args, **kwargs)
        if kwargs["request"].url.path == "/api/auth/password":
            authenticated.set()
            assert release.wait(timeout=10), "stale password change was not released"
        return user

    app.dependency_overrides[current_user] = pause_after_authentication
    stale_change = threading.Thread(target=run_request, args=(
        results, "change", lambda: client.patch(
            "/api/auth/password", headers=auth(token), json={
                "current_password": PASSWORD,
                "new_password": "A password from the revoked session 2026",
            },
        ),
    ))
    try:
        stale_change.start()
        assert authenticated.wait(timeout=5), "request did not finish bearer authentication"
        # current_user has committed its activity update. A security transition
        # can now revoke the bearer before its handler starts. Logout/rotation
        # leave token_version unchanged and require an exact session re-check.
        if transition == "reset":
            reset = client.post("/api/auth/password-reset/confirm", json={
                "identifier": username, "code": reset_code, "new_password": NEW_PASSWORD,
            })
            assert reset.status_code == 204, reset.text
        elif transition == "logout":
            logged_out = client.post("/api/auth/logout", headers=auth(token))
            assert logged_out.status_code == 204, logged_out.text
        elif transition == "refresh":
            refreshed = client.post("/api/auth/refresh", headers=auth(token))
            assert refreshed.status_code == 200, refreshed.text
        else:
            jti = app.state.token_service.decode(token)["jti"]
            with app.state.database.session_factory() as db:
                db.get(AuthSession, jti).expires_at = utcnow() - timedelta(seconds=1)
                db.commit()
    finally:
        release.set()
        stale_change.join(timeout=10)
        app.dependency_overrides.pop(current_user, None)
    assert not stale_change.is_alive()
    assert not isinstance(results.get("change"), BaseException)
    assert results["change"].status_code == 401, results["change"].text
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        expected_password = NEW_PASSWORD if transition == "reset" else PASSWORD
        assert app.state.password_service.verify(user.password_hash, expected_password)


def test_login_rehash_cannot_restore_the_password_after_an_accepted_reset(client, app, mail,
                                                                       monkeypatch):
    username = "rehash-reset-race"
    token = register_and_login(client, username)
    add_verified_email(client, mail, token, "reset-race@example.com")
    reset_code = request_reset(client, mail, username)
    hashed, release, reset_finished = threading.Event(), threading.Event(), threading.Event()
    results = {}
    original_hash = app.state.password_service.hash

    def pause_rehash(password):
        result = original_hash(password)
        if password == PASSWORD and not hashed.is_set():
            hashed.set()
            assert release.wait(timeout=10), "login rehash was not released"
        return result

    # Model an Argon2 parameter upgrade, which triggers login's existing
    # migration path while the password is still the same.
    monkeypatch.setattr(app.state.password_service, "needs_rehash", lambda password_hash: True)
    monkeypatch.setattr(app.state.password_service, "hash", pause_rehash)
    login = threading.Thread(target=run_request, args=(
        results, "login", lambda: client.post("/api/auth/login", json={
            "username": username, "password": PASSWORD,
        }),
    ))

    def reset_request():
        try:
            return client.post("/api/auth/password-reset/confirm", json={
                "identifier": username, "code": reset_code, "new_password": NEW_PASSWORD,
            })
        finally:
            reset_finished.set()

    reset = threading.Thread(target=run_request, args=(results, "reset", reset_request))
    try:
        login.start()
        assert hashed.wait(timeout=5), "login did not reach the Argon2 rehash"
        reset.start()
        # If login holds the account lock, reset waits. Otherwise force the
        # accepted reset to commit before releasing the stale rehash write.
        reset_finished.wait(timeout=5)
    finally:
        release.set()
        login.join(timeout=10)
        if reset.ident is not None:
            reset.join(timeout=10)
    assert not login.is_alive() and not reset.is_alive()
    assert not isinstance(results.get("login"), BaseException)
    assert not isinstance(results.get("reset"), BaseException)
    assert results["login"].status_code in (200, 401), results["login"].text
    assert results["reset"].status_code in (204, 400), results["reset"].text
    if results["reset"].status_code == 204:
        with app.state.database.session_factory() as db:
            user = db.scalar(select(User).where(User.username == username))
            assert app.state.password_service.verify(user.password_hash, NEW_PASSWORD)
            assert not app.state.password_service.verify(user.password_hash, PASSWORD)
