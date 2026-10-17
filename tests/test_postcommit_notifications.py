"""Optional post-commit work cannot conceal a completed security operation."""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import event, func, select
from sqlalchemy.exc import OperationalError

from src.app.account_recovery import notify, send_code
from src.app.audit_chain import verify_chain
from src.app.mailer import MailUnavailable
from src.app.models import AuditEvent, AuthSession, User
from src.app.security import SlidingWindowRateLimiter
from tests.conftest import register_and_login
from tests.test_account_recovery import NEW_PASSWORD, PASSWORD, Recorder, auth
from tests.test_account_transactions import prepare_action
from tests.test_mfa import enroll_and_enable


@pytest.fixture
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


@contextmanager
def unavailable_notice_lookup(app):
    attempts = []

    def fail_lookup(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().lower().startswith("select account_emails."):
            attempts.append(True)
            if app.state.database.engine.dialect.name == "postgresql":
                # A real PostgreSQL statement failure aborts its transaction.
                # The independent notice session must absorb that rollback.
                return "SELECT 1 / 0", {}
            raise OperationalError("private recipient query", None, RuntimeError("private recipient fault"))
        return statement, _parameters

    event.listen(app.state.database.engine, "before_cursor_execute", fail_lookup, retval=True)
    try:
        yield attempts
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_lookup)


@pytest.mark.parametrize("method", ["password", "mfa_recovery"])
def test_completed_login_returns_its_single_session_when_notice_lookup_fails(
    client, app, mail, caplog, method,
):
    username = "postcommit-notice"
    if method == "mfa_recovery":
        _secret, _old_token, codes = enroll_and_enable(client, username)
        challenge = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()
        path = "/api/auth/mfa/verify"
        payload = {"mfa_token": challenge["mfa_token"], "code": codes[0]}
    else:
        register_and_login(client, username)
        path, payload = "/api/auth/login", {"username": username, "password": PASSWORD}
    with app.state.database.session_factory() as db:
        before = db.scalar(select(func.count()).select_from(AuthSession))
    with unavailable_notice_lookup(app) as attempts:
        response = client.post(path, json=payload)
    assert attempts == [True], "The new-device notification must exercise its own recipient lookup"
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 200
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == before + 1
        assert db.get(AuthSession, app.state.token_service.decode(token)["jti"]).revoked_at is None
        assert verify_chain(db, app.state.audit_key).intact
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == "auth.login.new_device")) is not None
    assert "private recipient" not in caplog.text


@pytest.mark.parametrize("operation", ["password", "mfa_disable"])
def test_completed_account_change_keeps_response_when_notice_lookup_fails(
    client, app, mail, operation,
):
    token, method, path, payload, expected_status, _event = prepare_action(client, app, mail, operation)
    with unavailable_notice_lookup(app) as attempts:
        response = client.request(method, path, headers=auth(token), json=payload)
    assert attempts == [True]
    assert response.status_code == expected_status, response.text
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "account-transaction"))
        if operation == "password":
            assert app.state.password_service.verify(user.password_hash, NEW_PASSWORD)
        else:
            assert user.mfa_enabled is False
        assert verify_chain(db, app.state.audit_key).intact


def test_notice_lookup_uses_a_separate_short_lived_session(client, app, mail, monkeypatch):
    register_and_login(client, "notice-session")
    reads = []
    with app.state.database.session_factory() as caller:
        user = caller.scalar(select(User).where(User.username == "notice-session"))

        def unavailable(reader, _user_id):
            reads.append(reader)
            assert reader is not caller
            raise OperationalError("private recipient query", None, RuntimeError("private fault"))

        monkeypatch.setattr("src.app.account_recovery.verified_email", unavailable)
        assert notify(caller, app.state.mailer, user_id=user.id, username=user.username,
                      kind="new_device", ip="192.0.2.1") is False
        assert reads and reads[0].in_transaction() is False
        assert caller.scalar(select(User.username).where(User.id == user.id)) == "notice-session"
        assert user.username == "notice-session"


def test_notice_delivery_failure_is_optional_but_proof_delivery_still_propagates(
    app, monkeypatch, caplog,
):
    app.state.mailer.transport = Recorder()

    def unavailable(*args, **kwargs):
        raise MailUnavailable("private mailbox failure")

    monkeypatch.setattr(app.state.mailer, "send", unavailable)
    with app.state.database.session_factory() as db:
        assert notify(db, app.state.mailer, user_id="user", username="notice-user",
                      kind="new_device", ip="192.0.2.1", to="owner@example.com") is False
    with pytest.raises(MailUnavailable):
        send_code(app.state.mailer, "owner@example.com", purpose="password_reset",
                  username="notice-user", code="abcdefghjk", minutes=5)
    assert "private mailbox" not in caplog.text


def fail_cleanup(monkeypatch, prefix):
    original = SlidingWindowRateLimiter.reset
    calls = []

    def unavailable(limiter, key):
        if key.startswith(prefix):
            calls.append(True)
            raise RedisConnectionError("private redis cleanup failure")
        return original(limiter, key)

    monkeypatch.setattr(SlidingWindowRateLimiter, "reset", unavailable)
    return calls


def test_mfa_activation_returns_usable_recovery_codes_when_throttle_cleanup_fails(
    client, app, monkeypatch, caplog,
):
    token = register_and_login(client, "postcommit-activation")
    enrolled = client.post("/api/auth/mfa/enroll", headers=auth(token))
    secret = enrolled.json()["secret"]
    with monkeypatch.context() as patch:
        attempts = fail_cleanup(patch, "mfa-activate:")
        response = client.post("/api/auth/mfa/activate", headers=auth(token),
                               json={"code": app.state.totp_service.now_code(secret)})
    assert attempts == [True]
    assert response.status_code == 200, response.text
    assert len(response.json()["recovery_codes"]) == app.state.settings.mfa_recovery_codes
    challenge = client.post("/api/auth/login", json={"username": "postcommit-activation", "password": PASSWORD}).json()
    recovered = client.post("/api/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"],
                                                        "code": response.json()["recovery_codes"][0]})
    assert recovered.status_code == 200, recovered.text
    assert "private redis" not in caplog.text


@pytest.mark.parametrize("operation,prefix", [
    ("step_up", "step-up:"), ("mfa_disable", "mfa-disable:"), ("password_reset", "login:"),
])
def test_completed_security_change_survives_optional_throttle_cleanup_failure(
    client, app, mail, monkeypatch, caplog, operation, prefix,
):
    token, method, path, payload, status, _event = prepare_action(client, app, mail, operation)
    with monkeypatch.context() as patch:
        attempts = fail_cleanup(patch, prefix)
        response = client.request(method, path, headers=auth(token), json=payload)
    assert attempts
    assert response.status_code == status, response.text
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "account-transaction"))
        if operation == "password_reset":
            assert app.state.password_service.verify(user.password_hash, NEW_PASSWORD)
        elif operation == "mfa_disable":
            assert user.mfa_enabled is False
        else:
            session = db.get(AuthSession, app.state.token_service.decode(token)["jti"])
            assert session.last_step_up_at is not None
        assert verify_chain(db, app.state.audit_key).intact
    assert "private redis" not in caplog.text


@pytest.mark.parametrize("method,prefix", [("password", "login:"), ("mfa_recovery", "mfa:")])
def test_precommit_throttle_failure_still_rejects_without_issuing_session(
    client, app, monkeypatch, method, prefix,
):
    username = "precommit-cleanup"
    if method == "mfa_recovery":
        _secret, _token, codes = enroll_and_enable(client, username)
        challenge = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()
        path = "/api/auth/mfa/verify"
        payload = {"mfa_token": challenge["mfa_token"], "code": codes[0]}
    else:
        register_and_login(client, username)
        path, payload = "/api/auth/login", {"username": username, "password": PASSWORD}
    with app.state.database.session_factory() as db:
        before = db.scalar(select(func.count()).select_from(AuthSession))
    with monkeypatch.context() as patch:
        attempts = fail_cleanup(patch, prefix)
        response = client.post(path, json=payload)
    assert attempts
    assert response.status_code == 503, response.text
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuthSession)) == before
    # Failure before the security transaction commits must preserve a claimed
    # recovery proof, unlike the optional cleanup after a completed operation.
    retry = client.post(path, json=payload)
    assert retry.status_code == 200, retry.text
