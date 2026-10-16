"""Security-account mutations keep authority, state and audit in one transaction."""
from __future__ import annotations

import functools
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.db import utcnow
from src.app.models import (
    AccountEmail,
    AccountRecoveryCode,
    AuditEvent,
    AuthSession,
    MfaRecoveryCode,
    User,
    WebAuthnChallenge,
    WebAuthnCredential,
)
from tests.conftest import register_and_login
from tests.test_account_recovery import NEW_PASSWORD, PASSWORD, Recorder, add_verified_email, auth
from tests.test_passkeys import register_passkey
from tests.webauthn_soft import SoftAuthenticator


@pytest.fixture
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


def prepare_action(client, app, mail, operation):
    username = "account-transaction"
    token = register_and_login(client, username)
    method, status, payload = "POST", 204, None
    if operation.startswith("email") or operation == "password_reset":
        add_verified_email(client, mail, token, "old@example.com")
    if operation in {"mfa_activate", "mfa_disable"}:
        secret = client.post("/api/auth/mfa/enroll", headers=auth(token)).json()["secret"]
        code = app.state.totp_service.now_code(secret)
        payload = {"code": code}
        if operation == "mfa_disable":
            enabled = client.post("/api/auth/mfa/activate", headers=auth(token), json=payload)
            assert enabled.status_code == 200, enabled.text
            codes = enabled.json()["recovery_codes"]
            challenge = client.post("/api/auth/login", json={"username": username, "password": PASSWORD}).json()
            login = client.post("/api/auth/mfa/verify", json={"mfa_token": challenge["mfa_token"], "code": codes[0]})
            assert login.status_code == 200, login.text
            token = login.json()["access_token"]
            payload = {"password": PASSWORD, "code": codes[1]}
    if operation == "password":
        method, path, event_type = "PATCH", "/api/auth/password", "auth.password_change"
        payload = {"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    elif operation == "password_reset":
        response = client.post("/api/auth/password-reset/request", json={"identifier": username})
        assert response.status_code == 202
        path, event_type = "/api/auth/password-reset/confirm", "auth.password_reset"
        payload = {"identifier": username, "code": mail.code_for("old@example.com"), "new_password": NEW_PASSWORD}
    elif operation.startswith("mfa_"):
        path = "/api/auth/mfa/" + operation.removeprefix("mfa_")
        event_type = {"mfa_enroll": "auth.mfa.enroll", "mfa_activate": "auth.mfa.enabled", "mfa_disable": "auth.mfa.disabled"}[operation]
        status = 204 if operation == "mfa_disable" else 200
    elif operation == "email_remove":
        method, path, event_type = "DELETE", "/api/auth/email", "account.email.remove"
    elif operation in {"email_request", "email_verify"}:
        path, event_type, status = "/api/auth/email", "account.email.verification", 202
        payload = {"email": "new@example.com"}
        if operation == "email_verify":
            assert client.post(path, headers=auth(token), json=payload).status_code == 202
            path, event_type, status = "/api/auth/email/verify", "account.email.verify", 200
            payload = {"code": mail.code_for("new@example.com")}
    elif operation == "passkey_register":
        device = SoftAuthenticator()
        options = client.post("/api/auth/passkeys/registration/options", headers=auth(token)).json()
        path, event_type, status = "/api/auth/passkeys/registration/verify", "auth.passkey.add", 201
        payload = {"challenge_id": options["challenge_id"], "credential": device.register(options["public_key"])}
    elif operation == "passkey_remove":
        created = register_passkey(client, token, SoftAuthenticator())
        assert created.status_code == 201
        method, path, event_type = "DELETE", f"/api/auth/passkeys/{created.json()['id']}", "auth.passkey.remove"
    elif operation == "step_up":
        path, event_type, status = "/api/auth/step-up", "auth.step_up", 200
        payload = {"password": PASSWORD}
    elif operation == "session_revoke":
        # Revoke the requesting device: the transaction must preserve it on a
        # failed audit and the same bearer must then be usable for a retry.
        jti = app.state.token_service.decode(token)["jti"]
        method, path, event_type = "DELETE", f"/api/auth/sessions/{jti}", "auth.session_revoke"
    else:
        assert operation == "logout_all"
        path, event_type = "/api/auth/logout-all", "auth.logout_all"
    return token, method, path, payload, status, event_type


def security_snapshot(app):
    """Exclude request activity while retaining credentials and revocation state."""
    columns = (
        (User, ("id", "password_hash", "is_active", "token_version", "mfa_enabled", "mfa_secret_ciphertext", "mfa_secret_nonce", "mfa_last_counter")),
        (AccountEmail, ("user_id", "email", "normalized_email", "verified_at")),
        (AccountRecoveryCode, ("id", "code_hash", "consumed_at", "attempts")),
        (MfaRecoveryCode, ("id", "code_hash", "used_at")),
        (WebAuthnCredential, ("id", "credential_id", "public_key", "sign_count")),
        (WebAuthnChallenge, ("id", "consumed_at")),
        (AuthSession, ("jti", "revoked_at", "last_step_up_at")),
        (AuditEvent, ("id", "event_type", "entry_hash")),
    )
    with app.state.database.session_factory() as db:
        return {
            model.__name__: sorted(
                [tuple(getattr(row, name) for name in names) for row in db.scalars(select(model))],
                key=lambda row: str(row[0]),
            )
            for model, names in columns
        }


@pytest.mark.parametrize("operation", [
    "password", "password_reset", "mfa_enroll", "mfa_activate", "mfa_disable",
    "email_request", "email_verify", "email_remove", "passkey_register", "passkey_remove",
    "step_up", "session_revoke", "logout_all",
])
def test_account_mutation_and_one_time_proofs_roll_back_with_failed_audit(client, app, mail, operation):
    token, method, path, payload, expected_status, event_type = prepare_action(client, app, mail, operation)
    before = security_snapshot(app)
    sent_before = len(mail.messages)

    def fail_insert(_conn, _cursor, statement, _params, _context, _many):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("audit unavailable", None, RuntimeError("test storage fault"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_insert)
    try:
        response = client.request(method, path, headers=auth(token), json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_insert)
    assert response.status_code == 503, response.text
    assert security_snapshot(app) == before
    assert len(mail.messages) == sent_before
    # In particular, a failed MFA activation/password reset/registration does
    # not burn the proof while hiding its successful response from the user.
    retry = client.request(method, path, headers=auth(token), json=payload)
    assert retry.status_code == expected_status, retry.text
    with app.state.database.session_factory() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == event_type)) is not None
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("operation", [
    "mfa_enroll", "mfa_activate", "mfa_disable", "email_request", "email_verify",
    "email_remove", "passkey_register", "passkey_remove", "step_up", "session_revoke", "logout_all",
])
def test_account_mutation_rejects_logout_after_dependency_authentication(client, app, mail, operation):
    token, method, path, payload, _status, _event = prepare_action(client, app, mail, operation)
    _assert_revoked_mutation(client, app, token, method, path, payload, "logout")


@pytest.mark.parametrize("transition", ["logout_all", "refresh", "expiry", "step_up_expiry"])
def test_passkey_registration_rechecks_current_session_and_step_up(client, app, mail, transition):
    token, method, path, payload, _status, _event = prepare_action(client, app, mail, "passkey_register")
    _assert_revoked_mutation(client, app, token, method, path, payload, transition)


def _assert_revoked_mutation(client, app, token, method, path, payload, transition):
    # All account routes share this dependency, including parameterized paths.
    route = next(item for item in app.routes if getattr(item, "path", "") == "/api/auth/password")
    current_user = next(item.call for item in route.dependant.dependencies if item.name == "user")
    authenticated, release = threading.Event(), threading.Event()
    paused = False

    @functools.wraps(current_user)
    def pause_after_authentication(*args, **kwargs):
        nonlocal paused
        user = current_user(*args, **kwargs)
        if kwargs["request"].url.path == path and not paused:
            paused = True
            authenticated.set()
            assert release.wait(10)
        return user

    app.dependency_overrides[current_user] = pause_after_authentication
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client.request, method, path, headers=auth(token), json=payload)
            try:
                assert authenticated.wait(10)
                if transition in {"expiry", "step_up_expiry"}:
                    jti = app.state.token_service.decode(token)["jti"]
                    with app.state.database.session_factory() as db:
                        session = db.get(AuthSession, jti)
                        if transition == "expiry":
                            session.expires_at = utcnow() - timedelta(seconds=1)
                        else:
                            session.last_step_up_at = utcnow() - timedelta(hours=1)
                        db.commit()
                else:
                    endpoint = {"logout_all": "logout-all", "refresh": "refresh", "logout": "logout"}[transition]
                    revoked = client.post(f"/api/auth/{endpoint}", headers=auth(token))
                    assert revoked.status_code in {200, 204}, revoked.text
                before = security_snapshot(app)
            finally:
                release.set()
            response = pending.result(timeout=10)
    finally:
        app.dependency_overrides.pop(current_user, None)
    if transition == "step_up_expiry":
        assert response.status_code == 403, response.text
        assert response.headers.get("X-Step-Up-Required") == "true"
    else:
        assert response.status_code == 401, response.text
        assert 'error="invalid_token"' in response.headers.get("WWW-Authenticate", "")
    assert security_snapshot(app) == before
