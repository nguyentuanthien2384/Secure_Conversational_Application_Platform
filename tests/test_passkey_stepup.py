"""Passkey reauthentication uses real ES256 assertions and the exact live bearer."""
from __future__ import annotations

import functools
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.db import utcnow
from src.app.models import AuditEvent, AuthSession, User, WebAuthnChallenge, WebAuthnCredential
from tests.conftest import register_and_login
from tests.test_passkeys import PASSWORD, auth, register_passkey
from tests.webauthn_soft import SoftAuthenticator, b64url, unb64url

OPTIONS = "/api/auth/passkeys/step-up/options"
VERIFY = "/api/auth/passkeys/step-up/verify"


def setup_key(client, app, username="passkey-reauth"):
    token = register_and_login(client, username)
    device = SoftAuthenticator()
    assert register_passkey(client, token, device).status_code == 201
    jti = app.state.token_service.decode(token)["jti"]
    with app.state.database.session_factory() as db:
        db.get(AuthSession, jti).last_step_up_at = None
        db.commit()
    return token, device, jti


def begin(client, token):
    response = client.post(OPTIONS, headers=auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def verify(client, token, options, credential):
    return client.post(VERIFY, headers=auth(token), json={
        "challenge_id": options["challenge_id"], "credential": credential,
    })


def security_snapshot(app):
    with app.state.database.session_factory() as db:
        return {
            "challenges": [(row.id, row.consumed_at) for row in db.scalars(
                select(WebAuthnChallenge).order_by(WebAuthnChallenge.id),
            )],
            "credentials": [(row.id, row.sign_count, row.last_used_at) for row in db.scalars(
                select(WebAuthnCredential).order_by(WebAuthnCredential.id),
            )],
            "sessions": [(row.jti, row.last_step_up_at) for row in db.scalars(
                select(AuthSession).order_by(AuthSession.jti),
            )],
            "audit": [row.id for row in db.scalars(select(AuditEvent).order_by(AuditEvent.id))],
        }


def test_real_passkey_step_up_grants_only_the_presented_bearer(client, app):
    token, device, jti = setup_key(client, app)
    other_token = client.post("/api/auth/login", json={
        "username": "passkey-reauth", "password": PASSWORD,
    }).json()["access_token"]
    other_jti = app.state.token_service.decode(other_token)["jti"]
    with app.state.database.session_factory() as db:
        db.get(AuthSession, other_jti).last_step_up_at = None
        db.commit()
    protected = "/api/auth/passkeys/registration/options"
    assert client.post(protected, headers=auth(token)).status_code == 403
    options = begin(client, token)
    assert options["public_key"]["userVerification"] == "required"
    assert options["public_key"]["rpId"] == "localhost"
    assert options["public_key"]["allowCredentials"] == [{
        "id": b64url(device.credential_id), "type": "public-key",
    }]
    with app.state.database.session_factory() as db:
        challenge = db.get(WebAuthnChallenge, options["challenge_id"])
        assert challenge.auth_session_id == jti
        assert challenge.purpose == "step_up"
        assert challenge.user_id == db.get(AuthSession, jti).user_id
    response = verify(client, token, options, device.assert_(options["public_key"]))
    assert response.status_code == 200, response.text
    assert response.json()["valid_for_seconds"] == app.state.settings.step_up_minutes * 60
    assert "access_token" not in response.json()
    assert client.post(protected, headers=auth(token)).status_code == 200
    assert client.post(protected, headers=auth(other_token)).status_code == 403
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is not None
        assert db.get(AuthSession, other_jti).last_step_up_at is None
        row = db.scalars(select(WebAuthnCredential)).one()
        assert row.sign_count == 1 and row.last_used_at is not None
        audited = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "auth.step_up")))
        assert audited[-1].target_id == jti and audited[-1].outcome == "success"
        assert json.loads(audited[-1].details_json)["method"] == "passkey"
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("target", ["same_account", "other_account", "refreshed"])
def test_challenge_cannot_move_to_another_account_or_bearer(client, app, target):
    token, device, jti = setup_key(client, app)
    options = begin(client, token)
    credential = device.assert_(options["public_key"], sign_count=0)
    if target == "other_account":
        other = register_and_login(client, "passkey-foreign")
    elif target == "refreshed":
        response = client.post("/api/auth/refresh", headers=auth(token))
        assert response.status_code == 200, response.text
        other = response.json()["access_token"]
    else:
        other = client.post("/api/auth/login", json={
            "username": "passkey-reauth", "password": PASSWORD,
        }).json()["access_token"]
    other_jti = app.state.token_service.decode(other)["jti"]
    with app.state.database.session_factory() as db:
        db.get(AuthSession, other_jti).last_step_up_at = None
        db.commit()
    assert verify(client, other, options, credential).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.get(WebAuthnChallenge, options["challenge_id"]).consumed_at is None
        assert db.get(AuthSession, other_jti).last_step_up_at is None
        assert db.get(AuthSession, jti).last_step_up_at is None
    if target != "refreshed":
        assert verify(client, token, options, credential).status_code == 200
    else:
        assert verify(client, token, options, credential).status_code == 401


@pytest.mark.parametrize("change", ["origin", "rp_id", "no_uv", "signature", "user_handle", "credential"])
def test_invalid_assertions_burn_the_bound_challenge_without_elevating(client, app, change):
    token, device, jti = setup_key(client, app)
    options = begin(client, token)
    request_options = dict(options["public_key"])
    kwargs = {}
    if change == "origin":
        kwargs["origin"] = "https://localhost.evil.example"
    elif change == "no_uv":
        kwargs["uv"] = False
    elif change == "user_handle":
        kwargs["user_handle"] = b"another-account"
    elif change == "rp_id":
        request_options["rpId"] = "evil.example"
    credential = device.assert_(request_options, **kwargs)
    if change == "signature":
        signature = bytearray(unb64url(credential["response"]["signature"]))
        signature[-1] ^= 1
        credential["response"]["signature"] = b64url(signature)
    elif change == "credential":
        credential["id"] = credential["rawId"] = b64url(b"unknown credential")
    response = verify(client, token, options, credential)
    assert response.status_code == 401, response.text
    with app.state.database.session_factory() as db:
        assert db.get(WebAuthnChallenge, options["challenge_id"]).consumed_at is not None
        assert db.get(AuthSession, jti).last_step_up_at is None
        assert db.scalars(select(WebAuthnCredential)).one().sign_count == 0
        audited = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "auth.step_up")))
        assert audited[-1].outcome == "failure"
        assert verify_chain(db, app.state.audit_key).intact
    assert verify(client, token, options, device.assert_(options["public_key"])).status_code == 401


def test_another_accounts_valid_credential_cannot_step_up_this_account(client, app):
    token, _device, jti = setup_key(client, app)
    foreign = register_and_login(client, "passkey-stranger")
    foreign_device = SoftAuthenticator()
    assert register_passkey(client, foreign, foreign_device).status_code == 201
    options = begin(client, token)
    assert verify(client, token, options, foreign_device.assert_(options["public_key"])).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is None
        assert all(row.sign_count == 0 for row in db.scalars(select(WebAuthnCredential)))


def test_successful_assertion_is_single_use_even_with_zero_sign_count(client, app):
    token, device, _jti = setup_key(client, app)
    options = begin(client, token)
    credential = device.assert_(options["public_key"], sign_count=0)
    assert verify(client, token, options, credential).status_code == 200
    before = security_snapshot(app)
    assert verify(client, token, options, credential).status_code == 401
    after = security_snapshot(app)
    assert after["credentials"] == before["credentials"]
    assert after["sessions"] == before["sessions"]


def test_expired_and_other_purpose_challenges_cannot_authorize_step_up(client, app):
    token, device, jti = setup_key(client, app)
    options = begin(client, token)
    with app.state.database.session_factory() as db:
        db.get(WebAuthnChallenge, options["challenge_id"]).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert verify(client, token, options, device.assert_(options["public_key"])).status_code == 401
    login_options = client.post("/api/auth/passkeys/authentication/options").json()
    assert verify(client, token, login_options, device.assert_(login_options["public_key"])).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is None
        assert db.get(WebAuthnChallenge, login_options["challenge_id"]).consumed_at is None


def test_step_up_assertion_is_not_a_passwordless_login_assertion(client, app):
    token, device, _jti = setup_key(client, app)
    options = begin(client, token)
    credential = device.assert_(options["public_key"])
    assert client.post("/api/auth/passkeys/authentication/verify", json={
        "challenge_id": options["challenge_id"], "credential": credential,
    }).status_code == 401
    assert verify(client, token, options, credential).status_code == 200


@pytest.mark.parametrize("valid", [True, False])
def test_step_up_and_challenge_counter_audit_are_one_transaction(client, app, valid):
    token, device, _jti = setup_key(client, app)
    options = begin(client, token)
    credential = device.assert_(options["public_key"], uv=valid)
    before = security_snapshot(app)
    failures = []

    def reject_audit(_conn, _cursor, statement, _params, context, _many):
        if (statement.lstrip().lower().startswith("insert into audit_events")
                and any(item.get("event_type") == "auth.step_up" for item in context.compiled_parameters)):
            failures.append(True)
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", reject_audit)
    try:
        response = verify(client, token, options, credential)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", reject_audit)
    assert failures == [True]
    assert response.status_code == 503, response.text
    assert security_snapshot(app) == before
    retry = verify(client, token, options, credential)
    assert retry.status_code == (200 if valid else 401), retry.text


@pytest.mark.parametrize("transition", ["logout", "refresh", "logout-all"])
@pytest.mark.parametrize("stage", ["options", "verify"])
def test_inflight_ceremony_rechecks_exact_bearer_after_revocation(client, app, transition, stage):
    token, device, _jti = setup_key(client, app)
    revoker = token
    if transition == "logout-all":
        # Logout-all itself needs fresh authentication. Use a separate fresh
        # session while leaving the target bearer awaiting reauthentication.
        revoker = client.post("/api/auth/login", json={
            "username": "passkey-reauth", "password": PASSWORD,
        }).json()["access_token"]
    path = OPTIONS if stage == "options" else VERIFY
    body = None
    if stage == "verify":
        options = begin(client, token)
        body = {"challenge_id": options["challenge_id"], "credential": device.assert_(options["public_key"])}
    route = next(item for item in app.routes if getattr(item, "path", "") == path)
    dependency = next(item.call for item in route.dependant.dependencies if item.name == "user")
    reached, release = threading.Event(), threading.Event()

    @functools.wraps(dependency)
    def pause(*args, **kwargs):
        user = dependency(*args, **kwargs)
        if kwargs["request"].url.path == path:
            reached.set()
            assert release.wait(15)
        return user

    app.dependency_overrides[dependency] = pause
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(client.post, path, headers=auth(token), json=body)
            try:
                assert reached.wait(15)
                response = client.post(f"/api/auth/{transition}", headers=auth(revoker))
                assert response.status_code in {200, 204}, response.text
                before = security_snapshot(app)
            finally:
                release.set()
            response = pending.result(timeout=15)
    finally:
        app.dependency_overrides.pop(dependency, None)
    assert response.status_code == 401, response.text
    assert security_snapshot(app) == before


def test_removed_credential_cannot_reauthenticate_an_outstanding_ceremony(client, app):
    token, device, jti = setup_key(client, app)
    options = begin(client, token)
    with app.state.database.session_factory() as db:
        db.delete(db.scalars(select(WebAuthnCredential)).one())
        db.commit()
    assert verify(client, token, options, device.assert_(options["public_key"])).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is None


def test_keyless_account_uses_password_fallback_and_anonymous_cannot_get_options(client, app):
    token = register_and_login(client, "passkey-keyless")
    assert client.post(OPTIONS, headers=auth(token)).status_code == 409
    assert client.post(OPTIONS).status_code == 401
    assert client.post(VERIFY, json={"challenge_id": "a" * 36, "credential": {}}).status_code == 401
    with app.state.database.session_factory() as db:
        assert list(db.scalars(select(WebAuthnChallenge))) == []


def test_step_up_counter_regression_is_rejected(client, app):
    token, device, _jti = setup_key(client, app)
    options = begin(client, token)
    assert verify(client, token, options, device.assert_(options["public_key"], sign_count=3)).status_code == 200
    options = begin(client, token)
    assert verify(client, token, options, device.assert_(options["public_key"], sign_count=2)).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.scalars(select(WebAuthnCredential)).one().sign_count == 3
        audited = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "auth.step_up")))
        assert json.loads(audited[-1].details_json)["reason"] == "sign_count_regression"


def test_concurrent_login_and_step_up_never_move_a_credential_counter_backwards(client, app, monkeypatch):
    """On PostgreSQL, distinct challenge rows must still serialize on User.

    The lower-counter login pauses during real signature verification. An
    unlocked step-up could commit counter 3 before the stale login writes 2.
    SQLite's writer lock additionally serializes the same public workflow.
    """
    from src.app import passkeys

    token, device, _jti = setup_key(client, app)
    login = client.post("/api/auth/passkeys/authentication/options").json()
    login_credential = device.assert_(login["public_key"], sign_count=2)
    step_up = begin(client, token)
    step_up_credential = device.assert_(step_up["public_key"], sign_count=3)
    reached, release, higher_entered = threading.Event(), threading.Event(), threading.Event()
    original = passkeys.verify_authentication_response

    def pause_lower_counter(**kwargs):
        data = unb64url(kwargs["credential"]["response"]["authenticatorData"])
        counter = int.from_bytes(data[33:37], "big")
        if counter == 2:
            reached.set()
            assert release.wait(15)
        elif counter == 3:
            higher_entered.set()
        return original(**kwargs)

    monkeypatch.setattr(passkeys, "verify_authentication_response", pause_lower_counter)
    with ThreadPoolExecutor(max_workers=2) as executor:
        lower = executor.submit(client.post, "/api/auth/passkeys/authentication/verify", json={
            "challenge_id": login["challenge_id"], "credential": login_credential,
        })
        try:
            assert reached.wait(15)
            higher = executor.submit(verify, client, token, step_up, step_up_credential)
            # Give an unlocked PostgreSQL contender the chance to expose a lost
            # update. The correct implementation waits for the User lock.
            higher_entered.wait(0.5)
        finally:
            release.set()
        lower_response, higher_response = lower.result(timeout=15), higher.result(timeout=15)
    assert lower_response.status_code == 200, lower_response.text
    assert higher_response.status_code == 200, higher_response.text
    with app.state.database.session_factory() as db:
        assert db.scalars(select(WebAuthnCredential)).one().sign_count == 3
        assert verify_chain(db, app.state.audit_key).intact


@pytest.mark.parametrize("transition", ["suspend", "remove_key"])
def test_passwordless_login_rechecks_account_and_credential_after_candidate_lookup(client, app, monkeypatch, transition):
    token, device, _jti = setup_key(client, app)
    options = client.post("/api/auth/passkeys/authentication/options").json()
    credential = device.assert_(options["public_key"])
    reached, release = threading.Event(), threading.Event()
    original = app.state.passkeys.authentication_user_id

    def pause_lookup(db, payload):
        owner = original(db, payload)
        reached.set()
        assert release.wait(15)
        return owner

    monkeypatch.setattr(app.state.passkeys, "authentication_user_id", pause_lookup)
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(client.post, "/api/auth/passkeys/authentication/verify", json={
            "challenge_id": options["challenge_id"], "credential": credential,
        })
        try:
            assert reached.wait(15)
            with app.state.database.session_factory() as db:
                row = db.scalars(select(WebAuthnCredential)).one()
                if transition == "suspend":
                    db.get(User, row.user_id).is_active = False
                else:
                    db.delete(row)
                db.commit()
        finally:
            release.set()
        response = pending.result(timeout=15)
    assert response.status_code == 401, response.text
    with app.state.database.session_factory() as db:
        assert len(list(db.scalars(select(AuthSession)))) == 1
        assert db.get(WebAuthnChallenge, options["challenge_id"]).consumed_at is not None


@pytest.mark.parametrize("ceremony,valid", [("login", True), ("login", False), ("register", False)])
def test_passwordless_and_failed_registration_proofs_roll_back_with_failed_audit(client, app, ceremony, valid):
    token = register_and_login(client, "passkey-login-atomic")
    device = SoftAuthenticator()
    if ceremony == "login":
        assert register_passkey(client, token, device).status_code == 201
        options = client.post("/api/auth/passkeys/authentication/options").json()
        credential = device.assert_(options["public_key"], uv=valid)
        path, headers, event_type = "/api/auth/passkeys/authentication/verify", {}, "auth.passkey.login"
    else:
        options = client.post("/api/auth/passkeys/registration/options", headers=auth(token)).json()
        credential = device.register(options["public_key"], uv=False)
        path, headers, event_type = "/api/auth/passkeys/registration/verify", auth(token), "auth.passkey.add"
    body = {"challenge_id": options["challenge_id"], "credential": credential}
    before = security_snapshot(app)
    failures = []

    def reject_audit(_conn, _cursor, statement, _params, context, _many):
        if (statement.lstrip().lower().startswith("insert into audit_events")
                and any(item.get("event_type") == event_type for item in context.compiled_parameters)):
            failures.append(True)
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", reject_audit)
    try:
        response = client.post(path, headers=headers, json=body)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", reject_audit)
    assert failures == [True]
    assert response.status_code == 503, response.text
    assert security_snapshot(app) == before
    retry = client.post(path, headers=headers, json=body)
    expected = 200 if valid else (401 if ceremony == "login" else 400)
    assert retry.status_code == expected, retry.text
