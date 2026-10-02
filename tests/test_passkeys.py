"""Passkeys (WebAuthn) through the real verification path, with a software authenticator."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.app.models import AuditEvent, AuthSession, User, WebAuthnCredential
from src.app.passkeys import validate_webauthn_config
from tests.conftest import register_and_login
from tests.webauthn_soft import SoftAuthenticator, b64url

PASSWORD = "Correct Horse Battery1"


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def register_passkey(client, token, authenticator, name="Laptop", **kwargs):
    options = client.post("/api/auth/passkeys/registration/options", headers=auth(token))
    assert options.status_code == 200, options.text
    body = options.json()
    credential = authenticator.register(body["public_key"], **kwargs)
    return client.post(
        "/api/auth/passkeys/registration/verify", headers=auth(token),
        json={"challenge_id": body["challenge_id"], "credential": credential, "name": name},
    )


def passkey_sign_in(client, authenticator, **kwargs):
    options = client.post("/api/auth/passkeys/authentication/options").json()
    credential = authenticator.assert_(options["public_key"], **kwargs)
    response = client.post(
        "/api/auth/passkeys/authentication/verify",
        json={"challenge_id": options["challenge_id"], "credential": credential},
    )
    return response, options, credential


def events(app, event_type):
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == event_type)))
        for row in rows:
            db.expunge(row)
        return rows


def test_options_require_user_verification_and_a_discoverable_key(client: TestClient):
    token = register_and_login(client, "pk-options")
    body = client.post("/api/auth/passkeys/registration/options", headers=auth(token)).json()
    public_key = body["public_key"]
    assert public_key["rp"]["id"] == "localhost"
    assert public_key["authenticatorSelection"]["userVerification"] == "required"
    assert public_key["authenticatorSelection"]["residentKey"] == "required"
    assert public_key["attestation"] == "none"
    # The user handle is the opaque account id, never the name.
    assert "pk-options" not in public_key["user"]["id"]
    sign_in = client.post("/api/auth/passkeys/authentication/options").json()["public_key"]
    assert sign_in["userVerification"] == "required"
    assert sign_in.get("allowCredentials", []) == []  # usernameless: reveals no account


def test_register_then_sign_in_without_a_password(client: TestClient, app):
    token = register_and_login(client, "pk-user")
    device = SoftAuthenticator()
    created = register_passkey(client, token, device)
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "Laptop"
    listed = client.get("/api/auth/passkeys", headers=auth(token)).json()
    assert [item["name"] for item in listed] == ["Laptop"]

    response, _, _ = passkey_sign_in(client, device)
    assert response.status_code == 200, response.text
    session_token = response.json()["access_token"]
    assert response.json()["device_token"]
    assert client.get("/api/auth/me", headers=auth(session_token)).json()["username"] == "pk-user"
    login_event = events(app, "auth.passkey.login")[-1]
    assert login_event.outcome == "success"
    with app.state.database.session_factory() as db:
        stored = db.scalars(select(WebAuthnCredential)).one()
        assert stored.sign_count == 1 and stored.last_used_at is not None
        # Only public material is stored.
        assert "private" not in stored.public_key.lower()


def test_passkey_sign_in_counts_as_a_fresh_strong_authentication(client: TestClient, app):
    token = register_and_login(client, "pk-stepup")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    response, _, _ = passkey_sign_in(client, device)
    jti = app.state.token_service.decode(response.json()["access_token"])["jti"]
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is not None


def test_a_challenge_can_be_used_once(client: TestClient):
    """Synced passkeys usually report a counter of 0, so the counter cannot catch
    a replayed assertion; the single-use challenge is the only defence."""
    token = register_and_login(client, "pk-replay")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    response, options, credential = passkey_sign_in(client, device, sign_count=0)
    assert response.status_code == 200
    replay = client.post(
        "/api/auth/passkeys/authentication/verify",
        json={"challenge_id": options["challenge_id"], "credential": credential},
    )
    assert replay.status_code == 401


@pytest.mark.parametrize("change", [
    {"origin": "https://localhost.evil.example"},  # phishing look-alike origin
    {"uv": False},                                  # no PIN/biometric
])
def test_phishing_origin_and_missing_user_verification_are_rejected(client: TestClient, change):
    token = register_and_login(client, "pk-reject")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    response, _, _ = passkey_sign_in(client, device, **change)
    assert response.status_code == 401


def test_registration_from_a_foreign_origin_is_rejected(client: TestClient, app):
    token = register_and_login(client, "pk-reg-origin")
    response = register_passkey(
        client, token, SoftAuthenticator(), origin="https://scap.evil.example"
    )
    assert response.status_code == 400
    assert events(app, "auth.passkey.add")[-1].outcome == "failure"


def test_cloned_authenticator_is_detected_by_its_counter(client: TestClient, app):
    token = register_and_login(client, "pk-clone")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    for _ in range(3):
        assert passkey_sign_in(client, device)[0].status_code == 200
    stale, _, _ = passkey_sign_in(client, device, sign_count=2)
    assert stale.status_code == 401
    failure = events(app, "auth.passkey.login")[-1]
    assert failure.outcome == "failure" and "sign_count_regression" in failure.details_json
    with app.state.database.session_factory() as db:
        owner = db.scalar(select(User).where(User.username == "pk-clone"))
        assert failure.actor_id == owner.id


def test_a_mismatched_user_handle_is_rejected(client: TestClient):
    token = register_and_login(client, "pk-handle")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    response, _, _ = passkey_sign_in(client, device, user_handle=b"someone-else")
    assert response.status_code == 401


def test_unknown_credential_and_malformed_payloads_fail_closed(client: TestClient):
    stranger = SoftAuthenticator()
    response, _, _ = passkey_sign_in(client, stranger)
    assert response.status_code == 401
    options = client.post("/api/auth/passkeys/authentication/options").json()
    garbage = client.post(
        "/api/auth/passkeys/authentication/verify",
        json={"challenge_id": options["challenge_id"], "credential": {"id": 1, "rawId": [2]}},
    )
    assert garbage.status_code == 401


def test_adding_a_passkey_needs_a_recent_reauthentication(client: TestClient, app):
    token = register_and_login(client, "pk-stale")
    with app.state.database.session_factory() as db:
        for row in db.scalars(select(AuthSession)):
            row.last_step_up_at = None
        db.commit()
    options = client.post("/api/auth/passkeys/registration/options", headers=auth(token))
    assert options.status_code == 403


def test_the_same_authenticator_cannot_be_registered_twice(client: TestClient):
    token = register_and_login(client, "pk-dup")
    device = SoftAuthenticator()
    assert register_passkey(client, token, device).status_code == 201
    options = client.post("/api/auth/passkeys/registration/options", headers=auth(token)).json()
    excluded = [item["id"] for item in options["public_key"]["excludeCredentials"]]
    assert excluded == [b64url(device.credential_id)]
    again = client.post(
        "/api/auth/passkeys/registration/verify", headers=auth(token),
        json={"challenge_id": options["challenge_id"],
              "credential": device.register(options["public_key"])},
    )
    assert again.status_code == 400


def test_removed_passkey_no_longer_signs_in(client: TestClient):
    token = register_and_login(client, "pk-remove")
    device = SoftAuthenticator()
    passkey_id = register_passkey(client, token, device).json()["id"]
    other = register_and_login(client, "pk-other-owner")
    assert client.delete(f"/api/auth/passkeys/{passkey_id}", headers=auth(other)).status_code == 404
    assert client.delete(f"/api/auth/passkeys/{passkey_id}", headers=auth(token)).status_code == 204
    assert passkey_sign_in(client, device)[0].status_code == 401


def test_suspended_account_cannot_use_its_passkey(client: TestClient, app):
    token = register_and_login(client, "pk-suspended")
    device = SoftAuthenticator()
    register_passkey(client, token, device)
    with app.state.database.session_factory() as db:
        db.scalar(select(User).where(User.username == "pk-suspended")).is_active = False
        db.commit()
    assert passkey_sign_in(client, device)[0].status_code == 401


@pytest.mark.parametrize(("rp_id", "origins"), [
    ("127.0.0.1", ("http://127.0.0.1:8000",)),          # IP addresses are not RP IDs
    ("scap.example", ("http://scap.example",)),         # HTTP only for localhost
    ("scap.example", ("https://evil.example",)),        # origin outside the RP ID
    ("localhost", ()),
])
def test_unsafe_webauthn_configuration_fails_at_startup(rp_id, origins):
    with pytest.raises(RuntimeError):
        validate_webauthn_config(rp_id, origins)


def test_subdomain_origins_over_https_are_accepted():
    validate_webauthn_config("scap.example", ("https://scap.example", "https://app.scap.example"))


def test_deleting_an_account_removes_its_passkeys_and_recovery_email(client: TestClient, app):
    from src.app.db import utcnow
    from src.app.models import AccountEmail

    token = register_and_login(client, "pk-delete-me")
    register_passkey(client, token, SoftAuthenticator())
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "pk-delete-me"))
        db.add(AccountEmail(user_id=user.id, email="gone@example.com",
                            normalized_email="gone@example.com", verified_at=utcnow()))
        db.add(User(username="pk-admin", password_hash=app.state.password_service.hash(PASSWORD),
                    role="admin"))
        db.commit()
        user_id = user.id
    admin = client.post(
        "/api/auth/login", json={"username": "pk-admin", "password": PASSWORD}
    ).json()["access_token"]
    assert client.delete(f"/api/admin/users/{user_id}", headers=auth(admin)).status_code == 204
    with app.state.database.session_factory() as db:
        assert db.scalars(select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)).all() == []
        assert db.get(AccountEmail, user_id) is None


def test_retention_prunes_expired_passkey_challenges_and_recovery_codes(client: TestClient, app):
    from datetime import timedelta

    from src.app.db import utcnow
    from src.app.models import AccountRecoveryCode, WebAuthnChallenge
    from src.app.retention import enforce_retention

    register_and_login(client, "pk-retention")
    for _ in range(3):
        client.post("/api/auth/passkeys/authentication/options")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "pk-retention"))
        past = utcnow() - timedelta(hours=1)
        for row in db.scalars(select(WebAuthnChallenge)):
            row.expires_at = past
        db.add(AccountRecoveryCode(user_id=user.id, purpose="password_reset",
                                   code_hash="0" * 64, expires_at=past))
        db.commit()
        result = enforce_retention(db)
        assert result.expired_passkey_challenges == 3 and result.expired_recovery_codes == 1
        assert db.scalars(select(WebAuthnChallenge)).all() == []
