from __future__ import annotations

import hashlib
import io
import unicodedata

import pytest
from sqlalchemy import select

from src.app.models import AccountRecoveryCode, User
from src.app.security import PwnedPasswordChecker
from tests.conftest import register_and_login
from tests.test_account_recovery import (
    NEW_PASSWORD,
    PASSWORD,
    Recorder,
    add_verified_email,
    auth,
)
from tests.test_passkeys import register_passkey
from tests.webauthn_soft import SoftAuthenticator, b64url


@pytest.fixture()
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


@pytest.mark.parametrize("change", ["email", "password"])
def test_reset_code_is_invalid_after_recovery_credentials_change(client, app, mail, change):
    username = f"reset-bound-{change}"
    token = register_and_login(client, username)
    add_verified_email(client, mail, token, "previous@example.com")
    requested = client.post("/api/auth/password-reset/request", json={"identifier": username})
    assert requested.status_code == 202
    old_code = mail.code_for("previous@example.com")

    current_password = PASSWORD
    current_email = "previous@example.com"
    if change == "email":
        current_email = "replacement@example.com"
        add_verified_email(client, mail, token, current_email)
    else:
        current_password = "A newly chosen long password 2026"
        changed = client.patch(
            "/api/auth/password", headers=auth(token),
            json={"current_password": PASSWORD, "new_password": current_password},
        )
        assert changed.status_code == 204, changed.text

    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        password_hash, token_version = user.password_hash, user.token_version
        if change == "email":
            reset_codes = list(db.scalars(select(AccountRecoveryCode).where(
                AccountRecoveryCode.user_id == user.id,
                AccountRecoveryCode.purpose == "password_reset",
            )))
            assert all(row.consumed_at is not None for row in reset_codes)

    rejected = client.post("/api/auth/password-reset/confirm", json={
        "identifier": username, "code": old_code, "new_password": NEW_PASSWORD,
    })
    assert rejected.status_code == 400, rejected.text
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        assert (user.password_hash, user.token_version) == (password_hash, token_version)
    login = client.post("/api/auth/login", json={
        "username": username, "password": current_password,
    })
    assert login.status_code == 200, login.text

    # The new password/mailbox context can still recover the account.
    fresh = client.post("/api/auth/password-reset/request", json={"identifier": username})
    assert fresh.status_code == 202
    confirmed = client.post("/api/auth/password-reset/confirm", json={
        "identifier": username, "code": mail.code_for(current_email),
        "new_password": NEW_PASSWORD,
    })
    assert confirmed.status_code == 204, confirmed.text
    login = client.post("/api/auth/login", json={
        "username": username, "password": NEW_PASSWORD,
    })
    assert login.status_code == 200, login.text


@pytest.mark.parametrize("response", [None, [], "malformed", 3])
def test_malformed_passkey_response_is_denied_and_burns_challenge(client, response):
    token = register_and_login(client, "pk-malformed-response")
    device = SoftAuthenticator()
    assert register_passkey(client, token, device).status_code == 201
    options = client.post("/api/auth/passkeys/authentication/options").json()
    denied = client.post("/api/auth/passkeys/authentication/verify", json={
        "challenge_id": options["challenge_id"],
        "credential": {"id": b64url(device.credential_id), "response": response},
    })
    assert denied.status_code == 401, denied.text
    replay = client.post("/api/auth/passkeys/authentication/verify", json={
        "challenge_id": options["challenge_id"],
        "credential": device.assert_(options["public_key"]),
    })
    assert replay.status_code == 401, replay.text


def test_password_breach_screening_uses_the_password_normalization_used_for_storage(monkeypatch):
    canonical = "Trésor long password 2026"
    decomposed = unicodedata.normalize("NFD", canonical)
    assert canonical != decomposed
    breached_hash = hashlib.sha1(canonical.encode("utf-8")).hexdigest().upper()

    class CorpusOpener:
        def open(self, request, *, timeout):
            prefix = request.full_url.rsplit("/", 1)[-1]
            result = f"{breached_hash[5:]}:42" if prefix == breached_hash[:5] else ""
            return io.BytesIO(result.encode("ascii"))

    monkeypatch.setattr(
        "src.app.security.urllib.request.build_opener", lambda *handlers: CorpusOpener()
    )
    checker = PwnedPasswordChecker(enabled=True, fail_closed=True)
    assert checker.is_compromised(canonical)
    assert checker.is_compromised(decomposed)
