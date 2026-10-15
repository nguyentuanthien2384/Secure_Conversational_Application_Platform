"""Consecutive wrong second factors lock 2FA for unfamiliar sources.

A correct password clears the login counters, so before this lock someone who
knew the password could cycle the per-window MFA limiter indefinitely
(NIST SP 800-63B §5.2.2 caps consecutive failed attempts per account).
"""

from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select, text

from src.app.audit import sign_ui_client_context
from src.app.db import Database
from src.app.models import User
from src.app.security import TotpService
from tests.test_account_recovery import NEW_PASSWORD, Recorder, add_verified_email

PASSWORD = "Correct Horse Battery1"
totp = TotpService()


@pytest.fixture()
def settings(settings):
    # A small threshold; a generous per-window limiter stays out of the way.
    return replace(
        settings, mfa_lockout_attempts=3, mfa_max_attempts=50, mfa_lockout_max_seconds=1500
    )


@pytest.fixture()
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def browser(app, ip: str) -> dict[str, str]:
    return sign_ui_client_context(app.state.ui_client_context_key, ip, "x")


def sign_in(client: TestClient, username: str, headers, password: str = PASSWORD):
    return client.post(
        "/api/auth/login", headers=headers, json={"username": username, "password": password}
    )


def challenge(client: TestClient, username: str, headers, password: str = PASSWORD) -> str:
    response = sign_in(client, username, headers, password)
    assert response.status_code == 200, response.text
    return response.json()["mfa_token"]


def verify(client: TestClient, headers, mfa_token: str, code: str):
    return client.post(
        "/api/auth/mfa/verify", headers=headers, json={"mfa_token": mfa_token, "code": code}
    )


def next_code(secret: str) -> str:
    """The step after activation's: still inside the accepted window."""
    return totp.now_code(secret, timestamp=time.time() + totp.period)


def wrong_code(secret: str) -> str:
    valid = {totp.now_code(secret, timestamp=time.time() + step * totp.period)
             for step in (-1, 0, 1)}
    return next(code for code in ("000000", "111111", "222222", "333333") if code not in valid)


def enable_mfa(client: TestClient, username: str, home, *, mail=None) -> str:
    registered = client.post(
        "/api/auth/register", json={"username": username, "password": PASSWORD}
    )
    assert registered.status_code == 201, registered.text
    signed_in = sign_in(client, username, home)
    assert signed_in.status_code == 200, signed_in.text
    token = signed_in.json()["access_token"]
    if mail is not None:
        add_verified_email(client, mail, token, f"{username}@example.com")
    secret = client.post("/api/auth/mfa/enroll", headers=auth(token)).json()["secret"]
    activated = client.post(
        "/api/auth/mfa/activate", headers=auth(token), json={"code": totp.now_code(secret)}
    )
    assert activated.status_code == 200, activated.text
    return secret


def lock_state(app, username: str) -> tuple[int, float | None]:
    """(consecutive failures, seconds the second-factor lock still runs)."""
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == username))
        until = user.mfa_locked_until
        if until is None:
            return user.mfa_failed_attempts, None
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        return user.mfa_failed_attempts, (until - datetime.now(timezone.utc)).total_seconds()


def guess_until_locked(client: TestClient, username: str, headers, wrong: str) -> list[int]:
    # A fresh correct password per guess: that used to reset every counter.
    return [
        verify(client, headers, challenge(client, username, headers), wrong).status_code
        for _ in range(3)
    ]


def test_guessing_codes_locks_strangers_but_not_the_owner(client: TestClient, app):
    home = browser(app, "192.0.2.90")
    secret = enable_mfa(client, "lock-owner", home)
    stranger = browser(app, "198.51.100.90")

    assert guess_until_locked(client, "lock-owner", stranger, wrong_code(secret)) == [401, 401, 429]
    failures, remaining = lock_state(app, "lock-owner")
    assert failures == 3 and remaining is not None and 890 < remaining <= 900

    # While locked even the right code is refused to a stranger, and not consumed.
    blocked = verify(client, stranger, challenge(client, "lock-owner", stranger), next_code(secret))
    assert blocked.status_code == 429, blocked.text
    assert "tạm khóa" in blocked.json()["detail"]
    assert int(blocked.headers["Retry-After"]) > 0

    owner = verify(client, home, challenge(client, "lock-owner", home), next_code(secret))
    assert owner.status_code == 200, owner.text
    failures, remaining = lock_state(app, "lock-owner")
    assert failures == 0, "a successful second factor ends the consecutive run"
    assert remaining is not None, "the owner's sign-in does not unlock strangers"

    activity = client.get(
        "/api/auth/security-activity", headers=auth(owner.json()["access_token"])
    ).json()
    locked = [event for event in activity["events"]
              if event["event_type"] == "auth.mfa.verify" and event["outcome"] == "blocked"]
    assert locked and all(event["severity"] == "critical" for event in locked)
    assert any("bước 2FA đang tạm khóa" in event["title"] for event in locked)


def test_each_further_lock_doubles_up_to_the_cap(client: TestClient, app):
    home = browser(app, "192.0.2.91")
    secret = enable_mfa(client, "lock-escalate", home)
    stranger = browser(app, "198.51.100.91")
    wrong = wrong_code(secret)

    assert guess_until_locked(client, "lock-escalate", stranger, wrong)[-1] == 429
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "lock-escalate"))
        user.mfa_locked_until = None  # the first lock ran out
        db.commit()

    assert guess_until_locked(client, "lock-escalate", stranger, wrong)[-1] == 429
    failures, remaining = lock_state(app, "lock-escalate")
    # 900 s doubled is 1800 s, capped by mfa_lockout_max_seconds.
    assert failures == 6 and remaining is not None and 1490 < remaining <= 1500


def test_a_mailbox_reset_does_not_lift_the_second_factor_lock(
    client: TestClient, app, mail
):
    home = browser(app, "192.0.2.92")
    secret = enable_mfa(client, "lock-mailbox", home, mail=mail)
    stranger = browser(app, "198.51.100.92")
    assert guess_until_locked(client, "lock-mailbox", stranger, wrong_code(secret))[-1] == 429

    # Someone holding the mailbox resets the password, then tries the factor again.
    client.post("/api/auth/password-reset/request", json={"identifier": "lock-mailbox"})
    assert client.post("/api/auth/password-reset/confirm", json={
        "identifier": "lock-mailbox", "code": mail.code_for("lock-mailbox@example.com"),
        "new_password": NEW_PASSWORD,
    }).status_code == 204
    pending = challenge(client, "lock-mailbox", stranger, NEW_PASSWORD)
    assert verify(client, stranger, pending, next_code(secret)).status_code == 429
    failures, remaining = lock_state(app, "lock-mailbox")
    assert failures == 3 and remaining is not None


def test_provisioning_uri_separates_issuer_and_account_with_a_literal_colon():
    uri = totp.provisioning_uri("A" * 32, "a@b.example", "SCAP Lab")
    assert uri == f"otpauth://totp/SCAP%20Lab:a%40b.example?secret={'A' * 32}&issuer=SCAP%20Lab"


def test_legacy_users_table_gains_the_second_factor_lock_columns(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'legacy-mfa.db'}")
    try:
        database.create_all()
        with database.engine.begin() as connection:
            connection.execute(text("ALTER TABLE users DROP COLUMN mfa_failed_attempts"))
            connection.execute(text("ALTER TABLE users DROP COLUMN mfa_locked_until"))
        database.create_all()
        columns = {column["name"] for column in inspect(database.engine).get_columns("users")}
        assert {"mfa_failed_attempts", "mfa_locked_until"} <= columns
        database.assert_schema_ready()
    finally:
        database.engine.dispose()
