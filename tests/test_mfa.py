from __future__ import annotations

import time

from fastapi.testclient import TestClient

from src.app.security import TotpService
from tests.conftest import register_and_login

PASSWORD = "Correct Horse Battery1"
totp = TotpService()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def future_code(secret: str, steps: int = 1) -> str:
    """Return a code from a later accepted counter without sleeping in tests."""
    return totp.now_code(secret, timestamp=time.time() + steps * totp.period)


def enroll_and_enable(client: TestClient, username: str) -> tuple[str, str, list[str]]:
    """Register, turn on MFA, and return (secret, still-valid?, recovery_codes).

    The enrolling access token is intentionally revoked by activation, so callers
    should re-authenticate through the two-step MFA login afterwards.
    """
    token = register_and_login(client, username, PASSWORD)
    enroll = client.post("/api/auth/mfa/enroll", headers=auth(token))
    assert enroll.status_code == 200, enroll.text
    secret = enroll.json()["secret"]
    assert enroll.json()["provisioning_uri"].startswith("otpauth://totp/")

    activate = client.post(
        "/api/auth/mfa/activate", headers=auth(token), json={"code": totp.now_code(secret)}
    )
    assert activate.status_code == 200, activate.text
    recovery_codes = activate.json()["recovery_codes"]
    assert len(recovery_codes) == 10
    return secret, token, recovery_codes


def test_enroll_activate_marks_account_and_revokes_old_session(client: TestClient):
    secret, old_token, _ = enroll_and_enable(client, "mfa-user")
    # Activation forces re-authentication: the token used to enroll is now dead.
    assert client.get("/api/auth/me", headers=auth(old_token)).status_code == 401


def test_login_requires_second_factor_then_succeeds(client: TestClient):
    secret, _, _ = enroll_and_enable(client, "mfa-login")

    first = client.post("/api/auth/login", json={"username": "mfa-login", "password": PASSWORD})
    assert first.status_code == 200
    body = first.json()
    assert body.get("mfa_required") is True
    assert "access_token" not in body

    verify = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": future_code(secret)},
    )
    assert verify.status_code == 200
    token = verify.json()["access_token"]
    me = client.get("/api/auth/me", headers=auth(token))
    assert me.status_code == 200
    assert me.json()["mfa_enabled"] is True


def test_wrong_totp_is_rejected(client: TestClient):
    enroll_and_enable(client, "mfa-wrong")
    body = client.post(
        "/api/auth/login", json={"username": "mfa-wrong", "password": PASSWORD}
    ).json()
    verify = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "code": "000000"}
    )
    assert verify.status_code == 401


def test_totp_code_cannot_be_replayed(client: TestClient):
    secret, _, _ = enroll_and_enable(client, "mfa-replay")
    code = future_code(secret)

    body1 = client.post(
        "/api/auth/login", json={"username": "mfa-replay", "password": PASSWORD}
    ).json()
    first = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": body1["mfa_token"], "code": code}
    )
    assert first.status_code == 200

    body2 = client.post(
        "/api/auth/login", json={"username": "mfa-replay", "password": PASSWORD}
    ).json()
    replay = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": body2["mfa_token"], "code": code}
    )
    assert replay.status_code == 401


def test_recovery_code_is_single_use(client: TestClient):
    _, _, recovery_codes = enroll_and_enable(client, "mfa-recovery")
    backup = recovery_codes[0]

    body1 = client.post(
        "/api/auth/login", json={"username": "mfa-recovery", "password": PASSWORD}
    ).json()
    used = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": body1["mfa_token"], "code": backup}
    )
    assert used.status_code == 200

    body2 = client.post(
        "/api/auth/login", json={"username": "mfa-recovery", "password": PASSWORD}
    ).json()
    reused = client.post(
        "/api/auth/mfa/verify", json={"mfa_token": body2["mfa_token"], "code": backup}
    )
    assert reused.status_code == 401


def test_disable_requires_password_and_code(client: TestClient):
    secret, _, recovery_codes = enroll_and_enable(client, "mfa-disable")

    # Log back in through MFA to obtain a working token.
    body = client.post(
        "/api/auth/login", json={"username": "mfa-disable", "password": PASSWORD}
    ).json()
    token = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": future_code(secret)},
    ).json()["access_token"]

    wrong = client.post(
        "/api/auth/mfa/disable",
        headers=auth(token),
        json={"password": "wrong-password9", "code": recovery_codes[0]},
    )
    assert wrong.status_code == 401

    # A bad password must not consume the recovery code. Reuse it to complete a
    # fresh MFA challenge, then use a second code to authorize disabling MFA.
    body = client.post(
        "/api/auth/login", json={"username": "mfa-disable", "password": PASSWORD}
    ).json()
    token = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": recovery_codes[0]},
    ).json()["access_token"]
    ok = client.post(
        "/api/auth/mfa/disable",
        headers=auth(token),
        json={"password": PASSWORD, "code": recovery_codes[1]},
    )
    assert ok.status_code == 204

    # With MFA off, password login returns a bearer token directly again.
    plain = client.post("/api/auth/login", json={"username": "mfa-disable", "password": PASSWORD})
    assert plain.status_code == 200
    assert "access_token" in plain.json()


def test_mfa_challenge_token_cannot_access_the_api(client: TestClient):
    enroll_and_enable(client, "mfa-scope")
    body = client.post(
        "/api/auth/login", json={"username": "mfa-scope", "password": PASSWORD}
    ).json()
    # The short-lived challenge has a different audience; it must not authorize API calls.
    leaked = client.get("/api/auth/me", headers=auth(body["mfa_token"]))
    assert leaked.status_code == 401


def test_mfa_challenge_token_is_single_use(client: TestClient):
    secret, _, _ = enroll_and_enable(client, "mfa-challenge-replay")
    body = client.post(
        "/api/auth/login",
        json={"username": "mfa-challenge-replay", "password": PASSWORD},
    ).json()
    first = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": future_code(secret)},
    )
    assert first.status_code == 200
    replay = client.post(
        "/api/auth/mfa/verify",
        json={"mfa_token": body["mfa_token"], "code": future_code(secret, 2)},
    )
    assert replay.status_code == 401
