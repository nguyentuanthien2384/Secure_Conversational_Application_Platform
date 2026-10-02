"""Recovery email verification, password reset by email and security notices."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.app.account_recovery import CODE_LENGTH, MAX_CODE_ATTEMPTS
from src.app.audit import sign_ui_client_context
from src.app.mailer import Mailer, OutboxTransport, mask_email, normalize_email
from src.app.models import AccountRecoveryCode, User
from src.app.security import TotpService
from tests.conftest import register_and_login

PASSWORD = "Correct Horse Battery1"
NEW_PASSWORD = "Another Long Passphrase 2026"
CODE_RE = re.compile(r"Mã: ([a-z0-9]{5})-([a-z0-9]{5})")


class Recorder:
    def __init__(self):
        self.messages = []

    def send(self, message):
        self.messages.append(message)

    def to(self, address):
        return [item for item in self.messages if item["To"] == address]

    def code_for(self, address):
        body = self.to(address)[-1].get_content()
        match = CODE_RE.search(body)
        assert match, body
        return match.group(1) + match.group(2)


@pytest.fixture()
def mail(app):
    recorder = Recorder()
    app.state.mailer.transport = recorder
    app.state.mailer.background = False
    return recorder


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def add_verified_email(client, mail, token, address):
    sent = client.post("/api/auth/email", headers=auth(token), json={"email": address})
    assert sent.status_code == 202, sent.text
    verified = client.post(
        "/api/auth/email/verify", headers=auth(token), json={"code": mail.code_for(address)}
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def login(client, username, password=PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


# ───────────────────────── addresses ─────────────────────────


@pytest.mark.parametrize("value", [
    "user@example.com", "First.Last+tag@Sub.Example.ORG",
])
def test_valid_addresses_normalize(value):
    assert normalize_email(value) == value.strip().lower()


@pytest.mark.parametrize("value", [
    "no-at-sign", "a@b", "x@-bad.com", "a..b@example.com", "Name <a@example.com>",
    "a@example.com\r\nBcc: victim@example.com", "a@example.com,b@example.com",
])
def test_header_injection_and_ambiguous_addresses_are_rejected(value):
    assert normalize_email(value) is None


def test_mask_email_hides_the_local_part():
    assert mask_email("sinhvien@example.com") == "si•••@example.com"


def test_outbox_transport_writes_eml_files(tmp_path):
    mailer = Mailer(OutboxTransport(tmp_path), "SCAP <no-reply@scap.local>", background=False)
    mailer.send("a@example.com", "Chủ đề", "Nội dung", template="test")
    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1 and b"a@example.com" in files[0].read_bytes()


# ───────────────────────── recovery email ─────────────────────────


def test_email_is_attached_only_after_proving_the_mailbox(client: TestClient, mail):
    token = register_and_login(client, "mail-owner")
    assert client.get("/api/auth/email", headers=auth(token)).json()["email"] is None
    pending = client.post("/api/auth/email", headers=auth(token), json={"email": "Owner@Example.com"})
    assert pending.status_code == 202
    assert pending.json()["email"] is None and pending.json()["pending_email"] == "owner@example.com"
    assert len(mail.to("owner@example.com")) == 1

    wrong = client.post("/api/auth/email/verify", headers=auth(token), json={"code": "aaaaa-aaaaa"})
    assert wrong.status_code == 400
    data = add_verified_email(client, mail, token, "owner@example.com")
    assert data["email"] == "owner@example.com" and data["verified_at"]


def test_codes_burn_after_five_wrong_attempts(client: TestClient, app, mail):
    token = register_and_login(client, "mail-burn")
    client.post("/api/auth/email", headers=auth(token), json={"email": "burn@example.com"})
    good = mail.code_for("burn@example.com")
    for _ in range(MAX_CODE_ATTEMPTS):
        client.post("/api/auth/email/verify", headers=auth(token), json={"code": "zzzzz-zzzzz"})
    late = client.post("/api/auth/email/verify", headers=auth(token), json={"code": good})
    assert late.status_code == 400
    with app.state.database.session_factory() as db:
        assert all(row.consumed_at for row in db.scalars(select(AccountRecoveryCode)))


def test_codes_are_stored_as_keyed_hashes_only(client: TestClient, app, mail):
    token = register_and_login(client, "mail-hash")
    client.post("/api/auth/email", headers=auth(token), json={"email": "hash@example.com"})
    code = mail.code_for("hash@example.com")
    assert len(code) == CODE_LENGTH
    with app.state.database.session_factory() as db:
        stored = db.scalars(select(AccountRecoveryCode)).one()
        assert code not in stored.code_hash and len(stored.code_hash) == 64


def test_changing_the_recovery_email_needs_a_recent_reauthentication(client: TestClient, app, mail):
    token = register_and_login(client, "mail-stepup")
    with app.state.database.session_factory() as db:
        from src.app.models import AuthSession

        for row in db.scalars(select(AuthSession)):
            row.last_step_up_at = None
        db.commit()
    stale = client.post("/api/auth/email", headers=auth(token), json={"email": "s@example.com"})
    assert stale.status_code == 403 and stale.headers.get("x-step-up-required") == "true"
    assert mail.messages == []


def test_one_address_cannot_recover_two_accounts(client: TestClient, mail):
    first = register_and_login(client, "mail-first")
    add_verified_email(client, mail, first, "shared@example.com")
    second = register_and_login(client, "mail-second")
    client.post("/api/auth/email", headers=auth(second), json={"email": "shared@example.com"})
    clash = client.post(
        "/api/auth/email/verify", headers=auth(second),
        json={"code": mail.code_for("shared@example.com")},
    )
    assert clash.status_code == 409


def test_old_address_is_told_when_the_recovery_email_changes(client: TestClient, mail):
    token = register_and_login(client, "mail-change")
    add_verified_email(client, mail, token, "old@example.com")
    add_verified_email(client, mail, token, "new@example.com")
    subjects = [item["Subject"] for item in mail.to("old@example.com")]
    assert any("Email khôi phục đã thay đổi" in subject for subject in subjects)

    assert client.delete("/api/auth/email", headers=auth(token)).status_code == 204
    assert client.get("/api/auth/email", headers=auth(token)).json()["email"] is None
    assert any("Email khôi phục" in item["Subject"] for item in mail.to("new@example.com"))


def test_email_features_answer_503_when_mail_is_disabled(client: TestClient):
    token = register_and_login(client, "mail-off")
    assert client.post(
        "/api/auth/email", headers=auth(token), json={"email": "x@example.com"}
    ).status_code == 503
    assert client.post(
        "/api/auth/password-reset/request", json={"identifier": "mail-off"}
    ).status_code == 503


# ───────────────────────── password reset ─────────────────────────


def test_reset_request_does_not_reveal_whether_an_account_exists(client: TestClient, mail):
    token = register_and_login(client, "reset-known")
    add_verified_email(client, mail, token, "known@example.com")
    register_and_login(client, "reset-no-email")
    responses = [
        client.post("/api/auth/password-reset/request", json={"identifier": identifier})
        for identifier in ("reset-known", "reset-no-email", "nobody-here", "ghost@example.com")
    ]
    assert {response.status_code for response in responses} == {202}
    assert len({response.text for response in responses}) == 1
    assert len(mail.to("known@example.com")) == 2  # verification + reset code only


def test_password_reset_by_email_end_to_end(client: TestClient, mail):
    token = register_and_login(client, "reset-user")
    add_verified_email(client, mail, token, "reset@example.com")
    assert client.post(
        "/api/auth/password-reset/request", json={"identifier": "reset@example.com"}
    ).status_code == 202
    code = mail.code_for("reset@example.com")

    bad = client.post("/api/auth/password-reset/confirm", json={
        "identifier": "reset-user", "code": "aaaaa-aaaaa", "new_password": NEW_PASSWORD,
    })
    assert bad.status_code == 400
    done = client.post("/api/auth/password-reset/confirm", json={
        "identifier": "reset-user", "code": code, "new_password": NEW_PASSWORD,
    })
    assert done.status_code == 204, done.text

    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    assert login(client, "reset-user").status_code == 401
    assert login(client, "reset-user", NEW_PASSWORD).status_code == 200
    replay = client.post("/api/auth/password-reset/confirm", json={
        "identifier": "reset-user", "code": code, "new_password": PASSWORD + "-again!",
    })
    assert replay.status_code == 400
    assert any("đặt lại" in item["Subject"] for item in mail.to("reset@example.com"))


def test_a_reset_code_only_works_for_its_own_account(client: TestClient, mail):
    victim = register_and_login(client, "reset-victim")
    add_verified_email(client, mail, victim, "victim@example.com")
    attacker = register_and_login(client, "reset-attacker")
    add_verified_email(client, mail, attacker, "attacker@example.com")
    client.post("/api/auth/password-reset/request", json={"identifier": "reset-attacker"})
    own_code = mail.code_for("attacker@example.com")
    stolen = client.post("/api/auth/password-reset/confirm", json={
        "identifier": "reset-victim", "code": own_code, "new_password": NEW_PASSWORD,
    })
    assert stolen.status_code == 400
    assert login(client, "reset-victim").status_code == 200


def test_reset_keeps_two_factor_and_lifts_a_lockout(client: TestClient, app, mail):
    totp = TotpService()
    token = register_and_login(client, "reset-mfa")
    add_verified_email(client, mail, token, "mfa@example.com")
    secret = client.post("/api/auth/mfa/enroll", headers=auth(token)).json()["secret"]
    assert client.post(
        "/api/auth/mfa/activate", headers=auth(token), json={"code": totp.now_code(secret)}
    ).status_code == 200
    stranger = sign_ui_client_context(app.state.ui_client_context_key, "198.51.100.77", "x")
    for _ in range(5):
        client.post("/api/auth/login", headers=stranger,
                    json={"username": "reset-mfa", "password": "wrong password value!!"})

    client.post("/api/auth/password-reset/request", json={"identifier": "reset-mfa"})
    assert client.post("/api/auth/password-reset/confirm", json={
        "identifier": "reset-mfa", "code": mail.code_for("mfa@example.com"),
        "new_password": NEW_PASSWORD,
    }).status_code == 204
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "reset-mfa"))
        assert user.mfa_enabled and user.locked_until is None
    # The owner proved the mailbox: no lingering lock or account throttle, even
    # from a network never used before, and 2FA still applies.
    traveling = sign_ui_client_context(app.state.ui_client_context_key, "203.0.113.77", "x")
    response = client.post("/api/auth/login", headers=traveling,
                           json={"username": "reset-mfa", "password": NEW_PASSWORD})
    assert response.status_code == 200, response.text
    assert response.json()["mfa_required"] is True


def test_security_notices_reach_the_verified_address(client: TestClient, mail):
    token = register_and_login(client, "notice-user")
    add_verified_email(client, mail, token, "notice@example.com")
    assert client.patch("/api/auth/password", headers=auth(token), json={
        "current_password": PASSWORD, "new_password": NEW_PASSWORD,
    }).status_code == 204
    subjects = [item["Subject"] for item in mail.to("notice@example.com")]
    assert any("Mật khẩu đã được đổi" in subject for subject in subjects)
    body = mail.to("notice@example.com")[-1].get_content()
    assert PASSWORD not in body and NEW_PASSWORD not in body
