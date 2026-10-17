"""Notification opt-in, possession proof and isolated provider delivery."""
from __future__ import annotations

import base64
import json
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from email.parser import BytesParser
from email.policy import default

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app.db import utcnow
from src.app.main import create_app
from src.app.models import (
    AuthSession,
    SecurityPhone,
    SecurityPhoneChallenge,
    SecurityPushSubscription,
    User,
)
from src.app.notification_config import NotificationSettings
from src.app.security_notifications import (
    NotificationUnavailable,
    SecurityNotifications,
    SubscriptionExpired,
    _PinnedPushSession,
    validate_push_endpoint,
)
from tests.conftest import register_and_login


def auth(token):
    return {"Authorization": "Bearer " + token}


def subscription(suffix="one"):
    public = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")  # noqa: E731
    return {"endpoint": "https://fcm.googleapis.com/wp/" + suffix,
            "keys": {"p256dh": encode(public), "auth": encode(b"a" * 16)}, "expirationTime": None}


@pytest.fixture()
def settings(settings, tmp_path):
    return replace(settings, notification_settings=NotificationSettings(
        push_backend="outbox", sms_backend="outbox", outbox_dir=str(tmp_path / "notices"),
    ))


@pytest.fixture()
def notices(app):
    service = app.state.notifications
    service.background = False
    return service


def phone_request(client, token, notices, phone="+84901234567"):
    messages = []
    notices.sms_transport = lambda to, body: messages.append((to, body)) or "demo_outbox"
    response = client.post("/api/auth/notifications/phone/request", headers=auth(token), json={"phone": phone})
    assert response.status_code == 202, response.text
    code = messages[0][1].split("thoai ")[1].split(".")[0]
    return response.json()["challenge_id"], code


def verify_phone(client, token, challenge_id, code):
    return client.post("/api/auth/notifications/phone/verify", headers=auth(token), json={"challenge_id": challenge_id, "code": code})


def test_push_and_verified_phone_opt_in_are_encrypted_and_scope_owned(client, app, notices):
    token = register_and_login(client, "notice-owner")
    other = register_and_login(client, "notice-other")
    payload = subscription()
    push = client.post("/api/auth/notifications/push", headers=auth(token), json=payload)
    assert push.status_code == 201, push.text
    assert push.json()["delivery"] == "not_sent"
    assert client.post("/api/auth/notifications/push", headers=auth(other), json=payload).status_code == 409
    assert client.delete("/api/auth/notifications/push/" + push.json()["id"], headers=auth(other)).status_code == 404
    challenge, code = phone_request(client, token, notices)
    status = client.get("/api/auth/notifications/status", headers=auth(token)).json()
    assert status["sms"]["phone"] is None and status["sms"]["pending"]["challenge_id"] == challenge
    verified = verify_phone(client, token, challenge, code)
    assert verified.status_code == 200, verified.text
    assert verified.json()["sms"]["phone"] == "••••4567"
    assert verify_phone(client, token, challenge, code).status_code == 400
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "notice-owner"))
        push_row = db.get(SecurityPushSubscription, push.json()["id"])
        phone = db.get(SecurityPhone, user.id)
        proof = db.get(SecurityPhoneChallenge, challenge)
        assert payload["endpoint"] not in push_row.subscription_ciphertext
        assert "84901234567" not in phone.phone_ciphertext
        assert code not in proof.code_hash and proof.consumed_at is not None
    assert client.get("/api/auth/notifications/status", headers=auth(other)).json()["push"]["subscriptions"] == []
    assert client.delete("/api/auth/notifications/phone", headers=auth(token)).status_code == 204
    assert client.delete("/api/auth/notifications/push", headers=auth(token)).status_code == 204
    assert client.get("/api/auth/notifications/status", headers=auth(token)).json()["push"]["subscriptions"] == []


def test_proof_is_exact_session_bound_expires_and_has_five_guesses(client, app, notices):
    token = register_and_login(client, "phone-proof")
    challenge, code = phone_request(client, token, notices)
    second = client.post("/api/auth/login", json={"username": "phone-proof", "password": "Correct Horse Battery1"}).json()["access_token"]
    assert verify_phone(client, second, challenge, code).status_code == 400
    with app.state.database.session_factory() as db:
        assert db.get(SecurityPhoneChallenge, challenge).attempts == 0
    wrong = "12345678" if code != "12345678" else "87654321"
    for _ in range(5):
        assert verify_phone(client, token, challenge, wrong).status_code == 400
    assert verify_phone(client, token, challenge, code).status_code == 400
    challenge, code = phone_request(client, token, notices, "+84901234568")
    with app.state.database.session_factory() as db:
        db.get(SecurityPhoneChallenge, challenge).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert verify_phone(client, token, challenge, code).status_code == 400


def test_sensitive_opt_in_and_opt_out_require_recent_step_up(client, app, notices):
    token = register_and_login(client, "notice-step-up")
    with app.state.database.session_factory() as db:
        db.get(AuthSession, app.state.token_service.decode(token)["jti"]).last_step_up_at = None
        db.commit()
    for method, path, body in [
        ("POST", "push", subscription()), ("DELETE", "push", None),
        ("POST", "phone/request", {"phone": "+84901234567"}),
        ("POST", "phone/verify", {"challenge_id": "0" * 36, "code": "12345678"}),
        ("DELETE", "phone", None),
    ]:
        response = client.request(method, "/api/auth/notifications/" + path, headers=auth(token), json=body)
        assert response.status_code == 403 and response.headers["X-Step-Up-Required"] == "true"


def test_durable_hourly_issuance_budget_survives_target_change_and_supersedes_old_codes(client, app, notices):
    token = register_and_login(client, "phone-budget")
    challenge, code = phone_request(client, token, notices)
    newer, _ = phone_request(client, token, notices)
    assert verify_phone(client, token, challenge, code).status_code == 400
    phone_request(client, token, notices)
    response = client.post("/api/auth/notifications/phone/request", headers=auth(token), json={"phone": "+84901234599"})
    assert response.status_code == 429
    with app.state.database.session_factory() as db:
        assert db.get(SecurityPhoneChallenge, newer).consumed_at is not None


def test_failed_provider_never_enables_an_unverified_phone(client, app, notices):
    token = register_and_login(client, "failed-sms")
    def unavailable(*args):
        raise RuntimeError("SECRET-PROVIDER-CREDENTIAL")
    notices.sms_transport = unavailable
    response = client.post("/api/auth/notifications/phone/request", headers=auth(token), json={"phone": "+84901234567"})
    assert response.status_code == 503 and "SECRET" not in response.text
    assert client.get("/api/auth/notifications/status", headers=auth(token)).json()["sms"]["phone"] is None


def test_durable_daily_sms_budget_does_not_reset_after_one_hour(client, app, notices):
    token = register_and_login(client, "phone-daily-budget")
    claims = app.state.token_service.decode(token)
    with app.state.database.session_factory() as db:
        for index in range(10):
            db.add(SecurityPhoneChallenge(
                id=str(uuid.uuid4()), user_id=claims["sub"], auth_session_id=claims["jti"],
                phone_hash=str(index) * 64, phone_ciphertext="expired", phone_nonce="expired",
                code_hash="0" * 64, created_at=utcnow() - timedelta(hours=2),
                expires_at=utcnow() - timedelta(hours=1), consumed_at=utcnow(),
            ))
        db.commit()
    response = client.post("/api/auth/notifications/phone/request", headers=auth(token), json={"phone": "+84901234567"})
    assert response.status_code == 429


@pytest.mark.parametrize("operation", ["push", "phone", "verify", "remove"])
def test_notification_mutations_recheck_a_bearer_revoked_after_authentication(client, app, notices, operation):
    from tests.test_account_transactions import _assert_revoked_mutation
    token = register_and_login(client, "notification-revoked")
    if operation == "push":
        method, path, payload = "POST", "push", subscription()
    elif operation == "phone":
        method, path, payload = "POST", "phone/request", {"phone": "+84901234567"}
    elif operation == "verify":
        challenge, code = phone_request(client, token, notices)
        method, path, payload = "POST", "phone/verify", {"challenge_id": challenge, "code": code}
    else:
        method, path, payload = "DELETE", "phone", None
    _assert_revoked_mutation(client, app, token, method, "/api/auth/notifications/" + path, payload, "logout")


def test_sms_failure_cannot_hide_a_committed_password_change(client, app, notices):
    token = register_and_login(client, "notification-postcommit")
    challenge, code = phone_request(client, token, notices)
    assert verify_phone(client, token, challenge, code).status_code == 200
    calls = []
    def unavailable(*args):
        calls.append(args)
        raise RuntimeError("PRIVATE-SMS-ERROR")
    notices.sms_transport = unavailable
    response = client.patch("/api/auth/password", headers=auth(token), json={
        "current_password": "Correct Horse Battery1", "new_password": "Another Strong Password1",
    })
    assert response.status_code == 204, response.text
    assert len(calls) == 1
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    assert client.post("/api/auth/login", json={"username": "notification-postcommit", "password": "Another Strong Password1"}).status_code == 200


@pytest.mark.parametrize("operation", ["push", "request", "verify"])
def test_registration_and_audit_roll_back_together(client, app, notices, operation):
    token = register_and_login(client, "notice-atomic")
    if operation == "verify":
        challenge, code = phone_request(client, token, notices)
        path, payload = "phone/verify", {"challenge_id": challenge, "code": code}
    elif operation == "push":
        path, payload = "push", subscription()
    else:
        path, payload = "phone/request", {"phone": "+84901234567"}
    def fail(_conn, _cursor, statement, _params, context, _many):
        if statement.lstrip().lower().startswith("insert into audit_events") and any(item.get("event_type", "").startswith("account.notifications.") for item in context.compiled_parameters):
            raise OperationalError("private audit error", None, RuntimeError("secret"))
    event.listen(app.state.database.engine, "before_cursor_execute", fail)
    try:
        response = client.post("/api/auth/notifications/" + path, headers=auth(token), json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail)
    assert response.status_code == 503
    with app.state.database.session_factory() as db:
        assert db.scalar(select(SecurityPushSubscription)) is None
        assert db.scalar(select(SecurityPhone)) is None
        proof = db.scalar(select(SecurityPhoneChallenge))
        if operation == "request":
            assert proof is None
        if operation == "verify":
            assert proof.consumed_at is None and proof.attempts == 0


@pytest.mark.parametrize("url", [
    "http://fcm.googleapis.com/wp/x", "https://127.0.0.1/wp/x", "https://evil.example/wp/x",
    "https://fcm.googleapis.com.evil.example/wp/x", "https://fcm.googleapis.com@127.0.0.1/wp/x",
    "https://fcm.googleapis.com:444/wp/x", "https://fcm.googleapis.com/wp/x#fragment",
    "https://fcm.googleapis.com/wp/x?secret=y", "https://notify.windows.com/wp/x",
])
def test_push_endpoint_ssrf_surface_is_closed(url):
    with pytest.raises(ValueError):
        validate_push_endpoint(url)


def test_pinned_push_transport_rejects_private_dns_before_connect(monkeypatch):
    monkeypatch.setattr("src.app.security_notifications.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 443))])
    with pytest.raises(NotificationUnavailable):
        _PinnedPushSession().post("https://fcm.googleapis.com/wp/secret", data=b"ciphertext")


def test_shutdown_after_dns_prevents_any_new_network_connection(monkeypatch):
    stop = threading.Event()
    def resolve(*args, **kwargs):
        stop.set()
        return [(2, 1, 6, "", ("142.250.1.2", 443))]
    monkeypatch.setattr("src.app.security_notifications.socket.getaddrinfo", resolve)
    monkeypatch.setattr("src.app.security_notifications.socket.create_connection", lambda *a, **k: pytest.fail("No connection after stop"))
    with pytest.raises(NotificationUnavailable, match="đã dừng"):
        _PinnedPushSession(stop.is_set).post("https://fcm.googleapis.com/wp/secret", data=b"ciphertext")


def test_worker_budget_is_finite_and_shutdown_cancels_queued_notices(tmp_path, monkeypatch):
    service = SecurityNotifications(NotificationSettings(push_backend="outbox", outbox_dir=str(tmp_path / "notices")), None, None, b"key")
    reached, release = threading.Event(), threading.Event()
    def deliver(*args):
        reached.set()
        assert release.wait(10)
    monkeypatch.setattr(service, "_deliver", deliver)
    service.start()
    for _ in range(32):
        assert service.notify(user_id="user", kind="new_device")
    assert reached.wait(5)
    assert not service.notify(user_id="user", kind="new_device")
    with ThreadPoolExecutor(max_workers=1) as executor:
        closing = executor.submit(service.close)
        assert service._stop.wait(5)
        assert not service.notify(user_id="user", kind="new_device")
        release.set()
        closing.result(timeout=10)
    assert not service._pending
    assert not (tmp_path / "notices").exists()


def test_webpush_sdk_encrypts_payload_and_uses_the_restricted_transport(monkeypatch):
    pytest.importorskip("pywebpush")
    from requests import Response
    key = ec.generate_private_key(ec.SECP256R1())
    raw = base64.urlsafe_b64encode(key.private_numbers().private_value.to_bytes(32, "big")).decode().rstrip("=")
    service = SecurityNotifications(NotificationSettings(push_backend="webpush", vapid_private_key=raw, vapid_subject="mailto:security@example.com"), None, None, b"key")
    requests = []
    def post(_self, url, *, data, headers, **kwargs):
        requests.append((url, data, headers, kwargs))
        response = Response()
        response.status_code, response._content = 201, b""
        return response
    monkeypatch.setattr(_PinnedPushSession, "post", post)
    assert service._send_push(subscription(), "PRIVATE-ALERT-BODY") == "provider_accepted"
    url, ciphertext, headers, kwargs = requests[0]
    assert url == "https://fcm.googleapis.com/wp/one"
    assert b"PRIVATE-ALERT-BODY" not in ciphertext and len(ciphertext) > 64
    assert headers["content-encoding"] == "aes128gcm"
    assert headers["Authorization"].startswith("vapid ")
    assert kwargs["timeout"] == 5.0


def test_push_transport_pins_public_ip_preserves_tls_sni_and_never_follows_redirects(monkeypatch):
    connections, sockets, wraps = [], [], []
    monkeypatch.setattr("src.app.security_notifications.socket.getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("142.250.1.2", 443))])
    class Socket:
        def close(self):
            pass
    def connect(address, **kwargs):
        sockets.append((address, kwargs))
        return Socket()
    monkeypatch.setattr("src.app.security_notifications.socket.create_connection", connect)
    class Context:
        def wrap_socket(self, socket, **kwargs):
            wraps.append(kwargs)
            return socket
    monkeypatch.setattr("src.app.security_notifications.ssl.create_default_context", Context)
    class Connection:
        def __init__(self, host, *, context, timeout):
            self._context = context
            self.sock = None
            connections.append((host, timeout, self))
        def request(self, method, path, *, body, headers):
            self.request_data = method, path, body, headers
        def getresponse(self):
            class Response:
                status, headers = 307, {"Location": "http://127.0.0.1/private"}
                def read(self, length):
                    assert length == 4097
                    return b"redirect"
            return Response()
        def close(self):
            pass
    monkeypatch.setattr("src.app.security_notifications.http.client.HTTPSConnection", Connection)
    response = _PinnedPushSession().post("https://fcm.googleapis.com/wp/secret", data=b"encrypted", headers={"Authorization": "vapid token"})
    assert response.status_code == 307 and len(connections) == 1
    assert sockets == [(("142.250.1.2", 443), {"timeout": 5.0})]
    assert wraps == [{"server_hostname": "fcm.googleapis.com"}]
    assert connections[0][2].request_data == ("POST", "/wp/secret", b"encrypted", {"Authorization": "vapid token", "Host": "fcm.googleapis.com"})


def test_fixed_notice_payloads_fan_out_without_sensitive_context(client, app, notices, caplog):
    token = register_and_login(client, "notice-fanout")
    assert client.post("/api/auth/notifications/push", headers=auth(token), json=subscription()).status_code == 201
    challenge, code = phone_request(client, token, notices)
    assert verify_phone(client, token, challenge, code).status_code == 200
    pushes, sms = [], []
    notices.push_transport = lambda subscription, body: pushes.append(json.loads(body))
    notices.sms_transport = lambda phone, body: sms.append((phone, body))
    user_id = client.get("/api/auth/me", headers=auth(token)).json()["id"]
    assert notices.notify(user_id=user_id, kind="password_changed")
    assert len(pushes) == len(sms) == 1
    assert "notice-fanout" not in json.dumps(pushes) + sms[0][1]
    assert code not in json.dumps(pushes) + sms[0][1]
    assert set(pushes[0]) == {"title", "body"}
    def expired(*args):
        raise SubscriptionExpired("private endpoint")
    notices.push_transport = expired
    notices.sms_transport = lambda *a: (_ for _ in ()).throw(RuntimeError("PRIVATE-PHONE"))
    assert notices.notify(user_id=user_id, kind="new_device")
    assert "PRIVATE-PHONE" not in caplog.text and "private endpoint" not in caplog.text
    with app.state.database.session_factory() as db:
        assert db.scalar(select(SecurityPushSubscription)) is None


def test_demo_outbox_is_private_and_never_claims_a_real_delivery(notices):
    assert notices.send_verification("+84901234567", "12345678") == "demo_outbox"
    paths = list(notices._outbox.directory.glob("*.eml"))
    assert len(paths) == 1
    message = BytesParser(policy=default).parsebytes(paths[0].read_bytes())
    assert "no message sent" in message["Subject"]
    assert json.loads(message.get_content())["body"].startswith("SCAP: Ma xac minh")


def test_twilio_uses_fixed_origin_tls_no_proxy_and_reports_only_acceptance(monkeypatch):
    settings = NotificationSettings(sms_backend="twilio", twilio_account_sid="AC" + "a" * 32,
                                    twilio_auth_token="secret-token", twilio_from="+12025550123")
    notices = SecurityNotifications(settings, None, None, b"key")
    requests, options = [], []
    client_type = httpx.Client
    def handle(request):
        requests.append(request)
        return httpx.Response(201, json={"status": "queued"})
    def fake_client(**kwargs):
        options.append(kwargs)
        return client_type(transport=httpx.MockTransport(handle), **kwargs)
    monkeypatch.setattr("src.app.security_notifications.httpx.Client", fake_client)
    assert notices.send_verification("+84901234567", "12345678") == "provider_accepted"
    assert requests[0].url.host == "api.twilio.com" and requests[0].url.scheme == "https"
    assert "To=%2B84901234567" in requests[0].content.decode()
    assert options == [{"trust_env": False, "follow_redirects": False, "timeout": 5.0}]


@pytest.mark.parametrize("backend", ["push", "sms"])
def test_production_rejects_demo_outbox(monkeypatch, backend):
    monkeypatch.setenv("PUSH_BACKEND", "disabled")
    monkeypatch.setenv("SMS_BACKEND", "disabled")
    monkeypatch.setenv(backend.upper() + "_BACKEND", "outbox")
    with pytest.raises(RuntimeError, match="development/test"):
        NotificationSettings.from_env(environment="production")


def test_webpush_configuration_derives_public_key_from_a_secret_file(monkeypatch, tmp_path):
    pytest.importorskip("pywebpush")
    path = tmp_path / "vapid.pem"
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    monkeypatch.setenv("PUSH_BACKEND", "webpush")
    monkeypatch.setenv("SMS_BACKEND", "disabled")
    monkeypatch.setenv("VAPID_PRIVATE_KEY_FILE", str(path))
    monkeypatch.setenv("VAPID_SUBJECT", "mailto:security@example.com")
    config = NotificationSettings.from_env(environment="production")
    expected = base64.urlsafe_b64encode(key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).decode().rstrip("=")
    assert config.vapid_public_key == expected
    assert len(config.vapid_private_key) == 43 and config.vapid_private_key not in repr(config)


def test_sms_credentials_require_a_finite_secret_file_not_a_plain_environment_token(monkeypatch, tmp_path):
    monkeypatch.setenv("PUSH_BACKEND", "disabled")
    monkeypatch.setenv("SMS_BACKEND", "twilio")
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC" + "a" * 32)
    monkeypatch.setenv("TWILIO_FROM", "+12025550123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "b" * 32)
    monkeypatch.delenv("TWILIO_AUTH_TOKEN_FILE", raising=False)
    with pytest.raises(RuntimeError, match="AUTH_TOKEN_FILE"):
        NotificationSettings.from_env(environment="production")
    path = tmp_path / "twilio.txt"
    path.write_text("b" * 32)
    monkeypatch.setenv("TWILIO_AUTH_TOKEN_FILE", str(path))
    config = NotificationSettings.from_env(environment="production")
    assert config.twilio_auth_token == "b" * 32
    assert "b" * 32 not in repr(config)
    path.write_text("b" * 2048)
    with pytest.raises(RuntimeError, match="secret file"):
        NotificationSettings.from_env(environment="production")


def test_channels_are_disabled_by_default_and_opt_out_remains_possible(settings):
    from fastapi.testclient import TestClient
    with TestClient(create_app(replace(settings, notification_settings=NotificationSettings()))) as client:
        token = register_and_login(client, "notice-disabled")
        status = client.get("/api/auth/notifications/status", headers=auth(token)).json()
        assert status["push"]["available"] is status["sms"]["available"] is False
        assert client.post("/api/auth/notifications/push", headers=auth(token), json=subscription()).status_code == 501
        assert client.post("/api/auth/notifications/phone/request", headers=auth(token), json={"phone": "+84901234567"}).status_code == 501
        assert client.delete("/api/auth/notifications/push", headers=auth(token)).status_code == 204
        assert client.delete("/api/auth/notifications/phone", headers=auth(token)).status_code == 204
