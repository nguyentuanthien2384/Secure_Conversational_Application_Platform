"""Account protection that large identity providers ship by default.

Covers the UI's signed browser context (one shared loopback address no longer
lets a single attacker rate-limit or IDS-block every user), per-IP refunds,
smart lockout, new-device sign-in alerts and the user-facing security log.
"""

from __future__ import annotations

import time

from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from src.app import gradio_ui
from src.app.account_security import DEVICE_TOKEN_HEADER, describe_user_agent, device_family
from src.app.audit import (
    UI_CLIENT_IP_HEADER,
    UI_CLIENT_PROOF_HEADER,
    UI_CLIENT_TS_HEADER,
    client_ip,
    client_user_agent,
    derive_ui_client_context_key,
    sign_ui_client_context,
)
from src.app.models import AuditEvent, User
from src.app.security import SlidingWindowRateLimiter, TotpService
from tests.conftest import register_and_login

PASSWORD = "Correct Horse Battery1"
CHROME_WINDOWS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0"
SAFARI_IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1"
)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def browser(app, ip: str, user_agent: str = CHROME_WINDOWS) -> dict[str, str]:
    """Headers the in-process UI attaches for the browser it is serving."""
    return sign_ui_client_context(app.state.ui_client_context_key, ip, user_agent)


def login(client: TestClient, username: str, password: str = PASSWORD, headers=None):
    """Sign in; a reused ``headers`` dict keeps its device token like a browser cookie."""
    response = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers=headers or {},
    )
    if headers is not None and response.status_code == 200:
        device_token = response.json().get("device_token")
        if device_token:
            headers[DEVICE_TOKEN_HEADER] = device_token
    return response


def register(client: TestClient, username: str) -> None:
    response = client.post(
        "/api/auth/register", json={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 201, response.text


def create_user(app, username: str) -> None:
    """Insert directly: self-registration is rate-limited to five per hour."""
    with app.state.database.session_factory() as db:
        db.add(User(username=username, password_hash=app.state.password_service.hash(PASSWORD)))
        db.commit()


def last_event(app, event_type: str) -> AuditEvent:
    with app.state.database.session_factory() as db:
        event = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.event_type == event_type)
            .order_by(AuditEvent.id.desc())
        ).first()
        assert event is not None, event_type
        db.expunge(event)
        return event


def events(app, event_type: str) -> list[AuditEvent]:
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == event_type)))
        for row in rows:
            db.expunge(row)
        return rows


# ───────────────────────── signed UI browser context ─────────────────────────


def test_api_attributes_ui_calls_to_the_signed_browser_address(client: TestClient, app):
    register(client, "ctx-user")
    response = login(client, "ctx-user", headers=browser(app, "203.0.113.7", FIREFOX_LINUX))
    assert response.status_code == 200, response.text

    event = last_event(app, "auth.login")
    assert event.ip_address == "203.0.113.7"
    assert "Firefox" in (event.user_agent or "")
    sessions = client.get("/api/auth/sessions", headers=auth(response.json()["access_token"]))
    assert sessions.json()[0]["ip_address"] == "203.0.113.7"


def test_forged_or_stale_ui_context_is_ignored(client: TestClient, app):
    register(client, "ctx-forger")
    forged_key = derive_ui_client_context_key("attacker-guessed-secret-is-not-the-app-secret")
    attempts = [
        sign_ui_client_context(forged_key, "198.51.100.1", CHROME_WINDOWS),
        {**browser(app, "198.51.100.2"), UI_CLIENT_IP_HEADER: "198.51.100.3"},
        sign_ui_client_context(
            app.state.ui_client_context_key, "198.51.100.4", CHROME_WINDOWS,
            now=time.time() - 3600,
        ),
        {UI_CLIENT_IP_HEADER: "198.51.100.5", UI_CLIENT_PROOF_HEADER: "0" * 64,
         UI_CLIENT_TS_HEADER: str(int(time.time()))},
    ]
    for headers in attempts:
        assert login(client, "ctx-forger", "wrong password value!!", headers).status_code == 401
    recorded = {event.ip_address for event in events(app, "auth.login")}
    assert recorded == {"testclient"}


def test_unsigned_request_keeps_the_real_peer_and_user_agent(app):
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"user-agent", b"curl/8.9"), (b"x-scap-ui-client-ip", b"10.9.9.9")],
        "client": ("192.0.2.10", 5555),
        "app": app,
    })
    assert client_ip(request) == "192.0.2.10"
    assert client_user_agent(request) == "curl/8.9"


def test_one_ui_user_cannot_rate_limit_everyone_else(client: TestClient, app):
    register(client, "shared-victim")
    attacker = browser(app, "198.51.100.66")
    for index in range(6):
        login(client, f"nobody-{index}", "wrong password value!!", attacker)
    assert login(client, "nobody-x", "wrong password value!!", attacker).status_code == 429

    victim = login(client, "shared-victim", headers=browser(app, "192.0.2.44"))
    assert victim.status_code == 200, victim.text


def test_ids_block_triggered_through_the_ui_hits_only_the_offender(client: TestClient, app):
    register(client, "ids-attacker")
    register(client, "ids-victim")
    attacker = browser(app, "198.51.100.13")
    token = login(client, "ids-attacker", headers=attacker).json()["access_token"]
    payload = {"q": "' UNION SELECT password_hash FROM users--"}
    statuses = [
        client.get(
            "/api/search/messages", params=payload, headers={**attacker, **auth(token)}
        ).status_code
        for _ in range(4)
    ]
    assert 403 in statuses
    assert login(client, "ids-attacker", headers=attacker).status_code == 403

    blocked = {item["source_ip"] for item in app.state.intrusion_state.blocked_sources()}
    assert blocked == {"198.51.100.13"}
    victim = login(client, "ids-victim", headers=browser(app, "192.0.2.45"))
    assert victim.status_code == 200, victim.text


def test_ui_signs_the_browser_behind_the_current_gradio_event(app, monkeypatch):
    import gradio as gr
    from gradio.context import LocalContext

    monkeypatch.setattr(gradio_ui, "_CLIENT_CONTEXT_KEY", app.state.ui_client_context_key)
    browser_request = gr.Request(Request({
        "type": "http",
        "method": "POST",
        "path": "/gradio_api/queue/join",
        "headers": [(b"user-agent", SAFARI_IPHONE.encode())],
        "client": ("203.0.113.90", 443),
    }))
    marker = LocalContext.request.set(browser_request)
    try:
        headers = gradio_ui._browser_context_headers()
    finally:
        LocalContext.request.reset(marker)

    api_request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/auth/me",
        "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        "client": ("127.0.0.1", 40000),
        "app": app,
    })
    assert client_ip(api_request) == "203.0.113.90"
    assert client_user_agent(api_request) == SAFARI_IPHONE


def test_ui_sends_no_context_outside_a_gradio_event(app, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_CLIENT_CONTEXT_KEY", app.state.ui_client_context_key)
    assert gradio_ui._browser_context_headers() == {}


# ───────────────────────── per-IP refunds ─────────────────────────


def test_limiter_refund_returns_only_the_newest_slot():
    limiter = SlidingWindowRateLimiter()
    for _ in range(3):
        assert limiter.allow("k", 3, 60)[0]
    limiter.refund("k")
    assert limiter.allow("k", 3, 60)[0]
    assert not limiter.allow("k", 3, 60)[0]


def test_own_successful_login_does_not_erase_failed_guesses(client: TestClient, app):
    create_user(app, "spray-attacker")
    targets = [f"spray-target-{index}" for index in range(8)]
    for username in targets:
        create_user(app, username)

    statuses = []
    for username in targets:
        statuses.append(login(client, username, "Summer2026!Summer2026!").status_code)
        own = login(client, "spray-attacker")
        assert own.status_code in (200, 429)
    # Before the fix every own login wiped the per-IP bucket: all 8 got 401.
    assert statuses[:5] == [401] * 5
    assert set(statuses[5:]) == {429}


# ───────────────────────── smart lockout ─────────────────────────


def _lock_from(client, app, username: str, ip: str) -> None:
    attacker = browser(app, ip, FIREFOX_LINUX)
    for _ in range(5):
        login(client, username, "wrong password value!!", attacker)


def test_stranger_cannot_lock_owner_out_of_a_familiar_network(client: TestClient, app):
    register(client, "smart-owner")
    home = browser(app, "192.0.2.80")
    assert login(client, "smart-owner", headers=home).status_code == 200

    _lock_from(client, app, "smart-owner", "198.51.100.200")
    stranger = login(client, "smart-owner", headers=browser(app, "198.51.100.201"))
    assert stranger.status_code in (401, 429)  # still locked for unfamiliar sources

    owner = login(client, "smart-owner", headers=home)
    assert owner.status_code == 200, owner.text


def test_familiar_sign_in_does_not_clear_the_lock_for_strangers(client: TestClient, app):
    register(client, "smart-keeps-lock")
    home = browser(app, "192.0.2.81")
    assert login(client, "smart-keeps-lock", headers=home).status_code == 200
    _lock_from(client, app, "smart-keeps-lock", "198.51.100.210")
    assert login(client, "smart-keeps-lock", headers=home).status_code == 200

    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "smart-keeps-lock"))
        assert user.locked_until is not None
    assert login(
        client, "smart-keeps-lock", headers=browser(app, "198.51.100.211")
    ).status_code in (401, 429)


def test_familiar_failures_are_throttled_and_still_lock_out_strangers(
    client: TestClient, app
):
    register(client, "smart-budget")
    home = browser(app, "192.0.2.82")
    assert login(client, "smart-budget", headers=home).status_code == 200
    statuses = [
        login(client, "smart-budget", "wrong password value!!", home).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "smart-budget"))
        assert user.failed_login_attempts == 5 and user.locked_until is not None
    assert login(
        client, "smart-budget", headers=browser(app, "198.51.100.220")
    ).status_code in (401, 429)


def test_familiar_sign_in_clears_old_typos_when_no_lock_is_active(client: TestClient, app):
    register(client, "smart-typos")
    home = browser(app, "192.0.2.83")
    assert login(client, "smart-typos", headers=home).status_code == 200
    for _ in range(2):
        assert login(client, "smart-typos", "wrong password value!!", home).status_code == 401
    assert login(client, "smart-typos", headers=home).status_code == 200
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "smart-typos"))
        assert user.failed_login_attempts == 0 and user.locked_until is None


def test_unfamiliar_source_still_locks_without_history(client: TestClient, app):
    register(client, "smart-new")
    for _ in range(5):
        assert login(client, "smart-new", "wrong password value!!").status_code == 401
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "smart-new"))
        assert user.failed_login_attempts == 5 and user.locked_until is not None


# ───────────────────────── new-device alerts & activity ─────────────────────────


def test_device_family_ignores_versions_and_orders_lookalikes():
    assert device_family(CHROME_WINDOWS) == ("Chrome", "Windows")
    assert device_family(CHROME_WINDOWS.replace("141.0", "142.0")) == ("Chrome", "Windows")
    assert device_family(SAFARI_IPHONE) == ("Safari", "iOS")
    assert device_family(
        "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/141.0 Mobile Safari/537.36"
    ) == ("Chrome", "Android")
    assert device_family(CHROME_WINDOWS + " Edg/141.0.0.0") == ("Edge", "Windows")
    assert describe_user_agent("") is None
    assert describe_user_agent("weird") == "Thiết bị không xác định"


def test_new_device_sign_in_raises_an_alert_but_first_sign_in_does_not(
    client: TestClient, app
):
    register(client, "device-user")
    laptop = browser(app, "192.0.2.90")
    assert login(client, "device-user", headers=laptop).status_code == 200
    assert events(app, "auth.login.new_device") == []

    # Same browser (it still holds its device cookie) on another network.
    same_device_new_ip = {**browser(app, "192.0.2.91"), DEVICE_TOKEN_HEADER: laptop[DEVICE_TOKEN_HEADER]}
    assert login(client, "device-user", headers=same_device_new_ip).status_code == 200
    assert events(app, "auth.login.new_device") == []
    assert '"sign_in_source":"new_location"' in last_event(app, "auth.login").details_json

    phone = browser(app, "203.0.113.5", SAFARI_IPHONE)
    assert login(client, "device-user", headers=phone).status_code == 200
    alert = last_event(app, "auth.login.new_device")
    assert alert.ip_address == "203.0.113.5"
    assert '"device":"Safari · iOS"' in alert.details_json


def test_security_activity_summarises_what_happened_since_the_last_visit(
    client: TestClient, app
):
    register(client, "activity-user")
    laptop = browser(app, "192.0.2.100")
    assert login(client, "activity-user", headers=laptop).status_code == 200
    stranger = browser(app, "198.51.100.150", FIREFOX_LINUX)
    for _ in range(2):
        login(client, "activity-user", "wrong password value!!", stranger)

    token = login(client, "activity-user", headers=laptop).json()["access_token"]
    response = client.get("/api/auth/security-activity", headers=auth(token))
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["previous_sign_in"]["ip_address"] == "192.0.2.100"
    assert data["previous_sign_in"]["device"] == "Chrome · Windows"
    assert data["failed_sign_ins_since_previous"] == 2
    assert data["new_device_sign_ins_since_previous"] == 0

    failures = [
        event for event in data["events"]
        if event["event_type"] == "auth.login" and event["outcome"] == "failure"
    ]
    assert len(failures) == 2
    assert {event["ip_address"] for event in failures} == {"198.51.100.150"}
    assert {event["device"] for event in failures} == {"Firefox · Linux"}
    assert {event["severity"] for event in failures} == {"warning"}


def test_security_activity_is_scoped_to_the_caller_and_hides_admin_origin(
    client: TestClient, app
):
    member_token = register_and_login(client, "activity-member")
    register_and_login(client, "activity-other")
    with app.state.database.session_factory() as db:
        db.add(User(
            username="activity-admin",
            password_hash=app.state.password_service.hash(PASSWORD),
            role="admin",
        ))
        db.commit()
        member_id = db.scalar(select(User.id).where(User.username == "activity-member"))
    admin_token = login(
        client, "activity-admin", headers=browser(app, "10.20.30.40")
    ).json()["access_token"]
    changed = client.patch(
        f"/api/admin/users/{member_id}/role",
        headers={**auth(admin_token), **browser(app, "10.20.30.40")},
        json={"role": "moderator"},
    )
    assert changed.status_code == 200, changed.text

    member_token = login(client, "activity-member").json()["access_token"]
    data = client.get("/api/auth/security-activity", headers=auth(member_token)).json()
    admin_rows = [event for event in data["events"] if event["by_administrator"]]
    assert len(admin_rows) == 1
    assert admin_rows[0]["ip_address"] is None and admin_rows[0]["device"] is None
    assert admin_rows[0]["severity"] == "warning"
    assert all(event["ip_address"] != "10.20.30.40" for event in data["events"])

    with app.state.database.session_factory() as db:
        own_ids = {
            row for row in db.scalars(
                select(AuditEvent.actor_id).where(AuditEvent.event_type == "auth.login")
            )
        }
    assert len(own_ids) >= 3
    other_logins = [
        event for event in data["events"]
        if event["event_type"] == "auth.login" and not event["by_administrator"]
    ]
    assert len(other_logins) == 2  # the member's own two sign-ins only


def test_wrong_second_factor_after_correct_password_is_critical(client: TestClient):
    totp = TotpService()
    token = register_and_login(client, "activity-mfa")
    secret = client.post("/api/auth/mfa/enroll", headers=auth(token)).json()["secret"]
    activated = client.post(
        "/api/auth/mfa/activate", headers=auth(token), json={"code": totp.now_code(secret)}
    )
    assert activated.status_code == 200, activated.text

    challenge = login(client, "activity-mfa").json()["mfa_token"]
    wrong = "000000" if totp.now_code(secret) != "000000" else "111111"
    assert client.post(
        "/api/auth/mfa/verify", json={"mfa_token": challenge, "code": wrong}
    ).status_code == 401

    challenge = login(client, "activity-mfa").json()["mfa_token"]
    code = totp.now_code(secret, timestamp=time.time() + totp.period)
    verified = client.post("/api/auth/mfa/verify", json={"mfa_token": challenge, "code": code})
    assert verified.status_code == 200, verified.text

    data = client.get(
        "/api/auth/security-activity", headers=auth(verified.json()["access_token"])
    ).json()
    assert data["mfa_failures_since_previous"] == 1
    mfa_failure = next(
        event for event in data["events"]
        if event["event_type"] == "auth.mfa.verify" and event["outcome"] == "failure"
    )
    assert mfa_failure["severity"] == "critical"


def test_security_activity_requires_authentication(client: TestClient):
    assert client.get("/api/auth/security-activity").status_code == 401


def test_ui_activity_snapshot_flags_suspicious_events(monkeypatch):
    def fake_api(_token, _method, path, _body=None, *, params=None):
        assert path == "/api/auth/security-activity"
        return {
            "previous_sign_in": {
                "at": "2026-10-01T07:00:00Z", "ip_address": "192.0.2.1", "device": "Chrome · Windows",
            },
            "failed_sign_ins_since_previous": 3,
            "mfa_failures_since_previous": 1,
            "new_device_sign_ins_since_previous": 1,
            "events": [{
                "created_at": "2026-10-02T07:00:00Z", "title": "Đăng nhập từ thiết bị mới",
                "severity": "warning", "outcome_label": "Thành công", "ip_address": "203.0.113.5",
                "device": "Safari · iOS", "by_administrator": False,
            }],
        }

    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    summary, rows, alerts = gradio_ui._security_activity_snapshot("token")
    assert "192.0.2.1" in summary and "Chrome · Windows" in summary
    assert len(alerts) == 3
    assert "ĐÚNG mật khẩu" in alerts[0]
    assert rows == [[
        "02/10/2026 07:00", "🟠 Đăng nhập từ thiết bị mới", "Thành công", "203.0.113.5",
        "Safari · iOS",
    ]]
