"""Security account extensions cross the real UI/HTTP boundary safely."""
from __future__ import annotations

import asyncio
import base64
import json
import re
import threading
from dataclasses import replace

import gradio as gr
import pytest
from gradio.state_holder import SessionState
from sqlalchemy import select

from src.app import gradio_ui
from src.app.models import (
    AuthSession,
    SecurityPhone,
    SecurityPhoneChallenge,
    SecurityPushSubscription,
)
from src.app.notification_config import NotificationSettings
from tests.conftest import register_and_login
from tests.test_passkeys import PASSWORD, register_passkey
from tests.test_security_notifications import subscription
from tests.test_ui_feature_completion import callback
from tests.webauthn_soft import SoftAuthenticator


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture()
def settings(settings, tmp_path):
    return replace(settings, notification_settings=NotificationSettings(
        push_backend="outbox", sms_backend="outbox", outbox_dir=str(tmp_path / "notices"),
    ))


@pytest.fixture(autouse=True)
def notices(monkeypatch):
    messages = {"info": [], "warning": []}
    monkeypatch.setattr(gr, "Info", lambda value, **_kwargs: messages["info"].append(value))
    monkeypatch.setattr(gr, "Warning", lambda value, **_kwargs: messages["warning"].append(value))
    return messages


@pytest.fixture()
def http_api(client, app, monkeypatch):
    """Keep the actual _api adapter, including RFC step-up error handling."""
    app.state.notifications.background = False
    monkeypatch.setattr(gradio_ui, "_api_client", lambda: client)
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    monkeypatch.setattr(gradio_ui, "BASE_URL", "http://testserver")
    return client


def finish_payload(prepared, **change):
    return json.dumps({"mode": "step-up", "nonce": prepared[1]["nonce"], **change})


def check_arity(fn, values):
    assert len(values) == len(fn.outputs)


def test_passkey_step_up_callback_uses_real_assertion_and_closes_public_bridge(demo, http_api, app):
    token = register_and_login(http_api, "ui-passkey-step-up")
    device = SoftAuthenticator()
    assert register_passkey(http_api, token, device).status_code == 201
    jti = app.state.token_service.decode(token)["jti"]
    with app.state.database.session_factory() as db:
        db.get(AuthSession, jti).last_step_up_at = None
        db.commit()
    prepare = callback(demo, "prepare_passkey_step_up")
    prepared = prepare.fn(token)
    check_arity(prepare, prepared)
    assert prepared[1]["account"] == gradio_ui._token_digest(token)
    assert re.fullmatch(r"[a-f0-9]{32}", prepared[1]["nonce"])
    assert token not in prepared[0] and prepared[1]["challenge_id"] not in prepared[0]
    encoded = re.search(r'data-scap-passkey-options="([A-Za-z0-9_-]+)"', prepared[0])[1]
    public_key = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert public_key["userVerification"] == "required"
    finish = callback(demo, "finish_passkey_step_up")
    result = finish.fn(token, finish_payload(prepared, credential=device.assert_(public_key)), prepared[1])
    check_arity(finish, result)
    assert result[0:2] == ("", {})
    assert result[2]["visible"] is False and result[3]["visible"] is False and result[4] == ""
    with app.state.database.session_factory() as db:
        assert db.get(AuthSession, jti).last_step_up_at is not None


def test_rejected_passkey_proof_closes_consumed_ceremony_without_success_notice(demo, http_api, app, notices):
    token = register_and_login(http_api, "ui-passkey-rejected")
    device = SoftAuthenticator()
    assert register_passkey(http_api, token, device).status_code == 201
    prepared = callback(demo, "prepare_passkey_step_up").fn(token)
    encoded = re.search(r'data-scap-passkey-options="([A-Za-z0-9_-]+)"', prepared[0])[1]
    public_key = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    result = callback(demo, "finish_passkey_step_up").fn(
        token, finish_payload(prepared, credential=device.assert_(public_key, uv=False)), prepared[1],
    )
    assert result[0:2] == ("", {}) and result[3]["visible"] is False
    assert notices["warning"] and not notices["info"]


@pytest.mark.parametrize("change", ["account", "nonce", "mode", "oversize"])
def test_unbound_passkey_ui_result_never_reaches_verification(demo, monkeypatch, change):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    state = {"nonce": "a" * 32, "challenge_id": "private-challenge", "account": gradio_ui._token_digest("A")}
    payload = {"mode": "step-up", "nonce": state["nonce"], "credential": {"id": "public"}}
    token = "B" if change == "account" else "A"
    if change == "nonce":
        payload["nonce"] = "b" * 32
    elif change == "mode":
        payload["mode"] = "create"
    raw = "x" * 20_001 if change == "oversize" else json.dumps(payload)
    result = callback(demo, "finish_passkey_step_up").fn(token, raw, state)
    assert result[0:2] == ("", {}) and result[3]["visible"] is False
    assert calls == []


def test_push_ui_opt_in_persists_only_after_browser_proof_and_reports_demo_mode(demo, http_api, app):
    token = register_and_login(http_api, "ui-push-opt-in")
    prepare = callback(demo, "prepare_push")
    prepared = prepare.fn(token)
    check_arity(prepare, prepared)
    assert prepared[1]["account"] == gradio_ui._token_digest(token)
    assert token not in prepared[0] and "Đang tắt" not in prepared[4]
    assert "Demo outbox" in prepared[4]
    with app.state.database.session_factory() as db:
        assert db.scalar(select(SecurityPushSubscription)) is None
    body = subscription("ui-browser-proof")
    finish = callback(demo, "finish_push")
    result = finish.fn(token, json.dumps({"nonce": prepared[1]["nonce"], "subscription": body}), prepared[1], "", "")
    check_arity(finish, result)
    assert result[0:2] == ("", {}) and result[2]["visible"] is False
    assert "1 đăng ký" in result[-1] and "chưa gửi ra dịch vụ thật" in result[-1]
    assert "\n\n**SMS:**" in result[-1] and "\\n" not in result[-1]
    with app.state.database.session_factory() as db:
        row = db.scalars(select(SecurityPushSubscription)).one()
        assert body["endpoint"] not in row.subscription_ciphertext
    disable = callback(demo, "disable_push")
    disabled = disable.fn(token, "", "")
    check_arity(disable, disabled)
    assert "0 đăng ký" in disabled[0]


@pytest.mark.parametrize("change", ["account", "nonce", "permission", "malformed", "oversize", "depth"])
def test_push_permissions_and_account_binding_fail_closed_in_ui(demo, monkeypatch, notices, change):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    state = {"nonce": "a" * 32, "account": gradio_ui._token_digest("A")}
    payload = {"nonce": state["nonce"], "subscription": {"endpoint": "public-capability"}}
    token = "B" if change == "account" else "A"
    if change == "nonce":
        payload["nonce"] = "b" * 32
    elif change == "permission":
        payload["error"] = "NotAllowedError"
    raw = "x" * 8001 if change == "oversize" else ("[]" if change == "malformed" else json.dumps(payload))
    if change == "depth":
        raw = "[" * 1200 + "]" * 1200
    finish = callback(demo, "finish_push")
    result = finish.fn(token, raw, state, "password-must-not-be-used", "otp-must-not-be-used")
    check_arity(finish, result)
    assert result[:2] == ("", {}) and result[2]["visible"] is False
    assert calls == [] and notices["warning"] and not notices["info"]


def test_disabled_push_never_exposes_a_permission_marker_and_status_is_honest(demo, monkeypatch, notices):
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: {
        "push": {"available": False, "mode": "disabled", "subscriptions": []},
        "sms": {"available": False, "mode": "disabled", "phone": None},
    })
    prepared = callback(demo, "prepare_push").fn("A")
    assert prepared == tuple(gr.skip() for _ in range(5))
    assert notices["warning"]
    status = callback(demo, "notifications_snapshot").fn("A")
    assert status.count("Đang tắt") == 2
    assert "Chưa có số đã xác minh" in status


def test_sms_ui_verifies_real_possession_and_clears_proof_and_phone_inputs(demo, http_api, app):
    token = register_and_login(http_api, "ui-sms-opt-in")
    delivered = []
    app.state.notifications.sms_transport = lambda _phone, text: delivered.append(text) or "demo_outbox"
    request = callback(demo, "request_phone")
    requested = request.fn(token, "  +84901234567  ", "", "")
    check_arity(request, requested)
    assert "chưa gửi SMS thật" in requested[0]
    assert requested[1]["account"] == gradio_ui._token_digest(token)
    code = re.search(r"\b([0-9]{8})\b", delivered[-1])[1]
    assert code not in str(requested) and "+84901234567" not in str(requested)
    verify = callback(demo, "verify_phone")
    verified = verify.fn(token, code, requested[1])
    check_arity(verify, verified)
    assert "••••4567" in verified[0] and verified[1:] == ({}, "", "")
    with app.state.database.session_factory() as db:
        assert db.scalar(select(SecurityPhone)) is not None
    remove = callback(demo, "remove_phone")
    removed = remove.fn(token, "", "")
    check_arity(remove, removed)
    assert "Chưa có số đã xác minh" in removed[0] and removed[1:] == ({}, "", "", "", "")


def test_notification_status_does_not_render_raw_contact_or_server_html(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: {
        "push": {"available": True, "mode": "<script>private-mode</script>",
                 "subscriptions": [{"id": "private-capability-token"}]},
        "sms": {"available": True, "mode": "twilio", "phone": "+84901234567"},
    })
    shown = callback(demo, "notifications_snapshot").fn("A")
    assert "+84901234567" not in shown
    assert "private-capability-token" not in shown and "<script>" not in shown
    assert "Chưa có số đã xác minh" in shown and "Chưa xác định" in shown


def test_sms_ui_requests_step_up_before_sending_and_can_use_password_fallback(demo, http_api, app, notices):
    token = register_and_login(http_api, "ui-sms-step-up")
    delivered = []
    app.state.notifications.sms_transport = lambda _phone, text: delivered.append(text) or "demo_outbox"
    with app.state.database.session_factory() as db:
        db.get(AuthSession, app.state.token_service.decode(token)["jti"]).last_step_up_at = None
        db.commit()
    request = callback(demo, "request_phone")
    rejected = request.fn(token, "+84901234567", "", "")
    assert rejected == tuple(gr.skip() for _ in range(5))
    assert delivered == [] and notices["warning"]
    with app.state.database.session_factory() as db:
        assert db.scalar(select(SecurityPhoneChallenge)) is None
    accepted = request.fn(token, "+84901234567", PASSWORD, "")
    assert accepted[1]["challenge_id"] and len(delivered) == 1
    assert accepted[-2:] == ("", "")


def test_sms_ui_does_not_submit_a_previous_accounts_code(demo, monkeypatch, notices):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    result = callback(demo, "verify_phone").fn("B", "12345678", {
        "challenge_id": "old-account-proof", "account": gradio_ui._token_digest("A"),
    })
    assert result == tuple(gr.skip() for _ in range(4))
    assert calls == [] and notices["warning"]


@pytest.mark.parametrize("backend,available,text", [
    ("disabled", True, "đang tắt"), ("maxmind", False, "chưa thể kết luận"),
    ("maxmind", True, "không tự khóa tài khoản"),
])
def test_geoip_ui_distinguishes_disabled_unavailable_and_advisory(demo, monkeypatch, backend, available, text):
    calls = []

    def api(*args):
        calls.append(args)
        return {"backend": backend, "available": available, "action": "alert_only"}

    monkeypatch.setattr(gradio_ui, "_api", api)
    status = callback(demo, "load_geoip_status").fn("A")
    assert text in status
    assert calls == [("A", "GET", "/api/auth/sign-in-risk/status")]


def test_geoip_ui_explains_feed_place_rules_and_credits_db_ip():
    base = {"backend": "maxmind", "available": True, "action": "alert_only",
            "checked_at": "2026-10-20T06:07:08+00:00",
            "history_hours": 24, "min_distance_km": 500, "max_speed_kmh": 900,
            "database": {"type": "DBIP-City-Lite", "built": "2026-10-01", "age_days": 19,
                         "max_age_days": 90}}
    text = gradio_ui._geoip_status_markdown(
        {**base, "current": {"resolved": True, "country": "VN", "city": "Ha*noi"}})
    assert "cơ sở dữ liệu DB-IP City Lite, phát hành 01/10/2026 (19 ngày trước)" in text
    assert "Lần kiểm tra vị trí: 20/10/2026 13:07:08 (UTC+7)." in text
    assert "Ha\\*noi, VN" in text and "không được lưu" in text
    assert "500 km" in text and "900 km/h" in text and "24 giờ" in text
    assert "tự động" in text and "đăng nhập" in text and "tải lại trang" in text
    assert "cùng một IP" in text and "GPS" in text
    assert "[IP Geolocation by DB-IP](https://db-ip.com)" in text
    private = gradio_ui._geoip_status_markdown({**base, "current": {"resolved": False, "reason": "private"}})
    assert "địa chỉ nội bộ" in private
    maxmind = gradio_ui._geoip_status_markdown(
        {**base, "database": {**base["database"], "type": "GeoLite2-City"}})
    assert "GeoLite2\\-City" in maxmind and "DB-IP" not in maxmind  # Markdown-escaped name
    stale = gradio_ui._geoip_status_markdown({**base, "available": False})
    assert "chưa khả dụng" in stale and "90 ngày" in stale


@pytest.mark.parametrize("token", ["", None])
def test_geoip_automatic_refresh_without_a_session_clears_status_without_request(demo, monkeypatch, token):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    assert callback(demo, "load_geoip_status").fn(token) == ""
    assert calls == []


def test_every_completed_login_and_restored_session_refreshes_geoip_display(demo):
    dependencies = demo.config["dependencies"]
    names = {item["id"]: demo.fns[item["id"]].fn.__name__ for item in dependencies}
    starts = [item for item in dependencies if names[item["id"]] in {
        "restore_session", "do_login", "do_mfa_verify", "finish_passkey_login",
    }]
    assert len(starts) == 5  # Restoration, password, MFA click/Enter and passkey.
    manual = next(item for item in dependencies if names[item["id"]] == "load_geoip_status"
                  and item.get("trigger_after") is None)
    for start in starts:
        pending = [start]
        reached = []
        while pending:
            parent = pending.pop()
            for child in dependencies:
                if child.get("trigger_after") != parent["id"]:
                    continue
                if names[child["id"]] == "load_geoip_status":
                    reached.append(child)
                else:
                    pending.append(child)
        assert len(reached) == 1, names[start["id"]]
        refresh = reached[0]
        assert refresh["inputs"] == manual["inputs"]
        assert refresh["outputs"] == manual["outputs"]
        assert refresh["show_progress"] == "hidden"


def test_geoip_ui_reads_real_authenticated_status_without_revealing_lookup_path(demo, http_api):
    token = register_and_login(http_api, "ui-geoip-status")
    status = callback(demo, "load_geoip_status").fn(token)
    assert "GeoIP đang tắt" in status and ".mmdb" not in status


def test_logout_clears_all_extension_proof_states_and_private_inputs(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: {})

    async def scenario():
        state = SessionState(demo)
        passkey, push, phone, logout = (callback(demo, name) for name in (
            "finish_passkey_step_up", "finish_push", "verify_phone", "do_logout",
        ))
        state[passkey.inputs[0]._id] = "account-A-token"
        protected = [passkey.inputs[2], push.inputs[2], phone.inputs[2]]
        for component in protected:
            state[component._id] = {"account": gradio_ui._token_digest("account-A-token"), "nonce": "old-proof"}
        result = await demo.process_api(logout, [None], state=state)
        assert state[passkey.inputs[0]._id] == ""
        for component in protected:
            assert state[component._id] == {}
        outputs = dict(zip((item._id for item in logout.outputs), result["data"], strict=True))
        assert outputs[passkey.inputs[1]._id] == ""
        assert outputs[push.inputs[1]._id] == ""
        assert outputs[phone.inputs[1]._id] == ""
        for name in ("prepare_passkey_step_up", "prepare_push"):
            prepare = callback(demo, name)
            assert outputs[prepare.outputs[0]._id] == ""

    asyncio.run(scenario())


def test_pending_push_preparation_cannot_publish_into_a_logged_out_account(demo, monkeypatch):
    reached, release = threading.Event(), threading.Event()

    def api(token, method, path, *args, **kwargs):
        if path == "/api/auth/logout":
            return {}
        assert path == "/api/auth/notifications/status"
        reached.set()
        assert release.wait(15)
        return {"push": {"available": True, "mode": "outbox", "application_server_key": "B" * 87,
                         "subscriptions": []}, "sms": {"mode": "disabled"}}

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        prepare, logout = callback(demo, "prepare_push"), callback(demo, "do_logout")
        state = SessionState(demo)
        state[prepare.inputs[0]._id] = "account-A-token"
        pending = asyncio.create_task(demo.process_api(prepare, [None], state=state))
        try:
            assert await asyncio.to_thread(reached.wait, 10)
            await demo.process_api(logout, [None], state=state)
        finally:
            release.set()
        result = await pending
        assert result["data"] == [gr.skip()] * len(prepare.outputs)
        assert result["changed_state_ids"] == []
        assert state[prepare.outputs[1]._id] == {}

    asyncio.run(scenario())


@pytest.mark.parametrize("result", ["removed", "absent"])
def test_browser_local_push_removal_has_no_authenticated_server_side_effect(demo, monkeypatch, notices, result):
    def forbidden(*args, **kwargs):
        raise AssertionError("Browser-local unsubscribe must not call the authenticated API")

    monkeypatch.setattr(gradio_ui, "_api", forbidden)
    prepare = callback(demo, "prepare_push_local_remove")
    prepared = prepare.fn("B")
    check_arity(prepare, prepared)
    assert prepared[1]["action"] == "unsubscribe_browser"
    assert prepared[1]["account"] == gradio_ui._token_digest("B")
    assert 'data-scap-push-action="unsubscribe_browser"' in prepared[0]
    assert "data-scap-push-key" not in prepared[0]
    assert "Xác nhận gỡ" in prepared[2]["value"]
    finish = callback(demo, "finish_push")
    closed = finish.fn("B", json.dumps({
        "nonce": prepared[1]["nonce"], "action": "unsubscribe_browser", "status": result,
    }), prepared[1], "unused-password", "unused-code")
    check_arity(finish, closed)
    assert closed[0:2] == ("", {}) and closed[2]["visible"] is False
    assert "Chuẩn bị bật Push" in closed[-1]
    assert notices["info"] and not notices["warning"]


@pytest.mark.parametrize("change", ["account", "nonce", "action", "result", "result_type"])
def test_browser_local_removal_cannot_consume_a_different_prepared_action(demo, monkeypatch, notices, change):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args))
    prepared = callback(demo, "prepare_push_local_remove").fn("A")
    payload = {"nonce": prepared[1]["nonce"], "action": "unsubscribe_browser", "status": "removed"}
    token = "B" if change == "account" else "A"
    if change == "nonce":
        payload["nonce"] = "b" * 32
    elif change == "action":
        payload["action"] = "subscribe"
    elif change == "result":
        payload["status"] = "guessed"
    elif change == "result_type":
        payload["status"] = []
    closed = callback(demo, "finish_push").fn(token, json.dumps(payload), prepared[1], "", "")
    assert closed[:2] == ("", {}) and closed[2]["visible"] is False
    assert calls == [] and notices["warning"] and not notices["info"]


def test_cross_account_browser_subscription_conflict_has_manual_recovery_and_preserves_owner(demo, http_api, app, notices):
    account_a = register_and_login(http_api, "ui-shared-browser-a")
    account_b = register_and_login(http_api, "ui-shared-browser-b")
    current_subscription = subscription("shared-browser-old")
    response = http_api.post("/api/auth/notifications/push", json=current_subscription,
                             headers={"Authorization": "Bearer " + account_a})
    assert response.status_code == 201, response.text
    prepare, finish = callback(demo, "prepare_push"), callback(demo, "finish_push")
    prepared = prepare.fn(account_b)
    conflict = finish.fn(account_b, json.dumps({"nonce": prepared[1]["nonce"],
                                             "subscription": current_subscription}), prepared[1], "", "")
    assert conflict[:2] == ("", {}) and conflict[2]["visible"] is False
    assert any("Gỡ đăng ký Push trên trình duyệt này" in value for value in notices["warning"])
    assert not notices["info"]
    with app.state.database.session_factory() as db:
        rows = list(db.scalars(select(SecurityPushSubscription)))
        assert len(rows) == 1 and rows[0].user_id == app.state.token_service.decode(account_a)["sub"]
    # The explicit browser-local action does not revoke account A's server row.
    local = callback(demo, "prepare_push_local_remove").fn(account_b)
    finish.fn(account_b, json.dumps({"nonce": local[1]["nonce"], "action": "unsubscribe_browser",
                                    "status": "removed"}), local[1], "", "")
    prepared = prepare.fn(account_b)
    assert prepared[2]["value"] == "Cho phép và bật thông báo Push"
    renewed = finish.fn(account_b, json.dumps({"nonce": prepared[1]["nonce"],
                                             "subscription": subscription("shared-browser-new")}), prepared[1], "", "")
    assert "1 đăng ký" in renewed[-1]
    with app.state.database.session_factory() as db:
        assert len(list(db.scalars(select(SecurityPushSubscription)))) == 2
