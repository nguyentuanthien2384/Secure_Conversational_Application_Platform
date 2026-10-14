"""Kiểm thử đấu nối giao diện Gradio (bổ sung v2.2).

Gradio nối input/output theo **thứ tự vị trí**. Thêm một component vào ``STAGE2``
mà quên cập nhật ``load_workspace`` hoặc ``_reset_tuple`` sẽ làm mọi output lệch
một ô — giao diện hỏng theo kiểu rất khó lần ra. Các test dưới đây khoá lại bất
biến đó bằng cấu trúc mã và chạy handler đã được Gradio đăng ký, không cần
khởi động server.
"""

from __future__ import annotations

import ast
from pathlib import Path

import gradio as gr
import pytest

UI_SOURCE = Path(__file__).resolve().parents[1] / "src" / "app" / "gradio_ui.py"


def _build_ui_body() -> list[ast.stmt]:
    tree = ast.parse(UI_SOURCE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "build_ui":
            return node.body
    raise AssertionError("Không tìm thấy hàm build_ui()")


def _find_list_assign(body: list[ast.stmt], name: str) -> ast.List:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    assert isinstance(node.value, ast.List), f"{name} phải là một list"
                    return node.value
    raise AssertionError(f"Không tìm thấy {name}")


def _find_func(body: list[ast.stmt], name: str) -> ast.FunctionDef:
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"Không tìm thấy hàm {name}")


def _final_return_len(fn: ast.FunctionDef) -> int:
    """Số phần tử của tuple ở câu return cuối cùng."""
    returns = [
        n for n in ast.walk(fn) if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
    ]
    assert returns, f"{fn.name} phải return một tuple"
    return len(returns[-1].value.elts)


@pytest.fixture(scope="module")
def runtime_demo():
    from src.app.gradio_ui import build_ui

    return build_ui()


def _event_for(demo, target, event="click"):
    dependency = next(item for item in demo.config["dependencies"]
                      if (target._id, event) in item["targets"])
    return demo.fns[dependency["id"]], dependency


def _is_table(component):
    return isinstance(component, gr.Markdown) and "scap-table-block" in (component.elem_classes or [])


def _button_event(demo, label):
    button = next(component for component in demo.blocks.values()
                  if isinstance(component, gr.Button) and component.value == label)
    return _event_for(demo, button)


def test_login_click_and_enter_share_authentication_and_workspace_chain(runtime_demo, monkeypatch):
    from src.app import gradio_ui

    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args: calls.append(args) or {
        "access_token": "authenticated-token", "expires_in": 900,
    })
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    fields = {component.elem_id: component for component in runtime_demo.blocks.values()}
    click, dependency = _button_event(runtime_demo, "Đăng nhập")
    for field in ("li-user", "li-pass"):
        submit, submit_dependency = _event_for(runtime_demo, fields[field], "submit")
        assert submit is click
        assert submit_dependency == dependency
    assert dependency["inputs"] == [fields["li-user"]._id, fields["li-pass"]._id]
    assert dependency["trigger_mode"] == "once"
    result = click.fn("  saved-user  ", "saved-password")
    assert calls == [(None, "POST", "/api/auth/login", {
        "username": "saved-user", "password": "saved-password",
    })]
    assert result[0] == "authenticated-token"
    assert len(result) == len(dependency["outputs"])
    remember = next(item for item in runtime_demo.config["dependencies"]
                    if item["trigger_after"] == dependency["id"])
    assert runtime_demo.fns[remember["id"]].fn.__name__ == "remember_session"
    workspace = next(item for item in runtime_demo.config["dependencies"]
                     if item["trigger_after"] == remember["id"])
    assert runtime_demo.fns[workspace["id"]].fn.__name__ == "load_workspace"


def test_login_password_manager_hints_and_ready_signal(runtime_demo):
    fields = {component.elem_id: component for component in runtime_demo.blocks.values()}
    assert fields["li-user"].html_attributes.autocomplete == "username"
    assert fields["li-user"].max_lines == 1
    assert fields["li-pass"].html_attributes.autocomplete == "current-password"
    assert fields["re-pass"].html_attributes.autocomplete == "new-password"
    ready = next(item for item in runtime_demo.config["dependencies"]
                 if item["outputs"] == [fields["login-ready"]._id])
    workspace = runtime_demo.fns[ready["trigger_after"]]
    assert workspace.fn.__name__ == "load_workspace"
    assert "data-scap-login-ready" in runtime_demo.fns[ready["id"]].fn()


def test_login_completion_is_acknowledged_even_without_a_session_ticket(runtime_demo, monkeypatch):
    from src.app.ui_session import BrowserSessionStore, UISessionCapacityError

    callback = next(item for item in runtime_demo.fns.values()
                    if item.fn is not None and item.fn.__name__ == "remember_session")
    first = callback.fn("", 0)
    second = callback.fn("", 0)
    assert first != second
    assert "data-scap-login-result" in first
    assert "data-scap-session-ticket" not in first

    def full(*args):
        raise UISessionCapacityError()

    monkeypatch.setattr(BrowserSessionStore, "issue", full)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    full_result = callback.fn("private-token", float("inf"))
    assert "data-scap-login-result" in full_result
    assert "data-scap-session-ticket" not in full_result
    assert "private-token" not in full_result


def test_admin_actions_keep_the_selected_account_selected(runtime_demo, monkeypatch):
    """Lock then unlock used to answer "Chọn một người dùng trước." because every
    action reloaded the user list with the selection cleared."""
    from src.app import gradio_ui

    users = [{"id": f"user-{i}", "username": f"lab.{i}", "role": "user", "is_active": True,
              "mfa_enabled": False, "created_at": "2026-10-12T07:00:00+00:00"} for i in range(3)]
    stats = {"total_users": 3, "active_users": 3, "total_sessions": 0, "total_messages": 0,
             "recent_login_failures": 0, "recent_auth_denials": 0, "availability": None}

    def fake_api(token, method, path, *args, **kwargs):
        return {"/api/admin/stats": stats, "/api/admin/users": users}.get(path, [])

    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    for label in ("Khóa", "Mở khóa"):
        callback, dependency = _button_event(runtime_demo, label)
        result = callback.fn("token", "user-1")
        assert result[-1]["value"] == "user-1", label
    callback, _ = _button_event(runtime_demo, "Đổi vai trò")
    assert callback.fn("token", "user-2", "moderator")[-1]["value"] == "user-2"
    callback, _ = _button_event(runtime_demo, "Xóa tài khoản")
    users.pop(1)
    assert callback.fn("token", "user-1")[-1]["value"] is None


def test_mfa_activation_keeps_recovery_codes_on_screen_and_requires_a_fresh_login(runtime_demo, monkeypatch):
    """Activation revokes the token in use; the UI must not keep working with it."""
    from src.app import gradio_ui

    codes = [f"code{i:02d}-recovery" for i in range(10)]
    calls, notices = [], []
    monkeypatch.setattr(gradio_ui, "_api",
                        lambda *args: calls.append(args) or {"recovery_codes": codes})
    monkeypatch.setattr(gr, "Info", lambda message, **kwargs: notices.append((message, kwargs)))
    callback, dependency = _button_event(runtime_demo, "Kích hoạt")
    result = callback.fn("previous-token", "123456")
    assert calls[0][2] == "/api/auth/mfa/activate"
    updates = dict(zip(dependency["outputs"], result, strict=True))
    token_state = next(component for component in runtime_demo.blocks.values()
                       if component._id == dependency["outputs"][0])
    assert updates[token_state._id] == ""
    sticky = [message for message, kwargs in notices if kwargs.get("duration", 10) is None]
    assert len(sticky) == 1 and all(code in sticky[0] for code in codes)


@pytest.mark.parametrize("reason", ["logout", "logout_all", "password_change", "expiry", "revoked"])
def test_session_end_handlers_clear_previous_account_data(runtime_demo, monkeypatch, reason):
    """Run the registered callbacks, including wrappers and actual output wiring."""
    from src.app import gradio_ui

    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args: calls.append(args) or {})
    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    logout, logout_dependency = _button_event(runtime_demo, "Đăng xuất")
    if reason in ("expiry", "revoked"):
        timer = next(component for component in runtime_demo.blocks.values()
                     if isinstance(component, gr.Timer))
        tick, tick_dependency = _event_for(runtime_demo, timer, "tick")
        # The periodic tick only records the expiry; the state's change event
        # performs the full reset, so routine ticks stay small.
        if reason == "expiry":
            _, _, timer_update, expired_at = tick.fn(999, True)
            assert expired_at == 999 and timer_update.active is False
        else:
            # The API refused this tab's token (revoked elsewhere, locked, deleted).
            gradio_ui._mark_session_ended("previous-token")
            _, _, timer_update, expired_at = tick.fn(1600, True, "previous-token")
            assert expired_at == -1000 and timer_update.active is False
        expired_state = runtime_demo.blocks[tick_dependency["outputs"][-1]]
        callback, dependency = _event_for(runtime_demo, expired_state, "change")
        result = callback.fn(expired_at)
        assert calls == []
    else:
        label, args, expected_endpoint = {
            "logout": ("Đăng xuất", ("previous-token",), "/api/auth/logout"),
            "logout_all": ("Đăng xuất mọi thiết bị", ("previous-token",), "/api/auth/logout-all"),
            "password_change": (
                "Cập nhật mật khẩu", ("previous-token", "Old-password-for-lab", "New-password-for-lab"),
                "/api/auth/password",
            ),
        }[reason]
        callback, dependency = _button_event(runtime_demo, label)
        result = callback.fn(*args)
        assert calls[0][2] == expected_endpoint

    assert dependency["outputs"] == logout_dependency["outputs"]
    assert len(result) == len(callback.outputs) == len(dependency["outputs"])
    assert len(set(dependency["outputs"])) == len(result), "Duplicate output causes ambiguous resets"
    updates = dict(zip(dependency["outputs"], result, strict=True))
    # A simulated prior browser view has another user's data in every textbox,
    # table and download control. Each must receive an actual value replacement.
    for component in runtime_demo.blocks.values():
        table = _is_table(component)
        if table or isinstance(component, (gr.Textbox, gr.Chatbot, gr.DownloadButton)):
            assert component._id in updates, f"Reset omitted {component.label or component.elem_id}"
            update = updates[component._id]
            value = update.get("value", "previous-account-data") if isinstance(update, dict) else update
            if isinstance(component, gr.DownloadButton):
                assert value is None and update["visible"] is False
            elif table:
                assert value == component.value, f"Retained rows in {component.elem_id}"
                assert "scap-table-empty" in value
            elif isinstance(component, gr.Chatbot):
                assert value == []
            else:
                assert value == "", f"Retained text in {component.label}"

    notice = next(component for component in runtime_demo.blocks.values()
                  if component.elem_id == "chat-notice")
    assert updates[notice._id] == gr.update(value="", visible=False)
    qr = next(component for component in runtime_demo.blocks.values()
              if isinstance(component, gr.Markdown) and component.label == "Quét bằng ứng dụng xác thực")
    assert updates[qr._id] == gr.update(value="", visible=False)
    # 2FA activation and deactivation revoke the session, so they reuse this reset.
    for label in ("Kích hoạt", "Tắt 2FA"):
        _, mfa_dependency = _button_event(runtime_demo, label)
        assert mfa_dependency["outputs"] == logout_dependency["outputs"]
    # Previously fetched dashboard/log/security values are outputs of refresh
    # events: they must all belong to the reset, even while their tabs are hidden.
    for label in ("Làm mới dashboard", "Tải nhật ký", "Làm mới toàn bộ",
                  "Xác minh chuỗi", "Chạy kiểm chứng Hit/Miss"):
        _, refresh_dependency = _button_event(runtime_demo, label)
        assert set(refresh_dependency["outputs"]) <= updates.keys()
        assert all(updates[item] != gr.skip() for item in refresh_dependency["outputs"])
    assert result[-2:] == ("", False)
    assert isinstance(logout.outputs[-2], gr.Markdown)
    assert isinstance(logout.outputs[-1], gr.State)
    token, expiry, mfa_token = callback.outputs[:3]
    assert [updates[item._id] for item in (token, expiry, mfa_token)] == ["", 0.0, ""]
    password = next(component for component in runtime_demo.blocks.values()
                    if component.elem_id == "li-pass")
    assert updates[password._id]["type"] == "password"


def test_session_clock_tick_only_touches_the_clock(runtime_demo, monkeypatch):
    """A tick that returned every workspace output made tab switches freeze."""
    from src.app import gradio_ui

    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    timer = next(component for component in runtime_demo.blocks.values()
                 if isinstance(component, gr.Timer))
    assert timer.value == gradio_ui.SESSION_TICK_SECONDS > 1
    callback, dependency = _event_for(runtime_demo, timer, "tick")
    # Sign-in, restore and renewal change the expiry: show the clock at once.
    expiry_state = runtime_demo.blocks[dependency["inputs"][0]]
    assert isinstance(expiry_state, gr.State)
    assert (expiry_state._id, "change") in dependency["targets"]
    assert len(dependency["outputs"]) == 4

    countdown, warned, timer_update, expired = callback.fn(1600, False)
    assert 'data-scap-countdown="600"' in countdown and "10:00" in countdown
    assert warned is False and expired == gr.skip()
    assert timer_update.value == gradio_ui.SESSION_TICK_SECONDS and timer_update.active is True

    # Near the deadline the next tick lands exactly on it, not up to a cycle late.
    countdown, warned, timer_update, expired = callback.fn(1005, False)
    assert "0:05" in countdown and warned is True
    assert timer_update.value == 5 and expired == gr.skip()

    assert callback.fn(0, False)[:2] == ("", False)


def test_only_an_invalid_token_challenge_sends_the_tab_back_to_sign_in(runtime_demo, monkeypatch):
    """A 401 for a wrong step-up password keeps the session; a revoked token ends it."""
    import httpx

    from src.app import gradio_ui

    challenge = {"WWW-Authenticate": 'Bearer error="invalid_token"'}
    responses = {
        "/api/auth/step-up": httpx.Response(401, json={"detail": "Không xác thực được yêu cầu."}),
        "/api/auth/sessions": httpx.Response(401, json={"detail": "Tài khoản không hợp lệ."}, headers=challenge),
        "/api/auth/password-reset/request": httpx.Response(401, json={"detail": "x"}, headers=challenge),
    }
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda request: responses[request.url.path]), **kwargs))
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    warnings = []
    monkeypatch.setattr(gr, "Warning", lambda message, *args, **kwargs: warnings.append(message))
    timer = next(component for component in runtime_demo.blocks.values()
                 if isinstance(component, gr.Timer))
    tick, dependency = _event_for(runtime_demo, timer, "tick")
    _, logout_dependency = _button_event(runtime_demo, "Đăng xuất")
    assert dependency["inputs"][2] == logout_dependency["inputs"][0], "tick must read the tab token"

    with pytest.raises(gr.Error):
        gradio_ui._api("tab-token", "POST", "/api/auth/step-up", {"password": "wrong"})
    with pytest.raises(gr.Error):  # no tab token: nothing to end
        gradio_ui._api(None, "POST", "/api/auth/password-reset/request", {"identifier": "abc"})
    assert tick.fn(1600, False, "tab-token")[-1] == gr.skip()

    with pytest.raises(gr.Error):
        gradio_ui._api("tab-token", "GET", "/api/auth/sessions")
    assert tick.fn(1600, False, "another-tab")[-1] == gr.skip()
    assert tick.fn(0, False, "tab-token")[-1] == gr.skip(), "a signed-out tab has nothing to end"
    _, _, timer_update, expired_at = tick.fn(1600, False, "tab-token")
    assert expired_at == -1000 and timer_update.active is False
    assert tick.fn(1600, False, "tab-token")[-1] == gr.skip(), "the marker is consumed once"

    expired_state = runtime_demo.blocks[dependency["outputs"][-1]]
    callback, _ = _event_for(runtime_demo, expired_state, "change")
    callback.fn(expired_at)
    assert "không còn hiệu lực" in warnings[-1]
    callback.fn(999)
    assert "hết hạn" in warnings[-1]


def test_ended_token_markers_are_bounded_digests(monkeypatch):
    from src.app import gradio_ui

    monkeypatch.setattr(gradio_ui, "_ENDED_TOKENS", {})
    monkeypatch.setattr(gradio_ui, "_ENDED_TOKENS_MAX", 3)
    for index in range(5):
        gradio_ui._mark_session_ended(f"token-{index}")
    assert len(gradio_ui._ENDED_TOKENS) == 3
    assert not any("token-" in key for key in gradio_ui._ENDED_TOKENS)
    assert not gradio_ui._take_session_ended("token-0")
    assert gradio_ui._take_session_ended("token-4")


@pytest.mark.parametrize("action", ["create", "delete"])
def test_switching_conversation_programmatically_clears_notices_and_rename(runtime_demo, monkeypatch, action):
    """A DLP/consent notice belongs to the previous send; the rename box to the previous title."""
    from src.app import gradio_ui

    sessions = [{"id": "new", "title": "Hồ sơ mật", "security_mode": "confidential"},
                {"id": "old", "title": "Ôn tập", "security_mode": "secure"}]

    def api(token, method, path, body=None, **kwargs):
        if (method, path) == ("POST", "/api/sessions"):
            return {"id": "new", "title": body["title"]}
        if (method, path) == ("GET", "/api/sessions"):
            return sessions if action == "create" else sessions[1:]
        if path.endswith("/messages"):
            return []
        if method == "GET":
            return next(item for item in sessions if path.endswith(item["id"]))
        return {}

    monkeypatch.setattr(gradio_ui, "_api", api)
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    if action == "create":
        callback, dependency = _button_event(runtime_demo, "+ Hội thoại mới")
        result = callback.fn("token", "Hồ sơ mật", "confidential", "internal")
        expected_title = "Hồ sơ mật"
    else:
        callback, dependency = _button_event(runtime_demo, "Xóa")
        result = callback.fn("token", "new")
        expected_title = "Ôn tập"
    outputs = {runtime_demo.blocks[item].elem_id or getattr(runtime_demo.blocks[item], "label", None)
               or runtime_demo.blocks[item].value: value
               for item, value in zip(dependency["outputs"], result, strict=True)}
    assert outputs["chat-notice"] == gr.update(value="", visible=False)
    assert outputs["Đồng ý và gửi"] == gr.update(visible=False)
    assert outputs["Đổi tên"] == expected_title


def test_every_guarded_handler_skips_exactly_its_outputs(runtime_demo):
    """A failed API call returns one gr.skip() per output.

    Admin actions once skipped 4 of 8 outputs: refusing to lock oneself raised
    "didn't return enough output values" and left the user picker stuck.
    """
    checked = []
    for dependency in runtime_demo.config["dependencies"]:
        wrapper = runtime_demo.fns[dependency["id"]].fn
        code = getattr(wrapper, "__code__", None)
        if code is None or code.co_name != "wrapper" or "n_outputs" not in code.co_freevars:
            continue
        cells = dict(zip(
            code.co_freevars, (cell.cell_contents for cell in wrapper.__closure__), strict=True,
        ))
        outputs = len(dependency["outputs"])
        name = getattr(cells["fn"], "__name__", "?")
        assert cells["n_outputs"] == outputs or cells["n_outputs"] <= 1 >= outputs, (name, outputs)
        checked.append(name)
    assert {"set_role", "delete_user", "create_user"} <= set(checked)


def test_refused_admin_action_keeps_the_admin_panel_usable(runtime_demo, monkeypatch):
    from src.app import gradio_ui

    def refuse(*args, **kwargs):
        raise gr.Error("Admin không thể tự khóa chính mình.")

    monkeypatch.setattr(gradio_ui, "_api", refuse)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    for label, args in (("Khóa", ("token", "self")), ("Mở khóa", ("token", "self")),
                        ("Đổi vai trò", ("token", "self", "user")), ("Xóa tài khoản", ("token", "self")),
                        ("Tạo", ("token", "taken", "Long-enough-password-1", "user"))):
        callback, dependency = _button_event(runtime_demo, label)
        result = callback.fn(*args)
        assert len(result) == len(dependency["outputs"]), label
        assert all(value == gr.skip() for value in result), label


def test_validation_errors_reach_the_user_in_vietnamese(monkeypatch):
    import httpx

    from src.app import gradio_ui

    items = [
        {"type": "string_too_short", "loc": ["body", "username"], "msg": "String should have at least 3 characters"},
        {"type": "string_too_long", "loc": ["body", "title"], "msg": "String should have at most 120 characters"},
        {"type": "missing", "loc": ["body", "password"], "msg": "Field required"},
        {"type": "value_error", "loc": ["body", "data_classification"],
         "msg": "Value error, Dữ liệu nhạy cảm phải dùng chế độ confidential."},
        {"type": "literal_error", "loc": ["body", "role"], "msg": "Input should be 'user' or 'admin'"},
    ]
    expected = ("Tên đăng nhập phải có ít nhất 3 ký tự. Tiêu đề chỉ được tối đa 120 ký tự. Thiếu mật khẩu. "
                "Dữ liệu nhạy cảm phải dùng chế độ confidential. Vai trò không hợp lệ.")
    assert gradio_ui._validation_text(items) == expected
    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(lambda request: httpx.Response(422, json={"detail": items})), **kwargs))
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    with pytest.raises(gr.Error) as raised:
        gradio_ui._api("token", "POST", "/api/admin/users", {"username": "ab"})
    assert gradio_ui._error_text(raised.value) == expected


def test_admin_create_form_checks_lengths_before_calling_the_api(runtime_demo, monkeypatch):
    from src.app import gradio_ui

    calls, warnings = [], []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args, **kwargs: calls.append(args) or {})
    monkeypatch.setattr(gr, "Warning", lambda message, *args, **kwargs: warnings.append(message))
    callback, dependency = _button_event(runtime_demo, "Tạo")
    for username, password, expected in (("ab", "Long-enough-password-1", "Tên đăng nhập"),
                                         ("qa.admin", "short", "Mật khẩu")):
        result = callback.fn("token", username, password, "user")
        assert len(result) == len(dependency["outputs"]) and all(value == gr.skip() for value in result)
        assert warnings[-1].startswith(expected)
    assert calls == []


def test_moderator_security_refresh_marks_the_admin_only_blocklist_without_a_warning(
    runtime_demo, monkeypatch,
):
    from src.app import gradio_ui

    def api(token, method, path, body=None, **kwargs):
        if path in ("/api/admin/ids/blocklist", "/api/admin/ids/verify-detection", "/api/admin/audit/verify"):
            error = gr.Error("Không đủ quyền truy cập.")
            error.status_code = 403
            raise error
        return []

    warnings = []
    monkeypatch.setattr(gradio_ui, "_api", api)
    monkeypatch.setattr(gr, "Warning", lambda message, *args, **kwargs: warnings.append(message))
    callback, dependency = _button_event(runtime_demo, "Làm mới toàn bộ")
    result = callback.fn("moderator-token", 60)
    assert warnings == []
    assert "Cần vai trò admin" in result[2]
    assert "cần vai trò admin" in result[3], "chain verdict for a moderator"
    blocklist = runtime_demo.blocks[dependency["outputs"][-1]]
    assert result[-1] == gradio_ui._table_html(gradio_ui.BLOCKLIST_HEADERS, [])
    assert blocklist.elem_id == "sec-blocklist-table"

    verify, _ = _button_event(runtime_demo, "Chạy kiểm chứng Hit/Miss")
    verdict = verify.fn("moderator-token")
    assert "cần vai trò admin" in verdict and "'" not in verdict


def test_gradio_does_not_publish_an_api_catalogue_of_the_ui_handlers(runtime_demo):
    from fastapi.testclient import TestClient

    assert {dependency["api_visibility"] for dependency in runtime_demo.config["dependencies"]} == {"private"}
    with TestClient(runtime_demo.app) as client:
        info = client.get("/gradio_api/info").json()
    assert info["named_endpoints"] == {} and info["unnamed_endpoints"] == {}


def test_countdown_markup_is_numeric_only():
    from src.app import gradio_ui

    assert "1:02:05" in gradio_ui._countdown_markup(3725)
    assert "⏳" in gradio_ui._countdown_markup(121)
    assert "⚠️" in gradio_ui._countdown_markup(120)
    assert 'data-scap-countdown="0"' in gradio_ui._countdown_markup(-5)


def test_tables_render_untrusted_values_as_inert_text():
    from src.app import gradio_ui

    markup = gradio_ui._table_html(
        ("Tên", "Nội dung"),
        [['<img src=x onerror=alert(1)>', "a\n\n# heading $$x$$"], [None, "‮evil"]],
    )
    assert "<img" not in markup and "&lt;img src=x onerror=alert(1)&gt;" in markup
    # A blank line would end the HTML block and let Markdown interpret the rest.
    assert "\n" not in markup and "a # heading $$x$$" in markup
    assert "‮" not in markup and "\\u202E" in markup
    empty = gradio_ui._table_html(("A", "B"), [])
    assert 'colspan="2"' in empty and "scap-table-empty" in empty


def test_read_only_tables_do_not_use_the_slow_dataframe(runtime_demo):
    assert not any(isinstance(component, gr.Dataframe) for component in runtime_demo.blocks.values())
    tables = [component for component in runtime_demo.blocks.values() if _is_table(component)]
    assert len(tables) == 10
    assert all(table.latex_delimiters == [] for table in tables)


def test_logout_still_clears_local_state_when_server_cannot_confirm(runtime_demo, monkeypatch):
    from src.app import gradio_ui

    def unavailable(*args):
        raise gr.Error("server unavailable")

    monkeypatch.setattr(gradio_ui, "_api", unavailable)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    callback, dependency = _button_event(runtime_demo, "Đăng xuất")
    result = callback.fn("previous-token")
    assert len(result) == len(dependency["outputs"])
    assert result[0] == ""
    search_table = next(component for component in runtime_demo.blocks.values()
                        if component.elem_id == "global-search-table")
    assert result[dependency["outputs"].index(search_table._id)] == search_table.value


def test_load_workspace_returns_one_value_per_stage2_component():
    body = _build_ui_body()
    stage2 = len(_find_list_assign(body, "STAGE2").elts)
    got = _final_return_len(_find_func(body, "load_workspace"))
    assert got == stage2, f"load_workspace trả {got} giá trị nhưng STAGE2 có {stage2} component"


def test_security_tab_is_registered_in_stage2():
    """Tab Bảo mật phải được bật/tắt theo vai trò, nên bắt buộc có trong STAGE2."""
    body = _build_ui_body()
    names = [e.id for e in _find_list_assign(body, "STAGE2").elts if isinstance(e, ast.Name)]
    assert "sec_tab" in names
    assert "adm_tab" in names and "mod_tab" in names


def test_assistant_avatar_asset_is_shipped():
    """Avatar được tham chiếu bằng đường dẫn tệp — tệp đó phải tồn tại."""
    asset = UI_SOURCE.parent / "ui_assets" / "assistant.png"
    assert asset.is_file(), "Thiếu src/app/ui_assets/assistant.png"
    assert asset.stat().st_size > 200


def test_assistant_avatar_is_static_so_the_cache_sweep_cannot_break_it(runtime_demo):
    """delete_cache=(60, 60) removed the cached avatar a minute after start-up and
    every later chat reply showed a broken image (403 "File not allowed")."""
    from src.app.gradio_ui import _ASSISTANT_AVATAR

    chatbot = next(component for component in runtime_demo.blocks.values()
                   if isinstance(component, gr.Chatbot))
    served = chatbot.avatar_images[1]["path"]
    assert Path(served).resolve() == _ASSISTANT_AVATAR.resolve()


def test_session_labels_carry_the_lock_marker():
    source = UI_SOURCE.read_text(encoding="utf-8")
    assert "🔒" in source, "Nhãn phiên hội thoại cần ổ khoá nhắc trạng thái mã hoá"


def test_workspace_keeps_one_full_width_responsive_shell():
    """Mọi tab phải dùng chung shell rộng và header không được tràn viewport."""
    from src.app.gradio_ui import build_ui

    source = UI_SOURCE.read_text(encoding="utf-8")
    demo = build_ui()

    assert demo.fill_width is True
    assert "fill_width=True" in source
    assert "--scap-shell" not in source
    assert 'elem_id="app-sec"' in source
    assert 'elem_id="workspace-tabs"' in source
    assert 'grid-template-areas: "brand user timer extend logout"' in source
    assert '"brand timer"' in source
    assert '"extend logout"' in source
    assert 'elem_classes=["topbar-action", "topbar-extend"]' in source
    assert 'elem_classes=["topbar-action", "topbar-logout"]' in source
    # Audit IDs/IPs stay on one line; the table scrolls horizontally instead.
    audit_table = next(component for component in demo.blocks.values()
                       if component.elem_id == "audit-table")
    assert "scap-table-nowrap" in audit_table.elem_classes
    assert ".scap-table-nowrap .scap-table td { white-space: nowrap;" in source


def test_chat_history_uses_viewport_bounded_height():
    """Lịch sử chat dùng chiều cao giới hạn theo viewport và tự cuộn."""
    from src.app.gradio_ui import CHAT_HISTORY_HEIGHT, build_ui

    demo = build_ui()
    chatbots = [
        component for component in demo.blocks.values() if isinstance(component, gr.Chatbot)
    ]

    assert len(chatbots) == 1
    assert CHAT_HISTORY_HEIGHT == "clamp(320px, calc(100dvh - 360px), 480px)"
    assert chatbots[0].height == CHAT_HISTORY_HEIGHT
    assert chatbots[0].autoscroll is True


def test_audit_table_refreshes_when_the_row_limit_changes():
    """Đổi thanh hoặc ô số Số dòng phải tải lại dữ liệu audit."""
    from src.app.gradio_ui import build_ui

    demo = build_ui()
    sliders = [
        component
        for component in demo.blocks.values()
        if isinstance(component, gr.Slider) and component.label == "Số dòng"
    ]
    audit_tables = [
        component
        for component in demo.blocks.values()
        if component.elem_id == "audit-table"
    ]

    assert len(sliders) == 1
    assert len(audit_tables) == 1
    assert any(
        (sliders[0]._id, "change") in dependency["targets"]
        and sliders[0]._id in dependency["inputs"]
        and audit_tables[0]._id in dependency["outputs"]
        for dependency in demo.config["dependencies"]
    )


def test_dashboard_uses_metric_cards_for_report_ready_security_overview():
    """Khoá lại bố cục KPI của tab Quản trị/Bảo mật để refactor không làm mất dashboard."""
    source = UI_SOURCE.read_text(encoding="utf-8")
    assert "metric-card" in source
    assert "Trung tâm vận hành &amp; bảo mật" in source
    assert "Trung tâm giám sát an ninh" in source


def test_ai_consent_notice_is_inline_and_can_retry_the_composer():
    """Consent là lựa chọn riêng tư, không được thành toast che hội thoại."""
    source = UI_SOURCE.read_text(encoding="utf-8")
    assert "md_chat_notice = gr.Markdown" in source
    assert "btn_consent_send = gr.Button(" in source
    assert '"Đồng ý và gửi"' in source
    assert "EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE in str(err)" in source
    assert "Bấm **Đồng ý và gửi** bên dưới" in source
    assert "def consent_and_resend(token, session_id, message):" in source
    assert '"/api/auth/ai-consent", {"ai_data_consent": True}' in source
    assert 'gr.Warning("Đã che dữ liệu nhạy cảm' not in source


def test_send_button_and_enter_share_one_pending_event(runtime_demo):
    """Mobile can emit submit and click before its previous send has completed."""
    click, dependency = _button_event(runtime_demo, "Gửi")
    composer = runtime_demo.blocks[dependency["inputs"][-1]]
    submit, submit_dependency = _event_for(runtime_demo, composer, "submit")
    assert submit is click
    assert submit_dependency is dependency
    assert dependency["trigger_mode"] == "once"


@pytest.mark.parametrize("first_session", [None, "existing"])
def test_failed_send_keeps_composer_and_displays_persistent_error(
    runtime_demo, monkeypatch, first_session,
):
    from src.app import gradio_ui

    calls = []

    def api(token, method, path, body=None, **kwargs):
        calls.append((method, path))
        if (method, path) == ("POST", "/api/sessions"):
            return {"id": "new", "title": body["title"]}
        if method == "POST" and path.endswith("/messages"):
            raise gr.Error("AI tạm thời không khả dụng. Thử lại sau 30 giây.")
        if path == "/api/sessions":
            return [{"id": "new", "title": "Cuộc hội thoại mới", "security_mode": "secure"}]
        if path.endswith("/messages"):
            return []
        return {"id": path.rsplit("/", 1)[-1], "security_mode": "secure"}

    monkeypatch.setattr(gradio_ui, "_api", api)
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    callback, _ = _button_event(runtime_demo, "Gửi")
    result = callback.fn("token", first_session, "câu hỏi vẫn còn trong ô nhập")
    assert result[3] == gr.skip(), "A refused send must not clear typed text"
    assert result[4]["visible"] is True
    assert "AI tạm thời không khả dụng" in result[4]["value"]
    assert result[5] == gr.update(visible=False)
    if first_session is None:
        assert result[0]["value"] == result[1]["value"] == "new"
        callback.fn("token", result[0]["value"], "câu hỏi vẫn còn trong ô nhập")
        assert calls.count(("POST", "/api/sessions")) == 1
    else:
        assert result[:3] == (gr.skip(),) * 3


def test_successful_send_with_failed_history_read_does_not_invite_duplicate_retry(
    runtime_demo, monkeypatch,
):
    from src.app import gradio_ui

    def api(token, method, path, body=None, **kwargs):
        if method == "POST":
            return {"content": "trả lời", "dlp_redacted": []}
        if path == "/api/sessions":
            raise gr.Error("Máy chủ tạm thời bận.")
        return {"security_mode": "secure"}

    monkeypatch.setattr(gradio_ui, "_api", api)
    callback, _ = _button_event(runtime_demo, "Gửi")
    result = callback.fn("token", "existing", "đã được lưu")
    assert result[3] == ""
    assert result[4]["visible"] is True
    assert "Tin nhắn đã gửi" in result[4]["value"]
    assert "Xem tất cả" in result[4]["value"]


@pytest.mark.parametrize("failure", ["timeout", "protocol"])
def test_api_transport_errors_are_safe_user_notices(monkeypatch, failure):
    import httpx

    from src.app import gradio_ui

    def failed_transport(request):
        kind = httpx.ReadTimeout if failure == "timeout" else httpx.RemoteProtocolError
        raise kind("private upstream detail and secret credential", request=request)

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(
        transport=httpx.MockTransport(failed_transport), **kwargs,
    ))
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    with pytest.raises(gr.Error) as raised:
        gradio_ui._api("token", "POST", "/api/sessions/existing/messages", {"content": "hello"})
    message = gradio_ui._error_text(raised.value)
    assert "chưa xác nhận được" in message
    assert "lịch sử hội thoại" in message
    assert "secret" not in message and "private upstream" not in message


def test_export_is_a_same_origin_link_the_browser_redeems(runtime_demo, monkeypatch):
    """Gradio 6 copies a DownloadButton URL into its cache through an SSRF-checked
    server-side download: on the VPS that spent the one-use ticket and stored the
    plaintext export; locally the check failed and the button never appeared."""
    from src.app import gradio_ui

    source = UI_SOURCE.read_text(encoding="utf-8")
    assert "file_export = gr.DownloadButton(" not in source
    assert "file_export = gr.File(" not in source
    ticket = 'eyJhbGciOi.eyJzdWIi.sig"><script>'
    monkeypatch.setattr(gradio_ui, "_api", lambda *args: {"download_url": f"/api/exports/{ticket}"})
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    callback, dependency = _button_event(runtime_demo, "Xuất JSON")
    link_update, *_ = callback.fn("token", "session-id", "", "")
    markup = link_update["value"]
    assert link_update["visible"] is True
    assert 'href="/api/exports/eyJhbGciOi.eyJzdWIi.sig&quot;&gt;&lt;script&gt;"' in markup
    assert " download " in markup and "<script>" not in markup
    assert not markup.split('href="', 1)[1].startswith("http")


def test_totp_qr_is_inline_and_has_no_file_toolbar():
    """2FA QR must stay in page memory, without a downloadable cache file."""
    import base64

    from src.app.gradio_ui import QR_DISPLAY_PX, _totp_qr_markup, build_ui
    from src.app.security import TotpService

    uri = TotpService().provisioning_uri("A" * 32, "demo.boss", "SCAP")
    markup = _totp_qr_markup(uri, QR_DISPLAY_PX)
    encoded = markup.split("data:image/png;base64,", 1)[1].split('"', 1)[0]
    assert base64.b64decode(encoded).startswith(b"\x89PNG\r\n\x1a\n")
    assert "gradio_cache" not in markup
    assert "download" not in markup.lower()

    demo = build_ui()
    qr_panels = [
        component
        for component in demo.blocks.values()
        if isinstance(component, gr.Markdown)
        and component.label == "Quét bằng ứng dụng xác thực"
    ]
    assert len(qr_panels) == 1
    assert qr_panels[0].buttons == []
    assert not any(isinstance(component, gr.HTML) for component in demo.blocks.values()), (
        "Gradio HTML uses eval and cannot render under the enforced script policy"
    )
    assert not any(
        isinstance(component, gr.Image)
        and component.label == "Quét bằng ứng dụng xác thực"
        for component in demo.blocks.values()
    ), "QR không được quay lại gr.Image (sẽ tạo tệp cache)"
