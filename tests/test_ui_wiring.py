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


@pytest.mark.parametrize("reason", ["logout", "logout_all", "password_change", "expiry"])
def test_session_end_handlers_clear_previous_account_data(runtime_demo, monkeypatch, reason):
    """Run the registered callbacks, including wrappers and actual output wiring."""
    from src.app import gradio_ui

    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *args: calls.append(args) or {})
    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)
    logout, logout_dependency = _button_event(runtime_demo, "Đăng xuất")
    if reason == "expiry":
        timer = next(component for component in runtime_demo.blocks.values()
                     if isinstance(component, gr.Timer))
        callback, dependency = _event_for(runtime_demo, timer, "tick")
        result = callback.fn(999, True)
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
        if isinstance(component, (gr.Textbox, gr.Dataframe, gr.Chatbot, gr.DownloadButton)):
            assert component._id in updates, f"Reset omitted {component.label}"
            update = updates[component._id]
            value = update.get("value", "previous-account-data") if isinstance(update, dict) else update
            if isinstance(component, gr.DownloadButton):
                assert value is None and update["visible"] is False
            elif isinstance(component, (gr.Dataframe, gr.Chatbot)):
                assert value == []
            else:
                assert value == "", f"Retained text in {component.label}"

    notice = next(component for component in runtime_demo.blocks.values()
                  if component.elem_id == "chat-notice")
    assert updates[notice._id] == gr.update(value="", visible=False)
    qr = next(component for component in runtime_demo.blocks.values()
              if isinstance(component, gr.Markdown) and component.label == "Quét bằng ứng dụng xác thực")
    assert updates[qr._id] == gr.update(value="", visible=False)
    mfa_activation, _ = _button_event(runtime_demo, "Kích hoạt")
    recovery = mfa_activation.outputs[5]
    assert updates[recovery._id] == gr.update(value="", visible=False)
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


def test_live_countdown_preserves_work_and_only_updates_final_two_outputs(runtime_demo, monkeypatch):
    from src.app import gradio_ui

    monkeypatch.setattr(gradio_ui.time, "time", lambda: 1000)
    timer = next(component for component in runtime_demo.blocks.values()
                 if isinstance(component, gr.Timer))
    callback, dependency = _event_for(runtime_demo, timer, "tick")
    result = callback.fn(1600, False)
    assert len(result) == len(dependency["outputs"])
    assert all(value == gr.skip() for value in result[:-2])
    assert "10:00" in result[-2]
    assert result[-1] is False


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
                        if isinstance(component, gr.Dataframe)
                        and component.headers == ["Hội thoại", "Vai trò", "Nội dung", "Thời điểm"])
    assert result[dependency["outputs"].index(search_table._id)] == []


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
    assert "wrap=False" in source


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
        if isinstance(component, gr.Dataframe)
        and component.headers == ["#", "Sự kiện", "Kết quả", "Actor", "Đối tượng", "IP", "Thời điểm"]
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


def test_export_download_button_never_caches_the_plaintext_response(monkeypatch):
    """The browser must redeem the stream ticket; Gradio must not prefetch it."""
    source = UI_SOURCE.read_text(encoding="utf-8")
    assert "file_export = gr.DownloadButton(" in source
    assert "file_export = gr.File(" not in source

    def reject_server_side_fetch(*args, **kwargs):
        raise AssertionError("Gradio attempted to copy the export into its cache")

    monkeypatch.setattr(
        "gradio.processing_utils.save_url_to_cache",
        reject_server_side_fetch,
    )
    button = gr.DownloadButton()
    capability = "https://chat.example.test/api/exports/one-use-capability"
    rendered = button.postprocess(capability)
    assert rendered is not None
    assert rendered.path == capability


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
