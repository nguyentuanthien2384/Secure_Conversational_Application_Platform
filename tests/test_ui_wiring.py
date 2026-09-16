"""Kiểm thử đấu nối giao diện Gradio (bổ sung v2.2).

Gradio nối input/output theo **thứ tự vị trí**. Thêm một component vào ``STAGE2``
mà quên cập nhật ``load_workspace`` hoặc ``_reset_tuple`` sẽ làm mọi output lệch
một ô — giao diện hỏng theo kiểu rất khó lần ra. Các test dưới đây khoá lại bất
biến đó bằng cách phân tích cú pháp chính mã nguồn, nên không cần khởi động
server.
"""

from __future__ import annotations

import ast
from pathlib import Path

import gradio as gr

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


def test_stage_lists_and_reset_tuple_have_matching_arity():
    body = _build_ui_body()
    stage1 = len(_find_list_assign(body, "STAGE1").elts)
    stage2 = len(_find_list_assign(body, "STAGE2").elts)
    reset_len = _final_return_len(_find_func(body, "_reset_tuple"))
    # RESET_OUTS = STAGE1 + STAGE2 + [md_countdown, st_warned]
    assert reset_len == stage1 + stage2 + 2, (
        f"_reset_tuple trả {reset_len} giá trị nhưng RESET_OUTS cần "
        f"{stage1 + stage2 + 2} (STAGE1={stage1}, STAGE2={stage2}, +countdown/warned)"
    )


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
