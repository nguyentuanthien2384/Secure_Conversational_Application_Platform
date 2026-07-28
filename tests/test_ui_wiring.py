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
