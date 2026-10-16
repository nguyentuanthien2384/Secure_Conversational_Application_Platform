"""Security dashboards must distinguish unavailable evidence from a clean result."""

from __future__ import annotations

import gradio as gr
import httpx
import pytest

from src.app import gradio_ui


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *a, **k: None)
    monkeypatch.setattr(gr, "Warning", lambda *a, **k: None)


def callback(demo, name):
    return next(item.fn for item in demo.fns.values()
                if item.fn is not None and item.fn.__name__ == name)


def event(demo, label):
    button = next(item for item in demo.blocks.values()
                  if isinstance(item, gr.Button) and item.value == label)
    dep = next(item for item in demo.config["dependencies"]
               if (button._id, "click") in item["targets"])
    return demo.fns[dep["id"]].fn, dep


def error(message="API unavailable", status=503, step_up=False):
    err = gr.Error(message)
    err.status_code = status
    err.step_up_required = step_up
    return err


@pytest.mark.parametrize("extra,expected", [
    ({"checkpoint_intact": False, "checkpoint_reason": "checkpoint_root_mismatch",
      "external_checkpoint_required": True, "high_assurance_intact": False}, "Checkpoint không hợp lệ"),
    ({"checkpoint_intact": False, "checkpoint_present": False,
      "checkpoint_reason": "missing_checkpoint", "external_checkpoint_required": True,
      "high_assurance_intact": False}, "Chưa có checkpoint"),
    ({"checkpoint_intact": True, "external_checkpoint_required": False,
      "high_assurance_intact": False}, "chưa có neo WORM"),
    ({"checkpoint_intact": True, "external_checkpoint_required": True,
      "high_assurance_intact": False, "checkpoint_unanchored_events": 7}, "7"),
    ({}, "Chưa có kết quả checkpoint"),
])
def test_chain_ui_never_hides_checkpoint_limitations(demo, monkeypatch, extra, expected):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: {
        "chain_intact": True, "total_events": 10, "verified_events": 10, **extra,
    })
    result = callback(demo, "verify_chain_ui")("token")
    assert expected in result
    assert "Không có dấu hiệu bản ghi bị sửa, xóa" not in result


def test_chain_ui_checks_checkpoint_even_when_table_is_empty(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: {
        "chain_intact": True, "total_events": 0, "verified_events": 0,
        "checkpoint_intact": False, "checkpoint_reason": "tail_deleted",
    })
    assert "Checkpoint không hợp lệ" in callback(demo, "verify_chain_ui")("token")


def test_chain_ui_full_assurance_is_explicit_and_escapes_api_fields(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: {
        "chain_intact": True, "total_events": 10, "verified_events": 10,
        "checkpoint_intact": True, "high_assurance_intact": True,
        "external_checkpoint_required": True, "checked_by": "![x](https://x.invalid)",
    })
    result = callback(demo, "verify_chain_ui")("token")
    assert "neo WORM" in result and "![x](https://x.invalid)" not in result


def test_chain_ui_requests_new_verification_when_observation_scope_changed(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: {
        "chain_intact": True, "total_events": 10, "verified_events": 10,
        "checkpoint_intact": True, "high_assurance_intact": False,
        "external_checkpoint_required": True, "verification_scope_changed": True,
    })
    result = callback(demo, "verify_chain_ui")("token")
    assert "Nhật ký đã thay đổi trong lúc xác minh" in result
    assert "chạy xác minh lại" in result
    assert "Đủ bằng chứng neo WORM" not in result
    assert "Checkpoint không hợp lệ" not in result


def test_chain_ui_identifies_damaged_historical_checkpoint_without_rendering_markup(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: {
        "chain_intact": True, "total_events": 10, "verified_events": 10,
        "checkpoint_intact": False, "high_assurance_intact": False,
        "checkpoint_reason": "historical_checkpoint_root_mismatch",
        "checkpoint_failed_id": "![checkpoint](https://example.invalid)",
        "checkpoint_failed_event_id": 7,
    })
    result = callback(demo, "verify_chain_ui")("token")
    assert "Checkpoint không hợp lệ" in result and "Checkpoint lỗi:" in result
    assert "Bản ghi được neo: #7" in result
    assert "![checkpoint](https://example.invalid)" not in result
    assert "Đủ bằng chứng neo WORM" not in result


@pytest.mark.parametrize("status", [401, 403, 503])
def test_audit_refresh_error_replaces_previous_rows_with_persistent_diagnostic(demo, monkeypatch, status):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: [{
        "id": 1, "event_type": "OLD AUDIT ROW", "outcome": "success",
        "created_at": "2026-10-15T00:00:00Z",
    }])
    load = callback(demo, "load_audit")
    previous = load("token", 100)
    assert "OLD AUDIT ROW" in previous and "Cập nhật:" in previous

    def unavailable(*args, **kwargs):
        raise error("<script>unavailable</script>", status)

    monkeypatch.setattr(gradio_ui, "_api", unavailable)
    current = load("token", 100)
    assert isinstance(current, str) and "Không tải được nhật ký kiểm toán" in current
    assert "Lần thử:" in current
    assert "OLD AUDIT ROW" not in current and "<script>" not in current


def test_failed_security_requests_stay_unknown_in_cards_and_tables(demo, monkeypatch):
    def unavailable(*a, **k):
        raise error()
    monkeypatch.setattr(gradio_ui, "_api", unavailable)
    result = callback(demo, "refresh_security")("token", 60)
    assert len(result) == 6
    for item in result:
        assert "Không tải được" in item
        assert "## 0" not in item and "Chưa có dữ liệu" not in item


@pytest.mark.parametrize("failed_endpoint", ["stats", "security-alerts", "users"])
def test_admin_refresh_failure_clears_stale_observation_and_account_choice(demo, monkeypatch, failed_endpoint):
    def api(token, method, path, *args, **kwargs):
        if path == f"/api/admin/{failed_endpoint}":
            raise error("<script>unavailable</script>")
        if path.endswith("stats"):
            return {"total_users": 12, "active_users": 10, "total_sessions": 21,
                    "total_messages": 44, "recent_login_failures": 0, "recent_auth_denials": 0}
        return []
    monkeypatch.setattr(gradio_ui, "_api", api)
    result = callback(demo, "refresh_admin")("token", "stale-user")
    assert len(result) == 8
    for item in result[:7]:
        assert "Không tải được" in item and "Lần thử:" in item
        assert "## 0" not in item and "<script>" not in item
    assert result[7]["choices"] == [] and result[7]["value"] is None


def test_security_partial_failure_keeps_successful_data_and_role_boundary(demo, monkeypatch):
    def api(token, method, path, *a, **k):
        if path.endswith("detections"):
            return [{"rule_id": "rule-1"}]
        if path.endswith("blocklist"):
            raise error("Forbidden", 403)
        raise error("<script>alert(1)</script>")
    monkeypatch.setattr(gradio_ui, "_api", api)
    result = callback(demo, "refresh_security")("token", 30)
    assert "## 1" in result[0] and "rule-1" in result[3]
    assert "Không tải được" in result[1] and "Không tải được" in result[4]
    assert "Cần vai trò admin" in result[2] and "Cần vai trò admin" in result[5]
    assert "<script>" not in " ".join(result)


def test_anomaly_actions_update_card_and_table_together(demo, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", lambda *a, **k: [{"code": "anomaly-1"}])
    fn, dep = event(demo, "Phân tích")
    outputs = fn("token", 25)
    assert len(outputs) == len(dep["outputs"]) == 2
    assert "## 1" in outputs[0] and "25 phút" in outputs[0]
    assert "anomaly-1" in outputs[1]
    slider = next(item for item in demo.blocks.values()
                  if isinstance(item, gr.Slider) and item.label == "Cửa sổ thời gian (phút)")
    changed = next(item for item in demo.config["dependencies"]
                   if (slider._id, "change") in item["targets"])
    assert changed["outputs"] == dep["outputs"]


@pytest.mark.parametrize("label,args,path", [
    ("Đổi vai trò", ("u1", "moderator"), "/api/admin/users/u1/role"),
    ("Khóa", ("u1",), "/api/admin/users/u1/status"),
    ("Mở khóa", ("u1",), "/api/admin/users/u1/status"),
    ("Xóa tài khoản", ("u1",), "/api/admin/users/u1"),
    ("Tạo", ("newuser", "A long password value1!", "user"), "/api/admin/users"),
    ("Gỡ chặn", ("192.0.2.1",), "/api/admin/ids/blocklist/192.0.2.1"),
])
def test_admin_mutations_use_step_up_and_clear_credentials(demo, monkeypatch, label, args, path):
    calls, attempts = [], []
    def api(token, method, endpoint, body=None, **kwargs):
        calls.append((method, endpoint, body))
        if endpoint == path and method != "GET":
            attempts.append(endpoint)
            if len(attempts) == 1:
                raise error("Fresh credentials required", 403, True)
            return {}
        if endpoint.endswith("stats"):
            return {"total_users": 0, "active_users": 0, "total_sessions": 0,
                    "total_messages": 0, "recent_login_failures": 0, "recent_auth_denials": 0}
        return []
    monkeypatch.setattr(gradio_ui, "_api", api)
    fn, dep = event(demo, label)
    result = fn("token", *args, "Admin password value1!", "123456")
    assert len(result) == len(dep["outputs"])
    assert len(attempts) == 2
    assert ("POST", "/api/auth/step-up", {
        "password": "Admin password value1!", "code": "123456",
    }) in calls
    cleanup = next(item for item in demo.config["dependencies"]
                   if item["trigger_after"] == dep["id"])
    assert cleanup["trigger_only_on_success"] is False
    cleared = demo.fns[cleanup["id"]].fn()
    assert cleared == tuple("" for _ in cleanup["outputs"])
    if label == "Gỡ chặn":
        assert "## 0" in result[0] and "Chưa có dữ liệu" in result[1]


def test_real_api_step_up_header_is_retained(monkeypatch):
    class Client:
        def post(self, *a, **k):
            return httpx.Response(403, json={"detail": "Fresh credentials required"},
                                  headers={"X-Step-Up-Required": "true"})
    monkeypatch.setattr(gradio_ui, "_api_client", lambda: Client())
    monkeypatch.setattr(gradio_ui, "_SESSION_STORE", None)
    with pytest.raises(gr.Error) as caught:
        gradio_ui._api("token", "POST", "/api/admin/users", {})
    assert caught.value.step_up_required is True


@pytest.mark.parametrize("status", [403, 503])
def test_step_up_never_retries_unmarked_api_failure(monkeypatch, status):
    calls = []
    monkeypatch.setattr(gradio_ui, "_api", lambda *a: calls.append(a))
    def action():
        calls.append("write")
        raise error("Không thể xác thực lại thao tác", status)
    with pytest.raises(gr.Error):
        gradio_ui._with_step_up("token", "secret", "", action, "Tạo")
    assert calls == ["write"]
