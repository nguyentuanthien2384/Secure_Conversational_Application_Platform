"""Permanent conversation deletion through the registered Gradio callbacks.

These tests use an isolated fake API: no production sessions are read or deleted.
They exercise the click wiring, frozen confirmation target, and actual output
updates rather than only checking button labels or source code.
"""

from __future__ import annotations

import gradio as gr
import pytest

from src.app import gradio_ui


@pytest.fixture(scope="module")
def delete_demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def quiet_notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *_args, **_kwargs: None)


def _button_event(demo, label):
    button = next(component for component in demo.blocks.values()
                  if isinstance(component, gr.Button) and component.value == label)
    dependency = next(item for item in demo.config["dependencies"]
                      if (button._id, "click") in item["targets"])
    return demo.fns[dependency["id"]], dependency


def _mapped(demo, dependency, result):
    assert len(result) == len(dependency["outputs"])
    return {demo.blocks[component_id].elem_id or getattr(demo.blocks[component_id], "label", None) or component_id: value
            for component_id, value in zip(dependency["outputs"], result, strict=True)}


class _SessionApi:
    def __init__(self, *, failing_delete=False, require_step_up=False,
                 failing_step_up=False, failing_refresh=False):
        self.sessions = [
            {"id": "first", "title": "<img src=x onerror=alert(1)> **secret**",
             "security_mode": "secure", "data_classification": "internal"},
            {"id": "second", "title": "Hội thoại còn lại", "security_mode": "secure",
             "data_classification": "internal"},
        ]
        self.calls = []
        self.failing_delete = failing_delete
        self.require_step_up = require_step_up
        self.failing_step_up = failing_step_up
        self.failing_refresh = failing_refresh
        self.reauthenticated = False

    def __call__(self, _token, method, path, body=None, **_kwargs):
        self.calls.append((method, path, body))
        if method == "POST" and path == "/api/auth/step-up":
            if self.failing_step_up:
                raise gr.Error("Không xác thực được yêu cầu.")
            self.reauthenticated = True
            return {}
        if method == "GET" and path == "/api/sessions/page":
            if self.failing_refresh and self.deletes:
                raise gr.Error("Không tải lại được danh sách hội thoại.")
            return {"items": self.sessions, "total": len(self.sessions), "offset": 0,
                    "limit": 100, "has_more": False, "next_offset": None}
        if method == "GET" and path.endswith("/messages"):
            return [{"role": "assistant", "content": "Nội dung hội thoại còn lại"}]
        if method == "GET" and path.startswith("/api/sessions/"):
            session_id = path.rsplit("/", 1)[-1]
            return next(item for item in self.sessions if item["id"] == session_id)
        if method == "DELETE" and path.startswith("/api/sessions/"):
            if self.failing_delete:
                raise gr.Error("Máy chủ tạm thời chưa xóa được hội thoại. <img src=x onerror=alert(1)>")
            if self.require_step_up and not self.reauthenticated:
                raise gr.Error("Cần xác thực lại trước khi xóa hội thoại.")
            session_id = path.rsplit("/", 1)[-1]
            self.sessions = [item for item in self.sessions if item["id"] != session_id]
            return {}
        if method == "POST" and path == "/api/sessions":
            created = {"id": "new", "title": body["title"], "security_mode": "secure",
                       "data_classification": "internal"}
            self.sessions.insert(0, created)
            return created
        if method == "POST" and path == "/api/auth/logout":
            return {}
        raise AssertionError((method, path, body))

    @property
    def deletes(self):
        return [path for method, path, _body in self.calls if method == "DELETE"]


def _assert_confirmation_cleared(mapped):
    assert mapped["session-delete-confirm"] == gr.update(visible=False)
    assert mapped["session-delete-notice"] == ""
    assert mapped["session-delete-auth"] == gr.update(visible=False)
    assert mapped["session-delete-password"] == ""
    assert mapped["session-delete-code"] == ""


def _assert_deleted_views_cleared(demo, mapped):
    assert mapped["export-link"] == gr.update(value="", visible=False)
    assert mapped["Tin nhắn"] == ""
    for elem_id in ("cipher-table", "global-search-table"):
        component = next(item for item in demo.blocks.values() if item.elem_id == elem_id)
        assert mapped[elem_id] == component.value
        assert "scap-table-empty" in mapped[elem_id]


def _confirmation_state_id(demo):
    _request, dependency = _button_event(demo, "Xóa vĩnh viễn")
    component_id = dependency["outputs"][0]
    assert isinstance(demo.blocks[component_id], gr.State)
    return component_id


def _layout_path(tree, component_id):
    if tree.get("id") == component_id:
        return [component_id]
    for child in tree.get("children", []):
        path = _layout_path(child, component_id)
        if path:
            return [tree["id"], *path]
    return []


def test_permanent_delete_control_is_visible_outside_collapsed_accordions(delete_demo):
    button = next(item for item in delete_demo.blocks.values()
                  if item.elem_id == "btn-session-delete")
    path = _layout_path(delete_demo.config["layout"], button._id)
    assert path
    assert button.value == "Xóa vĩnh viễn" and button.visible is True
    assert not any(isinstance(delete_demo.blocks.get(item), gr.Accordion) for item in path)
    panel = next(item for item in delete_demo.blocks.values()
                 if item.elem_id == "session-delete-confirm")
    assert panel.visible is False


def test_request_freezes_owned_target_and_escapes_title_without_deleting(delete_demo, monkeypatch):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    request, dependency = _button_event(delete_demo, "Xóa vĩnh viễn")
    result = request.fn("token", "first")
    assert api.calls == [("GET", "/api/sessions/first", None)]
    assert result[0] == "first" and not api.deletes
    mapped = _mapped(delete_demo, dependency, result)
    assert mapped["session-delete-confirm"] == gr.update(visible=True)
    notice = mapped["session-delete-notice"]
    assert "&lt;img" in notice and "<img" not in notice
    assert "\\*\\*secret\\*\\*" in notice
    assert "không thể hoàn tác" in notice
    assert mapped["session-delete-auth"] == gr.update(visible=False)
    assert mapped["session-delete-password"] == mapped["session-delete-code"] == ""


def test_request_without_selection_clears_confirmation_without_api_calls(delete_demo, monkeypatch):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    request, dependency = _button_event(delete_demo, "Xóa vĩnh viễn")
    result = request.fn("token", None)
    assert not api.calls
    assert result[0] == ""
    _assert_confirmation_cleared(_mapped(delete_demo, dependency, result))


def test_cancel_clears_frozen_target_and_credentials_without_any_request(delete_demo, monkeypatch):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    cancel, dependency = _button_event(delete_demo, "Hủy xóa")
    result = cancel.fn()
    assert not api.calls and result[0] == ""
    _assert_confirmation_cleared(_mapped(delete_demo, dependency, result))


@pytest.mark.parametrize("selected, pending", [
    ("second", "first"), ("first", "second"), (None, "first"), ("first", ""), (None, ""),
])
def test_stale_or_missing_confirmation_never_deletes_either_session(
    delete_demo, monkeypatch, selected, pending,
):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    result = confirm.fn("token", selected, pending, "entered password", "123456")
    assert not api.calls
    assert [item["id"] for item in api.sessions] == ["first", "second"]
    assert result[5] == ""
    _assert_confirmation_cleared(_mapped(delete_demo, dependency, result))


def test_confirm_deletes_only_frozen_session_and_refreshes_selection_and_sensitive_ui(
    delete_demo, monkeypatch,
):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    assert len(confirm.inputs) == 5 and dependency["trigger_mode"] == "once"
    result = confirm.fn("token", "first", "first")
    assert api.deletes == ["/api/sessions/first"]
    assert [item["id"] for item in api.sessions] == ["second"]
    assert result[0]["value"] == result[1]["value"] == "second"
    assert all(value != "first" for _title, value in result[0]["choices"])
    assert result[2] == [{
        "role": "assistant", "content": gradio_ui._safe_chat_text("Nội dung hội thoại còn lại"),
    }]
    mapped = _mapped(delete_demo, dependency, result)
    assert mapped["Đổi tên"] == "Hội thoại còn lại"
    _assert_deleted_views_cleared(delete_demo, mapped)
    assert result[5] == ""
    _assert_confirmation_cleared(mapped)


def test_failed_delete_keeps_confirmation_and_text_but_clears_credentials(delete_demo, monkeypatch):
    api = _SessionApi(failing_delete=True)
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    result = confirm.fn("token", "first", "first", "entered password", "123456")
    assert api.deletes == ["/api/sessions/first"]
    assert [item["id"] for item in api.sessions] == ["first", "second"]
    assert all(value == gr.skip() for value in result[:5])
    mapped = _mapped(delete_demo, dependency, result)
    assert result[5] == "first"
    assert mapped["session-delete-confirm"] == gr.update(visible=True)
    assert "Chưa xóa được" in mapped["session-delete-notice"]
    assert "&lt;img" in mapped["session-delete-notice"] and "<img" not in mapped["session-delete-notice"]
    assert mapped["session-delete-password"] == mapped["session-delete-code"] == ""
    assert mapped["export-link"] == mapped["Tin nhắn"] == gr.skip()
    assert mapped["cipher-table"] == mapped["global-search-table"] == gr.skip()


def test_step_up_is_requested_only_when_server_requires_it_and_retries_same_target(
    delete_demo, monkeypatch,
):
    api = _SessionApi(require_step_up=True)
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    first = confirm.fn("token", "first", "first")
    mapped = _mapped(delete_demo, dependency, first)
    assert first[5] == "first"
    assert mapped["session-delete-auth"] == gr.update(visible=True)
    assert "Cần xác thực lại" in mapped["session-delete-notice"]
    assert not any(path == "/api/auth/step-up" for _method, path, _body in api.calls)
    result = confirm.fn("token", "first", "first", "local-test-password", " 123456 ")
    step_up = [(index, body) for index, (method, path, body) in enumerate(api.calls)
               if method == "POST" and path == "/api/auth/step-up"]
    assert len(step_up) == 1
    assert step_up[0][1] == {"password": "local-test-password", "code": "123456"}
    assert api.calls[step_up[0][0] + 1][:2] == ("DELETE", "/api/sessions/first")
    assert set(api.deletes) == {"/api/sessions/first"}
    _assert_confirmation_cleared(_mapped(delete_demo, dependency, result))


def test_unmarked_http_failure_mentioning_reauthentication_never_replays_the_delete(
    delete_demo, monkeypatch,
):
    """Only the server's X-Step-Up-Required flag may trigger step-up and a retry."""
    api = _SessionApi()

    def unavailable(token, method, path, body=None, **kwargs):
        if method == "DELETE":
            api.calls.append((method, path, body))
            error = gr.Error("Không thể xác thực lại lúc này; máy chủ đang quá tải.")
            error.status_code, error.step_up_required = 503, False
            raise error
        return api(token, method, path, body, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", unavailable)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    result = confirm.fn("token", "first", "first", "entered password", "123456")
    assert api.deletes == ["/api/sessions/first"], "the unknown-outcome DELETE is not repeated"
    assert not any(path == "/api/auth/step-up" for _method, path, _body in api.calls)
    mapped = _mapped(delete_demo, dependency, result)
    assert "Chưa xóa được" in mapped["session-delete-notice"]
    assert mapped["session-delete-password"] == mapped["session-delete-code"] == ""


def test_failed_reauthentication_preserves_target_and_clears_password_and_code(delete_demo, monkeypatch):
    api = _SessionApi(require_step_up=True, failing_step_up=True)
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    result = confirm.fn("token", "first", "first", "wrong-test-password", "123456")
    mapped = _mapped(delete_demo, dependency, result)
    assert result[5] == "first"
    assert mapped["session-delete-confirm"] == gr.update(visible=True)
    assert "Chưa xóa được" in mapped["session-delete-notice"]
    assert mapped["session-delete-password"] == mapped["session-delete-code"] == ""
    assert [item["id"] for item in api.sessions] == ["first", "second"]


def test_successful_delete_followed_by_failed_refresh_never_leaves_deleted_content_selected(
    delete_demo, monkeypatch,
):
    api = _SessionApi(failing_refresh=True)
    monkeypatch.setattr(gradio_ui, "_api", api)
    confirm, dependency = _button_event(delete_demo, "Xác nhận xóa vĩnh viễn")
    result = confirm.fn("token", "first", "first")
    mapped = _mapped(delete_demo, dependency, result)
    assert api.deletes == ["/api/sessions/first"]
    assert result[0] == result[1] == gr.update(choices=[], value=None)
    assert result[2] == [] and mapped["Đổi tên"] == ""
    assert mapped["chat-notice"]["visible"] is True
    assert "Đã xóa hội thoại" in mapped["chat-notice"]["value"]
    assert "Chưa xóa" not in mapped["chat-notice"]["value"]
    _assert_deleted_views_cleared(delete_demo, mapped)
    _assert_confirmation_cleared(mapped)


@pytest.mark.parametrize("action", ["pick", "create", "refresh"])
def test_navigation_invalidates_pending_delete_immediately_even_if_loading_fails(
    delete_demo, monkeypatch, action,
):
    def unavailable(*_args, **_kwargs):
        raise AssertionError("The immediate confirmation reset must not call the API")

    monkeypatch.setattr(gradio_ui, "_api", unavailable)
    target = next(component for component in delete_demo.blocks.values() if (
        component.elem_id == "session-list" if action == "pick" else
        isinstance(component, gr.Button) and component.value == {
            "create": "+ Hội thoại mới", "refresh": "Làm mới",
        }[action]
    ))
    state_id = _confirmation_state_id(delete_demo)
    dependency = next(item for item in delete_demo.config["dependencies"]
                      if (target._id, "input" if action == "pick" else "click") in item["targets"]
                      and state_id in item["outputs"])
    assert dependency["queue"] is False
    result = delete_demo.fns[dependency["id"]].fn()
    assert result[0] == ""
    _assert_confirmation_cleared(_mapped(delete_demo, dependency, result))


def test_logout_clears_pending_delete_confirmation_and_credentials(delete_demo, monkeypatch):
    api = _SessionApi()
    monkeypatch.setattr(gradio_ui, "_api", api)
    logout, dependency = _button_event(delete_demo, "Đăng xuất")
    result = logout.fn("token")
    mapped = _mapped(delete_demo, dependency, result)
    state_id = _confirmation_state_id(delete_demo)
    assert mapped[state_id] == ""
    assert not api.deletes
    _assert_confirmation_cleared(mapped)
