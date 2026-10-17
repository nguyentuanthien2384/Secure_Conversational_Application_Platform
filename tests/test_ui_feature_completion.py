"""Exercise paging, local search and irreversible admin actions through UI wiring."""

from __future__ import annotations

import asyncio
import threading
from datetime import timedelta

import gradio as gr
import pytest
from gradio.state_holder import SessionState

from src.app import gradio_ui
from src.app.models import ChatSession, SecureMessage, User, utcnow
from tests.conftest import register_and_login


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def quiet_notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *_args, **_kwargs: None)


def event(demo, label):
    control = next(item for item in demo.blocks.values()
                   if isinstance(item, gr.Button) and item.value == label)
    dependency = next(item for item in demo.config["dependencies"]
                      if (control._id, "click") in item["targets"])
    return demo.fns[dependency["id"]], dependency


def callback(demo, name):
    return next(item for item in demo.fns.values()
                if item.fn is not None and item.fn.__name__ == name)


def page(items, params):
    offset, limit = params.get("offset", 0), params.get("limit", 100)
    selected = items[offset:offset + limit]
    more = offset + len(selected) < len(items)
    return {"items": selected, "total": len(items), "offset": offset, "limit": limit,
            "has_more": more, "next_offset": offset + len(selected) if more else None}


class UiApi:
    def __init__(self):
        self.calls = []
        self.deleted = []
        self.require_step_up = False
        self.reauthenticated = False
        self.fail_delete = False
        self.fail_search = False
        self.users = [
            {"id": f"user-{i}", "username": f"member.{i}", "role": "user", "is_active": True,
             "mfa_enabled": False, "created_at": "2026-10-17T01:00:00Z"}
            for i in range(502)
        ]

    def __call__(self, token, method, path, body=None, *, params=None):
        params = params or {}
        self.calls.append((token, method, path, body, params))
        if path == "/api/admin/users/page":
            return page(self.users, params)
        if path == "/api/admin/stats":
            return {"total_users": len(self.users), "active_users": len(self.users),
                    "total_sessions": 101, "total_messages": 0, "recent_login_failures": 0,
                    "recent_auth_denials": 0}
        if path == "/api/admin/security-alerts":
            return []
        if method == "DELETE" and path.startswith("/api/admin/users/"):
            if self.require_step_up and not self.reauthenticated:
                error = gr.Error("Cần xác thực lại trước khi xóa tài khoản.")
                error.step_up_required = True
                raise error
            if self.fail_delete:
                raise gr.Error("Máy chủ bận <script>private error</script>")
            user_id = path.rsplit("/", 1)[-1]
            self.deleted.append(user_id)
            self.users = [item for item in self.users if item["id"] != user_id]
            return {}
        if path == "/api/auth/step-up":
            self.reauthenticated = True
            return {}
        if path == "/api/auth/logout":
            return {}
        if path == "/api/sessions/page":
            return page([self.session(token, index) for index in range(101)], params)
        if path.endswith("/messages/page") or path == "/api/search/messages/page":
            if self.fail_search:
                raise gr.Error("Không tải được kết quả <script>alert(1)</script>")
            query = params.get("query", params.get("q"))
            rows = [
                {"id": index + 1, "message_id": index + 1, "session_id": f"{token}-chat-0",
                 "session_title": f"{token} title", "role": "user", "content": f"{query} hit {index}",
                 "created_at": "2026-10-17T01:00:00Z"}
                for index in range(123)
            ]
            return page(rows, params)
        if path.endswith("/messages"):
            return []
        if path.startswith("/api/sessions/"):
            index = int(path.rsplit("-", 1)[-1])
            return self.session(token, index)
        raise AssertionError((method, path))

    @staticmethod
    def session(token, index):
        return {"id": f"{token}-chat-{index}", "title": f"{token} conversation {index}",
                "security_mode": "secure", "data_classification": "internal"}


@pytest.fixture()
def api(monkeypatch):
    instance = UiApi()
    monkeypatch.setattr(gradio_ui, "_api", instance)
    return instance


def test_sessions_load_more_reaches_the_101st_conversation(demo, api):
    refresh = callback(demo, "refresh_sessions")
    first = refresh.fn("A")
    assert len(first[0]["choices"]) == 100 and first[3]["has_more"] is True
    assert "100/101" in first[4] and first[5]["visible"] is True
    more, dependency = event(demo, "Tải thêm hội thoại")
    result = more.fn("A", first[0]["value"], first[3])
    assert len(result) == len(dependency["outputs"])
    assert len(result[0]["choices"]) == 101 and result[0]["value"] == first[0]["value"]
    assert result[2] == gr.skip()  # paging must not replace the selected chat
    assert "101/101" in result[4] and result[5]["visible"] is False


def test_session_refresh_preserves_an_owned_selection_outside_the_first_page(demo, api):
    result = callback(demo, "refresh_sessions").fn("A", "A-chat-100")
    assert result[0]["value"] == "A-chat-100"
    assert ("🔒  A conversation 100", "A-chat-100") in result[0]["choices"]


def test_more_sessions_does_not_reuse_the_previous_accounts_page(demo, api):
    first = callback(demo, "refresh_sessions").fn("A")
    more, _ = event(demo, "Tải thêm hội thoại")
    result = more.fn("B", None, first[3])
    assert all(value.startswith("B-") for _label, value in result[0]["choices"])
    assert result[3]["account"] == gradio_ui._token_digest("B")


def test_admin_can_reach_and_select_the_502nd_account(demo, api):
    first = callback(demo, "refresh_admin").fn("A")
    state = first[8]
    more, _ = event(demo, "Tải thêm tài khoản")
    while state["has_more"]:
        result = more.fn("A", None, state)
        state = result[2]
    assert len(state["items"]) == 502 and result[-1]["visible"] is False
    assert ("member.501 (user)", "user-501") in result[1]["choices"]
    request, dependency = event(demo, "Xóa tài khoản")
    confirmation = request.fn("A", "user-501", state)
    assert len(confirmation) == len(dependency["outputs"])
    assert confirmation[0]["id"] == "user-501" and not api.deleted


def test_global_search_reports_total_and_loads_remaining_results(demo, api):
    search, dependency = event(demo, "Tìm kiếm")
    first = search.fn("A", "needle")
    assert len(first) == len(dependency["outputs"])
    assert len(first[1]["items"]) == 50 and first[1]["total"] == 123
    assert "1–50/123" in first[2]["value"] and first[3]["visible"] is True
    more, _ = event(demo, "Tải thêm kết quả")
    second = more.fn("A", "needle", first[1])
    third = more.fn("A", "needle", second[1])
    assert len(third[1]["items"]) == 123
    assert "1–123/123" in third[2]["value"] and third[3]["visible"] is False


@pytest.mark.parametrize("account,query", [("B", "needle"), ("A", "changed")])
def test_load_more_restarts_when_account_or_query_changes(demo, api, account, query):
    search, _ = event(demo, "Tìm kiếm")
    first = search.fn("A", "needle")
    more, _ = event(demo, "Tải thêm kết quả")
    result = more.fn(account, query, first[1])
    assert len(result[1]["items"]) == 50
    assert result[1]["query"] == query
    assert all(item["session_id"].startswith(account + "-") for item in result[1]["items"])
    assert api.calls[-1][-1]["offset"] == 0


def test_local_search_uses_owned_session_endpoint_without_replacing_chat_history(demo, api):
    search, dependency = event(demo, "Tìm trong hội thoại")
    result = search.fn("A", "A-chat-100", "needle")
    assert result[1]["session_id"] == "A-chat-100"
    assert api.calls[-1][2] == "/api/sessions/A-chat-100/messages/page"
    assert api.calls[-1][-1]["query"] == "needle"
    chat = next(item for item in demo.blocks.values() if item.elem_id == "chat-history")
    assert chat._id not in dependency["outputs"]


def test_local_search_without_selection_never_calls_api(demo, api):
    search, _ = event(demo, "Tìm trong hội thoại")
    result = search.fn("A", None, "needle")
    assert not api.calls and result[1] == {}
    assert "Chọn hội thoại" in result[2]["value"]


def test_search_failure_removes_previous_result_and_hides_load_more(demo, api):
    api.fail_search = True
    search, _ = event(demo, "Tìm kiếm")
    result = search.fn("A", "needle")
    assert result[1] == {} and result[-1]["visible"] is False
    assert "Chưa tìm được" in result[0] and "<script>" not in result[0]


def test_search_retains_a_bounded_preview_window(demo, api, monkeypatch):
    monkeypatch.setattr(gradio_ui, "MAX_UI_SEARCH_ROWS", 60)
    search, _ = event(demo, "Tìm kiếm")
    first = search.fn("A", "needle")
    more, _ = event(demo, "Tải thêm kết quả")
    second = more.fn("A", "needle", first[1])
    assert len(second[1]["items"]) == 60
    assert "41–100/123" in second[2]["value"]
    assert "Chỉ giữ 60" in second[2]["value"]


def test_old_local_search_cannot_repopulate_results_after_switching_conversation(demo, api, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def paused(token, method, path, *args, **kwargs):
        if path == "/api/sessions/A-chat-0/messages/page":
            started.set()
            assert release.wait(10)
        return api(token, method, path, *args, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", paused)

    async def scenario():
        state = SessionState(demo)
        search, _ = event(demo, "Tìm trong hội thoại")
        clear = callback(demo, "clear_session_search")
        state[search.inputs[0]._id] = "A"
        state[search.inputs[1]._id].choices = [("A", "A-chat-0"), ("B", "A-chat-1")]
        state[search.inputs[3]._id] = "A-chat-0"
        pending = asyncio.create_task(demo.process_api(
            search, [None, "A-chat-0", "needle", None, None], state=state,
        ))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(clear, ["A-chat-1", None], state=state)
        finally:
            release.set()
        result = await pending
        assert result["data"] == [gr.skip()] * len(search.outputs)
        assert result["changed_state_ids"] == []
        assert state[search.outputs[1]._id] == {}
        assert "needle hit" not in str(state.config_values)

    asyncio.run(scenario())


def test_queued_search_for_previous_conversation_does_not_read_api(demo, api):
    search, _ = event(demo, "Tìm trong hội thoại")
    result = search.fn("A", "A-chat-0", "needle", "A-chat-1", 1)
    assert result == (gr.skip(),) * len(search.outputs)
    assert not api.calls


def _pending(demo, api):
    state = callback(demo, "refresh_admin").fn("A")[8]
    request, _ = event(demo, "Xóa tài khoản")
    return request.fn("A", "user-1", state)[0]


@pytest.mark.parametrize("token,selected,typed", [
    ("B", "user-1", "member.1"), ("A", "user-2", "member.1"),
    ("A", None, "member.1"), ("A", "user-1", "wrong"),
])
def test_account_delete_rejects_stale_or_unconfirmed_target(demo, api, token, selected, typed):
    pending = _pending(demo, api)
    confirm, dependency = event(demo, "Xác nhận xóa tài khoản vĩnh viễn")
    result = confirm.fn(token, selected, pending, typed, "private password", "123456")
    assert len(result) == len(dependency["outputs"])
    assert not api.deleted and result[-3:] == ("", "", "")


def test_confirmed_account_delete_reauthenticates_same_frozen_target_and_clears_secrets(demo, api):
    pending = _pending(demo, api)
    api.require_step_up = True
    confirm, _ = event(demo, "Xác nhận xóa tài khoản vĩnh viễn")
    result = confirm.fn("A", "user-1", pending, "member.1", "private password", " 123456 ")
    assert api.deleted == ["user-1"]
    assert [call[2] for call in api.calls if call[1] == "DELETE"] == [
        "/api/admin/users/user-1", "/api/admin/users/user-1",
    ]
    assert ("A", "POST", "/api/auth/step-up",
            {"password": "private password", "code": "123456"}, {}) in api.calls
    assert result[-6] == {} and result[-5] == gr.update(visible=False)
    assert result[-3:] == ("", "", "")


def test_failed_account_delete_keeps_diagnostic_and_clears_entered_credentials(demo, api):
    pending = _pending(demo, api)
    api.fail_delete = True
    confirm, _ = event(demo, "Xác nhận xóa tài khoản vĩnh viễn")
    result = confirm.fn("A", "user-1", pending, "member.1", "private password", "123456")
    assert not api.deleted and result[-6] == pending
    assert "Chưa xóa được" in result[-4] and "<script>" not in result[-4]
    assert result[-3:] == ("", "", "")


def test_new_sensitive_state_is_reset_on_logout(demo, api):
    logout, dependency = event(demo, "Đăng xuất")
    result = logout.fn("A")
    updates = dict(zip(dependency["outputs"], result, strict=True))
    for label, input_index in (("Tải thêm hội thoại", 2), ("Tải thêm tài khoản", 2),
                               ("Tải thêm kết quả", 2), ("Tải thêm kết quả trong hội thoại", 3),
                               ("Xác nhận xóa tài khoản vĩnh viễn", 2)):
        fn, _ = event(demo, label)
        assert updates[fn.inputs[input_index]._id] == {}, label
    for elem_id in ("account-delete-name", "session-search-query"):
        component = next(item for item in demo.blocks.values() if item.elem_id == elem_id)
        assert updates[component._id] == ""


def test_external_ai_consent_discloses_history_scope_before_both_consent_paths(demo):
    consent = next(item for item in demo.blocks.values()
                   if isinstance(item, gr.Checkbox) and item.info == gradio_ui.AI_CONSENT_SCOPE)
    assert "lịch sử" in consent.label
    for notice in (consent.info, gradio_ui.CONSENT_NOTICE):
        assert "tin nhắn hiện tại" in notice
        assert "mặc định 16" in notice and "tối đa 40 tin lịch sử" in notice
        assert "AI bên ngoài" in notice and "DLP" in notice


def test_private_e2ee_ui_points_to_independent_clients_without_fetching_plaintext(api):
    result = gradio_ui._chat_history("A", "private", {"security_mode": "private_e2ee"})
    assert not api.calls
    assert "client Olm độc lập" in result[0]["content"]
    assert "python -m scripts.demo_e2ee --check" in result[0]["content"]


def test_paging_and_local_search_through_real_authenticated_api(demo, client, app, monkeypatch):
    """Cross the UI/HTTP/database boundary using disposable, encrypted test rows."""
    token = register_and_login(client, "ui-page-review")
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    with app.state.database.session_factory() as db:
        owner = db.get(User, me["id"])
        owner.role = "admin"
        stamp = utcnow()
        for index in range(501):
            db.add(User(username=f"page.member.{index}", password_hash=owner.password_hash,
                        created_at=stamp + timedelta(seconds=index)))
        sessions = [ChatSession(
            owner_id=owner.id, title=f"Page chat {index}", updated_at=stamp + timedelta(seconds=index),
            retention_expires_at=stamp + timedelta(days=30),
        ) for index in range(101)]
        db.add_all(sessions)
        db.flush()
        for chat, count in ((sessions[0], 1), (sessions[-1], 51)):
            for index in range(count):
                ciphertext, nonce, version = app.state.crypto_service.encrypt(
                    f"needle result {index}", chat.id, "user",
                )
                db.add(SecureMessage(session_id=chat.id, role="user", message_index=index + 1,
                                     ciphertext=ciphertext, nonce=nonce, key_version=version))
        oldest_id = sessions[0].id
        db.commit()

    def http_api(bearer, method, path, body=None, *, params=None):
        response = client.request(method, path, json=body, params=params,
                                  headers={"Authorization": f"Bearer {bearer}"})
        assert response.status_code == 200, response.text
        return response.json()

    monkeypatch.setattr(gradio_ui, "_api", http_api)
    first = callback(demo, "refresh_sessions").fn(token)
    more, _ = event(demo, "Tải thêm hội thoại")
    last = more.fn(token, first[0]["value"], first[3])
    assert len(last[0]["choices"]) == 101
    assert oldest_id in {item_id for _label, item_id in last[0]["choices"]}
    users = callback(demo, "refresh_admin").fn(token)[8]
    more_users, _ = event(demo, "Tải thêm tài khoản")
    while users["has_more"]:
        users = more_users.fn(token, None, users)[2]
    assert len(users["items"]) == 502
    search, _ = event(demo, "Tìm kiếm")
    results = search.fn(token, "needle")
    assert results[1]["total"] == 52
    more_results, _ = event(demo, "Tải thêm kết quả")
    results = more_results.fn(token, "needle", results[1])
    assert len(results[1]["items"]) == 52 and results[1]["has_more"] is False
    assert oldest_id in {item["session_id"] for item in results[1]["items"]}
    local, _ = event(demo, "Tìm trong hội thoại")
    result = local.fn(token, oldest_id, "needle")
    assert result[1]["total"] == 1 and "needle result 0" in result[0]
