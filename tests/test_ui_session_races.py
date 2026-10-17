"""Publish callback results only into the authentication session that began them."""

from __future__ import annotations

import asyncio
import re
import threading

import gradio as gr
import pytest
from gradio.state_holder import SessionState
from starlette.requests import Request

from src.app import gradio_ui
from src.app.ui_session import COOKIE_NAME, BrowserSessionStore


@pytest.fixture(scope="module")
def demo():
    return gradio_ui.build_ui()


@pytest.fixture(autouse=True)
def notices(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *args, **kwargs: None)
    monkeypatch.setattr(gr, "Warning", lambda *args, **kwargs: None)


def callback(demo, name):
    return next(fn for fn in demo.fns.values() if fn.fn and fn.fn.__name__ == name)


def fake_api(token, method, path, body=None, **kwargs):
    if path == "/api/auth/logout":
        return {}
    if path == "/api/auth/login":
        return {"access_token": "user-B-token", "expires_in": 3600}
    if path == "/api/auth/me":
        return {
            "username": "admin-A" if token == "admin-A-token" else "user-B",
            "role": "admin" if token == "admin-A-token" else "user",
            "mfa_enabled": False, "created_at": "2026-10-15T00:00:00Z",
            "ai_data_consent": False,
        }
    if path == "/api/sessions/page":
        return {"items": [{"id": "conversation-" + token, "title": "Conversation", "security_mode": "secure"}],
                "total": 1, "offset": 0, "limit": 100, "has_more": False, "next_offset": None}
    if path.startswith("/api/sessions/"):
        return {"id": path.rsplit("/", 1)[-1], "title": "Conversation", "security_mode": "secure"}
    if path in ("/api/auth/sessions", "/api/admin/security-alerts"):
        return []
    if path == "/api/admin/stats":
        return {
            "total_users": 1, "active_users": 1, "total_sessions": 2,
            "total_messages": 3, "recent_login_failures": 0, "recent_auth_denials": 0,
        }
    raise AssertionError(path)


def test_old_admin_refresh_cannot_repopulate_tables_after_logout(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def api(token, method, path, *args, **kwargs):
        if path == "/api/admin/users/page":
            started.set()
            assert release.wait(10)
            return {"items": [{"id": "old-user", "username": "OLD ADMIN ACCOUNT", "role": "admin",
                               "is_active": True, "mfa_enabled": True, "created_at": "2026-10-15T00:00:00Z"}],
                    "total": 1, "offset": 0, "limit": 100, "has_more": False, "next_offset": None}
        return fake_api(token, method, path, *args, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        state = SessionState(demo)
        refresh, logout = callback(demo, "refresh_admin"), callback(demo, "do_logout")
        state[refresh.inputs[0]._id] = "admin-A-token"
        pending = asyncio.create_task(demo.process_api(refresh, [None], state=state))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(logout, [None], state=state)
        finally:
            release.set()
        stale = await pending
        assert stale["data"] == [gr.skip()] * len(refresh.outputs)
        assert stale["changed_state_ids"] == []
        assert "OLD ADMIN ACCOUNT" not in str(state.config_values)
        assert state[refresh.inputs[0]._id] == ""

    asyncio.run(scenario())


def test_old_workspace_cannot_reveal_previous_account_after_new_login(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(gradio_ui, "_api", fake_api)

    def history(token, *args):
        if token == "admin-A-token":
            started.set()
            assert release.wait(10)
            return [{"role": "user", "content": "PRIVATE OLD ACCOUNT MESSAGE"}]
        return [{"role": "user", "content": "NEW ACCOUNT MESSAGE"}]

    monkeypatch.setattr(gradio_ui, "_chat_history", history)

    async def scenario():
        state = SessionState(demo)
        workspace, logout, login = (callback(demo, name) for name in
                                   ("load_workspace", "do_logout", "do_login"))
        state[workspace.inputs[0]._id] = "admin-A-token"
        pending = asyncio.create_task(demo.process_api(workspace, [None], state=state))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(logout, [None], state=state)
            await demo.process_api(login, ["user-B", "password-value"], state=state)
            current = await demo.process_api(workspace, [None], state=state)
        finally:
            release.set()
        stale = await pending
        assert stale["data"] == [gr.skip()] * len(workspace.outputs)
        assert current["data"][0]["visible"] is False
        assert state[workspace.inputs[0]._id] == "user-B-token"
        assert state[workspace.outputs[0]._id].visible is False
        chat = state.config_values[workspace.outputs[6]._id]["props"]["value"]
        assert "NEW ACCOUNT MESSAGE" in str(chat)
        assert "PRIVATE OLD ACCOUNT MESSAGE" not in str(chat)

    asyncio.run(scenario())


def test_pending_login_cannot_undo_logout_even_when_initial_token_is_empty(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def api(token, method, path, *args, **kwargs):
        if path == "/api/auth/login":
            started.set()
            assert release.wait(10)
        return fake_api(token, method, path, *args, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        state = SessionState(demo)
        login, logout = callback(demo, "do_login"), callback(demo, "do_logout")
        pending = asyncio.create_task(demo.process_api(login, ["user-B", "password-value"], state=state))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(logout, [None], state=state)
        finally:
            release.set()
        stale = await pending
        assert stale["data"] == [gr.skip()] * len(login.outputs)
        assert state[logout.inputs[0]._id] == ""

    asyncio.run(scenario())


def test_other_browser_logout_does_not_discard_current_workspace(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(gradio_ui, "_api", fake_api)

    def history(*args):
        started.set()
        assert release.wait(10)
        return [{"role": "user", "content": "CURRENT ACCOUNT MESSAGE"}]

    monkeypatch.setattr(gradio_ui, "_chat_history", history)

    async def scenario():
        first, second = SessionState(demo), SessionState(demo)
        workspace, logout = callback(demo, "load_workspace"), callback(demo, "do_logout")
        first[workspace.inputs[0]._id] = "admin-A-token"
        second[workspace.inputs[0]._id] = "user-B-token"
        pending = asyncio.create_task(demo.process_api(workspace, [None], state=first))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(logout, [None], state=second)
        finally:
            release.set()
        current = await pending
        assert "CURRENT ACCOUNT MESSAGE" in str(current["data"][6])
        assert first[workspace.inputs[0]._id] == "admin-A-token"

    asyncio.run(scenario())


def test_mfa_cancel_discards_in_flight_verification_result(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def api(token, method, path, *args, **kwargs):
        assert path == "/api/auth/mfa/verify"
        started.set()
        assert release.wait(10)
        return {"access_token": "late-mfa-token", "expires_in": 3600}

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        state = SessionState(demo)
        verify = callback(demo, "do_mfa_verify")
        button = next(block for block in demo.blocks.values() if block.elem_id == "btn-mfa-cancel")
        dependency = next(dep for dep in demo.config["dependencies"]
                          if (button._id, "click") in dep["targets"])
        cancel = demo.fns[dependency["id"]]
        state[verify.inputs[0]._id] = "pending-challenge"
        pending = asyncio.create_task(demo.process_api(verify, [None, "123456"], state=state))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(cancel, [], state=state)
        finally:
            release.set()
        stale = await pending
        assert stale["data"] == [gr.skip()] * len(verify.outputs)
        assert state[verify.outputs[0]._id] == ""
        assert state[verify.inputs[0]._id] == ""

    asyncio.run(scenario())


def test_successful_login_ticket_restore_and_workspace_still_publish(monkeypatch):
    store = BrowserSessionStore()
    demo = gradio_ui.build_ui(session_store=store)
    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    monkeypatch.setattr(gradio_ui, "_chat_history", lambda *a: [{"role": "user", "content": "CURRENT CHAT"}])

    async def scenario():
        original, restored = SessionState(demo), SessionState(demo)
        login, remember, restore, workspace = (callback(demo, name) for name in
            ("do_login", "remember_session", "restore_session", "load_workspace"))
        await demo.process_api(login, ["user-B", "password-value"], state=original)
        remembered = await demo.process_api(remember, [None, None], state=original)
        ticket = re.search(r'data-scap-session-ticket="([A-Za-z0-9_-]{43})"', remembered["data"][0])[1]
        cookie = store.attach(ticket)
        request = gr.Request(Request({
            "type": "http", "scheme": "http", "method": "GET", "path": "/",
            "query_string": b"", "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 12345),
            "headers": [(b"cookie", f"{COOKIE_NAME}={cookie}".encode())],
        }))
        await demo.process_api(restore, [], state=restored, request=request)
        current = await demo.process_api(workspace, [None], state=restored)
        assert restored[workspace.inputs[0]._id] == "user-B-token"
        assert "CURRENT CHAT" in str(current["data"][6])
        assert "user-B" in current["data"][3]

    asyncio.run(scenario())


def test_obsolete_security_activity_warning_is_suppressed_after_logout(demo, monkeypatch):
    started, release = threading.Event(), threading.Event()
    warnings = []
    monkeypatch.setattr(gradio_ui, "_api", fake_api)
    monkeypatch.setattr(gr, "Warning", lambda message, *a, **k: warnings.append(message))

    def snapshot(token):
        started.set()
        assert release.wait(10)
        return "old summary", "old rows", ["PRIVATE OLD LOGIN LOCATION"]

    monkeypatch.setattr(gradio_ui, "_security_activity_snapshot", snapshot)

    async def scenario():
        state = SessionState(demo)
        activity, logout = callback(demo, "announce_security_activity"), callback(demo, "do_logout")
        state[activity.inputs[0]._id] = "admin-A-token"
        pending = asyncio.create_task(demo.process_api(activity, [None], state=state))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            await demo.process_api(logout, [None], state=state)
        finally:
            release.set()
        stale = await pending
        assert stale["data"] == [gr.skip()] * len(activity.outputs)
        assert "PRIVATE OLD LOGIN LOCATION" not in warnings

    asyncio.run(scenario())


def test_concurrent_reads_in_same_session_keep_their_data_and_notices(demo, monkeypatch):
    barrier = threading.Barrier(2)
    warnings = []
    monkeypatch.setattr(gr, "Warning", lambda message, *a, **k: warnings.append(message))

    def snapshot(token):
        barrier.wait(5)
        return "current summary", "current rows", ["CURRENT LOGIN NOTICE"]

    monkeypatch.setattr(gradio_ui, "_security_activity_snapshot", snapshot)

    async def scenario():
        state = SessionState(demo)
        activity = callback(demo, "announce_security_activity")
        state[activity.inputs[0]._id] = "user-B-token"
        results = await asyncio.gather(*(demo.process_api(activity, [None], state=state) for _ in range(2)))
        assert all(result["data"] == ["current summary", "current rows"] for result in results)
        assert warnings == ["CURRENT LOGIN NOTICE", "CURRENT LOGIN NOTICE"]

    asyncio.run(scenario())
