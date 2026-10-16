"""Queued browser actions keep the login which admitted their submitted inputs."""

from __future__ import annotations

import asyncio

import gradio as gr
import pytest
from gradio.data_classes import PredictBodyInternal
from gradio.server_messages import ProcessCompletedMessage

from src.app import gradio_ui
from src.app.gradio_capacity import GradioCapacity
from tests.test_gradio_retention_capacity import _process_next, _request, _ui
from tests.test_ui_session_races import callback, fake_api


@pytest.fixture
def ui(monkeypatch):
    monkeypatch.setattr(gr, "Info", lambda *a, **k: None)
    monkeypatch.setattr(gr, "Warning", lambda *a, **k: None)
    monkeypatch.setattr(gradio_ui, "_chat_history", lambda *a: [])
    return _ui(retained=8)


async def enqueue(ui, fn, data, session="browser"):
    request = _request()
    result = await ui._queue.push(PredictBodyInternal(
        data=data, fn_index=fn._id, session_hash=session, request=request,
    ), request, username=None)
    assert result[0], result
    return result[1]


def session_api(monkeypatch):
    writes = []

    def api(token, method, path, body=None, **kwargs):
        if path == "/api/sessions" and method == "POST":
            writes.append((token, body))
            return {"id": "created-conversation"}
        return fake_api(token, method, path, body, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", api)
    return writes


def completion(ui, event_id):
    return next(item for messages in ui._queue.pending_messages_per_session.values()
                for item in messages._queue
                if isinstance(item, ProcessCompletedMessage) and item.event_id == event_id)


def test_queued_old_account_draft_cannot_execute_using_new_account_bearer(ui, monkeypatch):
    writes = session_api(monkeypatch)

    async def scenario():
        create, logout, login = (callback(ui, name) for name in
                                 ("create_session", "do_logout", "do_login"))
        state = ui.state_holder["browser"]
        state[create.inputs[0]._id] = "admin-A-token"
        event_id = await enqueue(ui, create, [None, "PRIVATE ACCOUNT A DRAFT", "secure", "internal"])
        await ui.process_api(logout, [None], state=state)
        await ui.process_api(login, ["user-B", "password-value"], state=state)
        assert state[create.inputs[0]._id] == "user-B-token"
        await _process_next(ui)
        assert writes == []
        result = completion(ui, event_id)
        assert result.success is True
        assert result.output["data"] == [gr.skip()] * len(create.outputs)
        assert result.output["changed_state_ids"] == []

    asyncio.run(scenario())


def test_current_queued_action_runs_and_its_binding_is_retired_with_event(ui, monkeypatch):
    writes = session_api(monkeypatch)
    now = [100.0]
    ui.scap_capacity.clock = lambda: now[0]

    async def scenario():
        create = callback(ui, "create_session")
        state = ui.state_holder["browser"]
        state[create.inputs[0]._id] = "user-B-token"
        event_id = await enqueue(ui, create, [None, "CURRENT DRAFT", "secure", "internal"])
        await _process_next(ui)
        assert writes == [("user-B-token", {"title": "CURRENT DRAFT", "security_mode": "secure",
                                           "data_classification": "internal"})]
        assert completion(ui, event_id).success is True
        record = ui.scap_capacity.events[event_id]
        assert "user-B-token" not in repr(record)
        now[0] += 120
        ui.scap_capacity.prune()
        assert event_id not in ui.scap_capacity.events

    asyncio.run(scenario())


def test_logout_during_queue_admission_does_not_rebind_old_inputs(ui, monkeypatch):
    writes = session_api(monkeypatch)

    async def scenario():
        create, logout, login = (callback(ui, name) for name in
                                 ("create_session", "do_logout", "do_login"))
        state = ui.state_holder["browser"]
        state[create.inputs[0]._id] = "admin-A-token"
        entered, release = asyncio.Event(), asyncio.Event()
        original = ui.scap_capacity._push

        async def paused_push(*args, **kwargs):
            entered.set()
            await release.wait()
            return await original(*args, **kwargs)

        monkeypatch.setattr(ui.scap_capacity, "_push", paused_push)
        admission = asyncio.create_task(enqueue(ui, create, [None, "OLD DRAFT", "secure", "internal"]))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            await ui.process_api(logout, [None], state=state)
            await ui.process_api(login, ["user-B", "password-value"], state=state)
        finally:
            release.set()
        event_id = await admission
        await _process_next(ui)
        assert writes == []
        assert completion(ui, event_id).output["data"] == [gr.skip()] * len(create.outputs)

    asyncio.run(scenario())


def test_logout_during_preprocessing_cannot_run_callback_with_new_state_token(ui, monkeypatch):
    writes = session_api(monkeypatch)

    async def scenario():
        create, logout, login = (callback(ui, name) for name in
                                 ("create_session", "do_logout", "do_login"))
        state = ui.state_holder["browser"]
        state[create.inputs[0]._id] = "admin-A-token"
        event_id = await enqueue(ui, create, [None, "OLD DRAFT", "secure", "internal"])
        entered, release = asyncio.Event(), asyncio.Event()
        original = ui.preprocess_data

        async def paused_preprocess(fn, *args, **kwargs):
            if fn is create:
                entered.set()
                await release.wait()
            return await original(fn, *args, **kwargs)

        monkeypatch.setattr(ui, "preprocess_data", paused_preprocess)
        worker = asyncio.create_task(_process_next(ui))
        try:
            await asyncio.wait_for(entered.wait(), 5)
            await ui.process_api(logout, [None], state=state)
            await ui.process_api(login, ["user-B", "password-value"], state=state)
        finally:
            release.set()
        await worker
        assert writes == []
        assert completion(ui, event_id).output["data"] == [gr.skip()] * len(create.outputs)

    asyncio.run(scenario())


@pytest.mark.parametrize("mismatch", ["unknown_event", "other_session", "other_function"])
def test_queue_identity_mismatch_cannot_invoke_a_callback(ui, monkeypatch, mismatch):
    writes = session_api(monkeypatch)

    async def scenario():
        create = callback(ui, "create_session")
        state = ui.state_holder["browser"]
        state[create.inputs[0]._id] = "user-B-token"
        queued_fn = callback(ui, "load_workspace") if mismatch == "other_function" else create
        queued_data = [None] if mismatch == "other_function" else [None, "DRAFT", "secure", "internal"]
        event_id = await enqueue(ui, queued_fn, queued_data)
        result = await ui.process_api(
            create, [None, "DRAFT", "secure", "internal"], state=state,
            session_hash="another-browser" if mismatch == "other_session" else "browser",
            event_id="unknown-event" if mismatch == "unknown_event" else event_id,
        )
        assert writes == []
        assert result["data"] == [gr.skip()] * len(create.outputs)
        await ui._queue.clean_events(session_hash="browser")

    asyncio.run(scenario())


def test_old_queued_logout_does_not_revoke_new_login(ui, monkeypatch):
    calls = []

    def api(token, method, path, body=None, **kwargs):
        calls.append((token, method, path))
        return fake_api(token, method, path, body, **kwargs)

    monkeypatch.setattr(gradio_ui, "_api", api)

    async def scenario():
        logout, login = callback(ui, "do_logout"), callback(ui, "do_login")
        state = ui.state_holder["browser"]
        state[logout.inputs[0]._id] = "admin-A-token"
        event_id = await enqueue(ui, logout, [None])
        await ui.process_api(logout, [None], state=state)
        await ui.process_api(login, ["user-B", "password-value"], state=state)
        calls.clear()
        await _process_next(ui)
        assert calls == []
        assert state[logout.inputs[0]._id] == "user-B-token"
        assert completion(ui, event_id).output["data"] == [gr.skip()] * len(logout.outputs)

    asyncio.run(scenario())


def test_new_login_followup_is_bound_to_current_session(ui, monkeypatch):
    monkeypatch.setattr(gradio_ui, "_api", fake_api)

    async def scenario():
        login, remember, workspace = (callback(ui, name) for name in
                                     ("do_login", "remember_session", "load_workspace"))
        state = ui.state_holder["browser"]
        login_id = await enqueue(ui, login, ["user-B", "password-value"])
        await _process_next(ui)
        assert completion(ui, login_id).success is True
        remember_id = await enqueue(ui, remember, [None, None])
        await _process_next(ui)
        assert "data-scap-session-ticket" in completion(ui, remember_id).output["data"][0]
        workspace_id = await enqueue(ui, workspace, [None])
        await _process_next(ui)
        result = completion(ui, workspace_id)
        assert result.success is True
        assert "user-B" in result.output["data"][3]
        assert state[workspace.inputs[0]._id] == "user-B-token"

    asyncio.run(scenario())


def test_first_anonymous_event_gets_consistent_generated_session_binding(ui):
    async def scenario():
        fn = callback(ui, "_pw_meter_html")
        event_id = await enqueue(ui, fn, ["A long password value1!"], session=None)
        event = ui._queue.event_ids_to_events[event_id]
        assert event.session_hash in ui.state_holder.session_data
        assert ui.scap_capacity.events[event_id].session_hash == event.session_hash
        await _process_next(ui)
        result = completion(ui, event_id)
        assert result.success is True and "pw-bars" in result.output["data"][0]

    asyncio.run(scenario())


def test_batching_is_rejected_because_gradio_discards_individual_event_ids(ui):
    callback(ui, "create_session").batch = True
    with pytest.raises(RuntimeError, match="non-batched"):
        GradioCapacity(ui, retained_events=8, result_ttl_seconds=120, state_capacity=3)
