from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from gradio.data_classes import PredictBodyInternal
from gradio.server_messages import (
    EstimationMessage,
    HeartbeatMessage,
    LogMessage,
    ProcessCompletedMessage,
    ProcessStartsMessage,
)
from starlette.exceptions import HTTPException

from src.app.gradio_capacity import attach_gradio_capacity
from src.app.gradio_ui import build_ui


def _ui(*, retained=2, states=3):
    ui = build_ui(
        queue_max_size=4, concurrency_limit=1, retained_events=retained,
        result_ttl_seconds=120, state_capacity=states,
    )
    ui._queue.set_server_app(ui.app)
    return ui


def _request() -> Request:
    return Request({
        "type": "http", "method": "POST", "path": "/gradio_api/queue/join",
        "query_string": b"", "headers": [], "scheme": "http",
        "server": ("testserver", 80), "client": ("127.0.0.1", 12345),
    })


async def _push(ui, session="browser", *, event_id=None):
    fn = next(fn for fn in ui.fns.values() if fn.api_name == "_pw_meter_html")
    request = _request()
    return await ui._queue.push(
        PredictBodyInternal(
            data=["A long safe password"], fn_index=fn._id, session_hash=session,
            event_id=event_id, request=request,
        ), request, username=None,
    )


async def _process_next(ui):
    queue = ui._queue
    events, batch, concurrency_id = queue.get_events()
    # Follow the real worker dispatch; run the actual callback/pre/postprocess
    # and completion protocol without an open network stream consuming results.
    queue.active_jobs = [events]
    event_queue = queue.event_queue_per_concurrency_id[concurrency_id]
    event_queue.current_concurrency += 1
    started = time.time()
    event_queue.start_times_per_fn[events[0].fn].add(started)
    for event in events:
        queue.event_analytics[event._id]["status"] = "processing"
    await queue.process_events(events, batch, started)


def test_completed_jobs_without_sse_saturate_retention_then_recover_after_expiry():
    ui = _ui()
    now = [100.0]
    ui.scap_capacity.clock = lambda: now[0]

    async def scenario():
        for _ in range(2):
            assert (await _push(ui))[0]
            await _process_next(ui)
        messages = ui._queue.pending_messages_per_session["browser"]
        assert sum(isinstance(item, ProcessCompletedMessage) for item in messages._queue) == 2
        for _ in range(20):
            assert (await _push(ui))[2] == "queue_full"
        assert len(ui._queue) == 0
        assert len(ui.scap_capacity.events) == len(ui._queue.event_ids_to_events) == 2
        assert len(ui._queue.event_analytics) == 2
        assert messages.qsize() <= messages.maxsize

        now[0] += 120
        assert (await _push(ui, "retry"))[0]
        assert len(ui.scap_capacity.events) == len(ui._queue.event_ids_to_events) == 1
        assert "browser" not in ui._queue.pending_messages_per_session
        assert "browser" not in ui._queue.pending_event_ids_session
        await ui._queue.clean_events(session_hash="retry")
        assert not ui.scap_capacity.events and not ui._queue.event_analytics

    asyncio.run(scenario())


def test_browser_reads_successful_completion_and_capacity_is_reused():
    ui = _ui(retained=1)

    async def prepare():
        admitted = await _push(ui)
        assert admitted[0]
        await _process_next(ui)
        return admitted[1]

    event_id = asyncio.run(prepare())
    with TestClient(ui.app) as client:
        response = client.get("/gradio_api/queue/data", params={"session_hash": "browser"})
    assert response.status_code == 200
    assert '"msg":"process_completed"' in response.text
    assert '"success":true' in response.text
    assert event_id in response.text
    assert '"msg":"close_stream"' in response.text
    assert asyncio.run(_push(ui, "another-browser"))[0]
    assert event_id not in ui._queue.event_ids_to_events


def test_running_job_and_its_state_are_protected_from_ttl_and_state_eviction():
    ui = _ui(retained=1, states=1)
    now = [100.0]
    ui.scap_capacity.clock = lambda: now[0]

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        fn = next(fn for fn in ui.fns.values() if fn.api_name == "_pw_meter_html")

        async def paused_callback(_password):
            started.set()
            await release.wait()
            return "Done"

        fn.fn = paused_callback
        admitted = await _push(ui)
        worker = asyncio.create_task(_process_next(ui))
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            now[0] += 1_000
            ui.scap_capacity.prune()
            assert admitted[1] in ui._queue.event_ids_to_events
            assert (await _push(ui, "other"))[2] == "queue_full"
            with pytest.raises(HTTPException) as full:
                ui.state_holder["new-state"]
            assert full.value.status_code == 503
            assert "browser" in ui.state_holder.session_data
        finally:
            release.set()
            await asyncio.wait_for(worker, timeout=5)

    asyncio.run(scenario())


def test_result_updates_coalesce_without_discarding_completion():
    ui = _ui(retained=1)

    async def scenario():
        admitted = await _push(ui)
        event = ui._queue.event_ids_to_events[admitted[1]]
        for index in range(1_000):
            ui._queue.send_message(event, EstimationMessage(queue_size=index))
            ui._queue.send_message(event, LogMessage(log="Notice", level="info", title="Info"))
        messages = ui._queue.pending_messages_per_session["browser"]
        for _ in range(50):
            await messages.put(HeartbeatMessage())
        assert messages.qsize() <= messages.maxsize
        await _process_next(ui)
        for _ in range(1_000):
            ui._queue.send_message(event, LogMessage(log="Notice", level="info", title="Info"))
        completions = [item for item in messages._queue if isinstance(item, ProcessCompletedMessage)]
        assert len(completions) == 1 and completions[0].success
        assert sum(isinstance(item, ProcessStartsMessage) for item in messages._queue) == 1
        assert messages.qsize() <= messages.maxsize

    asyncio.run(scenario())


def test_state_sessions_and_last_use_metadata_both_remain_bounded():
    ui = _ui(states=2)
    for index in range(10):
        ui.state_holder[f"state-{index}"]
    assert len(ui.state_holder.session_data) == 2
    assert len(ui.state_holder.time_last_used) == 2
    assert set(ui.state_holder.session_data) == {"state-8", "state-9"}


def test_callback_threads_can_churn_state_while_event_maps_change_without_evicting_live_state():
    ui = _ui(retained=2, states=8)

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()
        fn = next(fn for fn in ui.fns.values() if fn.api_name == "_pw_meter_html")

        async def paused_callback(_password):
            started.set()
            await release.wait()
            return "Done"

        def churn_state(prefix):
            for index in range(100):
                ui.state_holder[f"thread-{prefix}-{index}"]
                assert "browser" in ui.scap_capacity._protected_sessions()

        fn.fn = paused_callback
        admitted = await _push(ui)
        worker = asyncio.create_task(_process_next(ui))
        try:
            await asyncio.wait_for(started.wait(), timeout=5)
            with ThreadPoolExecutor(max_workers=3) as executor:
                threads = [executor.submit(churn_state, index) for index in range(3)]
                for index in range(30):
                    assert (await _push(ui, f"temporary-{index}"))[0]
                    await ui._queue.clean_events(session_hash=f"temporary-{index}")
                    ui.scap_capacity.prune()
                    await asyncio.sleep(0)
                await asyncio.to_thread(lambda: [thread.result(timeout=10) for thread in threads])
            assert "browser" in ui.state_holder.session_data
            assert admitted[1] in ui._queue.event_ids_to_events
            assert len(ui.state_holder.session_data) <= 8
            assert len(ui.state_holder.time_last_used) <= 8
        finally:
            release.set()
            await asyncio.wait_for(worker, timeout=5)

    asyncio.run(scenario())


@pytest.mark.parametrize("field", ["session_hash", "event_id"])
@pytest.mark.parametrize("value", ["x" * 129, "unsafe/id", "không-hợp-lệ"])
def test_oversized_or_invalid_handles_are_rejected_before_state_or_event_allocation(field, value):
    ui = _ui()
    result = asyncio.run(_push(ui, value if field == "session_hash" else "browser",
                               event_id=value if field == "event_id" else None))
    assert result[0] is False and result[2] == "error"
    assert not ui.state_holder.session_data
    assert not ui._queue.event_ids_to_events
    assert not ui.scap_capacity.events


def test_opportunistic_pruning_releases_done_tasks_but_keeps_live_tasks():
    ui = _ui()

    async def scenario():
        done = asyncio.create_task(asyncio.sleep(0))
        await done
        live = asyncio.create_task(asyncio.Event().wait())
        ui._queue._asyncio_tasks.extend([done, live])
        ui.scap_capacity.prune()
        assert ui._queue._asyncio_tasks == [live]
        live.cancel()
        with pytest.raises(asyncio.CancelledError):
            await live

    asyncio.run(scenario())


def test_attach_rejects_unrelated_app_instead_of_silently_disabling_limits():
    ui = _ui()
    with pytest.raises(RuntimeError, match="bounded result retention"):
        attach_gradio_capacity(ui, object())
