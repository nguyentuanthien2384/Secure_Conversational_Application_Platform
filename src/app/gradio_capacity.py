"""Finite Gradio result retention for SCAP's non-streaming callbacks.

Cleanup is lazy on admission/read requests. Terminal results remain available
for a short retry window; queued/running work is never evicted to admit new work.
No Gradio vendor code or process-global classes are changed.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import threading
import time
from collections import deque
from dataclasses import dataclass

from gradio.queueing import Queue
from gradio.server_messages import (
    EstimationMessage,
    HeartbeatMessage,
    ProcessCompletedMessage,
    ProcessStartsMessage,
    ProgressMessage,
)
from gradio.state_holder import StateHolder
from gradio.utils import LRUCache
from starlette.exceptions import HTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

_HANDLE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z", re.ASCII)
_COMPATIBILITY_ERROR = "Installed Gradio does not support bounded result retention."


class _ResultQueue(asyncio.Queue):
    """Coalesce replaceable updates and reserve space for terminal messages."""

    def __init__(self, retained_events: int) -> None:
        super().__init__(maxsize=4 * retained_events + 8)
        self.lock = threading.RLock()
        if not isinstance(self._queue, deque):
            raise RuntimeError(_COMPATIBILITY_ERROR)

    @staticmethod
    def _replaceable(message) -> bool:
        return isinstance(message, (EstimationMessage, ProgressMessage, HeartbeatMessage))

    async def put(self, item) -> None:
        # Heartbeats use async put; they must never create a hidden wait queue.
        self.put_nowait(item)

    def put_nowait(self, item) -> None:
        with self.lock:
            self._put_bounded(item)

    def _get(self):
        with self.lock:
            return super()._get()

    def _put_bounded(self, item) -> None:
        if self._replaceable(item) or isinstance(item, ProcessCompletedMessage):
            for index, old in enumerate(self._queue):
                if type(old) is type(item) and old.event_id == item.event_id:
                    self._queue[index] = item
                    return
        if self.full():
            disposable = next(
                (old for old in self._queue
                 if not isinstance(old, (ProcessCompletedMessage, ProcessStartsMessage))), None
            )
            if disposable is None:
                # One completion per admitted event cannot fill this queue.
                # Fail closed if an incompatible callback protocol violates it.
                raise RuntimeError(_COMPATIBILITY_ERROR)
            self._queue.remove(disposable)
            self._unfinished_tasks = max(0, self._unfinished_tasks - 1)
        super().put_nowait(item)


@dataclass
class _RetainedEvent:
    session_hash: str
    terminal_at: float | None = None


class _StateHolder(StateHolder):
    def __init__(self, capacity, previous) -> None:
        super().__init__()
        self.retention = capacity
        self.lock = threading.RLock()
        self.set_blocks(capacity.blocks)
        self.session_data = previous.session_data
        self.time_last_used = LRUCache(self.capacity)
        for key in self.session_data:
            if key in previous.time_last_used:
                self.time_last_used[key] = previous.time_last_used[key]

    def __getitem__(self, session_id):
        if not isinstance(session_id, str) or not _HANDLE.fullmatch(session_id):
            raise HTTPException(400, "Invalid queue request identifier.")
        with self.lock:
            if session_id not in self.session_data and len(self.session_data) >= self.capacity:
                protected = self.retention._protected_sessions()
                candidate = next((key for key in self.session_data if key not in protected), None)
                if candidate is None:
                    raise HTTPException(503, "UI session capacity is full. Please retry later.")
                self.session_data.pop(candidate)
                self.time_last_used.pop(candidate, None)
            return super().__getitem__(session_id)


class GradioCapacity:
    def __init__(self, blocks, *, retained_events: int, result_ttl_seconds: int, state_capacity: int):
        values = (retained_events, result_ttl_seconds, state_capacity)
        if any(type(value) is not int or value < 1 for value in values):
            raise ValueError("Gradio retention limits must be positive integers.")
        self.blocks = blocks
        self.queue = blocks._queue
        self.maximum = retained_events
        self.ttl = result_ttl_seconds
        self.state_capacity = state_capacity
        self.clock = time.monotonic
        self.events: dict[str, _RetainedEvent] = {}
        self.processing: set[str] = set()
        self.admitting_sessions: set[str] = set()
        self.metadata_lock = threading.RLock()
        self.admission_lock = asyncio.Lock()
        self.analytics_lock = threading.RLock()
        self._validate_structure()
        # Each accepted event can create at most one result-session queue.
        # Match the cache size to admission so it cannot evict active sessions.
        self.queue.pending_messages_per_session.max_size = retained_events
        self._push = self.queue.push
        self._process_events = self.queue.process_events
        self._clean_events = self.queue.clean_events
        self._remove_from_queue = self.queue.remove_from_queue
        self._send_message = self.queue.send_message
        self._analytics = self.queue.compute_analytics_summary
        self.queue.push = self.push
        self.queue.process_events = self.process_events
        self.queue.clean_events = self.clean_events
        self.queue.remove_from_queue = self.remove_from_queue
        self.queue.send_message = self.send_message
        self.queue.compute_analytics_summary = self.compute_analytics_summary
        blocks.state_session_capacity = state_capacity

    def _validate_structure(self) -> None:
        queue = self.queue
        if not isinstance(queue, Queue) or self.blocks.state_session_capacity < 1:
            raise RuntimeError(_COMPATIBILITY_ERROR)
        for name in ("event_analytics", "event_ids_to_events", "pending_event_ids_session"):
            if not isinstance(getattr(queue, name, None), dict):
                raise RuntimeError(_COMPATIBILITY_ERROR)
        if not isinstance(queue.pending_messages_per_session, LRUCache):
            raise RuntimeError(_COMPATIBILITY_ERROR)
        if not isinstance(queue._asyncio_tasks, list) or not isinstance(queue.active_jobs, list):
            raise RuntimeError(_COMPATIBILITY_ERROR)
        for name, parameters in (
            ("push", {"body", "request", "username"}),
            ("process_events", {"events", "batch", "begin_time"}),
            ("clean_events", {"session_hash", "event_id"}),
        ):
            if not parameters.issubset(inspect.signature(getattr(queue, name)).parameters):
                raise RuntimeError(_COMPATIBILITY_ERROR)
        if any(inspect.isgeneratorfunction(fn.fn) or inspect.isasyncgenfunction(fn.fn)
               for fn in self.blocks.fns.values() if fn.fn is not None):
            raise RuntimeError("Bounded retention requires non-streaming Gradio callbacks.")
        if any(hasattr(fn.fn, "cache") for fn in self.blocks.fns.values() if fn.fn is not None):
            raise RuntimeError("Bounded retention does not support cached Gradio callbacks.")

    def attach_app(self, app) -> None:
        if not callable(getattr(app, "get_blocks", None)) or app.get_blocks() is not self.blocks:
            raise RuntimeError(_COMPATIBILITY_ERROR)
        holder = self.blocks.state_holder
        if holder is not app.state_holder or not isinstance(holder.time_last_used, dict):
            raise RuntimeError(_COMPATIBILITY_ERROR)
        holder.capacity = self.state_capacity
        while len(holder.session_data) > self.state_capacity:
            holder.session_data.popitem(last=False)
        if not isinstance(holder, _StateHolder):
            app.state_holder = _StateHolder(self, holder)
        if not getattr(app.state, "scap_capacity_attached", False):
            app.add_middleware(_RetentionMiddleware, capacity=self)
            app.state.scap_capacity_attached = True

    def _active_ids(self) -> set[str]:
        with self.metadata_lock:
            result = set(self.processing)
            for event_queue in list(self.queue.event_queue_per_concurrency_id.values()):
                result.update(event._id for event in list(event_queue.queue))
            for jobs in list(self.queue.active_jobs):
                if jobs:
                    result.update(event._id for event in list(jobs))
            return result

    def _protected_sessions(self) -> set[str]:
        with self.metadata_lock:
            active = self._active_ids()
            return set(self.admitting_sessions) | {
                record.session_hash for key, record in list(self.events.items())
                if record.terminal_at is None or key in active
            }

    def _retire(self, event_id: str, record: _RetainedEvent) -> None:
        with self.metadata_lock:
            self._retire_locked(event_id, record)

    def _retire_locked(self, event_id: str, record: _RetainedEvent) -> None:
        self.events.pop(event_id, None)
        with self.analytics_lock:
            self.queue.event_analytics.pop(event_id, None)
            self.queue.event_count_at_last_cache = min(
                self.queue.event_count_at_last_cache, len(self.queue.event_analytics)
            )
        self.queue.event_ids_to_events.pop(event_id, None)
        pending = self.queue.pending_event_ids_session.get(record.session_hash)
        if pending is not None:
            pending.discard(event_id)
        messages = self.queue.pending_messages_per_session.get(record.session_hash)
        if messages is not None:
            # The queue contains at most four messages per retained job plus a
            # small reserve. Remove only this terminal event's stale messages.
            with messages.lock:
                stale = [item for item in messages._queue if item.event_id == event_id]
                for item in stale:
                    messages._queue.remove(item)
                messages._unfinished_tasks = max(0, messages._unfinished_tasks - len(stale))
        if not pending and not any(
            item.session_hash == record.session_hash for item in self.events.values()
        ):
            self.queue.pending_event_ids_session.pop(record.session_hash, None)
            self.queue.pending_messages_per_session.pop(record.session_hash, None)

    def prune(self) -> None:
        # Gradio stores every processing Task until shutdown. Done tasks can
        # release their coroutine frames/results without touching live work.
        self.queue._asyncio_tasks[:] = [
            task for task in self.queue._asyncio_tasks if not task.done()
        ]
        with self.metadata_lock:
            now = self.clock()
            active = self._active_ids()
            for event_id, record in list(self.events.items()):
                if event_id in active or record.terminal_at is None:
                    continue
                pending = self.queue.pending_event_ids_session.get(record.session_hash, set())
                if event_id not in pending or now - record.terminal_at >= self.ttl:
                    self._retire(event_id, record)

    async def push(self, body, request, username):
        for value in (body.session_hash, body.event_id):
            if value is not None and (not isinstance(value, str) or not _HANDLE.fullmatch(value)):
                return False, "Invalid queue request identifier.", "error"
        async with self.admission_lock:
            self.prune()
            admitting = body.session_hash
            with self.metadata_lock:
                if len(self.events) >= self.maximum:
                    return False, "Result capacity is full. Please retry later.", "queue_full"
                if admitting is not None:
                    self.admitting_sessions.add(admitting)
            try:
                result = await self._push(body=body, request=request, username=username)
                if result[0]:
                    event = self.queue.event_ids_to_events[result[1]]
                    with self.metadata_lock:
                        self.events[result[1]] = _RetainedEvent(event.session_hash)
                return result
            finally:
                with self.metadata_lock:
                    self.admitting_sessions.discard(admitting)

    def send_message(self, event, event_message) -> None:
        messages = self.queue.pending_messages_per_session.get(event.session_hash)
        if messages is not None and not isinstance(messages, _ResultQueue):
            bounded = _ResultQueue(self.maximum)
            while not messages.empty():
                bounded.put_nowait(messages.get_nowait())
            self.queue.pending_messages_per_session[event.session_hash] = bounded
        self._send_message(event, event_message)

    async def process_events(self, events, batch, begin_time) -> None:
        event_ids = {event._id for event in events}
        with self.metadata_lock:
            self.processing.update(event_ids)
        try:
            await self._process_events(events, batch, begin_time)
        finally:
            with self.metadata_lock:
                self.processing.difference_update(event_ids)
                for event_id in event_ids:
                    if event_id in self.events:
                        self.events[event_id].terminal_at = self.clock()

    async def clean_events(self, *, session_hash=None, event_id=None) -> None:
        await self._clean_events(session_hash=session_hash, event_id=event_id)
        with self.metadata_lock:
            active = self._active_ids()
            for key, record in list(self.events.items()):
                if key not in active and (record.session_hash == session_hash or key == event_id):
                    record.terminal_at = self.clock()
        self.prune()

    async def remove_from_queue(self, event_id) -> None:
        await self._remove_from_queue(event_id)
        with self.metadata_lock:
            if event_id not in self._active_ids() and event_id in self.events:
                self._retire(event_id, self.events[event_id])

    def compute_analytics_summary(self, event_analytics):
        with self.analytics_lock:
            snapshot = {key: dict(value) for key, value in list(event_analytics.items())}
            return self._analytics(snapshot)


class _RetentionMiddleware:
    def __init__(self, app: ASGIApp, *, capacity: GradioCapacity) -> None:
        self.app = app
        self.capacity = capacity

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            self.capacity.prune()
        await self.app(scope, receive, send)


def install_gradio_capacity(blocks, *, retained_events: int, result_ttl_seconds: int,
                            state_capacity: int) -> None:
    blocks.scap_capacity = GradioCapacity(
        blocks, retained_events=retained_events, result_ttl_seconds=result_ttl_seconds,
        state_capacity=state_capacity,
    )
    attach_gradio_capacity(blocks, blocks.app)


def attach_gradio_capacity(blocks, mounted_app) -> None:
    """Attach after mounting, because Gradio creates a new app/state holder."""
    if not isinstance(getattr(blocks, "scap_capacity", None), GradioCapacity):
        raise RuntimeError(_COMPATIBILITY_ERROR)
    blocks.scap_capacity.attach_app(mounted_app)
