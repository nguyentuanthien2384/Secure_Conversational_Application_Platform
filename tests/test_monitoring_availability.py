"""Operational monitoring remains finite and covers admission failures and SSE."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest

from src.app.availability import AdmissionMiddleware, AvailabilityMonitor, CapacityBudget
from src.app.request_limits import MAX_URI_BYTES


@dataclass
class Clock:
    now: float = 100.0

    def __call__(self):
        return self.now


def scope_for(path="/api/health", *, method="GET", query=b"", headers=()):
    return {
        "type": "http", "path": path, "raw_path": path.encode(), "query_string": query,
        "method": method, "headers": list(headers), "scheme": "http",
        "client": ("192.0.2.12", 9999), "server": ("testserver", 80),
        "app": SimpleNamespace(state=SimpleNamespace(ui_client_context_key=None)),
    }


def middleware(settings, monitor, app):
    return AdmissionMiddleware(
        app, settings=settings, monitor=monitor,
        requests=CapacityBudget(2), streams=CapacityBudget(1),
    )


async def receive():
    return {"type": "http.request", "body": b"", "more_body": False}


async def send(_):
    pass


def test_recent_ring_expires_on_idle_and_reuses_slots_without_history_growth():
    clock = Clock()
    monitor = AvailabilityMonitor(clock=clock)
    monitor.observe_response(503, 0.3, streaming=False)
    clock.now += 59
    assert monitor.snapshot()["http_recent"]["requests"] == 1
    clock.now += 1
    assert monitor.snapshot()["http_recent"]["requests"] == 0
    for second in range(10000):
        clock.now = 200 + second
        monitor.observe_response(200, 0.1, streaming=False)
    assert len(monitor._response_buckets) == 60
    assert monitor.snapshot()["http_recent"]["requests"] == 60
    clock.now += 600
    assert monitor.snapshot()["http_recent"]["requests"] == 0


def test_histogram_has_fixed_nonoverlapping_bins_and_excludes_unanswered_latency():
    monitor = AvailabilityMonitor(clock=Clock())
    for status, seconds in ((101, 0.1), (200, 0.5), (302, 1), (403, 5), (503, 10), (500, 11)):
        monitor.observe_response(status, seconds, streaming=False)
    monitor.observe_response(None, 999, streaming=True)
    recent = monitor.snapshot()["http_recent"]
    assert recent["requests"] == 7 and recent["responses"] == 6
    assert recent["status_classes"] == {
        "1xx": 1, "2xx": 1, "3xx": 1, "4xx": 1, "5xx": 2, "unanswered": 1,
    }
    assert list(recent["latency_buckets_ms"].values()) == [1, 1, 1, 1, 1, 1]
    assert recent["average_latency_ms"] == 4600.0
    assert recent["slow_responses"] == 3
    assert recent["request_kinds"] == {"regular": 6, "stream": 1}


@pytest.mark.parametrize("latency", [-1.0, float("nan"), float("inf")])
def test_nonfinite_or_negative_measurements_cannot_poison_admin_snapshot(latency):
    monitor = AvailabilityMonitor(clock=Clock())
    monitor.observe_response(200, latency, streaming=False)
    recent = monitor.snapshot()["http_recent"]
    assert recent["average_latency_ms"] == 0
    assert recent["latency_buckets_ms"]["0_100"] == 1


def test_alerts_require_volume_then_clear_when_the_recent_window_expires():
    clock = Clock()
    monitor = AvailabilityMonitor(clock=clock)
    for _ in range(4):
        monitor.observe_response(503, 2, streaming=False)
    assert monitor.snapshot()["alerts"] == []
    monitor.observe_response(503, 2, streaming=False)
    assert {alert["code"] for alert in monitor.snapshot()["alerts"]} == {
        "http_overload", "http_server_errors",
    }
    for _ in range(15):
        monitor.observe_response(200, 0.1, streaming=False)
    assert "http_slow_headers" in {alert["code"] for alert in monitor.snapshot()["alerts"]}
    clock.now += 60
    assert monitor.snapshot()["alerts"] == []


def test_slow_or_error_ratio_below_threshold_does_not_raise_alert():
    monitor = AvailabilityMonitor(clock=Clock())
    for _ in range(101):
        monitor.observe_response(200, 0.1, streaming=False)
    for _ in range(5):
        monitor.observe_response(500, 2, streaming=False)
    assert monitor.snapshot()["alerts"] == []


def test_labels_and_log_summaries_cannot_retain_untrusted_dimensions(monkeypatch):
    clock = Clock()
    monitor = AvailabilityMonitor(clock=clock)
    emitted = []
    monkeypatch.setattr("src.app.availability.emit_security_event", lambda *a, **kw: emitted.append(kw))
    for number in range(1000):
        monitor.reject(f"/private/{number}?token=credential")
        monitor.sample_anonymous_audit(f"192.0.2.{number}")
    assert len(monitor._counts) == 2
    assert set(monitor._audit_samples) == {"other"}
    assert "credential" not in repr(monitor.snapshot()) + repr(emitted)
    assert "192.0.2." not in repr(monitor.snapshot()) + repr(emitted)
    assert emitted[0]["details"]["reason"] == "other"


def test_summary_sampling_and_recent_metrics_use_the_same_injected_clock(monkeypatch):
    clock = Clock()
    monitor = AvailabilityMonitor(clock=clock)
    emitted = []
    monkeypatch.setattr("src.app.availability.emit_security_event", lambda *a, **kw: emitted.append(kw))
    monitor.reject("request_rate")
    monitor.reject("request_rate")
    assert len(emitted) == 1
    assert monitor.sample_anonymous_audit("auth.login") == 0
    assert monitor.sample_anonymous_audit("auth.login") is None
    clock.now += 60
    monitor.reject("request_rate")
    assert len(emitted) == 2
    assert emitted[-1]["details"]["rejections_since_previous_summary"] == 2
    assert monitor.sample_anonymous_audit("auth.login") == 1


def test_concurrent_updates_preserve_counts_in_the_fixed_ring():
    monitor = AvailabilityMonitor(clock=Clock())

    def record(_):
        for _ in range(500):
            monitor.observe_response(200, 0.1, streaming=False)

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(record, range(4)))
    snapshot = monitor.snapshot()["http_recent"]
    assert snapshot["requests"] == 2000
    assert snapshot["average_latency_ms"] == 100
    assert len(monitor._response_buckets) == 60


def test_response_start_is_recorded_before_a_long_sse_finishes(settings):
    async def exercise():
        clock = Clock()
        monitor = AvailabilityMonitor(clock=clock)
        headers_sent = asyncio.Event()
        close_stream = asyncio.Event()

        async def streaming_app(scope, receive, send):
            clock.now += 0.25
            await send({"type": "http.response.start", "status": 200, "headers": []})
            headers_sent.set()
            await close_stream.wait()
            await send({"type": "http.response.body", "body": b"", "more_body": False})

        wrapped = middleware(settings, monitor, streaming_app)
        task = asyncio.create_task(wrapped(scope_for("/gradio_api/queue/data"), receive, send))
        await headers_sent.wait()
        recent = monitor.snapshot()["http_recent"]
        assert recent["requests"] == 1
        assert recent["request_kinds"] == {"regular": 0, "stream": 1}
        assert recent["average_latency_ms"] == 250
        clock.now += 120
        close_stream.set()
        await task
        assert monitor.snapshot()["http_recent"]["requests"] == 0
        assert wrapped.streams.snapshot()["active"] == 0

    asyncio.run(exercise())


@pytest.mark.parametrize("after_headers", [False, True])
def test_cancellation_records_once_and_releases_capacity(settings, after_headers):
    async def exercise():
        monitor = AvailabilityMonitor(clock=Clock())
        entered = asyncio.Event()

        async def hanging_app(scope, receive, send):
            if after_headers:
                await send({"type": "http.response.start", "status": 204, "headers": []})
            entered.set()
            await asyncio.Event().wait()

        wrapped = middleware(settings, monitor, hanging_app)
        task = asyncio.create_task(wrapped(scope_for(), receive, send))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        recent = monitor.snapshot()["http_recent"]
        assert recent["requests"] == 1
        assert recent["status_classes"]["2xx"] == int(after_headers)
        assert recent["status_classes"]["unanswered"] == int(not after_headers)
        assert wrapped.requests.snapshot()["active"] == 0

    asyncio.run(exercise())


def test_unhandled_error_records_no_headers_without_exposing_exception(settings):
    async def broken_app(scope, receive, send):
        raise RuntimeError("private credential in exception")

    monitor = AvailabilityMonitor(clock=Clock())
    wrapped = middleware(settings, monitor, broken_app)
    with pytest.raises(RuntimeError):
        asyncio.run(wrapped(scope_for("/private?secret=credential"), receive, send))
    assert monitor.snapshot()["http_recent"]["status_classes"]["unanswered"] == 1
    assert "credential" not in repr(monitor.snapshot())


def test_prehandler_throttle_is_observed_once_without_consuming_body(settings):
    async def accept(scope, receive, send):
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def forbidden_read():
        pytest.fail("admission should not read the body")

    monitor = AvailabilityMonitor(clock=Clock())
    wrapped = middleware(replace(settings, request_global_max_attempts=1), monitor, accept)
    asyncio.run(wrapped(scope_for(), forbidden_read, send))
    asyncio.run(wrapped(scope_for(), forbidden_read, send))
    recent = monitor.snapshot()["http_recent"]
    assert recent["requests"] == 2
    assert recent["status_classes"]["4xx"] == 1
    assert recent["throttled_responses"] == 1
    assert monitor.snapshot()["rejections"]["request_rate"] == 1


def test_metadata_rejection_and_non_http_scopes_are_handled_correctly(settings):
    async def boundary(scope, receive, send):
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 414, "headers": []})
            await send({"type": "http.response.body", "body": b""})

    monitor = AvailabilityMonitor(clock=Clock())
    wrapped = middleware(settings, monitor, boundary)
    asyncio.run(wrapped(scope_for("/" + "x" * MAX_URI_BYTES), receive, send))
    asyncio.run(wrapped({"type": "lifespan"}, receive, send))
    assert monitor.snapshot()["http_recent"]["requests"] == 1
    assert monitor.snapshot()["http_recent"]["status_classes"]["4xx"] == 1


def test_snapshot_is_independent_of_mutation_by_its_consumer():
    monitor = AvailabilityMonitor(clock=Clock())
    monitor.observe_response(503, 1, streaming=False)
    snapshot = monitor.snapshot()
    snapshot["http_recent"]["status_classes"]["5xx"] = 999
    snapshot["alerts"].append({"code": "external"})
    assert monitor.snapshot()["http_recent"]["status_classes"]["5xx"] == 1
    assert monitor.snapshot()["alerts"] == []
