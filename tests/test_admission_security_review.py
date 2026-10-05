from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from src.app.audit import record_audit, sign_ui_client_context
from src.app.availability import (
    AdmissionMiddleware,
    AvailabilityMonitor,
    CapacityBudget,
    ReadinessProbe,
)
from src.app.main import create_app
from src.app.models import AuditEvent
from src.app.security import SlidingWindowRateLimiter
from tests.conftest import register_and_login


def scope_for(path="/api/test", *, ip="192.0.2.10", method="GET", headers=(), context_key=None):
    return {
        "type": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
        "method": method, "headers": list(headers), "scheme": "http",
        "client": (ip, 12345), "server": ("testserver", 80),
        "app": SimpleNamespace(state=SimpleNamespace(ui_client_context_key=context_key)),
    }


def middleware_for(settings, app, *, shared=None, requests=None, streams=None):
    return AdmissionMiddleware(
        app, settings=settings, monitor=AvailabilityMonitor(),
        requests=requests or CapacityBudget(2), streams=streams or CapacityBudget(1),
        shared_limiter=shared,
    )


async def exercise(middleware, scope):
    sent = []
    reads = []

    async def receive():
        reads.append(True)
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    await middleware(scope, receive, send)
    return sent[0]["status"], reads


async def accept(scope, receive, send):
    await receive()
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b""})


def test_same_peer_cannot_rotate_forwarded_headers_to_evade_admission(settings):
    middleware = middleware_for(replace(settings, request_ip_max_attempts=1), accept)

    async def scenario():
        first = await exercise(middleware, scope_for(headers=[(b"x-forwarded-for", b"198.51.100.1")]))
        second = await exercise(middleware, scope_for(headers=[(b"x-forwarded-for", b"198.51.100.2")]))
        assert first == (204, [True])
        assert second == (429, [])

    asyncio.run(scenario())


def test_shared_global_budget_cannot_be_reset_by_switching_workers(settings):
    shared = SlidingWindowRateLimiter()
    configured = replace(settings, request_global_max_attempts=2)
    workers = [middleware_for(configured, accept, shared=shared) for _ in range(2)]

    async def scenario():
        assert (await exercise(workers[0], scope_for(ip="192.0.2.1")))[0] == 204
        assert (await exercise(workers[1], scope_for(ip="192.0.2.2")))[0] == 204
        assert await exercise(workers[0], scope_for(ip="192.0.2.3")) == (429, [])
        assert await exercise(workers[1], scope_for(ip="192.0.2.4")) == (429, [])

    asyncio.run(scenario())


def test_redis_failure_is_a_bounded_denial_and_releases_capacity(settings):
    class Unavailable:
        def allow(self, *args):
            raise TimeoutError("Redis unavailable")

    budget = CapacityBudget(1)
    middleware = middleware_for(settings, accept, requests=budget, shared=Unavailable())
    assert asyncio.run(exercise(middleware, scope_for())) == (503, [])
    assert budget.snapshot()["active"] == 0
    middleware.shared_limiter = None
    assert asyncio.run(exercise(middleware, scope_for()))[0] == 204


@pytest.mark.parametrize("path", [
    "/gradio_api/queue/data", "/gradio_api/queue/data/",
    "/gradio_api/call/do_login/event-id",
])
def test_exhausted_sse_budget_preserves_normal_request_capacity(settings, path):
    streams = CapacityBudget(1)
    assert streams.acquire()
    requests = CapacityBudget(1)
    middleware = middleware_for(settings, accept, requests=requests, streams=streams)
    assert asyncio.run(exercise(middleware, scope_for(path))) == (503, [])
    assert asyncio.run(exercise(middleware, scope_for()))[0] == 204
    streams.release()
    assert asyncio.run(exercise(middleware, scope_for(path)))[0] == 204
    assert streams.snapshot()["active"] == requests.snapshot()["active"] == 0


def test_capacity_slots_are_released_on_application_cancellation(settings):
    budget = CapacityBudget(1)

    async def scenario():
        entered = asyncio.Event()

        async def blocked(scope, receive, send):
            entered.set()
            await asyncio.Event().wait()

        middleware = middleware_for(settings, blocked, requests=budget)
        task = asyncio.create_task(exercise(middleware, scope_for()))
        await entered.wait()
        assert await exercise(middleware, scope_for(ip="192.0.2.11")) == (503, [])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert budget.snapshot()["active"] == 0
        middleware.app = accept
        assert (await exercise(middleware, scope_for()))[0] == 204

    asyncio.run(scenario())


def test_capacity_slots_are_released_on_unexpected_application_error(settings):
    async def broken(scope, receive, send):
        raise RuntimeError("application error")

    budget = CapacityBudget(1)
    middleware = middleware_for(settings, broken, requests=budget)
    with pytest.raises(RuntimeError, match="application error"):
        asyncio.run(exercise(middleware, scope_for()))
    assert budget.snapshot()["active"] == 0


def test_reentrant_ui_call_fails_promptly_when_request_budget_is_full(settings):
    total = CapacityBudget(1)

    async def downstream(scope, receive, send):
        assert scope["path"] == "/gradio_api/queue/join"
        status, reads = await exercise(middleware, scope_for(
            "/api/auth/login", ip="127.0.0.1", method="POST",
        ))
        assert (status, reads) == (503, [])
        await accept(scope, receive, send)

    middleware = middleware_for(settings, downstream, requests=total)

    async def scenario():
        response = await asyncio.wait_for(exercise(middleware, scope_for(
            "/gradio_api/queue/join", method="POST",
        )), timeout=1)
        assert response[0] == 204
        assert total.snapshot()["active"] == 0
        assert not middleware._sources

    asyncio.run(scenario())


def test_one_source_cannot_fill_other_clients_request_slots(settings):
    configured = replace(settings, request_ip_max_concurrent=1)
    total = CapacityBudget(2)

    async def scenario():
        entered = asyncio.Event()

        async def blocked(scope, receive, send):
            if scope["client"][0] == "192.0.2.10":
                entered.set()
                await asyncio.Event().wait()
            else:
                await accept(scope, receive, send)

        middleware = middleware_for(configured, blocked, requests=total)
        task = asyncio.create_task(exercise(middleware, scope_for()))
        await entered.wait()
        assert await exercise(middleware, scope_for()) == (503, [])
        assert (await exercise(middleware, scope_for(ip="192.0.2.11")))[0] == 204
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert total.snapshot()["active"] == 0
        assert not middleware._sources

    asyncio.run(scenario())


def test_verified_ui_context_has_browser_budget_without_trusting_plain_ip_headers(settings):
    context_key = b"server-side-test-context-key"
    middleware = middleware_for(replace(settings, request_ip_max_attempts=1), accept)

    def browser(ip):
        headers = [(key.lower().encode(), value.encode()) for key, value in
                   sign_ui_client_context(context_key, ip, "test browser").items()]
        return scope_for(ip="127.0.0.1", headers=headers, context_key=context_key)

    async def scenario():
        assert (await exercise(middleware, browser("192.0.2.1")))[0] == 204
        assert (await exercise(middleware, browser("192.0.2.2")))[0] == 204
        assert await exercise(middleware, browser("192.0.2.1")) == (429, [])

    asyncio.run(scenario())


def test_busy_password_budget_returns_retryable_error_without_hashing(client, app):
    budget = app.state.password_service.capacity
    for _ in range(budget.maximum):
        assert budget.acquire()
    try:
        response = client.post("/api/auth/login", json={
            "username": "nonexistent", "password": "Correct Horse Battery1",
        })
        assert response.status_code == 503
        assert int(response.headers["retry-after"]) > 0
    finally:
        for _ in range(budget.maximum):
            budget.release()
    assert client.post("/api/auth/login", json={
        "username": "nonexistent", "password": "Correct Horse Battery1",
    }).status_code == 401
    assert budget.snapshot()["active"] == 0


def test_liveness_does_not_open_database_session(client, app, monkeypatch):
    def fail_if_database_used():
        raise AssertionError("Liveness queried the database")

    monkeypatch.setattr(app.state.database, "session_factory", fail_if_database_used)
    assert client.get("/api/health").status_code == 200


def test_readiness_success_cache_and_failure_recovery_are_bounded(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("src.app.availability.time.monotonic", lambda: now[0])
    probe = ReadinessProbe(5)
    checks = []

    def success():
        checks.append(True)
        return True

    assert probe.check(success, cache_success=True)
    assert probe.check(lambda: pytest.fail("cache not used"), cache_success=True)
    now[0] += 5
    assert not probe.check(lambda: False, cache_success=True)
    assert probe.check(success, cache_success=True)
    assert len(checks) == 2
    # High-security callers explicitly bypass any earlier successful cache.
    assert not probe.check(lambda: False, cache_success=False)
    assert probe.check(success, cache_success=False)
    assert probe.capacity.snapshot()["active"] == 0


def test_high_profile_readiness_reports_dependency_loss_and_recovery_immediately(settings, monkeypatch):
    class Checkpoint:
        available = True

        def ensure_latest_anchored(self, *args, **kwargs):
            return SimpleNamespace(fully_anchored=self.available)

        def maybe_anchor(self, *args):
            return None

    checkpoint = Checkpoint()
    monkeypatch.setattr("src.app.main.AuditCheckpointService", lambda *args, **kwargs: checkpoint)
    configured = replace(settings, security_profile="high", audit_worm_endpoint="https://fake-worm.example")
    application = create_app(configured)
    with TestClient(application) as client:
        assert client.get("/api/ready").status_code == 200
        checkpoint.available = False
        assert client.get("/api/ready").status_code == 503
        checkpoint.available = True
        assert client.get("/api/ready").status_code == 200


def test_availability_metrics_require_admin_role(client):
    assert client.get("/api/admin/availability").status_code == 401
    token = register_and_login(client, "availability-ordinary-user")
    assert client.get("/api/admin/availability", headers={
        "Authorization": f"Bearer {token}",
    }).status_code == 403


def test_only_anonymous_rate_denials_are_sampled_while_credential_failure_is_durable(app, client):
    request = Request(scope_for())
    request.scope["app"] = app
    with app.state.database.session_factory() as db:
        first = record_audit(db, request, "auth.login", outcome="blocked", details={"reason": "rate_limit"})
        second = record_audit(db, request, "auth.login", outcome="blocked", details={"reason": "rate_limit"})
        failure = record_audit(db, request, "auth.login", outcome="failure", details={"reason": "invalid_credentials"})
        assert first is not None and second is None and failure is not None
        assert list(db.scalars(select(AuditEvent).where(AuditEvent.event_type == "auth.login"))) == [first, failure]
    snapshot = app.state.availability_monitor.snapshot()
    assert snapshot["rejections"]["anonymous_rate_denials"] == 2
    assert snapshot["anonymous_audit_suppressed"] == 1


@pytest.mark.parametrize("name, value", [
    ("request_max_concurrent", 0), ("request_max_streams", -1),
    ("request_global_max_attempts", True), ("request_ip_max_attempts", 1.5),
    ("password_max_concurrent", 0), ("gradio_queue_max_size", 0),
])
def test_availability_configuration_cannot_disable_limits(settings, name, value):
    with pytest.raises(ValueError):
        create_app(replace(settings, **{name: value}))
