"""Exercise persistent IDS through real application instances and admin routes."""
from __future__ import annotations

import asyncio
import threading

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.exc import OperationalError

from src.app.ids import Detection, PersistentIntrusionState
from src.app.main import create_app
from tests.test_privileged_step_up import ADMIN_PASSWORD, auth, create_account, login


def block_source(app):
    hit = Detection(
        rule_id="RUNTIME-TEST", severity="high", engine="test", description="Runtime test",
        source_ip="192.0.2.44", path="/test", method="GET", evidence_sha256="0" * 64,
    )
    app.state.intrusion_state.record(hit)
    app.state.intrusion_state.record(hit)


def test_running_apps_share_ids_and_unblock_through_admin_api(client, app, settings):
    assert isinstance(app.state.intrusion_state, PersistentIntrusionState)
    create_account(app, "shared-ids-admin", role="admin")
    token = login(client, "shared-ids-admin", ADMIN_PASSWORD)
    block_source(app)
    second = create_app(settings)
    with TestClient(second) as other:
        assert second.state.intrusion_state.is_blocked("192.0.2.44")[0]
        response = other.get("/api/admin/ids/detections", headers=auth(token))
        assert response.status_code == 200 and len(response.json()) == 2
        response = other.delete("/api/admin/ids/blocklist/192.0.2.44", headers=auth(token))
        assert response.status_code == 204, response.text
        assert app.state.intrusion_state.is_blocked("192.0.2.44") == (False, 0)


def test_unblock_is_rolled_back_with_failed_admin_audit(client, app):
    create_account(app, "unblock-atomic-admin", role="admin")
    token = login(client, "unblock-atomic-admin", ADMIN_PASSWORD)
    block_source(app)

    def fail_audit(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().lower().startswith("insert into audit_events"):
            raise OperationalError("audit unavailable", None, RuntimeError("test storage fault"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_audit)
    try:
        result = client.delete("/api/admin/ids/blocklist/192.0.2.44", headers=auth(token))
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_audit)
    assert result.status_code == 503
    assert app.state.intrusion_state.is_blocked("192.0.2.44")[0]


def test_ids_storage_does_not_run_on_the_async_request_loop(client, app, monkeypatch):
    threads = []

    def inspect_source(source):
        threads.append(threading.get_ident())
        return False, 0

    monkeypatch.setattr(app.state.intrusion_state, "is_blocked", inspect_source)

    async def request():
        loop_thread = threading.get_ident()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as api:
            result = await api.get("/api/health")
        assert result.status_code == 200
        assert threads and all(thread != loop_thread for thread in threads)

    asyncio.run(request())


def test_unavailable_ids_store_fails_closed_without_leaking_database_error(client, app, monkeypatch):
    def unavailable(source):
        raise OperationalError("private database address", None, RuntimeError("private error"))

    monkeypatch.setattr(app.state.intrusion_state, "is_blocked", unavailable)
    response = client.get("/api/health")
    assert response.status_code == 503
    assert response.headers["Retry-After"]
    assert response.headers["X-Request-ID"]
    assert "private" not in response.text
