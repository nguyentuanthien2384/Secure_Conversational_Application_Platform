from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from src.app import maintenance
from src.app.audit_chain import derive_audit_key, seal_event
from src.app.audit_checkpoint import AuditCheckpointService
from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.maintenance import SecurityMaintenance
from src.app.models import AuditCheckpoint, AuditEvent, ChatSession, User


@pytest.fixture
def database(settings):
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.engine.dispose()


@pytest.fixture
def enabled(settings):
    return replace(settings, security_maintenance_enabled=True)


@pytest.fixture
def events(monkeypatch):
    records = []
    monkeypatch.setattr(
        maintenance, "emit_security_event", lambda event, **data: records.append((event, data))
    )
    return records


@pytest.fixture
def clock(monkeypatch):
    current = [100_000.0]
    # Patch only the maintenance module's clock, not asyncio's global clock.
    monkeypatch.setattr(maintenance, "time", SimpleNamespace(monotonic=lambda: current[0]))
    return current


def _failed_logins(database, count=5):
    with database.session_factory() as db:
        for _ in range(count):
            db.add(
                AuditEvent(
                    event_type="auth.login",
                    outcome="failure",
                    ip_address="192.0.2.40",
                    details_json='{"password":"never-log-this-secret"}',
                )
            )
        db.commit()


def _expired_sessions(database, count=3):
    with database.session_factory() as db:
        owner = User(username="retention.owner", password_hash="unused-hash")
        db.add(owner)
        db.flush()
        for index in range(count):
            db.add(
                ChatSession(
                    owner_id=owner.id,
                    title=f"Expired {index}",
                    retention_expires_at=utcnow() - timedelta(days=1),
                )
            )
        db.commit()


def test_default_is_disabled_and_does_not_start_a_task(settings, database):
    worker = SecurityMaintenance(settings, session_factory=database.session_factory)
    # Disabled startup needs no running asyncio event loop.
    worker.start()
    assert worker._task is None
    assert worker.run_once() == {"status": "disabled"}


def test_anomaly_alerts_run_without_admin_polling_and_deduplicate(
    enabled, database, clock, events
):
    _failed_logins(database)
    worker = SecurityMaintenance(enabled, session_factory=database.session_factory)
    result = worker.run_once()
    assert result["anomalies_emitted"] == 1
    assert events[0][0] == "ids.anomaly"
    details = events[0][1]["details"]
    assert details["code"] == "IDS-BRUTEFORCE"
    assert details["count"] == 5
    assert details["response"] == "observe"
    assert "never-log-this-secret" not in json.dumps(events)
    assert "192.0.2.40" not in json.dumps(events)
    assert worker.run_once() == {"status": "not_due"}
    clock[0] += enabled.security_maintenance_interval_seconds
    assert worker.run_once()["anomalies_emitted"] == 0
    # Severity escalation is actionable even while the medium alert is suppressed.
    _failed_logins(database, count=5)
    clock[0] += enabled.security_maintenance_interval_seconds
    assert worker.run_once()["anomalies_emitted"] == 1
    assert events[-1][1]["details"]["anomaly_severity"] == "high"
    clock[0] += enabled.security_maintenance_anomaly_window_minutes * 60
    assert worker.run_once()["anomalies_emitted"] == 1


def test_retention_requires_separate_opt_in_and_deletes_only_one_batch(
    enabled, database, clock, events
):
    _expired_sessions(database)
    cache_clears = []
    worker = SecurityMaintenance(enabled, session_factory=database.session_factory)
    worker.run_once()
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ChatSession)) == 3
    worker = SecurityMaintenance(
        replace(
            enabled,
            security_maintenance_retention_enabled=True,
            security_maintenance_batch_size=2,
        ),
        session_factory=database.session_factory,
        clear_crypto_cache=lambda: cache_clears.append(True),
    )
    assert worker.run_once()["retention"]["expired_sessions"] == 2
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ChatSession)) == 1
    assert cache_clears == [True]
    clock[0] += enabled.security_maintenance_interval_seconds
    assert worker.run_once()["retention"]["expired_sessions"] == 1
    assert cache_clears == [True, True]
    assert [item[0] for item in events] == ["retention.sweep", "retention.sweep"]


def test_checkpoint_catches_up_a_quiet_tail_below_request_threshold(
    enabled, database, tmp_path, monkeypatch
):
    credential = tmp_path / "worm-token"
    credential.write_text("test-token", encoding="utf-8")
    checkpoint = AuditCheckpointService(
        enabled.secret_key,
        interval=100,
        endpoint="https://worm.example.test/checkpoints",
        token_file=str(credential),
    )
    deliveries = []

    def deliver(document, checkpoint_id):
        deliveries.append(checkpoint_id)
        return "sha256:" + "a" * 64

    monkeypatch.setattr(checkpoint, "_deliver", deliver)
    with database.session_factory() as db:
        event = AuditEvent(event_type="test.quiet-tail", outcome="success", details_json="{}")
        seal_event(db, event, derive_audit_key(enabled.secret_key))
        db.add(event)
        db.commit()
        assert checkpoint.maybe_anchor(db, event) is None
    worker = SecurityMaintenance(
        enabled,
        session_factory=database.session_factory,
        checkpoint_service=checkpoint,
    )
    result = worker.run_once()
    assert result["status"] == "completed"
    assert result["checkpoint_unanchored_events"] == 0
    assert result["checkpoint_externally_delivered"] is True
    assert len(deliveries) == 1


def test_corrupted_existing_checkpoint_is_not_replaced(enabled, database, events):
    checkpoint = AuditCheckpointService(enabled.secret_key)
    with database.session_factory() as db:
        event = AuditEvent(event_type="test.original", outcome="success", details_json="{}")
        seal_event(db, event, derive_audit_key(enabled.secret_key))
        db.add(event)
        db.commit()
        anchor = checkpoint.anchor(db)
        anchor.signature = "0" * 64
        db.commit()
        event = AuditEvent(event_type="test.new", outcome="success", details_json="{}")
        seal_event(db, event, derive_audit_key(enabled.secret_key))
        db.add(event)
        db.commit()
    worker = SecurityMaintenance(
        enabled, session_factory=database.session_factory, checkpoint_service=checkpoint
    )
    assert worker.run_once()["failed_phases"] == ["checkpoint"]
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(AuditCheckpoint)) == 1


def test_failed_phase_does_not_stop_retention_or_disclose_exception(
    enabled, database, events, monkeypatch
):
    _expired_sessions(database, count=1)
    checkpoint = AuditCheckpointService(enabled.secret_key)

    def fail(_db):
        raise RuntimeError("https://admin:private-secret@database.invalid")

    monkeypatch.setattr(checkpoint, "verify_latest", fail)
    worker = SecurityMaintenance(
        replace(enabled, security_maintenance_retention_enabled=True),
        session_factory=database.session_factory,
        checkpoint_service=checkpoint,
    )
    result = worker.run_once()
    assert result["status"] == "degraded"
    assert result["failed_phases"] == ["checkpoint"]
    assert result["retention"]["expired_sessions"] == 1
    assert "private-secret" not in json.dumps([result, events])


class _FakeRedis:
    def __init__(self, clock):
        self.clock = clock
        self.keys = {}

    def set(self, name, value, *, nx, ex):
        assert nx is True
        if self.keys.get(name, 0) > self.clock[0]:
            return False
        self.keys[name] = self.clock[0] + ex
        return True


def test_redis_coordinates_cadence_and_alerts_across_workers(
    enabled, database, clock, events, monkeypatch
):
    client = _FakeRedis(clock)
    monkeypatch.setattr(maintenance.redis.Redis, "from_url", lambda *a, **kw: client)
    configured = replace(enabled, redis_url="redis://localhost/0")
    _failed_logins(database)
    first = SecurityMaintenance(configured, session_factory=database.session_factory)
    second = SecurityMaintenance(configured, session_factory=database.session_factory)
    assert first.run_once()["anomalies_emitted"] == 1
    assert second.run_once()["status"] == "not_due"
    clock[0] += configured.security_maintenance_interval_seconds
    # A different worker leads the next cycle without duplicating the alert.
    assert second.run_once()["anomalies_emitted"] == 0
    assert len(events) == 1


def test_coordination_outage_skips_mutations(enabled, database, events, monkeypatch):
    _expired_sessions(database, count=1)
    worker = SecurityMaintenance(
        replace(enabled, security_maintenance_retention_enabled=True),
        session_factory=database.session_factory,
    )

    def unavailable(*args, **kwargs):
        raise RuntimeError("redis://user:private-secret@localhost")

    worker._redis = SimpleNamespace(set=unavailable)
    result = worker.run_once()
    assert result["failed_phases"] == ["coordination"]
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(ChatSession)) == 1
    assert "private-secret" not in json.dumps([result, events])


class _FakeConnection:
    def __init__(self, *, acquired=True, unlock_fails=False):
        self.acquired = acquired
        self.unlock_fails = unlock_fails
        self.held = False
        self.invalidated = False

    def execution_options(self, **options):
        assert options == {"isolation_level": "AUTOCOMMIT"}
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        assert not self.held or self.invalidated

    def scalar(self, query, params):
        assert "pg_try_advisory_lock" in str(query)
        self.held = self.acquired
        return self.acquired

    def execute(self, query, params):
        assert "pg_advisory_unlock" in str(query)
        if self.unlock_fails:
            raise RuntimeError("Connection lost")
        self.held = False

    def invalidate(self):
        self.invalidated = True


@pytest.mark.parametrize("acquired,unlock_fails", [(True, False), (False, False), (True, True)])
def test_postgres_lock_spans_phases_and_cannot_leak_into_pool(
    enabled, database, monkeypatch, acquired, unlock_fails, events
):
    worker = SecurityMaintenance(enabled, session_factory=database.session_factory)
    connection = _FakeConnection(acquired=acquired, unlock_fails=unlock_fails)
    worker.engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"), connect=lambda: connection
    )
    observed = []
    monkeypatch.setattr(worker, "_check_anomalies", lambda result: observed.append(connection.held))
    result = worker.run_once()
    assert observed == ([True] if acquired else [])
    assert connection.invalidated is unlock_fails
    assert result["status"] == ("degraded" if unlock_fails else "completed" if acquired else "busy")


def test_lifespan_shutdown_waits_for_current_cycle(enabled, database, monkeypatch):
    started = threading.Event()
    release = threading.Event()
    worker = SecurityMaintenance(enabled, session_factory=database.session_factory)

    def slow_cycle():
        started.set()
        assert release.wait(timeout=3)
        return {"status": "completed"}

    monkeypatch.setattr(worker, "run_once", slow_cycle)

    async def scenario():
        worker.start()
        original_task = worker._task
        worker.start()
        assert worker._task is original_task
        assert await asyncio.to_thread(started.wait, 1)
        stopping = asyncio.create_task(worker.stop())
        await asyncio.sleep(0)
        assert not stopping.done()
        release.set()
        await asyncio.wait_for(stopping, 2)
        assert worker._task is None

    asyncio.run(scenario())


def test_application_lifespan_drains_worker_before_disposing_database(enabled, monkeypatch):
    from fastapi.testclient import TestClient

    from src.app.main import create_app

    app = create_app(replace(enabled, retention_sweep_on_startup=False))
    worker = app.state.security_maintenance
    ordering = []
    original_stop = worker.stop
    original_dispose = app.state.database.engine.dispose

    async def stop():
        assert ordering == []
        await original_stop()
        assert worker._task is None
        ordering.append("stopped")

    def dispose():
        assert ordering == ["stopped"]
        ordering.append("disposed")
        original_dispose()

    monkeypatch.setattr(worker, "stop", stop)
    monkeypatch.setattr(app.state.database.engine, "dispose", dispose)
    with TestClient(app):
        assert worker._task is not None
    assert ordering == ["stopped", "disposed"]


@pytest.mark.parametrize(
    "name,value",
    [
        ("SECURITY_MAINTENANCE_INTERVAL_SECONDS", "0"),
        ("SECURITY_MAINTENANCE_INTERVAL_SECONDS", "86401"),
        ("SECURITY_MAINTENANCE_BATCH_SIZE", "5001"),
        ("SECURITY_MAINTENANCE_BATCH_SIZE", "many"),
        ("SECURITY_MAINTENANCE_ANOMALY_WINDOW_MINUTES", "0"),
        ("SECURITY_MAINTENANCE_ANOMALY_WINDOW_MINUTES", "1441"),
    ],
)
def test_maintenance_env_limits_are_validated(monkeypatch, name, value):
    monkeypatch.setattr("src.app.config.load_dotenv", lambda: None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match=name):
        Settings.from_env()
