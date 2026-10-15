"""Runtime IDS state must outlive a worker and serialize cross-worker decisions."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest
from sqlalchemy import func, inspect, select, text

from src.app.db import Database
from src.app.ids import Detection, PersistentIntrusionState
from src.app.models import IntrusionDetection, IntrusionSource


def _detection(ip="192.0.2.1", severity="high"):
    return Detection(
        rule_id="SQLI-001", severity=severity, engine="signature",
        description="SQL injection signature", source_ip=ip,
        path="/api/health", method="GET", evidence_sha256="1" * 16,
    )


@pytest.fixture
def database(tmp_path):
    database = Database(f"sqlite:///{tmp_path / 'ids.db'}")
    database.create_all()
    yield database
    database.engine.dispose()


def test_records_and_bans_are_shared_and_survive_new_database_instance(database):
    first = PersistentIntrusionState(database.session_factory)
    second_database = Database(str(database.engine.url))
    try:
        second = PersistentIntrusionState(second_database.session_factory)
        assert not first.record(_detection())
        assert second.record(_detection())
        assert first.is_blocked("192.0.2.1")[0]
        assert len(first.recent()) == len(second.recent()) == 2
        assert second.blocked_sources()[0]["source_ip"] == "192.0.2.1"
        assert first.unblock("192.0.2.1")
        assert second.is_blocked("192.0.2.1") == (False, 0)
        assert not second.record(_detection())
    finally:
        second_database.engine.dispose()


def test_restart_expiry_and_rolling_window_use_utc_not_monotonic(database, monkeypatch):
    now = [datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)]
    monkeypatch.setattr("src.app.ids.utcnow", lambda: now[0])
    first = PersistentIntrusionState(database.session_factory, block_seconds=10)
    first.record(_detection())
    assert first.record(_detection())
    now[0] += timedelta(seconds=10)
    restarted = PersistentIntrusionState(database.session_factory, block_seconds=10)
    assert restarted.is_blocked("192.0.2.1") == (False, 0)
    assert restarted.blocked_sources() == []
    assert not restarted.record(_detection())
    now[0] += timedelta(seconds=10)
    assert not restarted.record(_detection())
    assert restarted.record(_detection())


def test_concurrent_workers_do_not_lose_scores_or_duplicate_block_transition(database):
    workers = 12
    barrier = Barrier(workers)

    def record_from_worker(_):
        worker_db = Database(str(database.engine.url))
        try:
            state = PersistentIntrusionState(worker_db.session_factory, block_threshold=workers)
            barrier.wait(timeout=15)
            return state.record(_detection(severity="low"))
        finally:
            worker_db.engine.dispose()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        transitions = list(executor.map(record_from_worker, range(workers)))
    assert sum(transitions) == 1
    state = PersistentIntrusionState(database.session_factory, block_threshold=workers)
    assert state.is_blocked("192.0.2.1")[0]
    assert len(state.recent()) == workers


def test_capacity_pruning_preserves_bans_and_bounds_retained_data(database, monkeypatch):
    now = [datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)]
    monkeypatch.setattr("src.app.ids.utcnow", lambda: now[0])
    state = PersistentIntrusionState(
        database.session_factory, block_threshold=3, block_seconds=10, history=4, max_sources=2,
    )
    assert state.record(_detection("192.0.2.1"))
    assert not state.record(_detection("192.0.2.2", "low"))
    assert state.record(_detection("192.0.2.3"))
    assert not state.record(_detection("192.0.2.4"))
    for _ in range(10):
        assert not state.record(_detection("192.0.2.1"))
    assert {row["source_ip"] for row in state.blocked_sources()} == {"192.0.2.1", "192.0.2.3"}
    assert len(state.recent(1000)) == 4
    assert state.recent(0) == []
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(IntrusionSource)) == 2
        assert db.scalar(select(func.count()).select_from(IntrusionDetection)) == 4
        assert len(json.loads(db.get(IntrusionSource, "192.0.2.1").score_times_json)) == 3
    now[0] += timedelta(seconds=11)
    assert not state.record(_detection("192.0.2.5", "low"))
    with database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(IntrusionSource)) == 1


def test_detection_storage_contains_only_existing_sanitized_fields(database):
    state = PersistentIntrusionState(database.session_factory)
    detection = _detection()
    state.record(detection)
    assert state.recent() == [detection.as_dict()]
    with database.session_factory() as db:
        row = db.scalar(select(IntrusionDetection))
        assert json.loads(row.payload_json) == detection.as_dict()


def test_schema_upgrade_is_idempotent_and_runtime_rejects_missing_ids_table(database):
    database.create_all()
    database.assert_schema_ready()
    assert {"intrusion_sources", "intrusion_detections"} <= set(inspect(database.engine).get_table_names())
    with database.engine.begin() as conn:
        conn.execute(text("DROP TABLE intrusion_sources"))
    with pytest.raises(RuntimeError, match="intrusion_sources"):
        database.assert_schema_ready()


@pytest.mark.parametrize(
    "kwargs", [{"block_threshold": 0}, {"block_seconds": 0}, {"history": 0}, {"max_sources": 0}],
)
def test_persistent_state_rejects_invalid_limits(database, kwargs):
    with pytest.raises(ValueError, match="must be positive"):
        PersistentIntrusionState(database.session_factory, **kwargs)
