from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from src.app import ids
from src.app.db import Database
from src.app.ids import detect_anomalies
from src.app.maintenance import SecurityMaintenance
from src.app.models import AuditEvent
from src.app.siem import SIEM_LOGGER_NAME, emit_security_event

NOW = datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
DISTRIBUTED = "IDS-DISTRIBUTED-BRUTEFORCE"
SEQUENCE = "IDS-AUTH-SUCCESS-AFTER-FAILURES"


@pytest.fixture
def database(monkeypatch):
    monkeypatch.setattr(ids, "utcnow", lambda: NOW)
    database = Database("sqlite:///:memory:")
    database.create_all()
    yield database
    database.engine.dispose()


@pytest.fixture
def db(database):
    with database.session_factory() as session:
        yield session


def event(
    db,
    *,
    actor="victim-account",
    source="192.0.2.1",
    outcome="failure",
    event_type="auth.login",
    seconds_ago=60,
):
    row = AuditEvent(
        actor_id=actor,
        event_type=event_type,
        outcome=outcome,
        ip_address=source,
        created_at=NOW - timedelta(seconds=seconds_ago),
        details_json='{"password":"never-expose-raw-evidence"}',
    )
    db.add(row)
    db.flush()
    return row


def findings(db, code, **kwargs):
    return [item for item in detect_anomalies(db, **kwargs) if item.code == code]


def test_distributed_guessing_detects_sources_below_each_ip_threshold(db):
    for index in range(5):
        last = event(db, source=f"192.0.2.{index + 1}")
    result = detect_anomalies(db)
    assert not any(item.code == "IDS-BRUTEFORCE" for item in result)
    assert [item.code for item in result] == [DISTRIBUTED]
    found = result[0]
    assert found.count == found.source_count == 5
    assert found.subject == "victim-account"
    assert found.mitre_technique == "T1110.001"
    assert found.evidence_event_id == last.id
    assert "never-expose-raw-evidence" not in json.dumps(found.as_dict())


@pytest.mark.parametrize("count,sources", [(4, 4), (5, 2), (6, 1)])
def test_distributed_requires_both_attempt_and_source_thresholds(db, count, sources):
    for index in range(count):
        event(db, source=f"192.0.2.{index % sources + 1}")
    assert not findings(db, DISTRIBUTED)


def test_distributed_does_not_merge_accounts_or_unknown_actors(db):
    for actor in (None, "", "alice", "bob"):
        for index in range(4):
            event(db, actor=actor, source=f"192.0.2.{index + 1}")
    assert not findings(db, DISTRIBUTED)


@pytest.mark.parametrize("source", [None, "", "unknown"])
def test_distributed_does_not_count_missing_sources_as_new_addresses(db, source):
    for index in range(5):
        event(db, source=f"192.0.2.{index % 2 + 1}")
        event(db, source=source)
    assert not findings(db, DISTRIBUTED)


@pytest.mark.parametrize("seconds_ago", [3601, -1])
def test_correlations_ignore_old_and_future_events(db, seconds_ago):
    for index in range(5):
        event(db, source=f"192.0.2.{index + 1}", seconds_ago=seconds_ago)
    event(db, outcome="success", seconds_ago=0)
    assert not findings(db, DISTRIBUTED)
    assert not findings(db, SEQUENCE)


def test_success_sequence_includes_exact_window_boundary(db):
    for _ in range(5):
        event(db, seconds_ago=3600)
    completion = event(db, outcome="success", seconds_ago=0)
    found = findings(db, SEQUENCE)[0]
    assert found.count == 5
    assert found.evidence_event_id == completion.id


@pytest.mark.parametrize("completed_event", ["auth.login", "auth.mfa.verify"])
def test_success_sequence_requires_completed_authentication(db, completed_event):
    for index in range(5):
        event(db, event_type="auth.login" if index < 3 else "auth.mfa.verify")
    event(db, event_type="auth.mfa.challenge", outcome="success", seconds_ago=30)
    assert not findings(db, SEQUENCE)
    completion = event(db, event_type=completed_event, outcome="success", seconds_ago=15)
    found = findings(db, SEQUENCE)[0]
    assert found.count == 5
    assert found.evidence_event_id == completion.id
    assert found.source_count == 1
    assert found.mitre_technique == "T1110"


def test_success_before_failures_or_other_actor_cannot_complete_sequence(db):
    event(db, outcome="success", seconds_ago=120)
    for _ in range(5):
        event(db)
    event(db, actor="another-account", outcome="success", seconds_ago=30)
    assert not findings(db, SEQUENCE)


def test_each_completed_authentication_resets_consecutive_failure_count(db):
    for _ in range(3):
        event(db, seconds_ago=120)
    event(db, outcome="success", seconds_ago=100)
    for _ in range(3):
        event(db, seconds_ago=90)
    event(db, outcome="success", seconds_ago=60)
    assert not findings(db, SEQUENCE)


def test_equal_timestamps_use_event_order_and_report_only_latest_episode(db):
    for _ in range(5):
        event(db)
    event(db, outcome="success")
    for _ in range(6):
        event(db)
    completion = event(db, outcome="success")
    result = findings(db, SEQUENCE)
    assert len(result) == 1
    assert result[0].count == 6
    assert result[0].evidence_event_id == completion.id


def test_backfilled_ids_do_not_override_timestamp_chronology(db):
    # Newer episode inserted first, then an older episode is backfilled with
    # larger IDs. Return the newer successful event, not the largest ID.
    for _ in range(6):
        event(db, seconds_ago=60)
    newest = event(db, outcome="success", seconds_ago=30)
    for _ in range(5):
        event(db, seconds_ago=180)
    older = event(db, outcome="success", seconds_ago=120)
    assert older.id > newest.id
    found = findings(db, SEQUENCE)[0]
    assert found.count == 6
    assert found.evidence_event_id == newest.id


def test_backfilled_failures_after_success_do_not_reverse_sequence(db):
    for _ in range(5):
        event(db, seconds_ago=60)
    event(db, outcome="success", seconds_ago=120)
    assert not findings(db, SEQUENCE)


def test_missing_actor_events_are_not_joined_into_one_success_sequence(db):
    for actor in (None, ""):
        for _ in range(5):
            event(db, actor=actor)
        event(db, actor=actor, outcome="success", seconds_ago=30)
    assert not findings(db, SEQUENCE)


def test_unknown_outcomes_are_not_treated_as_authentication_failures(db):
    for index in range(5):
        event(db, outcome="challenge", source=f"192.0.2.{index + 1}")
    event(db, outcome="success", seconds_ago=30)
    assert not findings(db, DISTRIBUTED)
    assert not findings(db, SEQUENCE)


def test_findings_are_bounded_with_deterministic_order(db, monkeypatch):
    monkeypatch.setattr(ids, "MAX_CORRELATION_FINDINGS", 2)
    for actor in ("c", "b", "a"):
        for index in range(5):
            event(db, actor=actor, source=f"192.0.2.{index + 1}")
        event(db, actor=actor, outcome="success", seconds_ago=30)
    assert [item.subject for item in findings(db, DISTRIBUTED)] == ["a", "b"]
    assert [item.subject for item in findings(db, SEQUENCE)] == ["a", "b"]


@pytest.mark.parametrize("options", [
    {"window_minutes": 0}, {"window_minutes": 1441},
    {"brute_force_threshold": 0}, {"spray_account_threshold": 0},
    {"idor_threshold": 0}, {"distributed_source_threshold": 1},
])
def test_invalid_correlation_limits_fail_explicitly(db, options):
    with pytest.raises(ValueError):
        detect_anomalies(db, **options)


def test_maintenance_emits_private_observational_correlations_to_ecs(
    database, settings, monkeypatch,
):
    with database.session_factory() as db:
        for index in range(5):
            event(db, source=f"192.0.2.{index + 1}")
        completion = event(db, outcome="success", seconds_ago=30)
        db.commit()
        success_id = completion.id
    records = []
    logger = logging.getLogger(SIEM_LOGGER_NAME)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "log", lambda _level, _msg, **data: records.append(
        data["extra"]["security_event"]
    ))
    worker = SecurityMaintenance(
        replace(settings, security_maintenance_enabled=True),
        session_factory=database.session_factory,
    )
    result = worker.run_once()
    assert result["anomalies_emitted"] == 2
    assert result["failed_phases"] == []
    by_code = {record["scap.code"]: record for record in records}
    for record in records:
        assert record["scap.response"] == "observe"
        assert record["scap.subject_sha256"] == hashlib.sha256(b"victim-account").hexdigest()
        assert record["scap.source_count"] == 5
        assert record["threat.technique.id"] == ["T1110"]
    assert by_code[DISTRIBUTED]["threat.technique.subtechnique.id"] == ["T1110.001"]
    assert by_code[SEQUENCE]["scap.evidence_event_id"] == success_id
    serialized = json.dumps(records)
    for private in ("victim-account", "192.0.2.", "never-expose-raw-evidence"):
        assert private not in serialized
    # Repeat scans preserve alert suppression and never mutate auth/audit state.
    next_result = {"anomalies_detected": 0, "anomalies_emitted": 0}
    worker._check_anomalies(next_result)
    assert next_result["anomalies_emitted"] == 0
    # Another complete suspicious sequence must not disappear behind the
    # suppression key of the earlier successful login for the same account.
    with database.session_factory() as db:
        for _ in range(5):
            event(db, seconds_ago=20)
        new_completion = event(db, outcome="success", seconds_ago=10)
        db.commit()
        new_success_id = new_completion.id
    next_result = {"anomalies_detected": 0, "anomalies_emitted": 0}
    worker._check_anomalies(next_result)
    assert next_result["anomalies_emitted"] == 2  # New sequence plus source brute-force.
    new_sequences = [record for record in records if record["scap.code"] == SEQUENCE]
    assert len(new_sequences) == 2
    assert new_sequences[-1]["scap.evidence_event_id"] == new_success_id


@pytest.mark.parametrize("technique", ["T0000", ["T1110"], {"id": "T1110"}])
def test_siem_does_not_trust_unsupported_technique_metadata(monkeypatch, technique):
    records = []
    logger = logging.getLogger(SIEM_LOGGER_NAME)
    monkeypatch.setattr(logger, "disabled", False)
    monkeypatch.setattr(logger, "log", lambda _level, _msg, **data: records.append(
        data["extra"]["security_event"]
    ))
    emit_security_event("ids.anomaly", details={"mitre_technique": technique})
    assert "threat.technique.id" not in records[0]
