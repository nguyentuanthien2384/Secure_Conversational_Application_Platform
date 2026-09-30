"""Incident evidence, analyst decisions and API authorization boundaries."""

from __future__ import annotations

import base64
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, func, select, update

from src.app.audit_chain import append_lock, seal_event, verify_chain
from src.app.db import utcnow
from src.app.models import AuditEvent, IncidentTransition, SecurityIncident, User
from tests.conftest import register_and_login


@pytest.fixture()
def analyst(client, app):
    token = register_and_login(client, "incident-analyst")
    with app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "incident-analyst"))
        user.role = "moderator"
        db.commit()
        actor_id = user.id
        evidence_ids = db.scalars(select(AuditEvent.id).where(AuditEvent.actor_id == actor_id)).all()
    return {"Authorization": f"Bearer {token}"}, evidence_ids, actor_id


def open_case(client, analyst, **overrides):
    headers, evidence_ids, _ = analyst
    payload = {
        "title": "Điều tra đăng nhập bất thường", "stage": "initial_access",
        "severity": "high", "evidence_ids": [evidence_ids[-1]],
    }
    payload.update(overrides)
    return client.post("/api/admin/incidents", headers=headers, json=payload)


def change_case(client, analyst, case, status, resolution=None):
    payload = {"version": case["version"], "status": status}
    if resolution is not None:
        payload["resolution"] = resolution
    return client.patch(f"/api/admin/incidents/{case['id']}", headers=analyst[0], json=payload)


def test_actual_sealed_login_evidence_and_full_checkpoint_workflow(client, app, analyst):
    created = open_case(client, analyst)
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["version"] == 1 and case["status"] == "new" and case["evidence_count"] == 1
    assert case["evidence"][0]["event_type"] == "auth.login"
    assert case["evidence"][0]["entry_hash"]
    assert case["transitions"][0]["from_status"] is None
    assert case["created_at"].endswith("Z") or case["created_at"].endswith("+00:00")
    with app.state.database.session_factory() as db:
        evidence = db.get(AuditEvent, case["evidence"][0]["audit_id"])
        assert case["evidence"][0]["entry_hash"] == evidence.entry_hash
        auth_before = db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True)))
    for version, status, resolution in ((2, "investigating", None), (3, "contained", None), (4, "closed", "confirmed")):
        response = change_case(client, analyst, case, status, resolution)
        assert response.status_code == 200, response.text
        case = response.json()
        assert case["status"] == status and case["version"] == version
        assert len(case["transitions"]) == version
    assert case["transitions"][-1]["resolution"] == "confirmed"
    loaded = client.get(f"/api/admin/incidents/{case['id']}", headers=analyst[0])
    assert loaded.json() == case
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) == auth_before
        records = db.scalars(select(AuditEvent).where(AuditEvent.target_id == case["id"]).order_by(AuditEvent.id)).all()
        assert [row.event_type for row in records] == ["incident.created"] + ["incident.status_changed"] * 3
        assert all(row.entry_hash and row.actor_id == analyst[2] for row in records)
        assert verify_chain(db, app.state.audit_key).intact
        assert json.loads(records[-2].details_json)["containment_is_analyst_checkpoint"] is True
    assert app.state.intrusion_state.blocked_sources() == []


@pytest.mark.parametrize("status,resolution", [
    ("closed", "confirmed"), ("contained", None), ("new", None),
])
def test_new_case_cannot_skip_investigation(client, analyst, status, resolution):
    case = open_case(client, analyst).json()
    response = change_case(client, analyst, case, status, resolution)
    assert response.status_code == 409
    assert client.get(f"/api/admin/incidents/{case['id']}", headers=analyst[0]).json()["version"] == 1


@pytest.mark.parametrize("resolution", ["false_positive", "duplicate"])
def test_investigation_can_close_an_unconfirmed_alert(client, analyst, resolution):
    case = open_case(client, analyst).json()
    case = change_case(client, analyst, case, "investigating").json()
    response = change_case(client, analyst, case, "closed", resolution)
    assert response.status_code == 200
    case = response.json()
    assert case["version"] == 3 and case["transitions"][-1]["resolution"] == resolution
    assert change_case(client, analyst, case, "investigating").status_code == 409


def test_confirmed_case_cannot_close_until_containment_is_recorded(client, analyst):
    case = open_case(client, analyst).json()
    case = change_case(client, analyst, case, "investigating").json()
    assert change_case(client, analyst, case, "closed", "confirmed").status_code == 409
    assert change_case(client, analyst, case, "closed").status_code == 422
    assert change_case(client, analyst, case, "contained", "confirmed").status_code == 422
    case = change_case(client, analyst, case, "contained").json()
    assert change_case(client, analyst, case, "closed", "false_positive").status_code == 409


def test_stale_version_does_not_change_case_or_append_a_decision(client, app, analyst):
    original = open_case(client, analyst).json()
    current = change_case(client, analyst, original, "investigating").json()
    response = change_case(client, analyst, original, "investigating")
    assert response.status_code == 409
    assert client.get(f"/api/admin/incidents/{original['id']}", headers=analyst[0]).json() == current
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(IncidentTransition).where(IncidentTransition.incident_id == original["id"])) == 2


def test_atomic_compare_and_update_allows_only_one_concurrent_transition(client, app, analyst):
    original = open_case(client, analyst).json()
    # Two real HTTP requests carry the same case version. Exactly one wins;
    # this also exercises the configured SQLite writer timeout and audit lock.
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: change_case(client, analyst, original, "investigating"), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 409]
    with app.state.database.session_factory() as db:
        assert db.get(SecurityIncident, original["id"]).version == 2
        assert db.scalar(select(func.count()).select_from(IncidentTransition).where(IncidentTransition.incident_id == original["id"])) == 2
        assert verify_chain(db, app.state.audit_key).intact


def test_incident_and_unrelated_audit_writer_share_safe_lock_order(client, app, analyst):
    with app.state.database.session_factory() as db:
        db.get(User, analyst[2]).role = "admin"
        db.commit()
    with ThreadPoolExecutor(max_workers=2) as pool:
        incident = pool.submit(open_case, client, analyst)
        verification = pool.submit(client.get, "/api/admin/audit/verify", headers=analyst[0])
        assert incident.result(timeout=20).status_code == 201
        assert verification.result(timeout=20).status_code == 200
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


def test_audit_sealing_failure_rolls_back_case_and_evidence(client, app, analyst, monkeypatch):
    from src.app import incidents

    def unavailable(*_args):
        raise RuntimeError("Simulated sealing failure")

    monkeypatch.setattr(incidents, "seal_event", unavailable)
    with pytest.raises(RuntimeError, match="Simulated sealing failure"):
        open_case(client, analyst)
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityIncident)) == 0
        assert db.scalar(select(func.count()).select_from(IncidentTransition)) == 0


@pytest.mark.parametrize("changes", [
    {"evidence_ids": []}, {"evidence_ids": [1] * 21}, {"evidence_ids": [1, 1]},
    {"evidence_ids": [True]}, {"evidence_ids": [0]}, {"evidence_ids": [2**63]},
    {"evidence_ids": ["1"]}, {"title": "  "}, {"title": "x" * 121},
    {"title": "x\u202etest"}, {"title": "x\ntest"}, {"stage": "arbitrary"},
    {"severity": "arbitrary"}, {"notes": "unsupported arbitrary text"},
])
def test_create_boundaries_are_enforced(client, app, analyst, changes):
    assert open_case(client, analyst, **changes).status_code == 422
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityIncident)) == 0


@pytest.mark.parametrize("title", [
    "password:incident-secret", "Contact sensitive@example.com",
    "Contact (" + base64.b64encode(b"sensitive@example.com").decode("ascii") + ")",
])
def test_titles_cannot_import_detected_sensitive_material(client, analyst, title):
    response = open_case(client, analyst, title=title)
    assert response.status_code == 422
    assert title not in response.text


@pytest.mark.parametrize("kind", ["missing", "unsealed", "changed", "forged", "unicode_hash"])
def test_only_existing_verified_sealed_evidence_can_start_a_case(client, app, analyst, kind):
    with app.state.database.session_factory() as db:
        if kind == "missing":
            evidence_id = 2**62
        elif kind == "unsealed":
            row = AuditEvent(event_type="test.fixture", outcome="failure", created_at=utcnow())
            db.add(row)
            db.commit()
            evidence_id = row.id
        else:
            evidence_id = analyst[1][-1]
            field = {"changed": {"outcome": "failure"}, "forged": {"entry_hash": "0" * 64}, "unicode_hash": {"entry_hash": "é" * 64}}[kind]
            db.execute(update(AuditEvent).where(AuditEvent.id == evidence_id).values(**field))
            db.commit()
    response = open_case(client, analyst, evidence_ids=[evidence_id])
    assert response.status_code == 422
    with app.state.database.session_factory() as db:
        assert db.scalar(select(func.count()).select_from(SecurityIncident)) == 0


def test_disabled_audit_chain_refuses_case_mutations(client, app, analyst):
    app.state.audit_key = None
    assert open_case(client, analyst).status_code == 409


def test_evidence_projection_never_returns_audit_details_or_actor_identity(client, app, analyst):
    sensitive = "DO-NOT-EXPORT-original-message-password"
    with app.state.database.session_factory() as db:
        row = AuditEvent(
            actor_id="hidden-source-actor", event_type="test.evidence", outcome="failure",
            request_id="safe-correlation-id", target_id="private-target",
            ip_address="192.0.2.98", user_agent="private-device-agent",
            details_json=json.dumps({"message": sensitive}), created_at=utcnow(),
        )
        with append_lock(db):
            seal_event(db, row, app.state.audit_key)
            db.add(row)
            db.commit()
        evidence_id = row.id
    case = open_case(client, analyst, evidence_ids=[evidence_id]).json()
    assert set(case["evidence"][0]) == {"audit_id", "event_type", "outcome", "request_id", "created_at", "entry_hash"}
    for response in (case, client.get("/api/admin/incidents", headers=analyst[0]).json(),
                     client.get(f"/api/admin/incidents/{case['id']}", headers=analyst[0]).json()):
        saved = json.dumps(response)
        for value in (sensitive, "hidden-source-actor", "private-target", "192.0.2.98", "private-device-agent", "incident-analyst"):
            assert value not in saved
    with app.state.database.session_factory() as db:
        original = db.get(AuditEvent, evidence_id)
        assert sensitive in original.details_json
        # Snapshots preserve the exact verified evidence even if an owner
        # subsequently tampers with the original row; full chain verification
        # remains available separately and must then report the broken chain.
        original.details_json = "{}"
        db.commit()
        assert verify_chain(db, app.state.audit_key).intact is False
    assert client.get(f"/api/admin/incidents/{case['id']}", headers=analyst[0]).json()["evidence"] == case["evidence"]


def test_incident_routes_require_privileged_role_and_apply_high_mfa_gate(client, app, analyst):
    case = open_case(client, analyst).json()
    ordinary = {"Authorization": f"Bearer {register_and_login(client, 'ordinary-incident-user')}"}
    path = f"/api/admin/incidents/{case['id']}"
    actions = (
        lambda headers: client.get("/api/admin/incidents", headers=headers),
        lambda headers: client.get(path, headers=headers),
        lambda headers: client.post("/api/admin/incidents", headers=headers, json={
            "title": "Another case", "stage": "scanning", "severity": "medium", "evidence_ids": [analyst[1][-1]],
        }),
        lambda headers: client.patch(path, headers=headers, json={"version": 1, "status": "investigating"}),
        lambda headers: client.get("/api/admin/practice/catalog", headers=headers),
    )
    assert all(action({}).status_code == 401 for action in actions)
    assert all(action(ordinary).status_code == 403 for action in actions)
    # Settings construction/startup guard is tested elsewhere. Exercise the
    # runtime privilege gate on the same isolated SQLite app without real KMS.
    object.__setattr__(app.state.settings, "security_profile", "high")
    try:
        assert all(action(analyst[0]).status_code == 403 for action in actions)
    finally:
        object.__setattr__(app.state.settings, "security_profile", "standard")


def test_bounded_list_and_detail_queries_do_not_scan_all_evidence(client, app, analyst):
    cases = [open_case(client, analyst, title=f"Test incident {index}").json() for index in range(3)]
    statements = []

    @event.listens_for(app.state.database.engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        if "security_incidents" in statement or "incident_evidence" in statement or "incident_transitions" in statement:
            statements.append(statement)

    try:
        response = client.get("/api/admin/incidents?limit=2", headers=analyst[0])
        assert response.status_code == 200 and len(response.json()) == 2
        assert all("evidence" not in row and "transitions" not in row for row in response.json())
        assert client.get(f"/api/admin/incidents/{cases[0]['id']}", headers=analyst[0]).status_code == 200
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", capture)
    assert statements and all("WHERE" in statement or "LIMIT" in statement for statement in statements)
    assert client.get("/api/admin/incidents?limit=101", headers=analyst[0]).status_code == 422
    assert client.get(f"/api/admin/incidents/{uuid.uuid4()}", headers=analyst[0]).status_code == 404
    assert client.get("/api/admin/incidents/not-a-uuid", headers=analyst[0]).status_code == 422


def test_new_tables_receive_append_only_runtime_grants():
    from src.app.db import Database

    executed = []

    @contextmanager
    def begin():
        yield SimpleNamespace(execute=lambda statement: executed.append(str(statement)))

    database = object.__new__(Database)
    database.engine = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql", identifier_preparer=SimpleNamespace(quote=lambda value: value)),
        url=SimpleNamespace(database="isolated_grants_test"), begin=begin,
    )
    database.apply_postgres_least_privilege()
    sql = (Path(__file__).resolve().parents[1] / "scripts" / "db_least_privilege.sql").read_text(encoding="utf-8")
    for table in ("incident_evidence", "incident_transitions"):
        expected = f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE {table} FROM scap_app"
        assert expected in executed and expected in sql
    assert "REVOKE DELETE, TRUNCATE ON TABLE security_incidents FROM scap_app" in executed


def test_invalid_payload_errors_do_not_echo_sensitive_input(client, analyst):
    secret = "password:never-echo-this-secret"
    response = open_case(client, analyst, notes=secret)
    assert response.status_code == 422 and secret not in response.text
    response = open_case(client, analyst, title=secret * 8)
    assert response.status_code == 422 and secret not in response.text
