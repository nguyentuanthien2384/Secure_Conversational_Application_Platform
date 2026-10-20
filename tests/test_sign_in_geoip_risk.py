"""Approximate travel evidence is local, bounded, transactional and advisory."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from src.app import sign_in_risk
from src.app.audit_chain import verify_chain
from src.app.db import utcnow
from src.app.models import AuditEvent, AuthSession, User
from src.app.sign_in_risk import (
    LocalGeoIp,
    Location,
    SignInRiskService,
    SignInRiskSettings,
    conservative_distance_km,
)
from tests.conftest import register_and_login

DATABASE = Path(__file__).parent / "fixtures/maxmind/GeoIP2-City-Test.mmdb"


@pytest.fixture
def real_reader(monkeypatch):
    maxminddb = pytest.importorskip("maxminddb", reason="Install the geoip extra")
    with maxminddb.open_database(str(DATABASE)) as reader:
        epoch = reader.metadata().build_epoch

    class FixtureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(epoch + 86_400, tz=timezone.utc)

    monkeypatch.setattr(sign_in_risk, "datetime", FixtureClock)
    reader = LocalGeoIp(SignInRiskSettings(backend="maxmind", database_file=str(DATABASE)))
    yield reader
    reader.close()


def test_actual_maxmind_fd_reader_and_private_addresses(real_reader):
    location = real_reader.lookup("81.2.69.160")
    assert location == Location(51.5142, -0.0931, 100, "GB", "London")
    assert real_reader.lookup("127.0.0.1") is None
    assert real_reader.lookup("192.168.1.1") is None
    assert real_reader.lookup("not-an-address") is None
    assert real_reader.lookup("2001:db8::1") is None


def test_missing_or_non_city_database_fails_at_startup(tmp_path):
    pytest.importorskip("maxminddb")
    with pytest.raises(RuntimeError, match="recent local GeoIP"):
        LocalGeoIp(SignInRiskSettings(backend="maxmind", database_file=str(tmp_path / "missing")))
    not_mmdb = tmp_path / "geoip-city.mmdb"
    not_mmdb.write_bytes(b"not a MaxMind database" * 100)
    with pytest.raises(RuntimeError, match="recent local GeoIP"):
        LocalGeoIp(SignInRiskSettings(backend="maxmind", database_file=str(not_mmdb)))


def test_stale_database_at_startup_pauses_checks_instead_of_stopping_sign_in(monkeypatch):
    """A feed that expires while the app is down behaves like one expiring at runtime."""
    pytest.importorskip("maxminddb")
    future = datetime.now(timezone.utc) + timedelta(days=1000)

    class FutureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return future

    monkeypatch.setattr(sign_in_risk, "datetime", FutureClock)
    service = SignInRiskService(SignInRiskSettings(backend="maxmind", database_file=str(DATABASE)))
    try:
        assert service.geoip.lookup("81.2.69.160") is None
        status = service.status("81.2.69.160")
        assert status["available"] is False and status["database"]["type"] == "GeoIP2-City"
        assert status["database"]["age_days"] > 90 and status["current"] == {
            "resolved": False, "reason": "unknown"}
    finally:
        service.close()


def test_feed_without_accuracy_radius_uses_the_conservative_default(real_reader, monkeypatch):
    """DB-IP City Lite has coordinates but no accuracy_radius."""
    document = {"country": {"iso_code": "VN"}, "city": {"names": {"en": "Hanoi"}},
                "location": {"latitude": 21.0278, "longitude": 105.834}}
    monkeypatch.setattr(real_reader, "reader", SimpleNamespace(get=lambda _: document, close=lambda: None))
    assert real_reader.lookup("113.160.0.1") == Location(21.0278, 105.834, 200, "VN", "Hanoi")
    wider = LocalGeoIp(SignInRiskSettings())
    wider.settings = SignInRiskSettings(default_accuracy_km=350)
    wider.reader = real_reader.reader
    assert wider.lookup("113.160.0.1").accuracy_km == 350


def test_status_reports_feed_and_only_the_callers_approximate_place(real_reader, monkeypatch):
    service = SignInRiskService(SignInRiskSettings())
    service.settings = SignInRiskSettings(backend="maxmind", database_file=str(DATABASE))
    service.geoip = real_reader
    status = service.status("81.2.69.160")
    assert status["available"] is True and status["action"] == "alert_only"
    assert status["database"]["type"] == "GeoIP2-City" and status["database"]["age_days"] == 1
    assert (status["history_hours"], status["min_distance_km"], status["max_speed_kmh"]) == (24, 500, 900)
    assert status["current"] == {"resolved": True, "country": "GB", "city": "London"}
    assert "latitude" not in json.dumps(status) and "51.5" not in json.dumps(status)
    assert service.status("10.1.2.3")["current"] == {"resolved": False, "reason": "private"}
    assert service.status("not-an-address")["current"]["reason"] == "private"
    assert "current" not in SignInRiskService(SignInRiskSettings()).status("81.2.69.160")


def test_running_reader_stops_assessing_after_its_feed_expires(real_reader, monkeypatch):
    class FutureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.fromtimestamp(real_reader.build_epoch + 91 * 86400, tz=timezone.utc)

    monkeypatch.setattr(sign_in_risk, "datetime", FutureClock)
    assert real_reader.lookup("81.2.69.160") is None
    assert not real_reader.available and not real_reader.check_freshness()


@pytest.mark.parametrize("change", [{"backend": "cloud"}, {"backend": "maxmind"},
                                   {"min_distance_km": 0}, {"max_speed_kmh": 99},
                                   {"history_hours": 999}, {"max_database_age_days": 0},
                                   {"default_accuracy_km": 0}, {"default_accuracy_km": 501}])
def test_invalid_settings_are_rejected(change):
    with pytest.raises(ValueError):
        SignInRiskSettings(**change)


def test_distance_subtracts_both_accuracy_radii():
    london, new_york = Location(51.5, -0.1, 100, "GB"), Location(40.7, -74, 100, "US")
    assert 5300 < conservative_distance_km(london, new_york) < 5500
    assert conservative_distance_km(london, replace(london, latitude=51.6)) == 0
    assert conservative_distance_km(Location(0, 179.9, 0, "US"), Location(0, -179.9, 0, "US")) < 23


def _install_locations(app, monkeypatch):
    locations = {"81.2.69.160": Location(51.5, -0.1, 20, "GB"),
                 "89.160.20.112": Location(-33.9, 151.2, 20, "AU")}
    monkeypatch.setattr(app.state.sign_in_risk.geoip, "lookup", lambda value: locations.get(value))


def _set_ip(client, value):
    client._transport.client = (value, 50000)


def test_completed_login_adds_advisory_evidence_and_does_not_leak_coordinates(client, app, monkeypatch):
    _install_locations(app, monkeypatch)
    _set_ip(client, "81.2.69.160")
    token = register_and_login(client, "travel.demo")
    _set_ip(client, "89.160.20.112")
    response = client.post("/api/auth/login", json={"username": "travel.demo", "password": "Correct Horse Battery1"})
    assert response.status_code == 200
    headers = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    with app.state.database.session_factory() as db:
        item = db.scalar(select(AuditEvent).where(AuditEvent.event_type == sign_in_risk.TRAVEL_EVENT))
        data = json.loads(item.details_json)
        assert data["from_country"] == "GB" and data["to_country"] == "AU"
        assert data["action"] == "alert_only" and data["approximate"] is True
        assert "latitude" not in item.details_json and "longitude" not in item.details_json
        assert "51.5" not in item.details_json and "151.2" not in item.details_json
        assert verify_chain(db, app.state.audit_key).intact
    activity = client.get("/api/auth/security-activity", headers=headers)
    assert activity.status_code == 200 and "impossible_travel" in activity.text
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 200


def test_failed_password_is_not_a_travel_observation(client, app, monkeypatch):
    _install_locations(app, monkeypatch)
    _set_ip(client, "81.2.69.160")
    register_and_login(client, "travel.failed")
    _set_ip(client, "89.160.20.112")
    assert client.post("/api/auth/login", json={"username": "travel.failed", "password": "wrong"}).status_code == 401
    with app.state.database.session_factory() as db:
        assert db.scalar(select(AuditEvent).where(AuditEvent.event_type == sign_in_risk.TRAVEL_EVENT)) is None


def test_travel_audit_failure_rolls_back_new_bearer_and_login_evidence(client, app, monkeypatch):
    _install_locations(app, monkeypatch)
    _set_ip(client, "81.2.69.160")
    register_and_login(client, "travel.atomic")
    with app.state.database.session_factory() as db:
        before = ([row.jti for row in db.scalars(select(AuthSession))], [row.id for row in db.scalars(select(AuditEvent))])

    def fail_travel(_connection, _cursor, statement, parameters, *_):
        values = parameters.values() if isinstance(parameters, dict) else parameters
        if statement.lstrip().startswith("INSERT INTO audit_events") and sign_in_risk.TRAVEL_EVENT in values:
            raise OperationalError("synthetic failure", None, RuntimeError("fault"))

    _set_ip(client, "89.160.20.112")
    event.listen(app.state.database.engine, "before_cursor_execute", fail_travel)
    try:
        response = client.post("/api/auth/login", json={"username": "travel.atomic", "password": "Correct Horse Battery1"})
        assert response.status_code == 503
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_travel)
    with app.state.database.session_factory() as db:
        assert ([row.jti for row in db.scalars(select(AuthSession))], [row.id for row in db.scalars(select(AuditEvent))]) == before
        assert db.scalar(select(User).where(User.username == "travel.atomic")).is_active


def test_unknown_corrupt_feed_is_unavailable_and_status_requires_auth(client, app, monkeypatch):
    assert client.get("/api/auth/sign-in-risk/status").status_code == 401
    token = register_and_login(client, "travel.status")
    reader = app.state.sign_in_risk.geoip
    monkeypatch.setattr(reader, "reader", SimpleNamespace(get=lambda _: (_ for _ in ()).throw(RuntimeError()), close=lambda: None))
    assert reader.lookup("81.2.69.160") is None and not reader.available
    response = client.get("/api/auth/sign-in-risk/status", headers={"Authorization": "Bearer " + token})
    assert response.status_code == 200 and response.json()["available"] is False


def test_status_endpoint_locates_the_callers_own_address(client, app, monkeypatch):
    service = app.state.sign_in_risk
    monkeypatch.setattr(service, "settings", replace(service.settings, backend="maxmind",
                                                     database_file="feed.mmdb"))
    monkeypatch.setattr(service.geoip, "check_freshness", lambda: True)
    _install_locations(app, monkeypatch)
    _set_ip(client, "81.2.69.160")
    token = register_and_login(client, "travel.where")
    body = client.get("/api/auth/sign-in-risk/status",
                      headers={"Authorization": "Bearer " + token}).json()
    assert body["current"] == {"resolved": True, "country": "GB", "city": ""}
    assert body["external_ip_lookup"] is False


def test_old_location_and_same_ip_do_not_raise_travel(client, app, monkeypatch):
    _install_locations(app, monkeypatch)
    _set_ip(client, "81.2.69.160")
    token = register_and_login(client, "travel.old")
    with app.state.database.session_factory() as db:
        user_id = app.state.token_service.decode(token)["sub"]
        assert app.state.sign_in_risk.assess(db, user_id, "81.2.69.160", utcnow()) is None
        assert app.state.sign_in_risk.assess(db, user_id, "89.160.20.112", utcnow() + timedelta(days=2)) is None
