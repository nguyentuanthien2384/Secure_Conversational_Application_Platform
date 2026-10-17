"""Public prekey maintenance and reliable opaque-envelope synchronization."""
from __future__ import annotations

import os

from sqlalchemy import event, select, update
from sqlalchemy.exc import OperationalError

from src.app.audit_chain import verify_chain
from src.app.db import utcnow
from src.app.e2ee import canonical_json_bytes, encode_base64url
from src.app.models import E2eeDeviceChallenge, E2eeEnvelope, E2eePreKey
from tests.conftest import register_and_login
from tests.test_data_transactions import data_snapshot, prepare_data_action
from tests.test_high_security_features import auth, register_device


def prekey_update(client, token, device_id, key, *, count=2, rotate=False, keys=None):
    user_id = client.get("/api/auth/me", headers=auth(token)).json()["id"]
    challenge = client.post("/api/e2ee/devices/challenge", headers=auth(token)).json()
    signed = os.urandom(32) if rotate else None
    payload = {"challenge_id": challenge["id"], "challenge": challenge["challenge"],
               "one_time_prekeys": keys if keys is not None else [encode_base64url(os.urandom(32)) for _ in range(count)],
               "signed_prekey": encode_base64url(signed) if signed else None,
               "signed_prekey_signature": encode_base64url(key.sign(signed)) if signed else None}
    statement = {"account_id": user_id, "device_id": device_id,
                 **{name: payload[name] for name in ("challenge", "one_time_prekeys", "signed_prekey", "signed_prekey_signature")}}
    payload["update_signature"] = encode_base64url(key.sign(canonical_json_bytes(
        statement, schema="scap.e2ee.prekey-update",
    )))
    return payload


def test_device_refills_consumed_prekeys_rotates_signed_key_and_rejects_replay(client, app):
    token = register_and_login(client, "prekey-maintenance")
    device, key = register_device(client, token)
    bundle_path = f"/api/e2ee/users/prekey-maintenance/prekey-bundle?device_id={device}"
    assert client.get(bundle_path, headers=auth(token)).json()["one_time_prekey"]
    payload = prekey_update(client, token, device, key, rotate=True)
    response = client.post(f"/api/e2ee/devices/{device}/prekeys", headers=auth(token), json=payload)
    assert response.status_code == 200, response.text
    assert response.json() == {"device_id": device, "added": 2, "available": 2, "signed_prekey_rotated": True}
    bundles = [client.get(bundle_path, headers=auth(token)).json() for _ in range(3)]
    assert {item["one_time_prekey"] for item in bundles[:2]} == set(payload["one_time_prekeys"])
    assert bundles[-1]["one_time_prekey"] is None
    assert all(item["signed_prekey"] == payload["signed_prekey"] for item in bundles)
    assert client.post(f"/api/e2ee/devices/{device}/prekeys", headers=auth(token), json=payload).status_code == 409
    with app.state.database.session_factory() as db:
        assert verify_chain(db, app.state.audit_key).intact


def test_prekey_update_and_challenge_roll_back_if_audit_fails(client, app):
    token = register_and_login(client, "atomic-prekey-update")
    device, key = register_device(client, token)
    payload = prekey_update(client, token, device, key, rotate=True)
    before = data_snapshot(app)

    def fail_audit(_conn, _cursor, statement, _params, context, _many):
        if (statement.lstrip().lower().startswith("insert into audit_events")
                and any(item.get("event_type") == "e2ee.prekey.update" for item in context.compiled_parameters)):
            raise OperationalError("simulated audit failure", None, RuntimeError("test"))

    event.listen(app.state.database.engine, "before_cursor_execute", fail_audit)
    try:
        response = client.post(f"/api/e2ee/devices/{device}/prekeys", headers=auth(token), json=payload)
    finally:
        event.remove(app.state.database.engine, "before_cursor_execute", fail_audit)
    assert response.status_code == 503
    assert data_snapshot(app) == before
    assert client.post(f"/api/e2ee/devices/{device}/prekeys", headers=auth(token), json=payload).status_code == 200


def test_prekey_update_needs_possession_owner_and_recent_step_up(client, app):
    token = register_and_login(client, "prekey-owner-guard")
    other = register_and_login(client, "prekey-other-guard")
    device, key = register_device(client, token)
    payload = prekey_update(client, token, device, key)
    path = f"/api/e2ee/devices/{device}/prekeys"
    assert client.post(path, headers=auth(other), json=payload).status_code == 404
    changed = {**payload, "one_time_prekeys": [encode_base64url(os.urandom(32))]}
    assert client.post(path, headers=auth(token), json=changed).status_code == 422
    with app.state.database.session_factory() as db:
        assert db.get(E2eeDeviceChallenge, payload["challenge_id"]).consumed_at is not None
    assert client.post(path, headers=auth(token), json=payload).status_code == 409
    payload = prekey_update(client, token, device, key)
    from src.app.models import AuthSession
    with app.state.database.session_factory() as db:
        db.get(AuthSession, app.state.token_service.decode(token)["jti"]).last_step_up_at = None
        db.commit()
    response = client.post(path, headers=auth(token), json=payload)
    assert response.status_code == 403 and response.headers["X-Step-Up-Required"] == "true"


def test_prekeys_cannot_be_reused_even_after_consumption_and_capacity_is_bounded(client, app):
    token = register_and_login(client, "prekey-reuse-guard")
    device, key = register_device(client, token)
    bundle = client.get(f"/api/e2ee/users/prekey-reuse-guard/prekey-bundle?device_id={device}", headers=auth(token)).json()
    path = f"/api/e2ee/devices/{device}/prekeys"
    duplicate = prekey_update(client, token, device, key, keys=[bundle["one_time_prekey"]])
    assert client.post(path, headers=auth(token), json=duplicate).status_code == 422
    filled = prekey_update(client, token, device, key, count=100)
    assert client.post(path, headers=auth(token), json=filled).status_code == 200
    extra = prekey_update(client, token, device, key, count=1)
    assert client.post(path, headers=auth(token), json=extra).status_code == 409
    with app.state.database.session_factory() as db:
        assert len(list(db.scalars(select(E2eePreKey).where(
            E2eePreKey.device_id == device, E2eePreKey.consumed_at.is_(None),
        )))) == 100


def test_compound_e2ee_cursor_delivers_tied_timestamps_without_loss_or_duplicates(client, app):
    token, method, path, body, _audit, _status = prepare_data_action(client, "e2ee_send")
    first = client.request(method, path, headers=auth(token), json=body)
    second = client.request(method, path, headers=auth(token), json={**body, "client_message_id": "second-message"})
    assert first.status_code == second.status_code == 201
    with app.state.database.session_factory() as db:
        db.execute(update(E2eeEnvelope).where(E2eeEnvelope.session_id == first.json()["session_id"]).values(created_at=utcnow()))
        db.commit()
    params = {"recipient_device_id": body["recipient_device_id"], "limit": 1}
    page = client.get(path, headers=auth(token), params=params).json()
    assert client.get(path, headers=auth(token), params={**params, "after": page[0]["created_at"]}).status_code == 409
    following = client.get(path, headers=auth(token), params={**params, "after": page[0]["created_at"], "after_id": page[0]["id"]}).json()
    assert len(following) == 1 and following[0]["id"] != page[0]["id"]
    end = client.get(path, headers=auth(token), params={**params, "after": following[0]["created_at"], "after_id": following[0]["id"]}).json()
    assert end == []
    assert client.get(path, headers=auth(token), params={**params, "after_id": page[0]["id"]}).status_code == 422


def test_active_member_can_read_routing_state_and_removed_member_cannot(client):
    owner = register_and_login(client, "routing-owner")
    member = register_and_login(client, "routing-member")
    sid = client.post("/api/sessions", headers=auth(owner), json={"title": "Private state", "security_mode": "private_e2ee"}).json()["id"]
    added = client.post(f"/api/sessions/{sid}/e2ee/members", headers=auth(owner), json={"username": "routing-member"})
    assert added.status_code == 201
    state = client.get(f"/api/sessions/{sid}/e2ee/state", headers=auth(member))
    assert state.status_code == 200 and state.json()["epoch"] == added.json()["epoch"]
    assert state.json()["session_id"] == sid
    assert client.delete(f"/api/sessions/{sid}/e2ee/members/routing-member", headers=auth(owner)).status_code == 204
    assert client.get(f"/api/sessions/{sid}/e2ee/state", headers=auth(member)).status_code == 404
