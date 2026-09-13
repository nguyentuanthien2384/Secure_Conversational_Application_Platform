from __future__ import annotations

import os
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import replace

from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from src.app.e2ee import PROTOCOL_DOUBLE_RATCHET, PROTOCOL_MLS, encode_base64url
from src.app.main import create_app
from src.app.models import ChatSession, ConversationMember, User
from src.app.security import TotpService
from tests.conftest import register_and_login
from tests.test_high_security_features import register_device


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@contextmanager
def pause_after_sql(engine, statement_fragment: str):
    """Pause the first matching write after it has acquired its DB lock."""
    acquired = threading.Event()
    release = threading.Event()
    hook_error: list[BaseException] = []

    def after_cursor_execute(_conn, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.lower().split())
        if not acquired.is_set() and statement_fragment in normalized:
            acquired.set()
            if not release.wait(timeout=10):
                error = TimeoutError(f"Timed out while pausing SQL: {statement_fragment}")
                hook_error.append(error)
                raise error

    event.listen(engine, "after_cursor_execute", after_cursor_execute)
    try:
        yield acquired, release, hook_error
    finally:
        release.set()
        event.remove(engine, "after_cursor_execute", after_cursor_execute)


def run_request(results: dict[str, object], key: str, request_callable) -> None:
    try:
        results[key] = request_callable()
    except BaseException as exc:  # pragma: no cover - surfaced by caller assertions
        results[key] = exc


def admin_token(client: TestClient, app, username: str) -> str:
    password = "Lifecycle Admin Passphrase 2026"
    with app.state.database.session_factory() as db:
        db.add(
            User(
                username=username,
                password_hash=app.state.password_service.hash(password),
                role="admin",
            )
        )
        db.commit()
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def create_private_session_with_member(
    client: TestClient, owner_token: str, member_username: str
) -> tuple[str, int]:
    created = client.post(
        "/api/sessions",
        headers=auth(owner_token),
        json={"title": "Lifecycle E2EE", "security_mode": "private_e2ee"},
    )
    assert created.status_code == 201, created.text
    session_id = created.json()["id"]
    added = client.post(
        f"/api/sessions/{session_id}/e2ee/members",
        headers=auth(owner_token),
        json={"username": member_username},
    )
    assert added.status_code == 201, added.text
    return session_id, added.json()["epoch"]


def test_removed_member_cannot_send_or_receive_even_with_a_current_epoch(client: TestClient, app):
    owner_token = register_and_login(client, "member-removal-owner")
    member_token = register_and_login(client, "member-removal-target")
    session_id, previous_epoch = create_private_session_with_member(
        client, owner_token, "member-removal-target"
    )

    removed = client.delete(
        f"/api/sessions/{session_id}/e2ee/members/member-removal-target",
        headers=auth(owner_token),
    )
    assert removed.status_code == 204, removed.text
    current_epoch = client.get(f"/api/sessions/{session_id}", headers=auth(owner_token)).json()[
        "current_crypto_epoch"
    ]
    assert current_epoch == previous_epoch + 1

    sender_device = str(uuid.uuid4())
    recipient_device = str(uuid.uuid4())
    send = client.post(
        f"/api/sessions/{session_id}/e2ee/envelopes",
        headers=auth(member_token),
        json={
            "version": 1,
            "protocol": PROTOCOL_DOUBLE_RATCHET,
            "recipient": recipient_device,
            "recipient_device_id": recipient_device,
            "epoch": current_epoch,
            "client_message_id": "removed-member-message",
            "sender_device_id": sender_device,
            "message_kind": "application",
            "header": encode_base64url(os.urandom(32)),
            "ciphertext": encode_base64url(os.urandom(64)),
        },
    )
    receive = client.get(
        f"/api/sessions/{session_id}/e2ee/envelopes",
        headers=auth(member_token),
        params={"recipient_device_id": recipient_device},
    )
    assert send.status_code == receive.status_code == 404

    with app.state.database.session_factory() as db:
        member_id = db.scalar(select(User.id).where(User.username == "member-removal-target"))
        membership = db.scalar(
            select(ConversationMember).where(
                ConversationMember.session_id == session_id,
                ConversationMember.user_id == member_id,
            )
        )
        assert membership is not None
        assert membership.removed_at is not None
        assert membership.removed_epoch == current_epoch


def test_suspension_revokes_e2ee_membership_and_reactivation_does_not_restore_it(
    client: TestClient, app
):
    owner_token = register_and_login(client, "suspension-owner")
    member_token = register_and_login(client, "suspension-member")
    member_id = client.get("/api/auth/me", headers=auth(member_token)).json()["id"]
    session_id, previous_epoch = create_private_session_with_member(
        client, owner_token, "suspension-member"
    )
    operator_token = admin_token(client, app, "suspension-admin")

    suspended = client.patch(
        f"/api/admin/users/{member_id}/status",
        headers=auth(operator_token),
        json={"is_active": False},
    )
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["is_active"] is False
    assert client.get("/api/auth/me", headers=auth(member_token)).status_code == 401

    with app.state.database.session_factory() as db:
        chat_session = db.get(ChatSession, session_id)
        membership = db.scalar(
            select(ConversationMember).where(
                ConversationMember.session_id == session_id,
                ConversationMember.user_id == member_id,
            )
        )
        assert chat_session is not None and membership is not None
        assert chat_session.current_crypto_epoch == previous_epoch + 1
        assert membership.removed_at is not None
        assert membership.removed_epoch == chat_session.current_crypto_epoch

    reactivated = client.patch(
        f"/api/admin/users/{member_id}/status",
        headers=auth(operator_token),
        json={"is_active": True},
    )
    assert reactivated.status_code == 200, reactivated.text
    new_member_token = client.post(
        "/api/auth/login",
        json={"username": "suspension-member", "password": "Correct Horse Battery1"},
    ).json()["access_token"]
    assert (
        client.get(
            f"/api/sessions/{session_id}/e2ee/members",
            headers=auth(new_member_token),
        ).status_code
        == 404
    )


def test_admin_delete_advances_shared_e2ee_epoch_and_zeroizes_dek_cache(client: TestClient, app):
    target_token = register_and_login(client, "delete-lifecycle-target")
    target_id = client.get("/api/auth/me", headers=auth(target_token)).json()["id"]
    owned = client.post(
        "/api/sessions", headers=auth(target_token), json={"title": "Owned encrypted data"}
    )
    assert owned.status_code == 201, owned.text
    owned_session_id = owned.json()["id"]

    other_owner_token = register_and_login(client, "delete-lifecycle-owner")
    shared_session_id, previous_epoch = create_private_session_with_member(
        client, other_owner_token, "delete-lifecycle-target"
    )
    assert app.state.envelope_crypto_service._cache
    operator_token = admin_token(client, app, "delete-lifecycle-admin")

    deleted = client.delete(f"/api/admin/users/{target_id}", headers=auth(operator_token))
    assert deleted.status_code == 204, deleted.text
    assert app.state.envelope_crypto_service._cache == {}

    with app.state.database.session_factory() as db:
        assert db.get(User, target_id) is None
        assert db.get(ChatSession, owned_session_id) is None
        shared = db.get(ChatSession, shared_session_id)
        assert shared is not None
        assert shared.current_crypto_epoch == previous_epoch + 1
        assert (
            db.scalar(
                select(ConversationMember.id).where(
                    ConversationMember.session_id == shared_session_id,
                    ConversationMember.user_id == target_id,
                )
            )
            is None
        )


def test_security_boundary_cannot_change_after_plaintext_content_exists(client: TestClient, app):
    token = register_and_login(client, "security-transition-content")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Existing content"}
    ).json()["id"]
    sent = client.post(
        f"/api/sessions/{session_id}/messages",
        headers=auth(token),
        json={"content": "already encrypted on the server"},
    )
    assert sent.status_code == 201, sent.text

    changed = client.patch(
        f"/api/sessions/{session_id}/security",
        headers=auth(token),
        json={
            "security_mode": "private_e2ee",
            "data_classification": "e2ee_private",
        },
    )
    assert changed.status_code == 409
    with app.state.database.session_factory() as db:
        chat_session = db.get(ChatSession, session_id)
        assert chat_session is not None
        assert chat_session.security_mode == "secure"
        assert chat_session.wrapped_dek is not None


def test_concurrent_message_waits_for_security_transition_and_observes_new_boundary(
    client: TestClient, app
):
    token = register_and_login(client, "transition-race-owner")
    session_id = client.post(
        "/api/sessions", headers=auth(token), json={"title": "Transition race"}
    ).json()["id"]
    results: dict[str, object] = {}

    with pause_after_sql(
        app.state.database.engine,
        "update chat_sessions set current_crypto_epoch=chat_sessions.current_crypto_epoch",
    ) as (locked, release, hook_error):
        transition = threading.Thread(
            target=run_request,
            args=(
                results,
                "transition",
                lambda: client.patch(
                    f"/api/sessions/{session_id}/security",
                    headers=auth(token),
                    json={
                        "security_mode": "private_e2ee",
                        "data_classification": "e2ee_private",
                    },
                ),
            ),
        )
        transition.start()
        assert locked.wait(timeout=5), "security transition did not acquire its row lock"
        send = threading.Thread(
            target=run_request,
            args=(
                results,
                "send",
                lambda: client.post(
                    f"/api/sessions/{session_id}/messages",
                    headers=auth(token),
                    json={"content": "must not cross the changed boundary"},
                ),
            ),
        )
        send.start()
        time.sleep(0.15)
        assert send.is_alive(), "concurrent content write bypassed the transition lock"
        release.set()
        transition.join(timeout=10)
        send.join(timeout=10)

    assert not transition.is_alive() and not send.is_alive()
    assert not hook_error
    assert not isinstance(results.get("transition"), BaseException)
    assert not isinstance(results.get("send"), BaseException)
    assert results["transition"].status_code == 200
    assert results["send"].status_code == 403
    with app.state.database.session_factory() as db:
        chat_session = db.get(ChatSession, session_id)
        assert chat_session is not None
        assert chat_session.security_mode == "private_e2ee"
        assert chat_session.messages == []


def test_concurrent_e2ee_send_rechecks_membership_after_removal_lock(client: TestClient, app):
    owner_token = register_and_login(client, "removal-race-owner")
    member_token = register_and_login(client, "removal-race-member")
    member_device, _ = register_device(client, member_token)
    session_id, previous_epoch = create_private_session_with_member(
        client, owner_token, "removal-race-member"
    )
    results: dict[str, object] = {}

    with pause_after_sql(
        app.state.database.engine,
        "update chat_sessions set current_crypto_epoch=chat_sessions.current_crypto_epoch",
    ) as (locked, release, hook_error):
        removal = threading.Thread(
            target=run_request,
            args=(
                results,
                "removal",
                lambda: client.delete(
                    f"/api/sessions/{session_id}/e2ee/members/removal-race-member",
                    headers=auth(owner_token),
                ),
            ),
        )
        removal.start()
        assert locked.wait(timeout=5), "member removal did not acquire its row lock"
        send = threading.Thread(
            target=run_request,
            args=(
                results,
                "send",
                lambda: client.post(
                    f"/api/sessions/{session_id}/e2ee/envelopes",
                    headers=auth(member_token),
                    json={
                        "version": 1,
                        "protocol": PROTOCOL_MLS,
                        "recipient": session_id,
                        "epoch": previous_epoch + 1,
                        "client_message_id": "membership-race-envelope",
                        "sender_device_id": member_device,
                        "message_kind": "application",
                        "header": encode_base64url(os.urandom(32)),
                        "ciphertext": encode_base64url(os.urandom(64)),
                    },
                ),
            ),
        )
        send.start()
        time.sleep(0.15)
        assert send.is_alive(), "concurrent envelope send bypassed the membership lock"
        release.set()
        removal.join(timeout=10)
        send.join(timeout=10)

    assert not removal.is_alive() and not send.is_alive()
    assert not hook_error
    assert not isinstance(results.get("removal"), BaseException)
    assert not isinstance(results.get("send"), BaseException)
    assert results["removal"].status_code == 204
    assert results["send"].status_code == 404


def test_concurrent_sensitive_creation_observes_completed_mfa_disable(settings):
    high_settings = replace(settings, security_profile="high")
    password = "Correct Horse Battery1"
    totp = TotpService()
    with TestClient(create_app(high_settings)) as high_client:
        token = register_and_login(high_client, "mfa-disable-race", password)
        enrolled = high_client.post("/api/auth/mfa/enroll", headers=auth(token)).json()
        activated = high_client.post(
            "/api/auth/mfa/activate",
            headers=auth(token),
            json={"code": totp.now_code(enrolled["secret"])},
        )
        assert activated.status_code == 200, activated.text
        challenge = high_client.post(
            "/api/auth/login",
            json={"username": "mfa-disable-race", "password": password},
        ).json()
        verified = high_client.post(
            "/api/auth/mfa/verify",
            json={
                "mfa_token": challenge["mfa_token"],
                "code": activated.json()["recovery_codes"][0],
            },
        )
        access_token = verified.json()["access_token"]
        results: dict[str, object] = {}

        with pause_after_sql(
            high_client.app.state.database.engine,
            "update users set token_version=? where users.id = ? and users.mfa_enabled is 1",
        ) as (locked, release, hook_error):
            disable = threading.Thread(
                target=run_request,
                args=(
                    results,
                    "disable",
                    lambda: high_client.post(
                        "/api/auth/mfa/disable",
                        headers=auth(access_token),
                        json={
                            "password": password,
                            "code": activated.json()["recovery_codes"][1],
                        },
                    ),
                ),
            )
            disable.start()
            assert locked.wait(timeout=5), "MFA disable did not acquire its account lock"
            create = threading.Thread(
                target=run_request,
                args=(
                    results,
                    "create",
                    lambda: high_client.post(
                        "/api/sessions",
                        headers=auth(access_token),
                        json={"title": "Sensitive race", "security_mode": "confidential"},
                    ),
                ),
            )
            create.start()
            time.sleep(0.15)
            assert create.is_alive(), "sensitive session creation bypassed the account lock"
            release.set()
            disable.join(timeout=10)
            create.join(timeout=10)

        assert not disable.is_alive() and not create.is_alive()
        assert not hook_error
        assert not isinstance(results.get("disable"), BaseException)
        assert not isinstance(results.get("create"), BaseException)
        assert results["disable"].status_code == 204
        assert results["create"].status_code in {401, 403}
        with high_client.app.state.database.session_factory() as db:
            user = db.scalar(select(User).where(User.username == "mfa-disable-race"))
            assert user is not None and user.mfa_enabled is False
            sensitive_count = db.scalar(
                select(func.count())
                .select_from(ChatSession)
                .where(
                    ChatSession.owner_id == user.id,
                    ChatSession.security_mode == "confidential",
                )
            )
            assert sensitive_count == 0
