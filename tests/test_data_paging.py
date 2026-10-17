"""Paged endpoints cover complete owner-scoped data without changing legacy lists."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from src.app.db import utcnow
from src.app.models import ChatSession, User
from tests.conftest import register_and_login
from tests.test_high_security_features import auth


@pytest.fixture
def paged_data(client, app):
    token = register_and_login(client, "paging-owner")
    foreign = register_and_login(client, "paging-foreign")
    with app.state.database.session_factory() as db:
        owner = db.scalar(select(User).where(User.username == "paging-owner"))
        owner.role = "admin"
        other = db.scalar(select(User).where(User.username == "paging-foreign"))
        now = utcnow()
        rows = [ChatSession(owner_id=owner.id, title=f"Paged {index:03}",
                            created_at=now, updated_at=now, retention_expires_at=now + timedelta(days=5))
                for index in range(105)]
        db.add_all(rows)
        hidden = ChatSession(owner_id=other.id, title="Foreign conversation", retention_expires_at=now + timedelta(days=5))
        db.add(hidden)
        db.flush()
        target = rows[0]
        for index in range(8):
            app.state.chat_service.store_message(db, target.id, "user", f"needle result {index}")
        # Keep the only searchable conversation behind the legacy first-100
        # window. Message-key creation otherwise updates its session timestamp.
        target.updated_at = now - timedelta(days=1)
        db.commit()
        ids = {"target": target.id, "hidden": hidden.id}
    return token, foreign, ids


def test_session_pages_reach_beyond_legacy_cap_and_keep_owner_scope(client, paged_data):
    token, _foreign, ids = paged_data
    legacy = client.get("/api/sessions", headers=auth(token))
    assert legacy.status_code == 200 and isinstance(legacy.json(), list) and len(legacy.json()) == 100
    all_ids, offset = [], 0
    while True:
        response = client.get("/api/sessions/page", headers=auth(token), params={"offset": offset, "limit": 17})
        assert response.status_code == 200, response.text
        page = response.json()
        assert page["total"] == 105 and page["offset"] == offset
        all_ids.extend(item["id"] for item in page["items"])
        if not page["has_more"]:
            assert page["next_offset"] is None
            break
        offset = page["next_offset"]
    assert len(set(all_ids)) == len(all_ids) == 105
    assert ids["target"] in all_ids and ids["hidden"] not in all_ids


def test_global_and_current_session_search_pages_count_exact_matches(client, paged_data):
    token, _foreign, ids = paged_data
    response = client.get("/api/search/messages/page", headers=auth(token), params={"q": "needle", "offset": 6, "limit": 1})
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 8 and page["next_offset"] == 7 and page["has_more"] is True
    assert page["items"][0]["session_id"] == ids["target"]
    assert page["items"][0]["content"] == "needle result 6"
    path = f"/api/sessions/{ids['target']}/messages/page"
    current = client.get(path, headers=auth(token), params={"query": "needle", "offset": 7, "limit": 2})
    assert current.status_code == 200, current.text
    assert current.json()["total"] == 8 and current.json()["has_more"] is False
    assert [item["content"] for item in current.json()["items"]] == ["needle result 7"]
    ordinary = client.get(path, headers=auth(token), params={"offset": 2, "limit": 3}).json()
    assert ordinary["total"] == 8
    assert [item["content"] for item in ordinary["items"]] == [f"needle result {index}" for index in (2, 3, 4)]
    assert client.get(f"/api/sessions/{ids['hidden']}/messages/page", headers=auth(token)).status_code == 404


def test_user_pages_pass_legacy_cap_without_exposing_credentials(client, app, paged_data):
    token, foreign, _ids = paged_data
    with app.state.database.session_factory() as db:
        owner = db.scalar(select(User).where(User.username == "paging-owner"))
        db.add_all(User(username=f"paged-user-{index:04}", password_hash=owner.password_hash) for index in range(505))
        db.commit()
    legacy = client.get("/api/admin/users", headers=auth(token))
    assert legacy.status_code == 200 and isinstance(legacy.json(), list) and len(legacy.json()) == 500
    response = client.get("/api/admin/users/page", headers=auth(token), params={"offset": 500, "limit": 20})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 507 and len(data["items"]) == 7 and data["has_more"] is False
    assert "password_hash" not in response.text and "mfa_secret" not in response.text
    assert client.get("/api/admin/users/page", headers=auth(foreign)).status_code == 403


@pytest.mark.parametrize("path,params", [
    ("/api/sessions/page", {"offset": -1}),
    ("/api/sessions/page", {"limit": 101}),
    ("/api/admin/users/page", {"limit": 0}),
    ("/api/search/messages/page", {"q": "x", "limit": 201}),
])
def test_page_parameters_are_bounded(client, app, path, params):
    token = register_and_login(client, "paging-limits")
    if path.startswith("/api/admin/"):
        with app.state.database.session_factory() as db:
            db.scalar(select(User).where(User.username == "paging-limits")).role = "admin"
            db.commit()
    assert client.get(path, headers=auth(token), params=params).status_code == 422
