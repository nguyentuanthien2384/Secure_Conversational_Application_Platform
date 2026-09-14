from __future__ import annotations

import threading
import time

from fastapi.testclient import TestClient

from tests.conftest import register_and_login
from tests.test_security_lifecycle import auth, pause_after_sql, run_request

AUTH_SESSION_CLAIM_SQL = (
    "update auth_sessions set revoked_at=auth_sessions.revoked_at "
    "where auth_sessions.jti = ?"
)


def test_two_concurrent_refreshes_mint_only_one_successor(client: TestClient, app):
    token = register_and_login(client, "refresh-race-user")
    results: dict[str, object] = {}

    with pause_after_sql(app.state.database.engine, AUTH_SESSION_CLAIM_SQL) as (
        claimed,
        release,
        hook_error,
    ):
        first = threading.Thread(
            target=run_request,
            args=(
                results,
                "first",
                lambda: client.post("/api/auth/refresh", headers=auth(token)),
            ),
        )
        first.start()
        assert claimed.wait(timeout=5), "first refresh did not claim the bearer session"
        second = threading.Thread(
            target=run_request,
            args=(
                results,
                "second",
                lambda: client.post("/api/auth/refresh", headers=auth(token)),
            ),
        )
        second.start()
        time.sleep(0.15)
        assert second.is_alive(), "second refresh bypassed the session claim"
        release.set()
        first.join(timeout=10)
        second.join(timeout=10)

    assert not first.is_alive() and not second.is_alive()
    assert not hook_error
    assert not isinstance(results.get("first"), BaseException)
    assert not isinstance(results.get("second"), BaseException)
    responses = [results["first"], results["second"]]
    assert sorted(response.status_code for response in responses) == [200, 401]
    successor = next(response.json()["access_token"] for response in responses if response.status_code == 200)
    assert client.get("/api/auth/me", headers=auth(successor)).status_code == 200
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401


def test_logout_wins_even_when_refresh_claimed_the_old_token_first(client: TestClient, app):
    token = register_and_login(client, "refresh-logout-race-user")
    results: dict[str, object] = {}

    with pause_after_sql(app.state.database.engine, AUTH_SESSION_CLAIM_SQL) as (
        claimed,
        release,
        hook_error,
    ):
        refresh = threading.Thread(
            target=run_request,
            args=(
                results,
                "refresh",
                lambda: client.post("/api/auth/refresh", headers=auth(token)),
            ),
        )
        refresh.start()
        assert claimed.wait(timeout=5), "refresh did not claim the bearer session"
        logout = threading.Thread(
            target=run_request,
            args=(
                results,
                "logout",
                lambda: client.post("/api/auth/logout", headers=auth(token)),
            ),
        )
        logout.start()
        time.sleep(0.15)
        assert logout.is_alive(), "logout bypassed the session claim"
        release.set()
        refresh.join(timeout=10)
        logout.join(timeout=10)

    assert not refresh.is_alive() and not logout.is_alive()
    assert not hook_error
    assert not isinstance(results.get("refresh"), BaseException)
    assert not isinstance(results.get("logout"), BaseException)
    assert results["refresh"].status_code == 200
    assert results["logout"].status_code == 204
    successor = results["refresh"].json()["access_token"]
    assert client.get("/api/auth/me", headers=auth(token)).status_code == 401
    assert client.get("/api/auth/me", headers=auth(successor)).status_code == 401
