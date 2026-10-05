from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest
import redis

from src.app.security import RedisSlidingWindowRateLimiter, SlidingWindowRateLimiter


@pytest.fixture()
def clock(monkeypatch):
    now = [100.0]
    monkeypatch.setattr("src.app.security.time.monotonic", lambda: now[0])
    return now


def test_rotating_keys_cannot_evict_an_active_login_budget(clock):
    limiter = SlidingWindowRateLimiter(max_keys=2)
    assert limiter.allow("victim", 1, 60) == (True, 0)
    assert limiter.allow("other", 2, 60) == (True, 0)
    for index in range(100):
        allowed, retry = limiter.allow(f"rotation-{index}", 1, 60)
        assert not allowed and retry == 60
    assert limiter.allow("victim", 1, 60) == (False, 60)
    assert limiter.allow("other", 2, 60) == (True, 0)
    assert len(limiter._events) == len(limiter._expires_at) == 2


def test_expired_keys_are_reclaimed_when_capacity_is_reached(clock):
    limiter = SlidingWindowRateLimiter(max_keys=1, cleanup_interval_seconds=60)
    assert limiter.allow("old", 1, 5)[0]
    clock[0] += 5
    assert limiter.allow("new", 1, 5) == (True, 0)
    assert "old" not in limiter._events


def test_periodic_cleanup_removes_inactive_keys_below_capacity(clock):
    limiter = SlidingWindowRateLimiter(max_keys=10, cleanup_interval_seconds=2)
    assert limiter.allow("short", 1, 1)[0]
    assert limiter.allow("active", 1, 30)[0]
    clock[0] += 2
    assert limiter.allow("new", 1, 30)[0]
    assert "short" not in limiter._events
    assert limiter.allow("active", 1, 30) == (False, 28)


def test_expiry_follows_last_accepted_request(clock):
    limiter = SlidingWindowRateLimiter(max_keys=1, cleanup_interval_seconds=1)
    assert limiter.allow("active", 2, 10)[0]
    clock[0] += 9
    assert limiter.allow("active", 2, 10)[0]
    clock[0] += 2
    assert limiter.allow("rotation", 1, 10) == (False, 8)
    assert limiter.allow("active", 2, 10)[0]


def test_denials_do_not_perpetually_extend_bucket_lifetime(clock):
    limiter = SlidingWindowRateLimiter(max_keys=1)
    assert limiter.allow("full", 1, 5)[0]
    clock[0] += 4.5
    assert limiter.allow("full", 1, 5) == (False, 1)
    clock[0] += 0.5
    assert limiter.allow("new", 1, 5)[0]


def test_refund_and_reset_release_only_the_appropriate_budget(clock):
    limiter = SlidingWindowRateLimiter(max_keys=1)
    assert limiter.allow("active", 2, 10)[0]
    assert limiter.allow("active", 2, 10)[0]
    limiter.refund("active")
    assert not limiter.allow("rotation", 1, 10)[0]
    assert limiter.allow("active", 2, 10)[0]
    assert not limiter.allow("active", 2, 10)[0]
    limiter.reset("active")
    assert limiter.allow("new", 1, 10)[0]
    limiter.refund("new")
    assert limiter.allow("replacement", 1, 10)[0]


def test_concurrent_new_keys_cannot_exceed_capacity(clock):
    limiter = SlidingWindowRateLimiter(max_keys=8)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda index: limiter.allow(str(index), 1, 60), range(80)))
    assert sum(allowed for allowed, _ in results) == 8
    assert len(limiter._events) == len(limiter._expires_at) == 8


@pytest.mark.parametrize("kwargs", [
    {"max_keys": 0}, {"max_keys": -1}, {"cleanup_interval_seconds": 0},
    {"cleanup_interval_seconds": float("inf")},
])
def test_invalid_memory_limiter_configuration_fails_closed(kwargs):
    with pytest.raises(ValueError):
        SlidingWindowRateLimiter(**kwargs)


@pytest.mark.parametrize("attempts, window", [(0, 60), (1, 0), (-1, 60), (1, -1)])
def test_invalid_budgets_are_rejected_without_allocating_keys(attempts, window):
    limiter = SlidingWindowRateLimiter()
    with pytest.raises(ValueError):
        limiter.allow("never-stored", attempts, window)
    assert not limiter._events


def test_redis_url_cannot_override_bounded_waits_or_restore_retries(monkeypatch):
    monkeypatch.setattr(redis.Redis, "ping", lambda self: True)
    limiter = RedisSlidingWindowRateLimiter(
        "rediss://redis.example/0?socket_timeout=9999&socket_connect_timeout=9999"
        "&retry_on_timeout=true&max_connections=9999&ssl_cert_reqs=required&ssl_check_hostname=true"
    )
    options = limiter._client.connection_pool.connection_kwargs
    assert options["socket_timeout"] == 3.0
    assert options["socket_connect_timeout"] == 3.0
    assert options["retry_on_timeout"] is False
    assert options["retry_on_error"] == []
    assert options["ssl_cert_reqs"] == "required"
    assert options["ssl_check_hostname"] is True
    assert limiter._client.connection_pool.max_connections == 16
    calls = []

    def unavailable():
        calls.append(True)
        raise redis.TimeoutError("unavailable")

    with pytest.raises(redis.TimeoutError):
        options["retry"].call_with_retry(unavailable, lambda error: None)
    assert len(calls) == 1


def test_redis_unavailable_at_startup_keeps_the_existing_fail_closed_error(monkeypatch):
    def unavailable(self):
        raise redis.TimeoutError("unavailable")

    monkeypatch.setattr(redis.Redis, "ping", unavailable)
    with pytest.raises(RuntimeError, match="Không thể kết nối Redis"):
        RedisSlidingWindowRateLimiter("redis://localhost/0")


@pytest.mark.parametrize("kwargs", [
    {"connect_timeout_seconds": 0}, {"socket_timeout_seconds": -1},
    {"socket_timeout_seconds": float("nan")}, {"connect_timeout_seconds": float("inf")},
])
def test_unbounded_redis_timeout_settings_are_rejected(kwargs):
    with pytest.raises(ValueError):
        RedisSlidingWindowRateLimiter("redis://localhost/0", **kwargs)
