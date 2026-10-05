"""Finite admission budgets; overload never creates another waiting queue."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from src.app.audit import client_ip
from src.app.config import Settings
from src.app.request_limits import MAX_HEADER_BYTES, MAX_HEADER_COUNT, MAX_URI_BYTES
from src.app.security import (
    PasswordService,
    RedisSlidingWindowRateLimiter,
    SlidingWindowRateLimiter,
)
from src.app.siem import emit_security_event


class CapacityExceeded(RuntimeError):
    """A bounded resource has no free slot; callers must retry later."""


class CapacityBudget:
    def __init__(self, maximum: int) -> None:
        if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
            raise ValueError("Capacity must be a positive integer.")
        self.maximum = maximum
        self._active = 0
        self._rejected = 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self._active >= self.maximum:
                self._rejected += 1
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                raise RuntimeError("Capacity slot released without an acquisition.")
            self._active -= 1

    @contextmanager
    def claim(self) -> Iterator[None]:
        if not self.acquire():
            raise CapacityExceeded("Resource temporarily busy.")
        try:
            yield
        finally:
            self.release()

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {"limit": self.maximum, "active": self._active, "rejected": self._rejected}


class BoundedPasswordService(PasswordService):
    """Bound Argon2 RAM across login, reset, MFA recovery and admin operations."""

    def __init__(self, maximum: int) -> None:
        self.capacity = CapacityBudget(maximum)
        super().__init__()

    def hash(self, password: str) -> str:
        with self.capacity.claim():
            return super().hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        with self.capacity.claim():
            return super().verify(password_hash, password)


class AvailabilityMonitor:
    """Counters have fixed labels, never IPs, paths, credentials or prompts."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._last_emit = float("-inf")
        self._since_emit = 0
        self._audit_samples: dict[str, tuple[float, int]] = {}

    def reject(self, reason: str) -> None:
        # Reasons are constants chosen by this module, not request values.
        now = time.monotonic()
        summary = None
        with self._lock:
            self._counts[reason] = self._counts.get(reason, 0) + 1
            self._since_emit += 1
            if now - self._last_emit >= 60:
                summary = {"rejections_since_previous_summary": self._since_emit,
                           "reason": reason, "scope": "worker"}
                self._since_emit = 0
                self._last_emit = now
        if summary is not None:
            emit_security_event("availability.overload", outcome="blocked", details=summary)

    def sample_anonymous_audit(self, event_type: str) -> int | None:
        """One durable sample per fixed auth event/minute; count every denial."""
        now = time.monotonic()
        with self._lock:
            last, suppressed = self._audit_samples.get(event_type, (float("-inf"), 0))
            self._counts["anonymous_rate_denials"] = self._counts.get("anonymous_rate_denials", 0) + 1
            if now - last < 60:
                self._audit_samples[event_type] = (last, suppressed + 1)
                return None
            self._audit_samples[event_type] = (now, 0)
            return suppressed

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"scope": "worker", "rejections": dict(self._counts),
                    "anonymous_audit_suppressed": sum(count for _, count in self._audit_samples.values())}


class ReadinessProbe:
    """Single flight, with a short success cache only for the standard profile."""

    def __init__(self, cache_seconds: int) -> None:
        self.cache_seconds = cache_seconds
        self.capacity = CapacityBudget(1)
        self._valid_until = 0.0

    def check(self, callback: Callable[[], bool], *, cache_success: bool) -> bool:
        if cache_success and time.monotonic() < self._valid_until:
            return True
        if not self.capacity.acquire():
            return False
        try:
            if cache_success and time.monotonic() < self._valid_until:
                return True
            ready = callback()
            if ready and cache_success:
                self._valid_until = time.monotonic() + self.cache_seconds
            return ready
        finally:
            self.capacity.release()


class AdmissionMiddleware:
    """Reject before buffering JSON, opening DB sessions or invoking the UI.

    Local counters protect the Redis dependency itself. Redis additionally
    enforces global/IP quotas across workers. Slots cover the full response
    lifetime; long-lived Gradio SSE uses a separate finite budget.
    """

    def __init__(
        self, app: ASGIApp, *, settings: Settings, monitor: AvailabilityMonitor,
        requests: CapacityBudget, streams: CapacityBudget,
        shared_limiter: RedisSlidingWindowRateLimiter | None = None,
    ) -> None:
        self.app = app
        self.settings = settings
        self.monitor = monitor
        self.requests = requests
        self.streams = streams
        self.local_limiter = SlidingWindowRateLimiter()
        self.shared_limiter = shared_limiter
        self._source_lock = threading.Lock()
        self._sources: dict[tuple[str, bool], int] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        path = scope.get("path", "")
        query = scope.get("query_string", b"")
        # Delegate oversized metadata to the inner request boundary, which
        # rejects it without reading a body. Never decode unbounded headers.
        if (len(headers) > MAX_HEADER_COUNT
            or sum(len(k) + len(v) + 4 for k, v in headers) > MAX_HEADER_BYTES
            or len(scope.get("raw_path", path.encode("utf-8"))) + 1 + len(query) > MAX_URI_BYTES
            or len(path) + 1 + len(query) > MAX_URI_BYTES):
            await self.app(scope, receive, send)
            return
        settings = self.settings
        ip = client_ip(Request(scope))
        limits = [
            (f"ip:{ip}", settings.request_ip_max_attempts),
            ("global", settings.request_global_max_attempts),
        ]
        if scope.get("method") == "POST" and path.startswith("/api/auth/"):
            limits.append(("auth-global", settings.auth_global_max_attempts))
        if path.rstrip("/") == "/api/ready":
            limits.append(("readiness-global", settings.readiness_max_attempts))
        for key, maximum in limits:
            allowed, retry_after = self.local_limiter.allow(key, maximum, settings.request_window_seconds)
            if not allowed:
                await self._reject(scope, receive, send, 429, "request_rate", retry_after)
                return
        streaming = scope.get("method") == "GET" and (
            path.rstrip("/") == "/gradio_api/queue/data"
            or path.startswith("/gradio_api/call/")
        )
        budget = self.streams if streaming else self.requests
        if not budget.acquire():
            await self._reject(scope, receive, send, 503, "request_capacity", 1)
            return
        source_key = (ip, streaming)
        source_maximum = settings.request_ip_max_streams if streaming else settings.request_ip_max_concurrent
        with self._source_lock:
            source_active = self._sources.get(source_key, 0)
            source_allowed = source_active < source_maximum
            if source_allowed:
                self._sources[source_key] = source_active + 1
        if not source_allowed:
            budget.release()
            await self._reject(scope, receive, send, 503, "request_source_capacity", 1)
            return
        try:
            # Liveness must not depend on Redis availability. It still obeys
            # local size/rate/capacity limits and never performs DB work.
            if self.shared_limiter is not None and not (
                scope.get("method") == "GET" and path == "/api/health"
            ):
                def shared_check() -> tuple[bool, int]:
                    for key, maximum in limits:
                        allowed, retry = self.shared_limiter.allow(key, maximum, settings.request_window_seconds)
                        if not allowed:
                            return False, retry
                    return True, 0

                try:
                    # Redis is synchronous; never stall the ASGI event loop.
                    # The request slot also bounds the number of waiting calls.
                    allowed, retry_after = await anyio.to_thread.run_sync(shared_check)
                except Exception:  # noqa: BLE001 - dependency failures fail closed
                    await self._reject(scope, receive, send, 503, "rate_backend_unavailable", 3)
                    return
                if not allowed:
                    await self._reject(scope, receive, send, 429, "request_rate", retry_after)
                    return
            await self.app(scope, receive, send)
        finally:
            with self._source_lock:
                remaining = self._sources[source_key] - 1
                if remaining:
                    self._sources[source_key] = remaining
                else:
                    self._sources.pop(source_key)
            budget.release()

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send,
        status_code: int, reason: str, retry_after: int,
    ) -> None:
        self.monitor.reject(reason)
        response = JSONResponse(
            {"detail": "Hệ thống đang bận hoặc nhận quá nhiều yêu cầu. Vui lòng thử lại sau."},
            status_code=status_code,
            headers={"Retry-After": str(max(1, retry_after)), "X-Request-ID": str(uuid.uuid4()),
                     "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                     "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                     "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"},
        )
        await response(scope, receive, send)
