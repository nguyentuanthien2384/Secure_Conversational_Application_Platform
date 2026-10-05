"""Finite admission budgets; overload never creates another waiting queue."""

from __future__ import annotations

import math
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

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


_STATUS_LABELS = ("1xx", "2xx", "3xx", "4xx", "5xx", "unanswered")
_LATENCY_BOUNDS_MS = (100, 500, 1000, 5000, 10000, float("inf"))
_LATENCY_LABELS = ("0_100", "100_500", "500_1000", "1000_5000", "5000_10000", "10000_plus")
_REJECTION_LABELS = frozenset({
    "request_rate", "request_capacity", "request_source_capacity", "rate_backend_unavailable",
    "password_capacity", "security_dependency_unavailable", "readiness_dependency",
    "ai_capacity_or_quota", "gradio_unavailable", "anonymous_rate_denials", "other",
})
_AUDIT_SAMPLE_LABELS = frozenset({
    "auth.login", "auth.register", "auth.password_reset.request", "auth.password_reset",
    "auth.passkey.login", "other",
})


@dataclass
class _ResponseBucket:
    second: int = -1
    statuses: list[int] = field(default_factory=lambda: [0] * len(_STATUS_LABELS))
    kinds: list[int] = field(default_factory=lambda: [0, 0])
    latencies: list[int] = field(default_factory=lambda: [0] * len(_LATENCY_LABELS))
    latency_total_ms: float = 0.0
    throttled: int = 0


class AvailabilityMonitor:
    """Fixed labels and a 60-slot ring; never retain request-identifying data.

    The recent window contains the current one-second bucket and the previous
    59 buckets. Latency ends at response headers, including for long-lived SSE.
    """

    WINDOW_SECONDS = 60

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self.clock = clock if clock is not None else time.monotonic
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}
        self._last_emit = float("-inf")
        self._since_emit = 0
        self._audit_samples: dict[str, tuple[float, int]] = {}
        self._response_buckets = [_ResponseBucket() for _ in range(self.WINDOW_SECONDS)]

    def observe_response(
        self, status_code: int | None, elapsed_seconds: float, *, streaming: bool,
    ) -> None:
        """Record one response start, or an interrupted request with no headers."""
        second = math.floor(self.clock())
        status_index = (
            status_code // 100 - 1
            if isinstance(status_code, int) and not isinstance(status_code, bool)
            and 100 <= status_code <= 599 else len(_STATUS_LABELS) - 1
        )
        latency_ms = elapsed_seconds * 1000
        if not math.isfinite(latency_ms) or latency_ms < 0:
            latency_ms = 0.0
        with self._lock:
            index = second % self.WINDOW_SECONDS
            bucket = self._response_buckets[index]
            if bucket.second != second:
                bucket = self._response_buckets[index] = _ResponseBucket(second=second)
            bucket.statuses[status_index] += 1
            bucket.kinds[1 if streaming else 0] += 1
            if status_code in {429, 503}:
                bucket.throttled += 1
            if status_index != len(_STATUS_LABELS) - 1:
                bucket.latency_total_ms += latency_ms
                for latency_index, upper in enumerate(_LATENCY_BOUNDS_MS):
                    if latency_ms <= upper:
                        bucket.latencies[latency_index] += 1
                        break

    def reject(self, reason: str) -> None:
        # Fail closed on future callers accidentally passing request values.
        reason = reason if reason in _REJECTION_LABELS else "other"
        now = self.clock()
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
        event_type = event_type if event_type in _AUDIT_SAMPLE_LABELS else "other"
        now = self.clock()
        with self._lock:
            last, suppressed = self._audit_samples.get(event_type, (float("-inf"), 0))
            self._counts["anonymous_rate_denials"] = self._counts.get("anonymous_rate_denials", 0) + 1
            if now - last < 60:
                self._audit_samples[event_type] = (last, suppressed + 1)
                return None
            self._audit_samples[event_type] = (now, 0)
            return suppressed

    def snapshot(self) -> dict[str, object]:
        second = math.floor(self.clock())
        with self._lock:
            current = [bucket for bucket in self._response_buckets
                       if second - self.WINDOW_SECONDS < bucket.second <= second]
            statuses = [sum(bucket.statuses[index] for bucket in current)
                        for index in range(len(_STATUS_LABELS))]
            latencies = [sum(bucket.latencies[index] for bucket in current)
                         for index in range(len(_LATENCY_LABELS))]
            requests = sum(statuses)
            responses = requests - statuses[-1]
            throttled = sum(bucket.throttled for bucket in current)
            slow = sum(latencies[3:])
            alerts = []
            if throttled >= 5:
                alerts.append({"code": "http_overload", "severity": "medium", "count": throttled})
            if statuses[4] >= 5 and statuses[4] >= responses * 0.1:
                alerts.append({"code": "http_server_errors", "severity": "high", "count": statuses[4]})
            if statuses[-1] >= 5:
                alerts.append({"code": "http_unanswered", "severity": "medium", "count": statuses[-1]})
            if responses >= 20 and slow >= responses * 0.2:
                alerts.append({"code": "http_slow_headers", "severity": "medium", "count": slow})
            return {
                "scope": "worker", "rejections": dict(self._counts),
                "anonymous_audit_suppressed": sum(count for _, count in self._audit_samples.values()),
                "http_recent": {
                    "window_seconds": self.WINDOW_SECONDS, "bucket_seconds": 1,
                    "requests": requests, "responses": responses,
                    "status_classes": dict(zip(_STATUS_LABELS, statuses, strict=True)),
                    "request_kinds": {
                        "regular": sum(bucket.kinds[0] for bucket in current),
                        "stream": sum(bucket.kinds[1] for bucket in current),
                    },
                    "latency_measurement": "response_headers",
                    "latency_buckets_ms": dict(zip(_LATENCY_LABELS, latencies, strict=True)),
                    "average_latency_ms": round(
                        sum(bucket.latency_total_ms for bucket in current) / responses, 2,
                    ) if responses else 0.0,
                    "throttled_responses": throttled, "slow_responses": slow,
                },
                "alerts": alerts,
            }


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
        path = scope.get("path", "")
        streaming = scope.get("method") == "GET" and len(path) <= MAX_URI_BYTES and (
            path.rstrip("/") == "/gradio_api/queue/data"
            or path.startswith("/gradio_api/call/")
        )
        started = self.monitor.clock()
        observed = False

        async def observed_send(message):
            nonlocal observed
            if message["type"] == "http.response.start" and not observed:
                observed = True
                self.monitor.observe_response(
                    message["status"], self.monitor.clock() - started, streaming=streaming,
                )
            await send(message)

        try:
            await self._admit(scope, receive, observed_send, streaming=streaming)
        finally:
            if not observed:
                self.monitor.observe_response(
                    None, self.monitor.clock() - started, streaming=streaming,
                )

    async def _admit(
        self, scope: Scope, receive: Receive, send: Send, *, streaming: bool,
    ) -> None:
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
