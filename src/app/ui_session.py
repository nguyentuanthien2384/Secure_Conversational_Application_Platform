"""Short-lived browser handles for restoring Gradio state after a page reload.

The access token stays in server memory. A one-use handoff ticket lets the
browser receive a fresh HttpOnly cookie through an ordinary HTTP response,
because a queued Gradio callback cannot set response cookies itself. This is a
single-process cache: restarting the application intentionally requires login.
Restoring a handle is not authentication; the caller must validate the token
against the existing API before displaying any account data.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from src.app.account_security import DEVICE_COOKIE_NAME
from src.app.browser_security import browser_request_denial

COOKIE_NAME = "scap_ui_session"
_HANDLE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_NO_STORE = {"Cache-Control": "no-store", "Vary": "Origin, Sec-Fetch-Site"}
_BRIDGE_PATH = Path(__file__).resolve().parent / "ui_assets" / "session_bridge.js"
_LOGIN_CREDENTIALS_PATH = _BRIDGE_PATH.with_name("login_credentials.js")
_PASSKEY_PATH = _BRIDGE_PATH.with_name("passkey.js")


class UISessionCapacityError(RuntimeError):
    """The bounded store is full; existing authenticated sessions are preserved."""


@dataclass(frozen=True)
class _Session:
    token: str = field(repr=False)
    expires_at: float
    # Browser-recognition token to place in an HttpOnly cookie at handoff.
    device_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _Ticket:
    session: _Session = field(repr=False)
    expires_at: float


def _token_key(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()


def _key(handle: str | None) -> str | None:
    if not isinstance(handle, str) or not _HANDLE_RE.fullmatch(handle):
        return None
    return hashlib.sha256(handle.encode("ascii")).hexdigest()


class BrowserSessionStore:
    """Bounded, thread-safe, expiring tickets and opaque browser sessions."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        max_tickets: int = 1024,
        max_sessions: int = 1024,
        ticket_ttl: float = 60,
    ) -> None:
        if max_tickets < 1 or max_sessions < 1 or not 0 < ticket_ttl <= 60:
            raise ValueError("Invalid browser-session limits.")
        self._clock = clock
        self._max_tickets = max_tickets
        self._max_sessions = max_sessions
        self._ticket_ttl = ticket_ttl
        self._tickets: dict[str, _Ticket] = {}
        self._sessions: dict[str, _Session] = {}
        # sha256(rotated token) -> successor. Another tab of the same browser
        # may still hold the rotated token; presenting it to the API after the
        # grace period would look like token theft and revoke the device.
        self._successors: dict[str, _Session] = {}
        # sha256(access token) -> device token awaiting the cookie handoff.
        self._pending_devices: dict[str, _Session] = {}
        self._lock = threading.RLock()

    def _prune(self, now: float) -> None:
        for key in [key for key, row in self._tickets.items() if row.expires_at <= now]:
            del self._tickets[key]
        for key in [key for key, row in self._sessions.items() if row.expires_at <= now]:
            del self._sessions[key]
        for table in (self._successors, self._pending_devices):
            for key in [key for key, row in table.items() if row.expires_at <= now]:
                del table[key]

    def issue(self, token: str, expires_at: float) -> str:
        """Mint a handoff only after successful password/MFA authentication."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 16384
                or not math.isfinite(expires_at)
                or expires_at <= now
            ):
                raise ValueError("Cannot remember an expired or invalid session.")
            if len(self._tickets) >= self._max_tickets:
                raise UISessionCapacityError("Browser session handoff capacity reached.")
            ticket = secrets.token_urlsafe(32)
            device = self._pending_devices.pop(_token_key(token), None)
            self._tickets[_key(ticket)] = _Ticket(
                _Session(token, expires_at, device.token if device else None),
                min(now + self._ticket_ttl, expires_at),
            )
            return ticket

    def remember_device(self, access_token: str, device_token: str) -> None:
        """Queue a device token so the next handoff for this login sets its cookie."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._pending_devices) >= self._max_tickets:
                return
            self._pending_devices[_token_key(access_token)] = _Session(
                device_token, now + self._ticket_ttl
            )

    def current_token(self, token: str) -> str:
        """Follow rotations so a stale tab presents the newest token of its login."""
        with self._lock:
            self._prune(self._clock())
            for _ in range(16):
                successor = self._successors.get(_token_key(token))
                if successor is None:
                    break
                token = successor.token
            return token

    def attach(self, ticket: str, previous_cookie: str | None = None) -> str:
        """Consume once, rotate the browser handle, and discard its old record."""
        with self._lock:
            self._prune(self._clock())
            key = _key(ticket)
            row = self._tickets.get(key)
            if row is None:
                raise ValueError("Browser session handoff expired or already used.")
            previous_key = _key(previous_cookie)
            replacing = previous_key in self._sessions
            if len(self._sessions) >= self._max_sessions and not replacing:
                raise UISessionCapacityError("Browser session capacity reached.")
            del self._tickets[key]
            if replacing:
                del self._sessions[previous_key]
            handle = secrets.token_urlsafe(32)
            self._sessions[_key(handle)] = row.session
            return handle

    def take_device_token(self, cookie: str | None) -> str | None:
        """Hand the pending device token to the cookie response exactly once."""
        with self._lock:
            key = _key(cookie)
            row = self._sessions.get(key) if key is not None else None
            if row is None or row.device_token is None:
                return None
            self._sessions[key] = _Session(row.token, row.expires_at)
            return row.device_token

    def restore(self, cookie: str | None) -> tuple[str, float] | None:
        """Read without extending expiry; API validation remains mandatory."""
        with self._lock:
            self._prune(self._clock())
            row = self._sessions.get(_key(cookie))
            return (row.token, row.expires_at) if row is not None else None

    def revoke(self, cookie: str | None) -> None:
        with self._lock:
            self._prune(self._clock())
            self._sessions.pop(_key(cookie), None)

    def rotate_token(self, previous: str, token: str, expires_at: float) -> None:
        """Keep F5 safe between API renewal and the browser's cookie handoff.

        Only called after the authentication API successfully rotates a token.
        No new browser handle is authorized by this operation.
        """
        with self._lock:
            self._prune(self._clock())
            updated = _Session(token, expires_at)
            if len(self._successors) < self._max_sessions * 4:
                self._successors[_token_key(previous)] = updated
            for key, row in self._sessions.items():
                if secrets.compare_digest(row.token, previous):
                    self._sessions[key] = updated
            for key, row in self._tickets.items():
                if secrets.compare_digest(row.session.token, previous):
                    self._tickets[key] = _Ticket(updated, min(row.expires_at, expires_at))


def _secure_cookie(request: Request) -> bool:
    # Do not trust forwarded headers here. Local HTTP is supported for the
    # school demo, including Docker with APP_ENV=production on loopback.
    if request.url.scheme != "http":
        return True
    host = request.url.hostname or ""
    if host.lower() == "localhost":
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def register_ui_session_routes(
    app: FastAPI,
    store: BrowserSessionStore,
    *,
    production: bool = False,
    device_cookie_days: int = 365,
) -> None:
    """Register same-origin cookie handoff endpoints before mounting Gradio.

    ``production`` is retained as explicit integration context; Secure is
    determined by the actual transport, with only the loopback HTTP exception.
    The application's CORS allowlist never grants access to these endpoints.
    """

    def error(code: int, message: str) -> JSONResponse:
        return JSONResponse({"detail": message}, status_code=code, headers=_NO_STORE)

    def denied(request: Request) -> bool:
        return (
            request.headers.getlist("x-scap-ui") != ["1"]
            or browser_request_denial(request) is not None
        )

    @app.get("/api/ui-session/bridge.js", include_in_schema=False)
    def bridge_script():
        # Fixed packaged asset, never a user-supplied path. An external local
        # script works with the existing CSP without requiring unsafe-eval.
        return FileResponse(
            _BRIDGE_PATH, media_type="text/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/api/ui-session/login-credentials.js", include_in_schema=False)
    def login_credentials_script():
        return FileResponse(
            _LOGIN_CREDENTIALS_PATH, media_type="text/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.get("/api/ui-session/passkey.js", include_in_schema=False)
    def passkey_script():
        return FileResponse(
            _PASSKEY_PATH, media_type="text/javascript",
            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    @app.post("/api/ui-session/attach", include_in_schema=False)
    async def attach(request: Request):
        if denied(request):
            return error(403, "Yêu cầu khôi phục phiên phải đến từ cùng trang ứng dụng.")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            return error(415, "Yêu cầu khôi phục phiên phải dùng JSON.")
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 512:
                return error(413, "Yêu cầu khôi phục phiên quá lớn.")
            body.extend(chunk)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return error(400, "Yêu cầu khôi phục phiên không hợp lệ.")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"ticket"}
            or _key(payload.get("ticket")) is None
        ):
            return error(400, "Yêu cầu khôi phục phiên không hợp lệ.")
        try:
            handle = store.attach(payload["ticket"], request.cookies.get(COOKIE_NAME))
        except ValueError:
            return error(401, "Yêu cầu khôi phục phiên đã hết hạn hoặc đã được sử dụng.")
        except UISessionCapacityError:
            return error(503, "Chưa thể lưu phiên; vui lòng thử lại.")
        restored = store.restore(handle)
        if restored is None:
            return error(401, "Phiên đăng nhập đã hết hạn.")
        response = Response(status_code=204, headers=_NO_STORE)
        response.set_cookie(
            COOKIE_NAME,
            handle,
            expires=datetime.fromtimestamp(restored[1], tz=timezone.utc),
            httponly=True,
            secure=_secure_cookie(request),
            samesite="strict",
            path="/",
        )
        device_token = store.take_device_token(handle)
        if device_token:
            # Recognition only (never authorization); it outlives logout so
            # the next sign-in from this browser is not a "new device".
            response.set_cookie(
                DEVICE_COOKIE_NAME,
                device_token,
                max_age=min(device_cookie_days, 400) * 86_400,
                httponly=True,
                secure=_secure_cookie(request),
                samesite="strict",
                path="/",
            )
        return response

    @app.post("/api/ui-session/clear", include_in_schema=False)
    async def clear(request: Request):
        if denied(request):
            return error(403, "Yêu cầu xóa phiên phải đến từ cùng trang ứng dụng.")
        store.revoke(request.cookies.get(COOKIE_NAME))
        response = Response(status_code=204, headers=_NO_STORE)
        response.delete_cookie(
            COOKIE_NAME, path="/", httponly=True,
            secure=_secure_cookie(request), samesite="strict",
        )
        return response
