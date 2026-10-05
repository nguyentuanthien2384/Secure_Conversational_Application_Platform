"""Exact Host validation, including IPv6, for local and deployed applications."""

from __future__ import annotations

import ipaddress
import re

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

LOCAL_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_allowed_hosts(hosts: tuple[str, ...]) -> tuple[str, ...]:
    """Reject schemes, ports, wildcards and ambiguous host configuration."""
    normalized = []
    for value in hosts:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError("ALLOWED_HOSTS must contain exact hostnames or IP addresses.")
        host = value.lower()
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        if any(char in host for char in "*%/\\@?#"):
            raise ValueError("ALLOWED_HOSTS does not permit wildcards, URLs or scoped addresses.")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in host.split(".")):
                raise ValueError("ALLOWED_HOSTS must contain exact hostnames or IP addresses.") from None
        if host not in normalized:
            normalized.append(host)
    return tuple(normalized)


def effective_allowed_hosts(hosts: tuple[str, ...], environment: str) -> tuple[str, ...]:
    if hosts:
        return normalize_allowed_hosts(hosts)
    if environment == "production":
        raise ValueError("ALLOWED_HOSTS is required in production.")
    return LOCAL_ALLOWED_HOSTS + (("testserver",) if environment == "test" else ())


def _request_host(value: bytes) -> str | None:
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text or any(ord(char) <= 32 or ord(char) >= 127 for char in text):
        return None
    if text.startswith("["):
        closing = text.find("]")
        if closing < 0:
            return None
        host, suffix = text[1:closing], text[closing + 1:]
        try:
            if "%" in host or ipaddress.ip_address(host).version != 6:
                return None
        except ValueError:
            return None
        if suffix and (not suffix.startswith(":") or not _valid_port(suffix[1:])):
            return None
    else:
        if text.count(":") > 1:
            return None
        host, separator, port = text.partition(":")
        if separator and not _valid_port(port):
            return None
    try:
        return normalize_allowed_hosts((host,))[0]
    except ValueError:
        return None


def _valid_port(value: str) -> bool:
    return value.isascii() and value.isdigit() and len(value) <= 5 and 1 <= int(value) <= 65535


class ExactHostMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_hosts: tuple[str, ...]) -> None:
        self.app = app
        self.allowed_hosts = frozenset(normalize_allowed_hosts(allowed_hosts))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        values = [value for key, value in scope.get("headers", []) if key.lower() == b"host"]
        host = _request_host(values[0]) if len(values) == 1 else None
        if host in self.allowed_hosts:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = JSONResponse(
            {"detail": "Host không được cho phép."}, status_code=400,
            headers={
                "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            },
        )
        await response(scope, receive, send)
