"""Bound request parsing even when a client omits or falsifies Content-Length."""

from __future__ import annotations

import json
import math
import re
import uuid

import anyio
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES = 1_048_576
MAX_URI_BYTES = 16_384
MAX_HEADER_BYTES = 32_768
MAX_HEADER_COUNT = 100
MAX_JSON_DEPTH = 64
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_SINGLETON_HEADERS = frozenset({
    b"host", b"authorization", b"content-type", b"content-length",
    b"transfer-encoding", b"origin", b"sec-fetch-site", b"x-request-id",
})


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        # Decode escapes before comparing so "role" and "ro\\u006ce" cannot
        # make two different consumers disagree about the same security field.
        key.encode("utf-8")
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _json_constant(_value: str) -> None:
    raise ValueError("non_finite_json_number")


def _json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non_finite_json_number")
    return number


def _json_strings(value: object) -> None:
    if isinstance(value, str):
        # json.loads accepts escaped lone UTF-16 surrogates. They cannot be
        # encoded as UTF-8 by storage, crypto or response code downstream.
        value.encode("utf-8")
    elif isinstance(value, dict):
        for child in value.values():
            _json_strings(child)
    elif isinstance(value, list):
        for child in value:
            _json_strings(child)


def _validate_json(body: bytearray) -> None:
    # Network JSON uses UTF-8. Accept its optional BOM, but avoid UTF-16/32
    # encodings which could evade a byte-oriented nesting check.
    text = body.decode("utf-8-sig")
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("json_nesting_limit")
        elif char in "]}":
            depth -= 1
    try:
        value = json.loads(
            text, object_pairs_hook=_json_object,
            parse_constant=_json_constant, parse_float=_json_float,
        )
    except json.JSONDecodeError:
        # Leave ordinary syntax/schema errors to the existing route handler,
        # preserving FastAPI's validation status and sanitized error format.
        return
    _json_strings(value)


class RequestLimitsMiddleware:
    """Bound headers, body bytes and JSON structure before any route runs.

    The bounded buffer is never written to disk. Response streaming is untouched.
    A total read deadline also bounds clients sending an endless slow body.
    """

    def __init__(self, app: ASGIApp, *, read_timeout: float = 30.0) -> None:
        self.app = app
        self.read_timeout = read_timeout

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        request_ids = [v for k, v in headers if k.lower() == b"x-request-id"]
        supplied_id = (
            request_ids[0].decode("latin-1")
            if len(request_ids) == 1 and len(request_ids[0]) <= 64
            else ""
        )
        request_id = supplied_id if _REQUEST_ID.fullmatch(supplied_id) else str(uuid.uuid4())

        async def reject(code: int, detail: str) -> None:
            response = JSONResponse(
                {"detail": detail},
                status_code=code,
                headers={
                    "X-Request-ID": request_id,
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Cross-Origin-Opener-Policy": "same-origin",
                    "Cross-Origin-Resource-Policy": "same-origin",
                    "X-Permitted-Cross-Domain-Policies": "none",
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                },
            )
            await response(scope, receive, send)

        if len(headers) > MAX_HEADER_COUNT or sum(
            len(name) + len(value) + 4 for name, value in headers
        ) > MAX_HEADER_BYTES:
            await reject(431, "Request headers vượt quá giới hạn cho phép.")
            return
        seen_headers: set[bytes] = set()
        for name, _value in headers:
            name = name.lower()
            if name in _SINGLETON_HEADERS and name in seen_headers:
                await reject(400, "Request headers không hợp lệ.")
                return
            seen_headers.add(name)
        if b"content-length" in seen_headers and b"transfer-encoding" in seen_headers:
            await reject(400, "Request framing không hợp lệ.")
            return
        path = scope.get("raw_path", scope.get("path", "").encode("utf-8"))
        query = scope.get("query_string", b"")
        # Also bound the decoded representation used by the IDS. The separator
        # is included so every accepted surface fits its exact scan budget.
        if (
            len(path) + 1 + len(query) > MAX_URI_BYTES
            or len(scope.get("path", "")) + 1 + len(query) > MAX_URI_BYTES
        ):
            await reject(414, "Request URI vượt quá 16 KiB.")
            return
        lengths = [v for k, v in headers if k.lower() == b"content-length"]
        if len(lengths) > 1 or (
            lengths and (len(lengths[0]) > 20 or not lengths[0].isdigit())
        ):
            await reject(400, "Content-Length không hợp lệ.")
            return
        if lengths and int(lengths[0]) > MAX_BODY_BYTES:
            await reject(413, "Request body vượt quá 1 MiB.")
            return
        body = bytearray()
        try:
            with anyio.fail_after(self.read_timeout):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > MAX_BODY_BYTES:
                        await reject(413, "Request body vượt quá 1 MiB.")
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await reject(408, "Hết thời gian đọc request body.")
            return
        content_type = next(
            (value.decode("latin-1").split(";", 1)[0].strip().lower()
             for name, value in headers if name.lower() == b"content-type"),
            "",
        )
        if body and (
            not content_type
            or content_type in {"application/json", "application/csp-report"}
            or (content_type.startswith("application/") and content_type.endswith("+json"))
            or scope.get("path") == "/api/security/csp-report"
        ):
            try:
                _validate_json(body)
            except (ValueError, RecursionError):
                # Never echo parser exceptions, keys, passwords or raw bodies.
                await reject(400, "JSON không hợp lệ hoặc vượt quá giới hạn cấu trúc.")
                return
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)
