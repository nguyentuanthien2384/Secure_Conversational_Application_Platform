"""Bound request parsing even when a client omits or falsifies Content-Length."""

from __future__ import annotations

import re
import uuid

import anyio
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_BYTES = 1_048_576
MAX_URI_BYTES = 16_384
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestLimitsMiddleware:
    """Read at most 1 MiB in RAM before any JSON parser or route runs.

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
        supplied_id = next(
            (v.decode("latin-1") for k, v in headers if k.lower() == b"x-request-id"), ""
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
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                },
            )
            await response(scope, receive, send)

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
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)
