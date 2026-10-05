"""Disable unused state-sharing and untrusted vendor origin overrides."""

from __future__ import annotations

from urllib.parse import parse_qsl, unquote

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

# Uvicorn interprets proxy headers only from its explicitly trusted peers and
# stores the result in the ASGI scope. Gradio otherwise re-interprets these raw
# headers without a peer check, which permits poisoning its frontend root URL.
_ORIGIN_OVERRIDES = frozenset({
    b"x-forwarded-host", b"x-forwarded-proto", b"x-forwarded-port",
    b"x-forwarded-prefix", b"x-gradio-server", b"forwarded",
})


def _deep_link_request(scope: Scope) -> bool:
    path = scope.get("path", "")
    for _ in range(2):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = path.rstrip("/").lower()
    if path == "/gradio_api/deep_link" or path.startswith("/gradio_api/deep_link/"):
        return True
    # The core API never loads Gradio snapshots. All vendor frontend routes
    # (including additional pages in a future UI) must reject this feature.
    if path == "/api" or path.startswith("/api/"):
        return False
    query = scope.get("query_string", b"").decode("latin-1")
    return any(key == "deep_link" for key, _ in parse_qsl(query, keep_blank_values=True))


class GradioBoundaryMiddleware:
    """Run after framing limits and before any vendor or application handler."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        scoped = dict(scope)
        scoped["headers"] = [
            (key, value) for key, value in scope.get("headers", [])
            if key.lower() not in _ORIGIN_OVERRIDES
        ]
        if scope["type"] == "http" and _deep_link_request(scope):
            # This endpoint serializes UI state to plaintext files. SCAP never
            # uses it; deny before loading sessions or touching the filesystem.
            response = JSONResponse(
                {"detail": "UI state sharing is not available."}, status_code=404,
                headers={
                    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                },
            )
            await response(scoped, receive, send)
            return
        await self.app(scoped, receive, send)
