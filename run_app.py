#!/usr/bin/env python3
"""Default launcher for the secure FastAPI application."""

from __future__ import annotations

import os

import uvicorn


def _server_limit(name: str, default: int, maximum: int) -> int:
    value = int(os.getenv(name, str(default)))
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}.")
    return value

if __name__ == "__main__":
    uvicorn.run(
        "src.app.main:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("APP_ENV", "development").lower() == "development",
        # Export tickets are short-lived capabilities embedded in a download
        # path. Structured security events replace raw request-path logging.
        access_log=False,
        # Direct local callers cannot select their rate-limit/audit IP.
        proxy_headers=False,
        limit_concurrency=_server_limit("UVICORN_LIMIT_CONCURRENCY", 64, 1_024),
        backlog=_server_limit("UVICORN_BACKLOG", 128, 4_096),
        timeout_keep_alive=_server_limit("UVICORN_KEEPALIVE_SECONDS", 5, 30),
        timeout_graceful_shutdown=_server_limit("UVICORN_SHUTDOWN_SECONDS", 20, 120),
        h11_max_incomplete_event_size=16_384,
    )
