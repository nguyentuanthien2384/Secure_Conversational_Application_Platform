"""Launch a disposable, offline SCAP demo: python -m scripts.demo_local.

This is a dedicated local-demo process, not a deployment entry point. Settings
are constructed explicitly; the import-time default app cannot load .env.
Only HTTP calls back to this exact loopback server are allowed, for Gradio's
API callbacks. The real authentication, DLP, encryption and audit code runs.
"""

from __future__ import annotations

import argparse
import base64
import importlib
import logging
import os
import secrets
import socket
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import uvicorn

from src.app.audit_chain import derive_audit_key
from src.app.config import Settings
from src.app.demo_seed import DEMO_PASSPHRASE, DEMO_USERS, seed_demo_data


def demo_settings(directory: Path, port: int) -> Settings:
    """No environment-derived URLs, credentials, cloud services or bootstrap."""
    return Settings(
        environment="development",
        database_url=f"sqlite:///{(directory / 'demo.db').as_posix()}",
        secret_key=secrets.token_urlsafe(48),
        master_encryption_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        allowed_hosts=("127.0.0.1", "localhost"),
        allowed_origins=(f"http://127.0.0.1:{port}", f"http://localhost:{port}"),
        seed_demo_data=False,
        docs_enabled=True,
        allow_demo_ai=True,
        google_genai_api_key="",
        password_breach_check=False,
        siem_json_logs=False,
        # Recovery/notification mail lands as .eml files inside this run's
        # temporary directory, so the demo needs no mail server.
        mail_backend="outbox",
        mail_outbox_dir=str(directory / "outbox"),
        # Browsers accept passkeys for a domain, never for an IP address.
        webauthn_rp_id="localhost",
        webauthn_origins=(f"http://localhost:{port}",),
    )


def _require_demo_destination(request: httpx.Request, port: int) -> None:
    if (
        request.url.scheme != "http"
        or request.url.host != "127.0.0.1"
        or (request.url.port or 80) != port
    ):
        raise RuntimeError("Demo ngoại tuyến chỉ cho phép HTTP tới API nội bộ.")


@contextmanager
def demo_application(directory: Path, port: int) -> Iterator[Any]:
    """Build and release an isolated app, restoring process globals for tests."""
    settings = demo_settings(directory, port)
    local_url = f"http://127.0.0.1:{port}"
    environment = {
        "SELF_BASE_URL": local_url,
        "PUBLIC_BASE_URL": local_url,
        "PORT": str(port),
        "GRADIO_ANALYTICS_ENABLED": "False",
        "HF_HUB_OFFLINE": "1",
        # A corporate/global proxy must never receive loopback API tokens.
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        **{name: "" for name in (
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"
        )},
    }
    sync_transport = httpx.HTTPTransport.handle_request
    async_transport = httpx.AsyncHTTPTransport.handle_async_request

    def local_request(transport, request):
        _require_demo_destination(request, port)
        return sync_transport(transport, request)

    async def local_async_request(transport, request):
        _require_demo_destination(request, port)
        return await async_transport(transport, request)

    logger = logging.getLogger("security.siem")
    previous_logging = (logger.disabled, logger.level, logger.propagate, list(logger.handlers))
    imported_here = "src.app.main" not in sys.modules
    module = None
    app = None
    try:
        with (
            patch.dict(os.environ, environment),
            patch.object(Settings, "from_env", return_value=settings),
            patch.object(httpx.HTTPTransport, "handle_request", local_request),
            patch.object(httpx.AsyncHTTPTransport, "handle_async_request", local_async_request),
        ):
            module = importlib.import_module("src.app.main")
            ui = importlib.import_module("src.app.gradio_ui")
            # Also covers an already-imported UI when invoked by a test runner.
            with patch.object(ui, "BASE_URL", local_url), patch.object(ui, "PUBLIC_BASE_URL", local_url):
                app = module.create_app(settings)
                seed_demo_data(
                    app.state.database,
                    app.state.password_service,
                    app.state.crypto_service,
                    audit_key=derive_audit_key(settings.secret_key),
                    refresh_telemetry=True,
                    log=lambda _message: None,
                )
                yield app
    finally:
        for instance in (app, module.app if imported_here and module is not None else None):
            if instance is not None:
                instance.state.envelope_crypto_service.clear_cache()
                instance.state.database.engine.dispose()
        for handler in logger.handlers:
            if handler not in previous_logging[3]:
                handler.close()
        logger.disabled, logger.level, logger.propagate, logger.handlers = previous_logging


def check_demo(app: Any, port: int) -> list[tuple[str, bool]]:
    """Smoke the real API with synthetic samples and return only fixed labels."""
    from fastapi.testclient import TestClient

    checks: list[tuple[str, bool]] = []
    with TestClient(app, base_url=f"http://127.0.0.1:{port}") as client:
        for label, path in (("health", "/api/health"), ("UI", "/"), ("API docs", "/docs")):
            checks.append((label, client.get(path).status_code == 200))
        tokens: dict[str, str] = {}
        for username, _role in DEMO_USERS:
            response = client.post("/api/auth/login", json={
                "username": username, "password": DEMO_PASSPHRASE,
            })
            success = response.status_code == 200 and bool(response.json().get("access_token"))
            checks.append((f"login {username}", success))
            if success:
                tokens[username] = response.json()["access_token"]
        if "demo.user" in tokens:
            headers = {"Authorization": f"Bearer {tokens['demo.user']}"}
            checks.append(("RBAC", client.get("/api/admin/users", headers=headers).status_code == 403))
            checks.append(("passkey ceremony options", client.post(
                "/api/auth/passkeys/authentication/options",
            ).status_code == 200))
            created = client.post("/api/sessions", json={"title": "Kiểm tra demo"}, headers=headers)
            checks.append(("create conversation", created.status_code == 201))
            if created.status_code == 201:
                response = client.post(f"/api/sessions/{created.json()['id']}/messages", headers=headers,
                                       json={"content": "Email mẫu: sinhvien@example.com"})
                payload = response.json()
                checks.append(("offline chat and DLP", response.status_code == 201
                               and "[DEMO AI]" in str(payload)
                               and bool(payload.get("dlp_redacted"))))
        if "demo.boss" in tokens:
            headers = {"Authorization": f"Bearer {tokens['demo.boss']}"}
            response = client.get("/api/admin/audit/verify", headers=headers)
            checks.append(("sealed audit chain", response.status_code == 200
                           and response.json().get("chain_intact") is True))
    return checks


def main(argv: list[str] | None = None) -> int:
    # Redirected output on Windows may use a legacy code page without Vietnamese
    # letters; degrade to "?" instead of crashing the demo at its first print.
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
            try:
                stream.reconfigure(errors="replace")
            except (AttributeError, ValueError):
                pass
    parser = argparse.ArgumentParser(description="Chạy demo SCAP ngoại tuyến, dữ liệu tạm riêng.")
    parser.add_argument("--port", type=int, default=8000, help="Cổng localhost (mặc định 8000).")
    parser.add_argument("--check", action="store_true", help="Kiểm tra demo rồi thoát, không mở cổng.")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port phải nằm trong khoảng 1–65535")
    with tempfile.TemporaryDirectory(prefix="scap-demo-") as temporary:
        with demo_application(Path(temporary), args.port) as app:
            if args.check:
                checks = check_demo(app, args.port)
                for label, passed in checks:
                    print(f"{'PASS' if passed else 'FAIL'}: {label}")
                return 0 if checks and all(passed for _label, passed in checks) else 1
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                try:
                    listener.bind(("127.0.0.1", args.port))
                except OSError:
                    print(f"Không mở được cổng {args.port}. Chọn cổng khác, ví dụ --port 8001.")
                    return 2
                print(f"\nSCAP DEMO NGOẠI TUYẾN: http://127.0.0.1:{args.port}")
                print("Tài khoản: " + ", ".join(username for username, _role in DEMO_USERS))
                print(f"Mật khẩu mẫu: {DEMO_PASSPHRASE}")
                print("Dữ liệu mẫu và cảnh báo được dựng cho buổi demo; AI trả lời mô phỏng.")
                print(f"Passkey cần mở bằng tên miền: http://localhost:{args.port}")
                print(f"Email xác minh/đặt lại mật khẩu (.eml) được ghi vào: {Path(temporary) / 'outbox'}")
                print("Ctrl+C để dừng. Lần chạy tiếp theo tạo dữ liệu mới; dữ liệu hiện có của bạn được giữ nguyên.")
                config = uvicorn.Config(app, host="127.0.0.1", port=args.port,
                                        access_log=False, proxy_headers=False, log_level="warning",
                                        timeout_graceful_shutdown=5)
                try:
                    uvicorn.Server(config).run(sockets=[listener])
                except KeyboardInterrupt:
                    # Uvicorn re-raises Ctrl+C after graceful shutdown. Keep
                    # the classroom exit clean while context managers dispose
                    # the database and remove this run's temporary files.
                    print("\nĐã dừng demo và kết thúc lượt dữ liệu tạm.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
