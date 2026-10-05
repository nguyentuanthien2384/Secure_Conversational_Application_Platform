from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from scripts.demo_local import _require_demo_destination, demo_application, demo_settings, main
from src.app.config import Settings


def test_fresh_demo_process_ignores_existing_config_and_cleans_temporary_data(tmp_path):
    sentinel = tmp_path / "existing.db"
    untouched = b"Existing user data: do not open, migrate or replace."
    sentinel.write_bytes(untouched)
    (tmp_path / ".env").write_text(
        f"DATABASE_URL=sqlite:///{sentinel.as_posix()}\nAPP_ENV=production\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "PYTHONUTF8": "1",
        "TEMP": str(tmp_path), "TMP": str(tmp_path), "TMPDIR": str(tmp_path),
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_ENV": "production", "SECURITY_PROFILE": "high",
        "APP_SECRET_KEY_FILE": str(tmp_path / "must-not-read-secret"),
        "GOOGLE_GENAI_API_KEY_FILE": str(tmp_path / "must-not-read-provider-key"),
        "GOOGLE_GENAI_API_KEY": "never-use-or-print-this-provider-secret",
        "SELF_BASE_URL": "https://example.invalid/never-use-this-api",
        "PUBLIC_BASE_URL": "https://example.invalid/never-use-this-url",
        "HTTP_PROXY": "http://example.invalid:9999",
    })
    result = subprocess.run(
        [sys.executable, "-m", "scripts.demo_local", "--check", "--port", "8765"],
        cwd=tmp_path, env=environment, capture_output=True, text=True, encoding="utf-8",
        timeout=90, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: offline chat and DLP" in result.stdout
    assert "PASS: sealed audit chain" in result.stdout
    assert "FAIL:" not in result.stdout
    assert "never-use-or-print-this-provider-secret" not in result.stdout + result.stderr
    assert sentinel.read_bytes() == untouched
    assert not (tmp_path / "secure_chat.db").exists()
    assert not list(tmp_path.glob("scap-demo-*"))


def test_demo_enforces_offline_settings_and_restores_process_globals(tmp_path, monkeypatch):
    from src.app import gradio_ui

    monkeypatch.setenv("SELF_BASE_URL", "https://existing.example.invalid")
    before = Settings.from_env.__func__
    original_ui = (gradio_ui.BASE_URL, gradio_ui.PUBLIC_BASE_URL)
    with demo_application(tmp_path, 8765) as app:
        settings = app.state.settings
        assert settings.google_genai_api_key == ""
        assert not settings.redis_url and not settings.audit_worm_endpoint
        assert not settings.password_breach_check
        assert settings.ids_enabled and settings.audit_chain_enabled
        assert settings.key_provider == "local"
        assert gradio_ui.BASE_URL == "http://127.0.0.1:8765"
        assert gradio_ui.PUBLIC_BASE_URL == gradio_ui.BASE_URL
        assert os.environ["HTTP_PROXY"] == ""
        with httpx.Client() as client, pytest.raises(RuntimeError, match="API nội bộ"):
            client.get("https://example.invalid/")
    assert Settings.from_env.__func__ is before
    assert (gradio_ui.BASE_URL, gradio_ui.PUBLIC_BASE_URL) == original_ui
    assert os.environ["SELF_BASE_URL"] == "https://existing.example.invalid"
    second = demo_settings(tmp_path, 8765)
    assert second.secret_key != settings.secret_key
    assert second.master_encryption_key != settings.master_encryption_key


@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8765/", "http://127.0.0.1:8000/", "http://localhost:8765/",
    "http://127.0.0.1.evil.example:8765/", "http://example.invalid:8765/",
])
def test_http_allowlist_requires_exact_loopback_server(url):
    with pytest.raises(RuntimeError, match="API nội bộ"):
        _require_demo_destination(httpx.Request("GET", url), 8765)
    _require_demo_destination(httpx.Request("POST", "http://127.0.0.1:8765/api/auth/login"), 8765)


@pytest.mark.parametrize("port", ["0", "65536", "-1"])
def test_invalid_port_is_rejected_before_creating_demo(port):
    with pytest.raises(SystemExit) as error:
        main(["--port", port])
    assert error.value.code == 2


def test_ctrl_c_disposes_demo_and_removes_its_temporary_directory(monkeypatch, capsys):
    from contextlib import contextmanager
    from unittest.mock import MagicMock

    directories = []

    @contextmanager
    def application(directory, _port):
        directories.append(directory)
        (directory / "disposable.db").write_text("temporary demo only", encoding="utf-8")
        yield MagicMock()

    def interrupt(server, *_args, **_kwargs):
        # An open browser event stream must not keep the demo alive forever.
        assert server.config.timeout_graceful_shutdown == 5
        assert server.config.limit_concurrency == 64
        assert server.config.backlog == 128
        assert server.config.timeout_keep_alive == 5
        assert server.config.proxy_headers is False
        raise KeyboardInterrupt

    monkeypatch.setattr("scripts.demo_local.demo_application", application)
    monkeypatch.setattr("scripts.demo_local.socket.socket", MagicMock())
    monkeypatch.setattr("scripts.demo_local.uvicorn.Server.run", interrupt)
    assert main([]) == 0
    assert directories and all(not path.exists() for path in directories)
    assert "Đã dừng demo" in capsys.readouterr().out
