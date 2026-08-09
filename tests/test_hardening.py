from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.app.config import Settings


def test_api_surface_ships_locked_down_csp(client: TestClient):
    response = client.get("/api/health")
    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "unsafe" not in csp


def test_ui_csp_drops_unsafe_eval_by_default(client: TestClient):
    # Any non-/api, non-/docs path receives the UI policy from the middleware.
    response = client.get("/does-not-exist")
    csp = response.headers.get("Content-Security-Policy", "")
    assert csp, "UI responses must carry a CSP header"
    assert "'unsafe-eval'" not in csp
    assert "object-src 'none'" in csp


def test_common_security_headers_present(client: TestClient):
    headers = client.get("/api/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_password_policy_enforces_length(client: TestClient):
    short = client.post(
        "/api/auth/register", json={"username": "shortpw", "password": "Sh0rtPass12"}
    )
    assert short.status_code == 422  # below the 15-char NIST-aligned minimum


def test_password_policy_blocks_exact_common_password(client: TestClient):
    weak = client.post(
        "/api/auth/register",
        json={"username": "weakpw", "password": "passwordpassword"},
    )
    assert weak.status_code == 422


def test_long_passphrase_without_composition_is_accepted(client: TestClient):
    # No uppercase/digit required: length + blocklist is the control, per NIST 800-63B-4.
    ok = client.post(
        "/api/auth/register",
        json={"username": "passphrase-user", "password": "correct horse battery staple"},
    )
    assert ok.status_code == 201, ok.text


def test_invalid_request_id_is_replaced(client: TestClient):
    response = client.get("/api/health", headers={"X-Request-ID": "bad id with spaces"})
    request_id = response.headers["X-Request-ID"]
    assert request_id != "bad id with spaces"
    assert len(request_id) == 36


def _set_production_env(monkeypatch, *, database_user: str = "scap_app") -> None:
    key = base64.urlsafe_b64encode(b"P" * 32).decode("ascii")
    values = {
        "APP_ENV": "production",
        "APP_SECRET_KEY": "production-secret-key-that-is-at-least-32-characters",
        "MASTER_ENCRYPTION_KEY": key,
        "DATABASE_URL": f"postgresql+psycopg://{database_user}:pw@db:5432/secure_chat",
        "REDIS_URL": "redis://redis:6379/0",
        "ALLOWED_ORIGINS": "https://chat.example.test",
        "ALLOWED_HOSTS": "chat.example.test",
        "AGENT_WORKSPACE_ROOT": "/tmp/scap-agent-workspaces",
        "DOCS_ENABLED": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_production_rejects_public_demo_accounts(monkeypatch):
    _set_production_env(monkeypatch)
    monkeypatch.setenv("SEED_DEMO_DATA", "true")
    with pytest.raises(RuntimeError, match="SEED_DEMO_DATA"):
        Settings.from_env()


def test_production_rejects_database_owner_account(monkeypatch):
    _set_production_env(monkeypatch, database_user="secure_chat")
    monkeypatch.setenv("SEED_DEMO_DATA", "false")
    with pytest.raises(RuntimeError, match="tài khoản chủ"):
        Settings.from_env()


def test_production_requires_dedicated_agent_workspace(monkeypatch):
    _set_production_env(monkeypatch)
    monkeypatch.delenv("AGENT_WORKSPACE_ROOT")
    monkeypatch.setenv("SEED_DEMO_DATA", "false")
    with pytest.raises(RuntimeError, match="AGENT_WORKSPACE_ROOT"):
        Settings.from_env()


def test_deployment_uses_runtime_database_role_and_rfc9116_expiry():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    caddy = Path("Caddyfile").read_text(encoding="utf-8")
    sql = Path("scripts/db_least_privilege.sql").read_text(encoding="utf-8")
    assert "DATABASE_URL: postgresql+psycopg://scap_app:" in compose
    assert "service_completed_successfully" in compose
    assert "change-me-app-password" not in sql
    assert "Expires: {$SECURITY_TXT_EXPIRES}" in caddy
