from __future__ import annotations

import base64
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.app.audit import safe_user_agent
from src.app.config import Settings
from src.app.main import _audit_safe_path, create_app
from src.app.security import PasswordBreachCheckUnavailable, PwnedPasswordChecker


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


def test_export_capability_is_removed_from_telemetry_paths():
    raw_token = "signed.secret.capability"
    safe = _audit_safe_path(f"/api/exports/{raw_token}")
    assert safe == "/api/exports/[capability-redacted]"
    assert raw_token not in safe


def test_user_agent_metadata_redacts_pii_and_credentials():
    raw = "client alice@example.com Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
    safe = safe_user_agent(raw)
    assert safe is not None
    assert "alice@example.com" not in safe
    assert "abcdefghijklmnopqrstuvwxyz" not in safe


def test_high_security_password_screening_fails_closed(monkeypatch):
    class UnavailableOpener:
        def open(self, *args, **kwargs):
            raise urllib.error.URLError("simulated outage")

    monkeypatch.setattr(
        "src.app.security.urllib.request.build_opener",
        lambda *handlers: UnavailableOpener(),
    )
    assert (
        PwnedPasswordChecker(enabled=True, fail_closed=False).is_compromised(
            "a sufficiently long candidate passphrase"
        )
        is False
    )
    with pytest.raises(PasswordBreachCheckUnavailable):
        PwnedPasswordChecker(enabled=True, fail_closed=True).is_compromised(
            "a sufficiently long candidate passphrase"
        )


def test_self_registration_can_be_disabled(settings: Settings):
    locked_settings = replace(settings, allow_self_registration=False)
    with TestClient(create_app(locked_settings)) as locked_client:
        response = locked_client.post(
            "/api/auth/register",
            json={
                "username": "not-self-provisioned",
                "password": "Correct Horse Battery1",
            },
        )
    assert response.status_code == 403


def test_lean_api_excludes_the_removed_agent_surface(client: TestClient):
    """Giữ phạm vi app ở chat bảo mật; không vô tình đưa Agent API trở lại."""
    paths = client.get("/openapi.json").json()["paths"]
    assert not any(path.startswith("/api/agent") for path in paths)


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
        "DOCS_ENABLED": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def _set_valid_high_env(monkeypatch) -> None:
    _set_production_env(monkeypatch)
    digest = "a" * 64
    values = {
        "SECURITY_PROFILE": "high",
        "KEY_PROVIDER": "vault",
        "MASTER_ENCRYPTION_KEY": "",
        "MASTER_ENCRYPTION_KEYS": "",
        "VAULT_ADDR": "https://vault.example.test",
        "VAULT_TOKEN_FILE": "/run/secrets/vault_token",
        "VAULT_ALLOW_INSECURE_HTTP": "false",
        "DATABASE_URL": (
            "postgresql+psycopg://scap_app:pw@db:5432/secure_chat"
            "?sslmode=verify-full&sslrootcert=/run/secrets/internal_ca_cert"
        ),
        "REDIS_URL": (
            "rediss://redis:6379/0?ssl_cert_reqs=required"
            "&ssl_ca_certs=/run/secrets/internal_ca_cert"
        ),
        "BASE_IMAGE": f"python:3.12-slim@sha256:{digest}",
        "POSTGRES_IMAGE": f"postgres:17-alpine@sha256:{digest}",
        "REDIS_IMAGE": f"redis:7.4-alpine@sha256:{digest}",
        "CADDY_IMAGE": f"caddy:2.10-alpine@sha256:{digest}",
        "ALLOW_SELF_REGISTRATION": "false",
        "ALLOW_DEMO_AI": "false",
        "SEED_DEMO_DATA": "false",
        "BOOTSTRAP_ADMIN_PASSWORD": "",
        "PASSWORD_BREACH_CHECK": "true",
        "AUDIT_WORM_ENDPOINT": "https://worm.example.test/checkpoints",
        "AUDIT_WORM_TOKEN_FILE": "/run/secrets/audit_worm_token",
        "GRADIO_AUTH_MODE": "oidc",
        "OIDC_PROXY_SECRET_FILE": "/run/secrets/oidc_proxy_secret",
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


def test_high_profile_rejects_mutable_infrastructure_images(monkeypatch):
    _set_production_env(monkeypatch)
    values = {
        "SECURITY_PROFILE": "high",
        "KEY_PROVIDER": "vault",
        "MASTER_ENCRYPTION_KEY": "",
        "MASTER_ENCRYPTION_KEYS": "",
        "VAULT_ADDR": "https://vault.example.test",
        "VAULT_TOKEN_FILE": "/run/secrets/vault_token",
        "BASE_IMAGE": "python:3.12-slim",
        "POSTGRES_IMAGE": "postgres:17-alpine",
        "REDIS_IMAGE": "redis:7.4-alpine",
        "CADDY_IMAGE": "caddy:2.10-alpine",
        "SEED_DEMO_DATA": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="BASE_IMAGE"):
        Settings.from_env()


def test_high_profile_rejects_vault_cleartext_override(monkeypatch):
    _set_valid_high_env(monkeypatch)
    monkeypatch.setenv("VAULT_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(RuntimeError, match="VAULT_ALLOW_INSECURE_HTTP"):
        Settings.from_env()


def test_high_profile_requires_verified_tls_for_postgres_and_redis(monkeypatch):
    _set_valid_high_env(monkeypatch)
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://scap_app:pw@db:5432/secure_chat"
    )
    with pytest.raises(RuntimeError, match="sslmode=verify-full"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch)
    monkeypatch.setenv("REDIS_URL", "redis://redis:6379/0")
    with pytest.raises(RuntimeError, match="Redis TLS"):
        Settings.from_env()


def test_high_profile_accepts_strict_internal_transport_settings(monkeypatch):
    _set_valid_high_env(monkeypatch)
    settings = Settings.from_env()
    assert "sslmode=verify-full" in settings.database_url
    assert settings.redis_url.startswith("rediss://")


def test_deployment_uses_runtime_database_role_and_rfc9116_expiry():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    local_compose = Path("docker-compose.local.yml").read_text(encoding="utf-8")
    high_compose = Path("docker-compose.high-security.yml").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    caddy = Path("Caddyfile").read_text(encoding="utf-8")
    sql = Path("scripts/db_least_privilege.sql").read_text(encoding="utf-8")
    assert "DATABASE_URL: postgresql+psycopg://scap_app:" in compose
    assert "service_completed_successfully" in compose
    assert "change-me-app-password" not in sql
    assert "Expires: {$SECURITY_TXT_EXPIRES}" in caddy
    assert "trusted_proxies static private_ranges" not in caddy
    assert "log_skip @export_download" in caddy
    assert "request>headers>Authorization delete" in caddy
    # Chỉ mô hình sau Caddy mới tin X-Forwarded-For. Khi demo local app được
    # publish trực tiếp, Uvicorn phải giữ IP socket thật để rate-limit/audit.
    assert '"--proxy-headers"' in compose
    assert '"--proxy-headers"' not in local_compose
    assert '"--proxy-headers"' not in dockerfile
    assert '"--no-access-log"' in compose
    assert '"--no-access-log"' in local_compose
    assert '"--no-access-log"' in dockerfile
    assert "sslmode=verify-full" in high_compose
    assert "rediss://redis:6379" in high_compose
    assert '"--tls-port"' in high_compose
    assert "postgres_tls_entrypoint.sh" in high_compose
    assert "--refresh-telemetry" in local_compose
    assert "image: scap-app" in local_compose
