from __future__ import annotations

import base64
import json
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from scripts import migrate_database
from src.app.audit import safe_user_agent
from src.app.config import Settings
from src.app.main import _audit_safe_path, _is_disabled_gradio_file_request, create_app
from src.app.security import PasswordBreachCheckUnavailable, PwnedPasswordChecker, safe_json
from src.app.siem import _scrub


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
    assert "img-src 'self' data: blob:;" in csp
    assert "connect-src 'self';" in csp
    assert "https:" not in csp
    assert " ws:" not in csp and " wss:" not in csp
    assert "report-uri /api/security/csp-report" in response.headers.get(
        "Content-Security-Policy-Report-Only", ""
    )


def test_unused_gradio_upload_and_remote_file_proxy_are_closed(
    client: TestClient, monkeypatch
):
    proxy_called = False

    async def fail_if_remote_proxy_runs(*_args, **_kwargs):
        nonlocal proxy_called
        proxy_called = True
        raise AssertionError("Gradio remote proxy must not run")

    monkeypatch.setattr("gradio.routes.secure_url_stream_response", fail_if_remote_proxy_runs)
    upload = client.post(
        "/gradio_api/upload",
        files={"files": ("payload.txt", b"untrusted content", "text/plain")},
    )
    progress = client.get("/gradio_api/upload_progress?upload_id=attacker-controlled")
    remote_file = client.get(
        "/gradio_api/file=https%3A%2F%2F127.0.0.1%3A9%2Fmetadata"
    )
    deprecated_remote_file = client.get("/gradio_api/file/https://evil.example/beacon")
    encoded_deprecated_remote_file = client.get(
        "/gradio_api/file/http%3A%2F%2Fevil.example%2Fbeacon"
    )
    unused_generic_proxy = client.get(
        "/gradio_api/proxy=https%3A%2F%2Fevil.example%2Fbeacon"
    )

    assert {
        upload.status_code,
        progress.status_code,
        remote_file.status_code,
        deprecated_remote_file.status_code,
        encoded_deprecated_remote_file.status_code,
        unused_generic_proxy.status_code,
    } == {404}
    assert proxy_called is False
    assert upload.json() == {"detail": "File transfer is not available."}
    assert upload.headers["Cache-Control"] == "no-store"
    assert upload.headers["X-Content-Type-Options"] == "nosniff"

    # Local files are still governed by Gradio's allowed/blocked path rules so
    # packaged avatars and generated QR codes keep working.
    assert not _is_disabled_gradio_file_request(
        "/gradio_api/file=D:/btl/scap/src/app/ui_assets/assistant.png"
    )
    assert _is_disabled_gradio_file_request(
        "/gradio_api/file=https%253A%252F%252Fevil.example%252Fbeacon.png"
    )
    assert _is_disabled_gradio_file_request(
        "/gradio_api/file/https%253A%252F%252Fevil.example%252Fbeacon.png"
    )


def test_csp_report_retains_metadata_without_secret_urls(
    client: TestClient, monkeypatch
):
    captured: dict[str, object] = {}

    def capture_event(event_type: str, **kwargs) -> None:
        captured["event_type"] = event_type
        captured.update(kwargs)

    monkeypatch.setattr("src.app.main.emit_security_event", capture_event)
    secret = "capability-secret-must-not-reach-logs"
    response = client.post(
        "/api/security/csp-report",
        content=json.dumps(
            {
                "csp-report": {
                    "document-uri": f"https://chat.example.test/private?token={secret}",
                    "blocked-uri": f"https://evil.example/payload.js?secret={secret}",
                    "effective-directive": "script-src-elem",
                    "violated-directive": "script-src-elem",
                    "script-sample": secret,
                    "status-code": 200,
                }
            }
        ),
        headers={"content-type": "application/csp-report"},
    )
    assert response.status_code == 204
    assert captured["event_type"] == "browser.csp.violation"
    assert captured["details"] == {
        "effective_directive": "script-src-elem",
        "violated_directive": "script-src-elem",
        "blocked_origin": "https://evil.example",
        "document_origin": "https://chat.example.test",
        "status_code": 200,
    }
    assert secret not in json.dumps(captured)


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


def test_unknown_audit_and_siem_fields_pass_through_dlp_redaction():
    raw = "alice@example.com Authorization: Bearer abcdefghijklmnop.qrstuvwx"
    persisted = safe_json({"future_unknown_field": raw})
    mirrored = str(_scrub(raw))
    for output in (persisted, mirrored):
        assert "alice@example.com" not in output
        assert "abcdefghijklmnop.qrstuvwx" not in output
        assert "[REDACTED:" in output


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


def _set_valid_high_env(monkeypatch, tmp_path: Path) -> None:
    _set_production_env(monkeypatch)
    app_secret = tmp_path / "app-secret"
    database_password = tmp_path / "database-password"
    redis_password = tmp_path / "redis-password"
    app_secret.write_text(
        "production-secret-key-loaded-from-a-protected-file", encoding="utf-8"
    )
    database_password.write_text("database password:with/specials", encoding="utf-8")
    redis_password.write_text("redis password:with/specials and spaces", encoding="utf-8")
    digest = "a" * 64
    values = {
        "SECURITY_PROFILE": "high",
        "KEY_PROVIDER": "vault",
        "MASTER_ENCRYPTION_KEY": "",
        "MASTER_ENCRYPTION_KEYS": "",
        "VAULT_ADDR": "https://vault.example.test",
        "VAULT_TOKEN_FILE": "/run/secrets/vault_token",
        "VAULT_ALLOW_INSECURE_HTTP": "false",
        "GOOGLE_GENAI_API_KEY": "",
        "GOOGLE_GENAI_API_KEY_FILE": "",
        "APP_SECRET_KEY": "",
        "APP_SECRET_KEY_FILE": str(app_secret),
        "DATABASE_PASSWORD_FILE": str(database_password),
        "REDIS_PASSWORD_FILE": str(redis_password),
        "DATABASE_URL": (
            "postgresql+psycopg://scap_app@db:5432/secure_chat"
            "?sslmode=verify-full&sslrootcert=/run/secrets/internal_ca_cert"
        ),
        "REDIS_URL": (
            "rediss://scap@redis:6379/0?ssl_cert_reqs=required"
            "&ssl_check_hostname=true"
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
        "AUDIT_CHECKPOINT_INTERVAL": "1",
        "AUDIT_MAX_UNANCHORED_EVENTS": "0",
        "AUDIT_WORM_PROBE_INTERVAL_SECONDS": "300",
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


def test_high_profile_rejects_vault_cleartext_override(monkeypatch, tmp_path: Path):
    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv("VAULT_ALLOW_INSECURE_HTTP", "true")
    with pytest.raises(RuntimeError, match="VAULT_ALLOW_INSECURE_HTTP"):
        Settings.from_env()


def test_high_profile_requires_verified_tls_for_postgres_and_redis(
    monkeypatch, tmp_path: Path
):
    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://scap_app@db:5432/secure_chat"
    )
    with pytest.raises(RuntimeError, match="sslmode=verify-full"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv("REDIS_URL", "redis://scap@redis:6379/0")
    with pytest.raises(RuntimeError, match="Redis TLS"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://scap_app@db:5432/secure_chat"
        "?sslmode=verify-full&sslmode=disable",
    )
    with pytest.raises(RuntimeError, match="sslmode=verify-full"):
        Settings.from_env()


def test_high_profile_rejects_redis_tls_query_bypasses(monkeypatch, tmp_path: Path):
    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "REDIS_URL",
        "rediss://scap@redis:6379/0?ssl_cert_reqs=none&ssl_cert_reqs=required"
        "&ssl_check_hostname=true",
    )
    with pytest.raises(RuntimeError, match="Redis TLS"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "REDIS_URL",
        "rediss://scap@redis:6379/0?ssl_cert_reqs=required&ssl_check_hostname=false",
    )
    with pytest.raises(RuntimeError, match="Redis TLS"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "REDIS_URL",
        "rediss://scap@redis:6379/0?ssl_cert_reqs=required"
        "&ssl_check_hostname=false&ssl_check_hostname=true",
    )
    with pytest.raises(RuntimeError, match="Redis TLS"):
        Settings.from_env()


def test_high_profile_secret_files_are_single_source_bounded_and_single_line(
    monkeypatch, tmp_path: Path
):
    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv("APP_SECRET_KEY", "environment-secret-that-must-not-be-accepted")
    with pytest.raises(RuntimeError, match="Chỉ cấu hình một"):
        Settings.from_env()

    _set_valid_high_env(monkeypatch, tmp_path)
    app_secret = tmp_path / "app-secret"
    app_secret.write_text("first line\nsecond line", encoding="utf-8")
    with pytest.raises(RuntimeError, match="một dòng"):
        Settings.from_env()

    app_secret.write_text("x" * 16_385, encoding="utf-8")
    with pytest.raises(RuntimeError, match="16 KiB"):
        Settings.from_env()


def test_high_profile_allows_file_backed_ai_key_but_rejects_environment_key(
    monkeypatch, tmp_path: Path
):
    _set_valid_high_env(monkeypatch, tmp_path)
    ai_key_file = tmp_path / "google-ai-key"
    ai_key_file.write_text("approved-provider-key-material", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_GENAI_API_KEY_FILE", str(ai_key_file))
    assert Settings.from_env().google_genai_api_key == "approved-provider-key-material"

    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv("GOOGLE_GENAI_API_KEY", "inspectable-environment-provider-key")
    with pytest.raises(RuntimeError, match="environment/URL"):
        Settings.from_env()


def test_high_profile_accepts_strict_internal_transport_settings(
    monkeypatch, tmp_path: Path
):
    _set_valid_high_env(monkeypatch, tmp_path)
    settings = Settings.from_env()
    assert "sslmode=verify-full" in settings.database_url
    assert settings.redis_url.startswith("rediss://")
    assert "database%20password%3Awith%2Fspecials" in settings.database_url
    assert "redis%20password%3Awith%2Fspecials%20and%20spaces" in settings.redis_url
    assert settings.audit_checkpoint_interval == 1
    assert settings.audit_max_unanchored_events == 0
    assert settings.audit_worm_probe_interval_seconds == 300


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("AUDIT_CHECKPOINT_INTERVAL", "2", "AUDIT_CHECKPOINT_INTERVAL=1"),
        ("AUDIT_MAX_UNANCHORED_EVENTS", "1", "AUDIT_MAX_UNANCHORED_EVENTS=0"),
        (
            "AUDIT_WORM_PROBE_INTERVAL_SECONDS",
            "301",
            "AUDIT_WORM_PROBE_INTERVAL_SECONDS",
        ),
    ],
)
def test_high_profile_rejects_an_unanchored_audit_tail_budget(
    monkeypatch, tmp_path: Path, name: str, value: str, message: str
):
    _set_valid_high_env(monkeypatch, tmp_path)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match=message):
        Settings.from_env()


def test_standard_profile_rejects_negative_unanchored_audit_budget(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("SECURITY_PROFILE", "standard")
    monkeypatch.setenv("AUDIT_MAX_UNANCHORED_EVENTS", "-1")

    with pytest.raises(RuntimeError, match="không được âm"):
        Settings.from_env()


def test_migration_uses_file_backed_database_password(monkeypatch, tmp_path: Path):
    password_file = tmp_path / "database-password"
    password_file.write_text("owner password:with/specials", encoding="utf-8")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://secure_chat@db:5432/secure_chat?sslmode=verify-full",
    )
    monkeypatch.setenv("DATABASE_PASSWORD_FILE", str(password_file))
    observed: dict[str, object] = {}

    class FakeEngine:
        def dispose(self) -> None:
            observed["disposed"] = True

    class FakeDatabase:
        def __init__(self, database_url: str) -> None:
            observed["database_url"] = database_url
            self.engine = FakeEngine()

        def create_all(self) -> None:
            observed["created"] = True

        def apply_postgres_least_privilege(self) -> None:
            observed["grants"] = True

    monkeypatch.setattr(migrate_database, "Database", FakeDatabase)
    migrate_database.main()

    assert "owner%20password%3Awith%2Fspecials" in str(observed["database_url"])
    assert observed == {
        "database_url": (
            "postgresql+psycopg://secure_chat:owner%20password%3Awith%2Fspecials"
            "@db:5432/secure_chat?sslmode=verify-full"
        ),
        "created": True,
        "grants": True,
        "disposed": True,
    }


def test_deployment_uses_runtime_database_role_and_rfc9116_expiry():
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    local_compose = Path("docker-compose.local.yml").read_text(encoding="utf-8")
    high_compose = Path("docker-compose.high-security.yml").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    caddy = Path("Caddyfile").read_text(encoding="utf-8")
    sql = Path("scripts/db_least_privilege.sql").read_text(encoding="utf-8")
    init_roles = Path("scripts/init_db_roles.sh").read_text(encoding="utf-8")
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
    assert "headers={'Host':host}" in dockerfile
    healthcheck = dockerfile.split("HEALTHCHECK", maxsplit=1)[1]
    assert "/api/ready" in healthcheck
    assert "/api/health" not in healthcheck
    db_service = compose.split("\n  redis:", maxsplit=1)[0]
    assert "read_only: true" in db_service
    assert "/var/run/postgresql" in db_service
    assert "SET log_statement = 'none'" in sql
    assert "SET log_min_duration_statement = -1" in sql
    assert "SET log_min_error_statement = 'panic'" in sql
    assert "--set app_password" not in init_roles
    assert "SCAP_APP_DB_PASSWORD" in init_roles
    assert "sslmode=verify-full" in high_compose
    assert "rediss://scap@redis:6379" in high_compose
    assert '"--tls-port"' in high_compose
    assert "/usr/bin/setpriv --reuid redis --regid redis --clear-groups" in high_compose
    assert "postgres_tls_entrypoint.sh" in high_compose
    assert "/opt/scap/enforce-postgres-tls.sh" in high_compose
    postgres_wrapper = Path("scripts/postgres_tls_entrypoint.sh").read_text(
        encoding="utf-8"
    )
    assert "export POSTGRES_PASSWORD_FILE=" in postgres_wrapper
    assert "export APP_DB_PASSWORD_FILE=" in postgres_wrapper
    assert "export AUDITOR_DB_PASSWORD_FILE=" in postgres_wrapper
    assert "hostnossl all all 0.0.0.0/0 reject" in Path(
        "scripts/enforce_postgres_tls.sh"
    ).read_text(encoding="utf-8")
    assert "PGSSLMODE=verify-full" in high_compose
    assert "env_file: !reset []" in high_compose
    assert 'AUDIT_WORM_PROBE_INTERVAL_SECONDS: "300"' in high_compose
    assert "uv==0.11.15" in dockerfile
    assert "ENV HOME=/app" in dockerfile
    for image_variable in ("BASE_IMAGE", "POSTGRES_IMAGE", "REDIS_IMAGE", "CADDY_IMAGE"):
        assert f"{image_variable}: ${{{image_variable}:?" in high_compose
    assert "--refresh-telemetry" in local_compose
    assert "image: scap-app" in local_compose


def test_gradio_mount_blocks_sensitive_files_and_debug_surfaces():
    main_source = Path("src/app/main.py").read_text(encoding="utf-8")
    ui_source = Path("src/app/gradio_ui.py").read_text(encoding="utf-8")
    assert 'blocked_paths=["/app/.env", "/run/secrets", "/proc", "/sys", "/etc"]' in (
        main_source
    )
    assert "show_error=False" in main_source
    assert "enable_monitoring=False" in main_source
    assert "analytics_enabled=False" in ui_source
    assert "delete_cache=(60, 60)" in ui_source
