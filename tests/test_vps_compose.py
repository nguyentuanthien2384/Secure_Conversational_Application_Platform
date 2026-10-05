from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKER = shutil.which("docker")
pytestmark = pytest.mark.skipif(DOCKER is None, reason="Docker Compose CLI is unavailable")


def resolved_compose(tmp_path: Path, *, overlay="vps-demo", overrides=None):
    """Validate merge behavior with synthetic credentials; never read local .env."""
    app_env = tmp_path / "app.env"
    app_env.write_text(
        "APP_SECRET_KEY=" + "test-only-" * 6 + "\n"
        "MASTER_ENCRYPTION_KEY=" + base64.urlsafe_b64encode(b"K" * 32).decode() + "\n"
        "APP_ENV=development\nSECURITY_PROFILE=high\nKEY_PROVIDER=vault\n"
        "DOCS_ENABLED=true\nSEED_DEMO_DATA=true\nMAIL_BACKEND=outbox\n"
        "BOOTSTRAP_ADMIN_PASSWORD=public-laptop-demo-password\n"
        "POSTGRES_PASSWORD=test-owner-password\n"
        "APP_DB_PASSWORD=test-app-password\n"
        "AUDITOR_DB_PASSWORD=test-auditor-password\n"
        "VAULT_ADDR=https://old-laptop.invalid\nVAULT_TOKEN_FILE=/old/token\n"
        "APP_SECRET_KEY_FILE=/old/app.key\nDATABASE_PASSWORD_FILE=/old/db.key\n"
        "REDIS_PASSWORD_FILE=/old/redis.key\nOIDC_PROXY_SECRET_FILE=/old/oidc.key\n",
        encoding="utf-8",
    )
    values = {
        "SCAP_ENV_FILE": app_env.as_posix(),
        "SCAP_APP_IMAGE": "scap:vps-demo-test",
        "PUBLIC_DOMAIN": "demo.example.org",
        "CADDY_EMAIL": "operator@example.org",
        "SECURITY_TXT_EXPIRES": "2099-01-01T00:00:00Z",
        "POSTGRES_PASSWORD": "test-owner-password",
        "APP_DB_PASSWORD": "test-app-password",
        "AUDITOR_DB_PASSWORD": "test-auditor-password",
        "BASE_IMAGE": "python:3.12-slim@sha256:" + "a" * 64,
        "POSTGRES_IMAGE": "postgres:17-alpine@sha256:" + "b" * 64,
        "REDIS_IMAGE": "redis:7.4-alpine@sha256:" + "c" * 64,
        "CADDY_IMAGE": "caddy:2.10-alpine@sha256:" + "d" * 64,
        "ALLOW_DEMO_AI": "true",
        "MAIL_BACKEND": "disabled",
        "SCAP_CADDY_IPV4": "172.30.45.2",
    }
    values.update(overrides or {})
    compose_env = tmp_path / "compose.env"
    compose_env.write_text(
        "".join(f"{name}={value}\n" for name, value in values.items()), encoding="utf-8"
    )
    process_env = os.environ.copy()
    process_env.update(values)
    completed = subprocess.run(
        [
            DOCKER, "compose", "--project-name", "scap-vps-config-test",
            "--env-file", str(compose_env), "-f", str(ROOT / "docker-compose.yml"),
            "-f", str(ROOT / f"docker-compose.{overlay}.yml"), "config", "--format", "json",
        ],
        cwd=ROOT, env=process_env, capture_output=True, text=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_vps_merge_preserves_network_and_proxy_boundary(tmp_path):
    services = resolved_compose(tmp_path)["services"]
    for name in ("app", "migrate", "db", "redis"):
        assert not services[name].get("ports")
    assert set(services["db"]["networks"]) == {"backend"}
    assert set(services["redis"]["networks"]) == {"backend"}
    assert set(services["caddy"]["networks"]) == {"edge"}
    assert {str(port["published"]) for port in services["caddy"]["ports"]} == {"80", "443"}
    command = services["app"]["command"]
    assert "--proxy-headers" in command
    assert "--forwarded-allow-ips=172.30.45.2" in command
    assert not any("--workers" in part for part in command)


def test_vps_merge_keeps_host_headroom_and_expensive_operations_bounded(tmp_path):
    services = resolved_compose(tmp_path)["services"]
    steady_ram = sum(int(services[name]["mem_limit"]) for name in ("app", "db", "redis", "caddy"))
    assert steady_ram == (1024 + 512 + 192 + 192) * 1024**2
    assert steady_ram <= 2 * 1024**3
    assert int(services["migrate"]["mem_limit"]) == 768 * 1024**2
    assert all(float(service["cpus"]) <= 1 for service in services.values())
    app_env = services["app"]["environment"]
    assert app_env["PASSWORD_MAX_CONCURRENT"] == "1"
    assert app_env["AI_MAX_CONCURRENT"] == "1"
    assert app_env["GRADIO_QUEUE_MAX_SIZE"] == "16"
    assert app_env["GRADIO_CONCURRENCY_LIMIT"] == "2"
    assert app_env["REQUEST_IP_MAX_CONCURRENT"] == "16"
    assert app_env["REQUEST_IP_MAX_STREAMS"] == "4"
    assert "noeviction" in services["redis"]["command"]
    assert "96mb" in services["redis"]["command"]
    assert "max_connections=32" in services["db"]["command"]


def test_vps_merge_rejects_local_demo_flags_and_stale_secret_paths(tmp_path):
    app_env = resolved_compose(tmp_path)["services"]["app"]["environment"]
    assert app_env["APP_ENV"] == "production"
    assert app_env["SECURITY_PROFILE"] == "standard"
    assert app_env["KEY_PROVIDER"] == "local"
    assert app_env["DOCS_ENABLED"] == "false"
    assert app_env["SEED_DEMO_DATA"] == "false"
    assert app_env["PASSWORD_BREACH_CHECK"] == "true"
    for name in (
        "BOOTSTRAP_ADMIN_PASSWORD", "VAULT_ADDR", "VAULT_TOKEN_FILE", "APP_SECRET_KEY_FILE",
        "DATABASE_PASSWORD_FILE", "REDIS_PASSWORD_FILE", "OIDC_PROXY_SECRET_FILE",
    ):
        assert app_env[name] == ""
    assert app_env["ALLOWED_ORIGINS"] == "https://demo.example.org"
    assert app_env["PUBLIC_BASE_URL"] == "https://demo.example.org"
    assert app_env["ALLOWED_HOSTS"] == "demo.example.org,127.0.0.1,localhost,::1"


def test_vps_merge_uses_one_imported_image_and_digest_build_guard(tmp_path):
    services = resolved_compose(tmp_path)["services"]
    assert services["app"]["image"] == services["migrate"]["image"] == "scap:vps-demo-test"
    for name in ("app", "migrate"):
        assert services[name]["build"]["args"]["REQUIRE_BASE_IMAGE_DIGEST"] == "true"
        assert "@sha256:" in services[name]["build"]["args"]["BASE_IMAGE"]
    for name in ("db", "redis", "caddy"):
        assert "@sha256:" in services[name]["image"]


def test_web_runtime_does_not_receive_owner_or_auditor_credentials(tmp_path):
    services = resolved_compose(tmp_path)["services"]
    app_env = services["app"]["environment"]
    for name in ("POSTGRES_PASSWORD", "AUDITOR_DB_PASSWORD", "APP_DB_PASSWORD"):
        assert app_env[name] == ""
    assert app_env["DATABASE_URL"] == (
        "postgresql+psycopg://scap_app:test-app-password@db:5432/secure_chat"
    )
    assert services["migrate"]["environment"]["DATABASE_URL"] == (
        "postgresql+psycopg://secure_chat:test-owner-password@db:5432/secure_chat"
    )
    assert all("test-owner-password" not in str(value) for value in app_env.values())
    assert all("test-auditor-password" not in str(value) for value in app_env.values())
    assert services["db"]["environment"]["POSTGRES_PASSWORD"] == "test-owner-password"
    assert services["db"]["environment"]["AUDITOR_DB_PASSWORD"] == "test-auditor-password"


def test_vps_demo_defaults_and_future_external_services_are_selectable(tmp_path):
    defaults = resolved_compose(tmp_path)["services"]["app"]["environment"]
    assert defaults["ALLOW_DEMO_AI"] == "true"
    assert defaults["MAIL_BACKEND"] == "disabled"
    configured = resolved_compose(
        tmp_path, overrides={"ALLOW_DEMO_AI": "false", "MAIL_BACKEND": "smtp"}
    )["services"]["app"]["environment"]
    assert configured["ALLOW_DEMO_AI"] == "false"
    assert configured["MAIL_BACKEND"] == "smtp"


def test_local_overlay_still_uses_loopback_and_development_guards(tmp_path):
    services = resolved_compose(tmp_path, overlay="local")["services"]
    app = services["app"]
    assert app["environment"]["APP_ENV"] == "development"
    assert app["environment"]["DOCS_ENABLED"] == "true"
    assert app["environment"]["SEED_DEMO_DATA"] == "true"
    assert app["ports"][0]["host_ip"] == "127.0.0.1"
    assert "--no-proxy-headers" in app["command"]
    for name in ("app", "migrate"):
        assert services[name]["build"]["args"]["REQUIRE_BASE_IMAGE_DIGEST"] == "false"
    assert "caddy" not in services
