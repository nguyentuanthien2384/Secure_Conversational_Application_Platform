from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from scripts import prepare_vps as vps
from src.app.private_storage import check_private_file, create_private_file

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def project(tmp_path, monkeypatch):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "vps.env.example").write_bytes((ROOT / "deploy/vps.env.example").read_bytes())
    for name in vps._read(deploy / "vps.env.example", private=False)[1]:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def values(project):
    return vps._read(project / "deploy/.env.vps", private=True)[1]


def replace(project, **changes):
    path = project / "deploy/.env.vps"
    lines, _ = vps._read(path, private=True)
    output = []
    for line in lines:
        match = vps._ASSIGNMENT.fullmatch(line)
        output.append(f"{match[1]}={changes.pop(match[1])}"
                      if match and match[1] in changes else line)
    output.extend(f"{name}={value}" for name, value in changes.items())
    path.write_text("\n".join(output) + "\n", encoding="utf-8")


PINNED = {name: f"{image}@sha256:" + character * 64
          for name, image, character in (
              ("BASE_IMAGE", "python:3.12-slim", "a"),
              ("POSTGRES_IMAGE", "postgres:17-alpine", "b"),
              ("REDIS_IMAGE", "redis:7.4-alpine", "c"),
              ("CADDY_IMAGE", "caddy:2.10-alpine", "d"),
          )}


def ready(project):
    vps.initialize(project, domain="chat.scap-demo.vn", email="admin@scap-demo.vn")
    replace(project, **PINNED)


def test_init_protects_separate_keys_and_preserves_local_files(project):
    local = project / ".env"
    database = project / "secure_chat.db"
    local.write_bytes(b"local credentials must not be loaded\xff")
    database.write_bytes(b"existing encrypted local database")
    original = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                for path in (local, database)}
    assert vps.initialize(project) == "created"
    check_private_file(project / "deploy/.env.vps")
    config = values(project)
    assert len(config["APP_SECRET_KEY"]) >= 64
    assert len(base64.urlsafe_b64decode(config["MASTER_ENCRYPTION_KEY"])) == 32
    assert len({config[key] for key in vps._PASSWORDS}) == 3
    assert config["PUBLIC_DOMAIN"] == ""
    assert config["ALLOW_DEMO_AI"] == "true"
    assert config["MAIL_BACKEND"] == "disabled"
    assert original == {path: (path.read_bytes(), path.stat().st_mtime_ns)
                        for path in (local, database)}


def test_rerun_never_reads_or_replaces_existing_deployment_keys(project, monkeypatch):
    path = project / "deploy/.env.vps"
    with create_private_file(path) as stream:
        stream.write(b"existing config\xff")
    original = path.read_bytes(), path.stat().st_mtime_ns

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Existing configuration must not be read or rekeyed.")

    monkeypatch.setattr(vps, "_read", forbidden)
    monkeypatch.setattr(vps.secrets, "token_urlsafe", forbidden)
    assert vps.initialize(project, domain="new.scap-demo.vn") == "unchanged"
    assert original == (path.read_bytes(), path.stat().st_mtime_ns)


def test_pending_check_only_names_missing_fields(project, capsys):
    vps.initialize(project)
    config = values(project)
    assert vps.main(["check", "--project", str(project)]) == 2
    output = capsys.readouterr().out
    assert "PUBLIC_DOMAIN" in output and "BASE_IMAGE" in output
    assert all(config[key] not in output for key in (*vps._PASSWORDS,
                                                    "APP_SECRET_KEY", "MASTER_ENCRYPTION_KEY"))


def test_completed_configuration_passes_without_starting_services(project):
    ready(project)
    assert vps.check(project) == []


def test_generated_profile_satisfies_application_production_guards(project, monkeypatch):
    from src.app import config as application_config
    from src.app.mailer import build_mailer

    ready(project)
    monkeypatch.setattr(application_config, "load_dotenv", lambda: None)
    for name, value in values(project).items():
        monkeypatch.setenv(name, value)
    settings = application_config.Settings.from_env()
    assert settings.environment == "production"
    assert settings.security_profile == "standard"
    assert settings.allow_demo_ai
    assert settings.mail_backend == "disabled"
    assert settings.webauthn_rp_id == "chat.scap-demo.vn"
    # The web process builds its mailer at startup even with mail disabled.
    assert build_mailer(settings).sender == "SCAP <no-reply@scap.local>"


@pytest.mark.parametrize("domain", ["localhost", "192.0.2.1", "*.scap-demo.vn", "SCAP.vn",
                                     "https://scap.vn", "scap.vn:443", "scap.vn/path",
                                     "demo.example.org", "demo.test", "scap.vn\nSECRET=value"])
def test_invalid_or_placeholder_domains_never_create_secrets(project, domain):
    with pytest.raises(vps.PreparationError, match="PUBLIC_DOMAIN"):
        vps.initialize(project, domain=domain)
    assert not (project / "deploy/.env.vps").exists()


@pytest.mark.parametrize("changes,field", [
    ({"DOCS_ENABLED": "true"}, "DOCS_ENABLED"),
    ({"SEED_DEMO_DATA": "true"}, "SEED_DEMO_DATA"),
    ({"BOOTSTRAP_ADMIN_PASSWORD": "private-value-must-not-leak"}, "BOOTSTRAP_ADMIN_PASSWORD"),
    ({"BASE_IMAGE": "python:3.12-slim"}, "BASE_IMAGE"),
    ({"ALLOWED_ORIGINS": "https://other.scap.vn"}, "ALLOWED_ORIGINS"),
    ({"WEBAUTHN_RP_ID": "localhost"}, "WEBAUTHN_RP_ID"),
    ({"MAIL_BACKEND": "outbox"}, "MAIL_BACKEND"),
    ({"ALLOW_DEMO_AI": "false"}, "GOOGLE_GENAI_API_KEY"),
    ({"PASSWORD_MAX_CONCURRENT": "8"}, "PASSWORD_MAX_CONCURRENT"),
    ({"REQUEST_IP_MAX_STREAMS": "2"}, "REQUEST_IP_MAX_STREAMS"),
    ({"MASTER_ENCRYPTION_KEY": "invalid-secret"}, "MASTER_ENCRYPTION_KEY"),
    ({"APP_SECRET_KEY": "tiny"}, "APP_SECRET_KEY"),
    ({"COMPOSE_FILE": "evil.yml"}, "COMPOSE_FILE"),
    ({"SCAP_CADDY_IPV4": "172.30.45.9"}, "SCAP_EDGE_SUBNET"),
    ({"SECURITY_TXT_EXPIRES": "2000-01-01T00:00:00Z"}, "SECURITY_TXT_EXPIRES"),
    ({"SMTP_PASSWORD_FILE": "/unmounted/key"}, "SMTP_PASSWORD_FILE"),
    ({"MAIL_FROM": "'SCAP <no-reply@localhost>'"}, "MAIL_FROM"),
])
def test_unsafe_configuration_reports_fields_without_values(project, changes, field):
    ready(project)
    replace(project, **changes)
    issues = vps.check(project)
    assert any(field in issue for issue in issues)
    assert "private-value-must-not-leak" not in "\n".join(issues)


def test_shell_override_detected_without_exposing_password(project, monkeypatch):
    ready(project)
    monkeypatch.setenv("APP_DB_PASSWORD", "shell-private-must-not-leak")
    issues = vps.check(project)
    assert any("APP_DB_PASSWORD: conflicting shell" in issue for issue in issues)
    assert "shell-private-must-not-leak" not in "\n".join(issues)


@pytest.mark.parametrize("line", ["PUBLIC_DOMAIN=duplicate.vn\n", "BAD=$(not-shell)\n",
                                  "SMTP_PASSWORD=secret#comment\n", "BAD=\"quoted\"\n",
                                  "BAD=secret\x00\n"])
def test_duplicate_or_interpolated_assignments_rejected_without_value(project, line, capsys):
    vps.initialize(project)
    with (project / "deploy/.env.vps").open("a", encoding="utf-8") as stream:
        stream.write(line)
    assert vps.main(["check", "--project", str(project)]) == 1
    error = capsys.readouterr().err
    assert "secret" not in error and "not-shell" not in error


def test_single_quoted_smtp_password_remains_literal(project):
    ready(project)
    replace(project, MAIL_BACKEND="smtp", SMTP_HOST="smtp.scap-demo.vn",
            SMTP_PASSWORD="'secret$with#symbols'", SMTP_USERNAME="operator")
    assert values(project)["SMTP_PASSWORD"] == "secret$with#symbols"
    assert vps.check(project) == []


def test_template_cannot_inject_real_provider_credentials(project):
    template = project / "deploy/vps.env.example"
    template.write_text(template.read_text().replace("GOOGLE_GENAI_API_KEY=",
                                                    "GOOGLE_GENAI_API_KEY=private-value"))
    with pytest.raises(vps.PreparationError, match="must not contain credentials"):
        vps.initialize(project)


def test_broad_permissions_rejected_on_posix(project):
    if os.name == "nt":
        pytest.skip("Windows ACL behavior is checked by the shared private-storage tests.")
    ready(project)
    (project / "deploy/.env.vps").chmod(0o644)
    assert vps.main(["check", "--project", str(project)]) == 1


def test_configure_completes_pending_profile_and_keeps_secrets(project):
    vps.initialize(project)
    secrets_before = {key: values(project)[key]
                      for key in (*vps._PASSWORDS, "APP_SECRET_KEY", "MASTER_ENCRYPTION_KEY")}
    changed = vps.configure(project, domain="chat.scap-demo.vn", email="admin@scap-demo.vn",
                            images=PINNED)
    assert "PUBLIC_DOMAIN" in changed and "CADDY_IMAGE" in changed
    check_private_file(project / "deploy/.env.vps")
    config = values(project)
    assert config["ALLOWED_HOSTS"] == "chat.scap-demo.vn,127.0.0.1,localhost,::1"
    assert config["WEBAUTHN_ORIGINS"] == "https://chat.scap-demo.vn"
    assert {key: config[key] for key in secrets_before} == secrets_before
    assert not (project / "deploy/.env.vps.new").exists()
    assert vps.check(project) == []


def test_configure_changes_only_requested_fields(project):
    ready(project)
    vps.configure(project, email="ops@scap-demo.vn")
    config = values(project)
    assert config["CADDY_EMAIL"] == "ops@scap-demo.vn"
    assert config["PUBLIC_DOMAIN"] == "chat.scap-demo.vn"
    assert vps.check(project) == []


@pytest.mark.parametrize("kwargs,field", [
    ({"domain": "demo.example.org"}, "PUBLIC_DOMAIN"),
    ({"email": "root@localhost"}, "CADDY_EMAIL"),
    ({"images": {"BASE_IMAGE": "python:3.12-slim"}}, "BASE_IMAGE"),
    ({"images": {"APP_SECRET_KEY": "x@sha256:" + "a" * 64}}, "APP_SECRET_KEY"),
    ({}, "Nothing to configure"),
])
def test_configure_rejects_invalid_values_without_writing(project, kwargs, field):
    vps.initialize(project)
    original = (project / "deploy/.env.vps").read_bytes()
    with pytest.raises(vps.PreparationError, match=field):
        vps.configure(project, **kwargs)
    assert (project / "deploy/.env.vps").read_bytes() == original


def test_configure_requires_existing_private_configuration(project):
    assert vps.main(["configure", "--project", str(project), "--domain", "chat.scap-demo.vn"]) == 1
    assert not (project / "deploy/.env.vps").exists()


def test_configure_cli_reports_field_names_only(project, capsys):
    vps.initialize(project)
    arguments = ["configure", "--project", str(project), "--domain", "chat.scap-demo.vn",
                 "--email", "admin@scap-demo.vn"]
    arguments += [part for key, value in PINNED.items() for part in ("--image", f"{key}={value}")]
    assert vps.main(arguments) == 0
    output = capsys.readouterr().out
    assert "PUBLIC_DOMAIN" in output and "@sha256:" not in output
    assert vps.main(["check", "--project", str(project)]) == 0


def test_configure_shared_proxy_upgrades_older_configuration(project):
    ready(project)
    path = project / "deploy/.env.vps"
    # Files created before shared-proxy support have no edge keys at all.
    lines = [line for line in vps._read(path, private=True)[0]
             if not line.startswith(tuple(vps._EDGE_DEFAULTS))]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert vps.check(project) == []
    secrets_before = {key: values(project)[key] for key in (*vps._PASSWORDS, "MASTER_ENCRYPTION_KEY")}
    assert "SCAP_EDGE_MODE" in vps.configure(project, edge_mode="shared-proxy")
    config = values(project)
    assert config["SCAP_EDGE_MODE"] == "shared-proxy"
    assert config["SCAP_FRONT_PROXY_IPV4"] == "172.30.47.2"
    assert {key: config[key] for key in secrets_before} == secrets_before
    assert vps.check(project) == []
    vps.configure(project, edge_mode="direct")
    assert sum(line.startswith("SCAP_EDGE_MODE=")
               for line in vps._read(path, private=True)[0]) == 1


@pytest.mark.parametrize("changes,field", [
    ({"SCAP_EDGE_MODE": "public"}, "SCAP_EDGE_MODE"),
    ({"SCAP_SHARED_EDGE_NETWORK": "bad name"}, "SCAP_SHARED_EDGE_NETWORK"),
    ({"SCAP_SHARED_SITES_VOLUME": ""}, "SCAP_SHARED_SITES_VOLUME"),
    ({"SCAP_FRONT_PROXY_IPV4": "172.30.47.3"}, "SCAP_FRONT_PROXY_IPV4"),
    ({"SCAP_FRONT_PROXY_IPV4": "172.30.45.5"}, "SCAP_FRONT_PROXY_IPV4"),
    ({"SCAP_FRONT_PROXY_IPV4": "8.8.8.8"}, "SCAP_FRONT_PROXY_IPV4"),
])
def test_shared_proxy_trusts_one_private_front_address(project, changes, field):
    ready(project)
    vps.configure(project, edge_mode="shared-proxy")
    replace(project, **changes)
    assert any(field in issue for issue in vps.check(project))


def test_configure_rejects_unknown_edge_mode(project):
    vps.initialize(project)
    with pytest.raises(vps.PreparationError, match="SCAP_EDGE_MODE"):
        vps.configure(project, edge_mode="public")


def test_symlink_configuration_is_not_followed(project, tmp_path):
    target = tmp_path / "outside.env"
    target.write_text("unchanged")
    path = project / "deploy/.env.vps"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable.")
    with pytest.raises(vps.PreparationError, match="ordinary file"):
        vps.initialize(project)
    assert target.read_text() == "unchanged"
