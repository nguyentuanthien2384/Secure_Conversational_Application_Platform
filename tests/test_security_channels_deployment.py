"""Offline key provisioning and security-channel deployment composition."""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from dotenv import dotenv_values

from scripts.generate_vapid_key import generate_vapid_key
from scripts.package_release import (
    ARCHIVE_ROOT,
    MANIFEST,
    ReleaseError,
    create_release,
    verify_release,
)
from src.app.notification_config import NotificationSettings
from src.app.private_storage import check_private_directory, check_private_file
from tests.test_remote_deploy_gate import deployment as deployment
from tests.test_vps_compose import DOCKER, resolved_compose

ROOT = Path(__file__).resolve().parents[1]


def run_generator(path: Path):
    return subprocess.run(
        [sys.executable, "-m", "scripts.generate_vapid_key", "--output", str(path)],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )


def test_cli_creates_private_p256_pem_and_prints_only_its_public_browser_key(tmp_path):
    output = tmp_path / "private-security-files" / "vapid.pem"
    result = run_generator(output)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert set(document) == {"public_key"}
    assert re.fullmatch(r"[A-Za-z0-9_-]{87}", document["public_key"])
    check_private_directory(output.parent)
    check_private_file(output)
    pem = output.read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1)
    public = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    assert document["public_key"] == base64.urlsafe_b64encode(public).decode().rstrip("=")
    private = base64.urlsafe_b64encode(key.private_numbers().private_value.to_bytes(32, "big")).decode().rstrip("=")
    assert private not in result.stdout + result.stderr
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    assert str(output) not in result.stdout + result.stderr


def test_cli_never_overwrites_an_existing_private_key_or_discloses_it(tmp_path):
    output = tmp_path / "private-security-files" / "vapid.pem"
    first = run_generator(output)
    assert first.returncode == 0
    original, before = output.read_bytes(), output.stat()
    repeated = run_generator(output)
    assert repeated.returncode == 1
    assert repeated.stdout == "" and "new filename" in repeated.stderr
    assert output.read_bytes() == original
    assert (output.stat().st_ino, output.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert "PRIVATE KEY" not in repeated.stderr and str(output) not in repeated.stderr


def test_generated_key_is_directly_loadable_by_the_real_provider_configuration(tmp_path, monkeypatch):
    pytest.importorskip("pywebpush")
    output = tmp_path / "private-security-files" / "vapid.pem"
    public = generate_vapid_key(output)["public_key"]
    monkeypatch.setenv("PUSH_BACKEND", "webpush")
    monkeypatch.setenv("SMS_BACKEND", "disabled")
    monkeypatch.setenv("VAPID_PRIVATE_KEY_FILE", str(output))
    monkeypatch.setenv("VAPID_SUBJECT", "mailto:security@example.org")
    settings = NotificationSettings.from_env(environment="production")
    assert settings.vapid_public_key == public and settings.push_backend == "webpush"
    assert settings.vapid_private_key and settings.vapid_private_key not in repr(settings)


def test_key_generator_is_independent_of_application_env_and_generates_distinct_keys(tmp_path, monkeypatch):
    # Invalid application settings cannot make this provisioning tool import
    # main.py, open an existing DB or load its production configuration.
    monkeypatch.setenv("DATABASE_URL", "not-a-database-url")
    monkeypatch.setenv("PUSH_BACKEND", "invalid")
    monkeypatch.setenv("SMS_BACKEND", "twilio")
    first = generate_vapid_key(tmp_path / "one" / "vapid.pem")
    second = generate_vapid_key(tmp_path / "two" / "vapid.pem")
    assert first["public_key"] != second["public_key"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions; Windows ACL covered by the CLI test")
def test_generator_refuses_an_existing_shared_directory_without_changing_permissions(tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    result = run_generator(directory / "vapid.pem")
    assert result.returncode == 1
    assert directory.stat().st_mode & 0o777 == 0o755
    assert not (directory / "vapid.pem").exists()


@pytest.mark.skipif(DOCKER is None, reason="Docker Compose CLI is unavailable")
def test_security_channel_mount_is_optional_and_default_backends_stay_disabled(tmp_path):
    default = resolved_compose(tmp_path)["services"]
    assert all(volume["target"] != "/run/scap-security" for volume in default["app"].get("volumes", []))
    app = resolved_compose(tmp_path, extra=("security-channels",), overrides={
        "SCAP_SECURITY_FILES_DIR": (tmp_path / "not-created-by-compose").as_posix(),
        "PUSH_BACKEND": "", "SMS_BACKEND": "", "GEOIP_BACKEND": "",
    })["services"]["app"]
    assert app["environment"]["PUSH_BACKEND"] == "disabled"
    assert app["environment"]["SMS_BACKEND"] == "disabled"
    assert app["environment"]["GEOIP_BACKEND"] == "disabled"
    assert not (tmp_path / "not-created-by-compose").exists()


@pytest.mark.skipif(DOCKER is None, reason="Docker Compose CLI is unavailable")
def test_security_overlay_uses_explicit_read_only_non_creating_bind_for_app_only(tmp_path):
    folder = tmp_path / "operator-files"
    folder.mkdir()
    services = resolved_compose(tmp_path, extra=("security-channels",), overrides={
        "SCAP_SECURITY_FILES_DIR": folder.as_posix(), "PUSH_BACKEND": "webpush",
        "SMS_BACKEND": "twilio", "GEOIP_BACKEND": "maxmind",
    })["services"]
    volume = next(item for item in services["app"]["volumes"] if item["target"] == "/run/scap-security")
    assert volume["type"] == "bind" and volume["read_only"] is True
    assert volume["bind"]["create_host_path"] is False
    assert Path(volume["source"]) == folder
    app_env = services["app"]["environment"]
    assert app_env["VAPID_PRIVATE_KEY_FILE"] == "/run/scap-security/vapid.pem"
    assert app_env["TWILIO_AUTH_TOKEN_FILE"] == "/run/scap-security/twilio-token"
    assert app_env["GEOIP_DATABASE_FILE"] == "/run/scap-security/GeoLite2-City.mmdb"
    assert (app_env["PUSH_BACKEND"], app_env["SMS_BACKEND"], app_env["GEOIP_BACKEND"]) == ("webpush", "twilio", "maxmind")
    for name in ("migrate", "db", "redis", "caddy"):
        assert all(item["target"] != "/run/scap-security" for item in services[name].get("volumes", []))
    assert "PRIVATE KEY" not in json.dumps(app_env) and "TWILIO_AUTH_TOKEN" not in app_env


@pytest.mark.parametrize("folder", ["", "/opt/scap/operator private files"])
def test_vps_wrapper_adds_security_overlay_only_when_operator_supplies_host_path(deployment, folder):
    path = deployment.project / "deploy/.env.vps"
    with path.open("a", encoding="utf-8", newline="\n") as target:
        target.write(f"SCAP_SECURITY_FILES_DIR={folder}\nTWILIO_AUTH_TOKEN=DO-NOT-PRINT-TOKEN\n")
    result, logs = deployment(script="vps-compose.sh", arguments=("config", "--quiet"))
    assert result.returncode == 0, result.stdout + result.stderr
    assert ("-f docker-compose.security-channels.yml" in logs["docker_log"]) == bool(folder)
    assert "--env-file deploy/.env.vps" in logs["docker_log"]
    assert "DO-NOT-PRINT-TOKEN" not in result.stdout + result.stderr + logs["docker_log"]
    assert not logs["curl_log"] and not logs["python_log"]


def test_templates_disable_channels_and_upload_bundle_includes_the_overlay_only():
    for name in (".env.example", "deploy/vps.env.example"):
        values = dotenv_values(ROOT / name)
        assert values["PUSH_BACKEND"] == values["SMS_BACKEND"] == values["GEOIP_BACKEND"] == "disabled"
        assert not values["SCAP_SECURITY_FILES_DIR"]
        assert not values["VAPID_SUBJECT"] and not values["TWILIO_ACCOUNT_SID"]
    source = (ROOT / "deploy/deploy.ps1").read_text(encoding="utf-8-sig")
    matched = re.search(r"\$BundleFiles\s*=\s*@\((.*?)\)", source, re.S)
    assert matched is not None
    files = re.findall(r'"([^"]+)"', matched[1])
    assert "docker-compose.security-channels.yml" in files
    assert "scripts" in files  # Includes generate_vapid_key.py without private outputs.
    assert not any("local_data" in name or "vapid.pem" in name or "security-files" in name for name in files)


@pytest.fixture
def release_project(tmp_path):
    # Small real files needed to build/run a source release. The independent
    # end-to-end CLI test below also packages and verifies the whole repository.
    from scripts.package_release import _REQUIRED

    project = tmp_path / "project"
    for name in _REQUIRED:
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((ROOT / name).read_bytes())
    return project


def test_source_release_is_deterministic_and_excludes_private_runtime_outputs(release_project, tmp_path):
    import hashlib

    private_paths = [
        ".env", "deploy/.env.vps", "deploy/out/private.py", "deploy/secrets/config.py",
        "src/app/.env", "src/app/credentials.json", "local_data/private.py", "client_data/profile.json",
        "clients/mls_native/target/private.py", "reports/private.py", "backups/private.py",
        "src/app/__pycache__/private.py", "src/app/private.pem", "src/app/private.db",
    ]
    for name in private_paths:
        target = release_project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"SYNTHETIC-PRIVATE-DATA-DO-NOT-PACKAGE")
    native_source = release_project / "clients/mls_native/src/main.rs"
    native_source.parent.mkdir(parents=True, exist_ok=True)
    native_source.write_text("fn main() {}\n", encoding="utf-8")
    native_license = release_project / "clients/mls_native/vendor/hpke-rs-libcrux/LICENSE-MPL-2.0"
    native_license.parent.mkdir(parents=True, exist_ok=True)
    native_license.write_text("SYNTHETIC PUBLIC LICENSE\n", encoding="utf-8")
    (native_license.parent / "provenance.json").write_text('{"source":"public upstream"}', encoding="utf-8")
    (native_license.parent / "Cargo.toml.orig").write_text("[package]\n", encoding="utf-8")
    first = create_release(release_project, tmp_path / "first.tar.gz")
    second = create_release(release_project, tmp_path / "second.tar.gz")
    assert first["sha256"] == second["sha256"]
    archive_bytes = (tmp_path / "first.tar.gz").read_bytes()
    assert hashlib.sha256(archive_bytes).hexdigest() == first["sha256"]
    assert (tmp_path / "first.tar.gz.sha256").read_text() == f"{first['sha256']}  first.tar.gz\n"
    with tarfile.open(tmp_path / "first.tar.gz", "r:gz") as archive:
        names = archive.getnames()
        assert len(names) == len(set(names)) == first["files"] + 1
        assert f"{ARCHIVE_ROOT}/clients/mls_native/src/main.rs" in names
        assert f"{ARCHIVE_ROOT}/clients/mls_native/vendor/hpke-rs-libcrux/LICENSE-MPL-2.0" in names
        assert f"{ARCHIVE_ROOT}/clients/mls_native/vendor/hpke-rs-libcrux/provenance.json" in names
        assert f"{ARCHIVE_ROOT}/clients/mls_native/vendor/hpke-rs-libcrux/Cargo.toml.orig" in names
        assert not any(f"{ARCHIVE_ROOT}/{name}" in names for name in private_paths)
        assert all(item.isfile() and not item.issym() and not item.islnk() for item in archive.getmembers())
        for item in archive.getmembers():
            assert b"SYNTHETIC-PRIVATE-DATA-DO-NOT-PACKAGE" not in archive.extractfile(item).read()


def test_source_release_refuses_overwrite_or_partial_overwrite(release_project, tmp_path):
    target = tmp_path / "release.tar.gz"
    create_release(release_project, target)
    before = target.read_bytes()
    with pytest.raises(ReleaseError, match="already exists"):
        create_release(release_project, target)
    assert target.read_bytes() == before
    sidecar_only = tmp_path / "sidecar-only.tar.gz.sha256"
    sidecar_only.write_text("KEEP", encoding="utf-8")
    with pytest.raises(ReleaseError, match="already exists"):
        create_release(release_project, tmp_path / "sidecar-only.tar.gz")
    assert sidecar_only.read_text() == "KEEP"
    assert not (tmp_path / "sidecar-only.tar.gz").exists()


def test_source_release_detects_corruption_and_does_not_need_git_docker_or_application_config(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("DATABASE_URL", "must-not-be-loaded")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", "must-not-be-loaded")
    monkeypatch.setenv("PUSH_BACKEND", "invalid")
    target = tmp_path / "complete-source.tar.gz"
    created = subprocess.run(
        [sys.executable, "-m", "scripts.package_release", "create", "--project", str(ROOT), "--output", str(target)],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert created.returncode == 0, created.stderr
    with tarfile.open(target, "r:gz") as archive:
        # All archive members are fixed allowlisted regular files. Using data
        # filtering additionally enforces confinement in this integration test.
        archive.extractall(tmp_path / "extracted", filter="data")
    extracted = tmp_path / "extracted" / ARCHIVE_ROOT
    assert (extracted / "clients/mls_native/src/main.rs").exists()
    assert (extracted / "src/app/private_storage.py").exists()
    assert (extracted / "deploy/vps.env.example").exists()
    assert not (extracted / "deploy/.env.vps").exists() and not (extracted / ".env").exists()
    verified = subprocess.run(
        [sys.executable, "-m", "scripts.package_release", "verify", "--project", "."],
        cwd=extracted, capture_output=True, text=True, timeout=30, check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["verified"] is True
    with (extracted / "src/app/main.py").open("ab") as modified:
        modified.write(b"\n# changed after release\n")
    with pytest.raises(ReleaseError, match="do not match"):
        verify_release(extracted)


@pytest.mark.parametrize("replacement", ["../outside.py", "/outside.py", "src/../outside.py", "src\\outside.py", ".env", "deploy/.env.vps"])
def test_release_manifest_rejects_traversal_or_private_paths_without_opening_them(release_project, replacement):
    document = {"schema_version": 1, "archive_root": ARCHIVE_ROOT, "files": [
        {"path": replacement, "size": 1, "mode": 0o644, "sha256": "0" * 64},
    ]}
    (release_project / MANIFEST).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReleaseError, match="invalid source entry"):
        verify_release(release_project)


def test_source_release_rejects_linked_source_and_never_emits_an_archive(release_project, tmp_path):
    linked = release_project / "src/app/linked.py"
    outside = tmp_path / "outside.py"
    outside.write_text("PRIVATE", encoding="utf-8")
    try:
        linked.symlink_to(outside)
    except OSError:
        pytest.skip("Current Windows token cannot create symbolic links")
    target = tmp_path / "linked-source.tar.gz"
    with pytest.raises(OSError):
        create_release(release_project, target)
    assert not target.exists() and not target.with_name(target.name + ".sha256").exists()


def test_powershell_package_action_is_independent_from_remote_deployment_checks():
    source = (ROOT / "deploy/deploy.ps1").read_text(encoding="utf-8-sig")
    matched = re.search(r'"package"\s*\{(.*?)\n        \}', source, re.S)
    assert matched is not None
    assert "scripts.package_release" in matched[1] and "Assert-Python" in matched[1]
    assert not any(value in matched[1] for value in ("Assert-Server", "Assert-Docker", "Test-Dns", "prepare_vps", "Get-Setting", "Invoke-Checked ssh"))


def test_extracted_source_layout_can_run_remote_acceptance_gate_without_git(deployment):
    # Source releases preserve deploy/, while the older prebuilt-image upload
    # layout puts wrappers at the root. Both must reach the same health gates.
    (deployment.project / ".git").rmdir()
    (deployment.project / "deploy/backup.sh").write_bytes((ROOT / "deploy/backup.sh").read_bytes())
    result, logs = deployment()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[OK] App/migration dung image" in result.stdout
    assert "https://gate.invalid/api/health" in logs["curl_log"]
    assert "/deploy/backup.sh" in logs["cron_content"]


def test_powershell_package_runs_locally_without_remote_or_docker_tools(tmp_path, monkeypatch):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("SCAP_VPS", "this is not a valid SSH target")
    monkeypatch.setenv("DATABASE_URL", "must-not-be-loaded")
    target = tmp_path / "powershell-source.tar.gz"
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ROOT / "deploy/deploy.ps1"),
         "package", "-Output", str(target)],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.exists() and target.with_name(target.name + ".sha256").exists()
