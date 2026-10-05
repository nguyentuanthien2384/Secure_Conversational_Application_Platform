"""Fresh setup protects new secrets without changing an existing installation."""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

import pytest
from dotenv import dotenv_values

from scripts import local_storage as local
from src.app.private_storage import (
    PrivateStorageError,
    check_private_directory,
    check_private_file,
    create_private_directory,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".env.example").write_bytes((ROOT / ".env.example").read_bytes())
    return tmp_path


def test_fresh_configuration_and_storage_are_private_with_independent_keys(project, tmp_path):
    report = local.initialize_local_project(project)
    assert report == {"status": "initialized", "storage": "local_data"}
    check_private_file(project / ".env")
    check_private_directory(project / "local_data")
    check_private_directory(project / "local_data" / "mail_outbox")
    values = dotenv_values(project / ".env")
    assert len(values["APP_SECRET_KEY"]) >= 64
    assert len(base64.urlsafe_b64decode(values["MASTER_ENCRYPTION_KEY"])) == 32
    assert values["DATABASE_URL"] == "sqlite:///./local_data/secure_chat.db"
    assert values["MAIL_OUTBOX_DIR"] == "local_data/mail_outbox"
    assert values["SEED_DEMO_DATA"] == "true"
    second = project / "second"
    second.mkdir()
    (second / ".env.example").write_bytes((ROOT / ".env.example").read_bytes())
    local.initialize_local_project(second)
    assert dotenv_values(second / ".env")["APP_SECRET_KEY"] != values["APP_SECRET_KEY"]
    assert not (project / "secure_chat.db").exists()
    assert not (project / "local_data" / "secure_chat.db").exists()


def test_existing_configuration_is_never_read_or_rewritten(project, monkeypatch):
    configuration = project / ".env"
    original = b"unknown keys and original non-UTF8 bytes\xff\r\n"
    configuration.write_bytes(original)
    before = configuration.stat()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Existing setup must not read secrets or generate replacements.")

    monkeypatch.setattr(local, "_read_template", forbidden)
    monkeypatch.setattr(local.secrets, "token_urlsafe", forbidden)
    assert local.initialize_local_project(project) == {"status": "unchanged"}
    after = configuration.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_mode) == (
        before.st_ino, before.st_mtime_ns, before.st_mode,
    )
    assert configuration.read_bytes() == original
    assert not (project / "local_data").exists()


@pytest.mark.parametrize("directory", ["", "local_data"])
@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_missing_configuration_never_selects_empty_database_over_old_data(project, directory, suffix):
    parent = project / directory
    parent.mkdir(exist_ok=True)
    database = parent / ("secure_chat.db" + suffix)
    database.write_bytes(b"existing account data")
    with pytest.raises(local.LocalStorageError, match="matching configuration"):
        local.initialize_local_project(project)
    assert database.read_bytes() == b"existing account data"
    assert not (project / ".env").exists()


@pytest.mark.parametrize("change", ["missing", "duplicate", "production", "bad_utf8", "oversize", "custom_db"])
def test_invalid_template_is_rejected_before_creating_private_storage(project, change):
    template = project / ".env.example"
    text = template.read_text(encoding="utf-8")
    if change == "missing":
        template.write_text(text.replace("APP_SECRET_KEY=\n", ""), encoding="utf-8")
    elif change == "duplicate":
        template.write_text(text + "\nAPP_SECRET_KEY=duplicate\n", encoding="utf-8")
    elif change == "production":
        template.write_text(text.replace("APP_ENV=development", "APP_ENV=production"), encoding="utf-8")
    elif change == "custom_db":
        (project / "existing-custom.db").write_bytes(b"existing encrypted accounts")
        template.write_text(
            text.replace("sqlite:///./secure_chat.db", "sqlite:///./existing-custom.db"), encoding="utf-8",
        )
    else:
        template.write_bytes(b"\xff" if change == "bad_utf8" else b"x" * 65_537)
    with pytest.raises(local.LocalStorageError):
        local.initialize_local_project(project)
    assert not (project / ".env").exists()
    assert not (project / "local_data").exists()


def test_existing_insecure_data_directory_is_not_repaired_or_used(project):
    directory = project / "local_data"
    directory.mkdir()
    if os.name != "nt":
        directory.chmod(0o755)
    with pytest.raises(PrivateStorageError):
        local.initialize_local_project(project)
    assert directory.exists() and not list(directory.iterdir())
    assert not (project / ".env").exists()


def test_existing_private_empty_storage_can_be_reused(project):
    create_private_directory(project / "local_data")
    assert local.initialize_local_project(project)["status"] == "initialized"
    check_private_directory(project / "local_data")


def test_environment_creation_race_keeps_other_configuration(project, monkeypatch):
    original_create = local.create_private_file
    sentinel = b"existing matching key configuration\n"

    def raced(path):
        path.write_bytes(sentinel)
        return original_create(path)

    monkeypatch.setattr(local, "create_private_file", raced)
    assert local.initialize_local_project(project) == {"status": "unchanged"}
    assert (project / ".env").read_bytes() == sentinel


def test_failed_secret_write_removes_only_own_partial_configuration(project, monkeypatch):
    def failed(_descriptor):
        raise OSError("Synthetic storage failure.")

    monkeypatch.setattr(local.os, "fsync", failed)
    with pytest.raises(OSError):
        local.initialize_local_project(project)
    assert not (project / ".env").exists()
    check_private_directory(project / "local_data")


def test_cli_does_not_print_generated_keys_or_paths(project, capsys):
    assert local.main(["init", "--project", str(project)]) == 0
    output = capsys.readouterr()
    values = dotenv_values(project / ".env")
    assert values["APP_SECRET_KEY"] not in output.out + output.err
    assert values["MASTER_ENCRYPTION_KEY"] not in output.out + output.err
    assert str(project) not in output.out + output.err
    assert local.main(["init", "--project", str(project)]) == 0
    assert "preserved unchanged" in capsys.readouterr().out


def test_mkdir_cli_is_new_only_and_private(tmp_path, capsys):
    directory = tmp_path / "operator-private"
    arguments = ["mkdir", "--directory", str(directory)]
    assert local.main(arguments) == 0
    check_private_directory(directory)
    assert local.main(arguments) == 1
    assert "already exists" in capsys.readouterr().err
    assert directory.exists() and not list(directory.iterdir())


@pytest.mark.parametrize("wrapper", ["setup.ps1", "setup.sh"])
def test_setup_wrappers_bootstrap_runtime_before_private_init(wrapper):
    content = (ROOT / wrapper).read_text(encoding="utf-8")
    assert content.index("uv sync --group dev") < content.index("python -m scripts.local_storage init")
    assert "Copy-Item" not in content and "cp .env.example .env" not in content
    assert "scripts/generate_secrets.py" not in content


@pytest.mark.skipif(os.name != "nt", reason="Verify actual Windows SQLite sidecar ACL inheritance.")
def test_fresh_sqlite_wal_sidecars_only_inherit_user_and_system_grants(project):
    from src.app import private_storage as storage

    local.initialize_local_project(project)
    database = project / "local_data" / "secure_chat.db"
    api = storage._windows()
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE synthetic(value TEXT)")
        connection.execute("INSERT INTO synthetic VALUES ('not a real secret')")
        connection.commit()
        for path in (database, Path(str(database) + "-wal"), Path(str(database) + "-shm")):
            handle = api.kernel.CreateFileW(str(path), api.READ_CONTROL, 7, None, 3, 0x02200000, None)
            assert handle != api.invalid_handle
            try:
                _owner, _control, entries = api.acl_entries(handle)
                assert {entry[3] for entry in entries} == {api.current_sid(), "S-1-5-18"}
                assert all(entry[0] == 0 and not entry[1] & 0x08 for entry in entries)
            finally:
                api.kernel.CloseHandle(handle)
