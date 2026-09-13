from __future__ import annotations

from pathlib import Path

import pytest

from scripts import rotate_database_credentials as rotation


class _FakeCursor:
    def __init__(self, statements: list[object]) -> None:
        self._statements = statements

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def execute(self, statement) -> None:
        self._statements.append(statement)


class _FakeConnection:
    def __init__(self, statements: list[object]) -> None:
        self._statements = statements

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._statements)


def _secret_file(tmp_path: Path, name: str, value: str) -> str:
    path = tmp_path / name
    path.write_text(value, encoding="utf-8")
    return str(path)


def test_rotation_uses_file_secrets_one_transaction_and_safe_role_order(
    monkeypatch, tmp_path: Path, capsys
):
    old_password = "old-owner-password-material-1234567890"
    new_owner = "new-owner-password-material-1234567890"
    new_app = "new-runtime-password-material-123456789"
    new_auditor = "new-auditor-password-material-12345678"
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://secure_chat@db:5432/secure_chat"
        "?sslmode=verify-full&sslrootcert=/run/secrets/internal_ca.crt",
    )
    monkeypatch.setenv(
        "DATABASE_PASSWORD_FILE", _secret_file(tmp_path, "current", old_password)
    )
    monkeypatch.setenv(
        "NEW_POSTGRES_PASSWORD_FILE", _secret_file(tmp_path, "owner", new_owner)
    )
    monkeypatch.setenv(
        "NEW_APP_DB_PASSWORD_FILE", _secret_file(tmp_path, "app", new_app)
    )
    monkeypatch.setenv(
        "NEW_AUDITOR_DB_PASSWORD_FILE", _secret_file(tmp_path, "auditor", new_auditor)
    )

    statements: list[object] = []
    connect_args: dict[str, object] = {}

    def fake_connect(**kwargs):
        connect_args.update(kwargs)
        return _FakeConnection(statements)

    monkeypatch.setattr(rotation.psycopg, "connect", fake_connect)
    rotation.main()

    assert connect_args == {
        "host": "db",
        "dbname": "secure_chat",
        "user": "secure_chat",
        "password": old_password,
        "port": 5432,
        "sslmode": "verify-full",
        "sslrootcert": "/run/secrets/internal_ca.crt",
    }
    assert statements[:3] == [
        "SET LOCAL log_statement = 'none'",
        "SET LOCAL log_min_duration_statement = -1",
        "SET LOCAL log_min_error_statement = 'panic'",
    ]
    rendered = [statement.as_string(None) for statement in statements[3:]]
    assert rendered == [
        f'ALTER ROLE "scap_app" WITH PASSWORD \'{new_app}\'',
        f'ALTER ROLE "scap_auditor" WITH PASSWORD \'{new_auditor}\'',
        f'ALTER ROLE "secure_chat" WITH PASSWORD \'{new_owner}\'',
    ]
    output = capsys.readouterr().out
    assert "rotated successfully" in output
    for secret in (old_password, new_owner, new_app, new_auditor):
        assert secret not in output


def test_rotation_rejects_runtime_role_as_owner(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://scap_app@db:5432/secure_chat"
    )
    monkeypatch.setenv(
        "DATABASE_PASSWORD_FILE",
        _secret_file(tmp_path, "current", "current-password-material-123456789"),
    )
    with pytest.raises(RuntimeError, match="database owner role"):
        rotation.main()


def test_rotation_rejects_short_or_multiline_new_secret(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+psycopg://secure_chat@db:5432/secure_chat"
    )
    monkeypatch.setenv(
        "DATABASE_PASSWORD_FILE",
        _secret_file(tmp_path, "current", "current-password-material-123456789"),
    )
    monkeypatch.setenv("NEW_POSTGRES_PASSWORD_FILE", _secret_file(tmp_path, "short", "short"))
    with pytest.raises(RuntimeError, match="at least 32"):
        rotation.main()

    monkeypatch.setenv(
        "NEW_POSTGRES_PASSWORD_FILE",
        _secret_file(tmp_path, "multiline", "x" * 32 + "\n" + "y" * 32),
    )
    with pytest.raises(RuntimeError, match="một dòng"):
        rotation.main()
