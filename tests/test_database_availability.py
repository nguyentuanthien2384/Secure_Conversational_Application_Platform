from __future__ import annotations

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from src.app.db import Database


class ConnectionObserved(Exception):
    """Stop immediately at the driver boundary, before any network activity."""


def _libpq_params(args, kwargs):
    # SQLAlchemy passes a Psycopg adapter context to connect(). It is not a
    # libpq connection parameter, so make_conninfo must not receive it.
    params = dict(kwargs)
    params.pop("context", None)
    return conninfo_to_dict(make_conninfo(*args, **params))


def test_postgresql_runtime_uses_finite_pool_and_driver_waits(monkeypatch):
    observed = {}

    def capture_connect(*args, **kwargs):
        observed.update(_libpq_params(args, kwargs))
        raise ConnectionObserved

    monkeypatch.setattr(psycopg, "connect", capture_connect)
    database = Database("postgresql+psycopg://scap_app@db:5432/secure_chat", runtime_limits=True)
    try:
        assert database.engine.pool.size() == 5
        assert database.engine.pool._max_overflow == 5
        assert database.engine.pool.timeout() == 5
        with pytest.raises(ConnectionObserved):
            database.engine.connect()
        assert observed["connect_timeout"] == "5"
        assert observed["options"] == "-c statement_timeout=30000 -c lock_timeout=5000"
        assert "idle_in_transaction" not in observed["options"]
        assert observed["user"] == "scap_app"
        assert observed["dbname"] == "secure_chat"
    finally:
        database.engine.dispose()


def test_runtime_limits_override_url_waits_without_weakening_tls_or_credentials(monkeypatch):
    observed = {}

    def capture_connect(*args, **kwargs):
        observed.update(_libpq_params(args, kwargs))
        raise ConnectionObserved

    monkeypatch.setattr(psycopg, "connect", capture_connect)
    database = Database(
        "postgresql+psycopg://scap_app:test%40secret@db:5432/secure_chat"
        "?sslmode=verify-full&sslrootcert=/run/secrets/ca.crt"
        "&connect_timeout=0&options=-c%20statement_timeout%3D0%20-c%20lock_timeout%3D0",
        runtime_limits=True,
    )
    try:
        with pytest.raises(ConnectionObserved):
            database.engine.connect()
        assert observed["connect_timeout"] == "5"
        assert observed["options"] == "-c statement_timeout=30000 -c lock_timeout=5000"
        assert observed["sslmode"] == "verify-full"
        assert observed["sslrootcert"] == "/run/secrets/ca.crt"
        assert observed["user"] == "scap_app"
        assert observed["password"] == "test@secret"
    finally:
        database.engine.dispose()


def test_maintenance_default_preserves_its_explicit_connection_options(monkeypatch):
    observed = {}

    def capture_connect(*args, **kwargs):
        observed.update(_libpq_params(args, kwargs))
        raise ConnectionObserved

    monkeypatch.setattr(psycopg, "connect", capture_connect)
    database = Database(
        "postgresql+psycopg://secure_chat@db/secure_chat"
        "?connect_timeout=90&options=-c%20statement_timeout%3D0"
    )
    try:
        with pytest.raises(ConnectionObserved):
            database.engine.connect()
        assert observed["connect_timeout"] == "90"
        assert observed["options"] == "-c statement_timeout=0"
        assert database.engine.pool._max_overflow == 10
        assert database.engine.pool.timeout() == 30
    finally:
        database.engine.dispose()


@pytest.mark.parametrize("runtime_limits", [False, True])
def test_sqlite_keeps_existing_busy_timeout_foreign_keys_and_wal(tmp_path, runtime_limits):
    database = Database(f"sqlite:///{tmp_path / 'local.db'}", runtime_limits=runtime_limits)
    try:
        with database.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 10_000
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
            assert connection.exec_driver_sql("SELECT 1").scalar_one() == 1
    finally:
        database.engine.dispose()
