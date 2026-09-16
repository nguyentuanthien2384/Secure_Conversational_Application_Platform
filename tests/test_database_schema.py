"""Regression checks for schema startup under the least-privilege app role."""

from __future__ import annotations

from sqlalchemy import event

from src.app.db import Database


def test_existing_auth_session_index_is_not_recreated_on_startup(tmp_path):
    """A normal app restart must not issue owner-only CREATE INDEX DDL again."""
    database = Database(f"sqlite:///{tmp_path / 'schema.db'}")
    database.create_all()

    statements: list[str] = []

    @event.listens_for(database.engine, "before_cursor_execute")
    def capture_statements(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    try:
        database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", capture_statements)
        database.engine.dispose()

    assert not any(
        "CREATE INDEX IF NOT EXISTS ix_auth_sessions_family_active" in statement
        for statement in statements
    )
