"""An existing local database keeps ceremonies and gains session-bound step-up."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError

from src.app.db import Database, utcnow
from src.app.models import AuthSession, User


@pytest.fixture(params=[False, True], ids=["old-schema", "partial-column"])
def legacy_database(tmp_path, request):
    database = Database(f"sqlite:///{tmp_path / 'legacy-passkeys.db'}")
    database.create_all()
    with database.session_factory() as db:
        user = User(id="legacy-owner", username="legacy-owner", password_hash="not-a-password")
        db.add(user)
        db.flush()
        db.add(AuthSession(jti="legacy-jti", user_id=user.id,
                           session_family_id="legacy-jti", expires_at=utcnow() + timedelta(hours=1)))
        db.commit()
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE webauthn_challenges")
        connection.exec_driver_sql("""
            CREATE TABLE webauthn_challenges (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                purpose VARCHAR(16) NOT NULL,
                challenge VARCHAR(128) NOT NULL,
                expires_at DATETIME NOT NULL,
                consumed_at DATETIME,
                created_at DATETIME NOT NULL,
                CONSTRAINT ck_webauthn_challenge_purpose CHECK (purpose IN ('register', 'authenticate'))
            )
        """)
        connection.exec_driver_sql("CREATE INDEX ix_webauthn_challenges_user_id ON webauthn_challenges(user_id)")
        if request.param:
            # Simulate an interrupted/manual schema addition before the CHECK
            # was migrated; a valid preexisting value must survive the rebuild.
            connection.exec_driver_sql(
                "ALTER TABLE webauthn_challenges ADD COLUMN auth_session_id VARCHAR(36) "
                "REFERENCES auth_sessions(jti) ON DELETE CASCADE",
            )
        connection.exec_driver_sql("""
            INSERT INTO webauthn_challenges (id, user_id, purpose, challenge, expires_at, consumed_at, created_at)
            VALUES ('legacy-register', 'legacy-owner', 'register', 'registration-proof',
                    '2026-10-17 12:03:00', NULL, '2026-10-17 12:00:00'),
                   ('legacy-authenticate', NULL, 'authenticate', 'authentication-proof',
                    '2026-10-17 12:03:00', '2026-10-17 12:01:00', '2026-10-17 12:00:00')
        """)
        if request.param:
            connection.exec_driver_sql(
                "UPDATE webauthn_challenges SET auth_session_id='legacy-jti' WHERE id='legacy-register'",
            )
    try:
        yield database, request.param
    finally:
        database.engine.dispose()


def legacy_rows(database):
    with database.engine.connect() as connection:
        return [tuple(row) for row in connection.execute(text(
            "SELECT id,user_id,purpose,challenge,expires_at,consumed_at,created_at "
            "FROM webauthn_challenges ORDER BY id",
        ))]


def test_upgrade_preserves_legacy_ceremonies_and_is_idempotent(legacy_database):
    database, had_column = legacy_database
    before = legacy_rows(database)
    database.create_all()
    database.assert_schema_ready()
    assert legacy_rows(database) == before
    inspector = inspect(database.engine)
    assert "auth_session_id" in {column["name"] for column in inspector.get_columns("webauthn_challenges")}
    checks = inspector.get_check_constraints("webauthn_challenges")
    assert any("step_up" in check["sqltext"] for check in checks)
    assert "ix_webauthn_challenges_user_id" in {
        index["name"] for index in inspector.get_indexes("webauthn_challenges")
    }
    with database.engine.connect() as connection:
        assert connection.scalar(text(
            "SELECT auth_session_id FROM webauthn_challenges WHERE id='legacy-register'",
        )) == ("legacy-jti" if had_column else None)
    ddl = []

    def capture(_conn, _cursor, statement, _params, _context, _many):
        if ("webauthn_challenges" in statement.lower()
                and statement.lstrip().lower().startswith(("create ", "alter ", "drop "))):
            ddl.append(statement)

    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)
    assert ddl == []
    assert legacy_rows(database) == before


def test_migrated_constraints_enforce_purpose_and_session_cascade(legacy_database):
    database, had_column = legacy_database
    database.create_all()
    with database.engine.begin() as connection:
        connection.exec_driver_sql("""
            INSERT INTO webauthn_challenges
                (id,user_id,auth_session_id,purpose,challenge,expires_at,created_at)
            VALUES ('bound-step-up','legacy-owner','legacy-jti','step_up','proof',
                    '2026-10-17 12:03:00','2026-10-17 12:00:00')
        """)
    for changed in [("bad-purpose", "legacy-jti", "unsupported"),
                    ("bad-session", "missing-jti", "step_up")]:
        with pytest.raises(IntegrityError), database.engine.begin() as connection:
            connection.execute(text("""
                INSERT INTO webauthn_challenges
                    (id,user_id,auth_session_id,purpose,challenge,expires_at,created_at)
                VALUES (:id,'legacy-owner',:session,:purpose,'proof',
                        '2026-10-17 12:03:00','2026-10-17 12:00:00')
            """), {"id": changed[0], "session": changed[1], "purpose": changed[2]})
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM auth_sessions WHERE jti='legacy-jti'")
        rows = list(connection.execute(text("SELECT id FROM webauthn_challenges ORDER BY id")))
        assert [row[0] for row in rows] == (["legacy-authenticate"] if had_column else [
            "legacy-authenticate", "legacy-register",
        ])
        connection.exec_driver_sql("DELETE FROM users WHERE id='legacy-owner'")
        assert list(connection.execute(text("SELECT id FROM webauthn_challenges"))) == [("legacy-authenticate",)]


def test_failed_sqlite_rebuild_rolls_back_without_losing_legacy_rows(legacy_database):
    database, had_column = legacy_database
    before = legacy_rows(database)

    def fail_after_drop(_conn, _cursor, statement, _params, _context, _many):
        if statement.startswith("ALTER TABLE webauthn_challenges_step_up_upgrade RENAME"):
            raise OperationalError("simulated rename failure", None, RuntimeError("test"))

    event.listen(database.engine, "before_cursor_execute", fail_after_drop)
    try:
        with pytest.raises(OperationalError):
            database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", fail_after_drop)
    assert legacy_rows(database) == before
    inspector = inspect(database.engine)
    assert "webauthn_challenges_step_up_upgrade" not in inspector.get_table_names()
    assert ("auth_session_id" in {column["name"] for column in inspector.get_columns("webauthn_challenges")}) == had_column
    assert not any("step_up" in check["sqltext"] for check in inspector.get_check_constraints("webauthn_challenges"))
    database.create_all()
    database.assert_schema_ready()
    assert legacy_rows(database) == before
