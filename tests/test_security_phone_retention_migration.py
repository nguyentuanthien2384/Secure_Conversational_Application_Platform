"""Legacy SMS schemas retain quota evidence through atomic FK upgrades."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError

from src.app.db import Database, utcnow
from src.app.models import AuthSession, User


@pytest.fixture(params=[True, False], ids=["cascade-fk", "partial-no-fk"])
def legacy_phone_database(tmp_path, request):
    database = Database(f"sqlite:///{tmp_path / 'legacy-sms.db'}")
    database.create_all()
    with database.session_factory() as db:
        db.add(User(id="sms-owner", username="sms-owner", password_hash="unused"))
        db.flush()
        db.add(AuthSession(jti="sms-session", user_id="sms-owner",
                           session_family_id="sms-session", expires_at=utcnow() + timedelta(hours=1)))
        db.commit()
    session_reference = " REFERENCES auth_sessions(jti) ON DELETE CASCADE" if request.param else ""
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE security_phone_challenges")
        connection.exec_driver_sql("""
            CREATE TABLE security_phone_challenges (
                id VARCHAR(36) NOT NULL PRIMARY KEY,
                user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                auth_session_id VARCHAR(36) NOT NULL""" + session_reference + """,
                phone_hash VARCHAR(64) NOT NULL, phone_ciphertext TEXT NOT NULL,
                phone_nonce VARCHAR(64) NOT NULL, code_hash VARCHAR(64) NOT NULL,
                attempts INTEGER NOT NULL, expires_at DATETIME NOT NULL,
                consumed_at DATETIME, created_at DATETIME NOT NULL,
                CONSTRAINT ck_security_phone_attempts CHECK(attempts >= 0 AND attempts <= 5)
            )
        """)
        proofs = [("legacy-bound", "sms-session")]
        if not request.param:
            proofs.append(("legacy-orphan", "missing-session"))
        for proof_id, session_id in proofs:
            connection.execute(text("""
                INSERT INTO security_phone_challenges
                    (id,user_id,auth_session_id,phone_hash,phone_ciphertext,phone_nonce,
                     code_hash,attempts,expires_at,consumed_at,created_at)
                VALUES (:id,'sms-owner',:session,'target-hash','ciphertext','nonce','code-hash',
                        2,'2026-10-17 12:05:00',NULL,'2026-10-17 12:00:00')
            """), {"id": proof_id, "session": session_id})
    try:
        yield database, request.param
    finally:
        database.engine.dispose()


def _rows(database):
    with database.engine.connect() as connection:
        return [tuple(row) for row in connection.execute(text(
            "SELECT id,user_id,phone_hash,phone_ciphertext,phone_nonce,code_hash,"
            "attempts,expires_at,consumed_at,created_at FROM security_phone_challenges ORDER BY id"
        ))]


def test_sms_upgrade_preserves_rows_indexes_and_is_idempotent(legacy_phone_database):
    database, had_fk = legacy_phone_database
    before = _rows(database)
    with pytest.raises(RuntimeError, match="SMS"):
        database.assert_schema_ready()
    database.create_all()
    database.assert_schema_ready()
    assert _rows(database) == before
    inspector = inspect(database.engine)
    assert {"ix_security_phone_created", "ix_security_phone_target_created",
            "ix_security_phone_challenges_user_id"} <= {
        index["name"] for index in inspector.get_indexes("security_phone_challenges")
    }
    with database.engine.connect() as connection:
        sessions = dict(connection.execute(text(
            "SELECT id,auth_session_id FROM security_phone_challenges"
        )).all())
    assert sessions["legacy-bound"] == "sms-session"
    if not had_fk:
        assert sessions["legacy-orphan"] is None
    ddl = []
    def capture(_conn, _cursor, statement, _params, _context, _many):
        if ("security_phone_challenges" in statement.lower()
                and statement.lstrip().lower().startswith(("create ", "alter ", "drop "))):
            ddl.append(statement)
    event.listen(database.engine, "before_cursor_execute", capture)
    try:
        database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", capture)
    assert ddl == []
    assert _rows(database) == before


def test_sms_upgrade_nulls_expired_bearer_keeps_user_cascade_and_guess_limit(legacy_phone_database):
    database, had_fk = legacy_phone_database
    database.create_all()
    with pytest.raises(IntegrityError), database.engine.begin() as connection:
        connection.exec_driver_sql("UPDATE security_phone_challenges SET attempts=6")
    with database.engine.begin() as connection:
        connection.exec_driver_sql("DELETE FROM auth_sessions WHERE jti='sms-session'")
        rows = connection.execute(text("SELECT auth_session_id FROM security_phone_challenges")).all()
        assert len(rows) == (1 if had_fk else 2)
        assert all(row[0] is None for row in rows)
        connection.exec_driver_sql("DELETE FROM users WHERE id='sms-owner'")
        assert connection.execute(text("SELECT id FROM security_phone_challenges")).all() == []


def test_sms_failed_sqlite_upgrade_rolls_back_without_losing_proofs(legacy_phone_database):
    database, _had_fk = legacy_phone_database
    before = _rows(database)
    def fail(_conn, _cursor, statement, _params, _context, _many):
        if statement.startswith("ALTER TABLE security_phone_challenges_retention_upgrade RENAME"):
            raise OperationalError("simulated SMS migration failure", None, RuntimeError("test"))
    event.listen(database.engine, "before_cursor_execute", fail)
    try:
        with pytest.raises(OperationalError):
            database.create_all()
    finally:
        event.remove(database.engine, "before_cursor_execute", fail)
    assert _rows(database) == before
    assert "security_phone_challenges_retention_upgrade" not in inspect(database.engine).get_table_names()
    with pytest.raises(RuntimeError, match="SMS"):
        database.assert_schema_ready()
    database.create_all()
    database.assert_schema_ready()
    assert _rows(database) == before
