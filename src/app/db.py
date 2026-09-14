from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, database_url: str):
        connect_args = (
            {"check_same_thread": False, "timeout": 10}
            if database_url.startswith("sqlite")
            else {}
        )
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
        if database_url.startswith("sqlite"):
            # SQLite does not enforce declared foreign keys unless each
            # connection opts in. Security-relevant ownership/cascade
            # guarantees must therefore be enabled at the driver boundary.
            @event.listens_for(self.engine, "connect")
            def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
                cursor = dbapi_connection.cursor()
                try:
                    cursor.execute("PRAGMA foreign_keys=ON")
                    # Give a concurrent writer a bounded chance to finish
                    # instead of surfacing a transient lock as HTTP 500.
                    cursor.execute("PRAGMA busy_timeout=10000")
                finally:
                    cursor.close()

            # WAL lets an existing reader finish while a policy/security writer
            # commits. This avoids the read-to-write upgrade deadlock inherent
            # in SQLite's rollback journal. High-security production still
            # requires PostgreSQL; this keeps local/teaching mode deterministic.
            with self.engine.connect() as connection:
                connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        self.session_factory = sessionmaker(
            bind=self.engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
            class_=Session,
        )

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)
        # The teaching project intentionally avoids a migration framework to keep startup simple.
        # This small, idempotent upgrade keeps databases created by the previous course version usable.
        inspector = inspect(self.engine)
        columns = {column["name"] for column in inspector.get_columns("users")}
        audit_columns = {column["name"] for column in inspector.get_columns("audit_events")}
        auth_session_columns = {
            column["name"] for column in inspector.get_columns("auth_sessions")
        }
        chat_session_columns = {
            column["name"] for column in inspector.get_columns("chat_sessions")
        }
        message_columns = {
            column["name"] for column in inspector.get_columns("secure_messages")
        }
        e2ee_envelope_columns = (
            {column["name"] for column in inspector.get_columns("e2ee_envelopes")}
            if "e2ee_envelopes" in inspector.get_table_names()
            else set()
        )
        with self.engine.begin() as connection:
            # Hash-chain columns for the tamper-evident audit trail.
            if "prev_hash" not in audit_columns:
                connection.execute(
                    text("ALTER TABLE audit_events ADD COLUMN prev_hash VARCHAR(64)")
                )
            if "entry_hash" not in audit_columns:
                connection.execute(
                    text("ALTER TABLE audit_events ADD COLUMN entry_hash VARCHAR(64)")
                )
            if "token_version" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1")
                )
            if "failed_login_attempts" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "ai_data_consent" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN ai_data_consent BOOLEAN NOT NULL DEFAULT 0")
                )
            if "ai_consent_at" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN ai_consent_at TIMESTAMP"))
            if "ai_consent_version" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN ai_consent_version VARCHAR(32)")
                )
            if "locked_until" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"))
            if "mfa_enabled" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0")
                )
            if "mfa_secret_ciphertext" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_ciphertext TEXT"))
            if "mfa_secret_nonce" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN mfa_secret_nonce VARCHAR(64)")
                )
            if "secret_wrapped_dek" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN secret_wrapped_dek TEXT"))
            if "secret_kek_uri" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN secret_kek_uri VARCHAR(512)")
                )
            if "secret_kek_version" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN secret_kek_version VARCHAR(128)")
                )
            if "secret_crypto_epoch" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN secret_crypto_epoch "
                        "INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "mfa_last_counter" not in columns:
                connection.execute(
                    text("ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER NOT NULL DEFAULT 0")
                )
            # Mốc đăng nhập gốc cho trần tuyệt đối của sliding session.
            if "root_issued_at" not in auth_session_columns:
                connection.execute(
                    text("ALTER TABLE auth_sessions ADD COLUMN root_issued_at TIMESTAMP")
                )
                # Phiên đã tồn tại chưa có mốc gốc: lấy chính thời điểm cấp phát,
                # nếu không chúng sẽ được coi là "vô hạn tuổi" và bị từ chối gia hạn.
                connection.execute(
                    text(
                        "UPDATE auth_sessions SET root_issued_at = issued_at "
                        "WHERE root_issued_at IS NULL"
                    )
                )
            if "last_step_up_at" not in auth_session_columns:
                connection.execute(
                    text("ALTER TABLE auth_sessions ADD COLUMN last_step_up_at TIMESTAMP")
                )
            if "session_family_id" not in auth_session_columns:
                connection.execute(
                    text("ALTER TABLE auth_sessions ADD COLUMN session_family_id VARCHAR(36)")
                )
                # Pre-upgrade rows cannot be linked retrospectively because the
                # former schema stored no parent relation. Treat each as its own
                # conservative family; all new rotations preserve this value.
                connection.execute(
                    text(
                        "UPDATE auth_sessions SET session_family_id = jti "
                        "WHERE session_family_id IS NULL"
                    )
                )
                if self.engine.dialect.name == "postgresql":
                    connection.execute(
                        text(
                            "ALTER TABLE auth_sessions "
                            "ALTER COLUMN session_family_id SET NOT NULL"
                        )
                    )
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_auth_sessions_family_active "
                    "ON auth_sessions (user_id, session_family_id, revoked_at)"
                )
            )

            # Conversation security policy and active envelope metadata.
            if "security_mode" not in chat_session_columns:
                connection.execute(
                    text(
                        "ALTER TABLE chat_sessions ADD COLUMN security_mode "
                        "VARCHAR(24) NOT NULL DEFAULT 'secure'"
                    )
                )
            if "data_classification" not in chat_session_columns:
                connection.execute(
                    text(
                        "ALTER TABLE chat_sessions ADD COLUMN data_classification "
                        "VARCHAR(32) NOT NULL DEFAULT 'internal'"
                    )
                )
            if "current_crypto_epoch" not in chat_session_columns:
                connection.execute(
                    text(
                        "ALTER TABLE chat_sessions ADD COLUMN current_crypto_epoch "
                        "INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "crypto_suite" not in chat_session_columns:
                connection.execute(
                    text(
                        "ALTER TABLE chat_sessions ADD COLUMN crypto_suite "
                        "VARCHAR(32) NOT NULL DEFAULT 'legacy-aes-256-gcm'"
                    )
                )
            if "wrapped_dek" not in chat_session_columns:
                connection.execute(text("ALTER TABLE chat_sessions ADD COLUMN wrapped_dek TEXT"))
            if "kek_uri" not in chat_session_columns:
                connection.execute(
                    text("ALTER TABLE chat_sessions ADD COLUMN kek_uri VARCHAR(512)")
                )
            if "kek_version" not in chat_session_columns:
                connection.execute(
                    text("ALTER TABLE chat_sessions ADD COLUMN kek_version VARCHAR(128)")
                )
            if "retention_expires_at" not in chat_session_columns:
                connection.execute(
                    text("ALTER TABLE chat_sessions ADD COLUMN retention_expires_at TIMESTAMP")
                )
            # Compatibility migrations cannot make the legacy column NOT NULL
            # on SQLite. Runtime access therefore fails closed on NULL and the
            # retention sweep backfills it from the original creation time.
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_chat_sessions_retention_expires_at "
                    "ON chat_sessions (retention_expires_at)"
                )
            )

            # Stronger, message-specific AAD for new envelope-encrypted rows.
            if "message_uuid" not in message_columns:
                connection.execute(
                    text("ALTER TABLE secure_messages ADD COLUMN message_uuid VARCHAR(64)")
                )
                connection.execute(
                    text(
                        "UPDATE secure_messages SET message_uuid = "
                        "'legacy-' || CAST(id AS VARCHAR) WHERE message_uuid IS NULL"
                    )
                )
            if "message_index" not in message_columns:
                connection.execute(
                    text("ALTER TABLE secure_messages ADD COLUMN message_index INTEGER")
                )
                connection.execute(
                    text(
                        "UPDATE secure_messages SET message_index = id "
                        "WHERE message_index IS NULL"
                    )
                )
            if "crypto_epoch" not in message_columns:
                connection.execute(
                    text(
                        "ALTER TABLE secure_messages ADD COLUMN crypto_epoch "
                        "INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "encryption_scheme" not in message_columns:
                connection.execute(
                    text(
                        "ALTER TABLE secure_messages ADD COLUMN encryption_scheme "
                        "VARCHAR(24) NOT NULL DEFAULT 'legacy-v1'"
                    )
                )
            connection.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_secure_message_index "
                    "ON secure_messages (session_id, message_index)"
                )
            )
            if e2ee_envelope_columns and "replay_key" not in e2ee_envelope_columns:
                connection.execute(
                    text("ALTER TABLE e2ee_envelopes ADD COLUMN replay_key VARCHAR(96)")
                )
                # Existing development rows predate the public E2EE API. Bind a
                # deterministic legacy value before creating the unique index.
                connection.execute(
                    text(
                        "UPDATE e2ee_envelopes SET replay_key = "
                        "'legacy:' || CAST(id AS VARCHAR) WHERE replay_key IS NULL"
                    )
                )
                connection.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_e2ee_replay_guard_v2 "
                        "ON e2ee_envelopes (replay_key)"
                    )
                )

    def assert_schema_ready(self) -> None:
        """Fail closed when the runtime account sees an incomplete schema.

        Production migrations run in a separate one-shot container with the
        owner credential. The web process must never silently regain DDL rights.
        """
        existing = set(inspect(self.engine).get_table_names())
        required = set(Base.metadata.tables)
        missing = sorted(required - existing)
        if missing:
            raise RuntimeError(
                "Database schema chưa được migrate; thiếu bảng: " + ", ".join(missing)
            )
        required_columns = {
            "users": {
                "ai_consent_at",
                "ai_consent_version",
                "secret_wrapped_dek",
                "secret_kek_uri",
                "secret_kek_version",
                "secret_crypto_epoch",
            },
            "auth_sessions": {"root_issued_at", "last_step_up_at", "session_family_id"},
            "chat_sessions": {
                "security_mode",
                "data_classification",
                "current_crypto_epoch",
                "wrapped_dek",
                "kek_uri",
                "kek_version",
                "retention_expires_at",
            },
            "secure_messages": {
                "message_uuid",
                "message_index",
                "crypto_epoch",
                "encryption_scheme",
            },
            "e2ee_envelopes": {"replay_key"},
        }
        incomplete: list[str] = []
        inspector = inspect(self.engine)
        for table, expected in required_columns.items():
            present = {column["name"] for column in inspector.get_columns(table)}
            missing_columns = sorted(expected - present)
            if missing_columns:
                incomplete.append(f"{table}({', '.join(missing_columns)})")
        if incomplete:
            raise RuntimeError(
                "Database schema chưa được migrate; thiếu cột: " + "; ".join(incomplete)
            )

    def apply_postgres_least_privilege(self) -> None:
        """Grant the runtime/auditor roles only the permissions they require."""
        if self.engine.dialect.name != "postgresql":
            raise RuntimeError("Least-privilege grants chỉ áp dụng cho PostgreSQL.")
        database_name = self.engine.url.database
        if not database_name:
            raise RuntimeError("DATABASE_URL không có tên database.")
        quoted_db = self.engine.dialect.identifier_preparer.quote(database_name)
        statements = (
            f"REVOKE ALL ON DATABASE {quoted_db} FROM PUBLIC",
            "REVOKE ALL ON SCHEMA public FROM PUBLIC",
            "GRANT CONNECT ON DATABASE " + quoted_db + " TO scap_app",
            "GRANT USAGE ON SCHEMA public TO scap_app",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO scap_app",
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO scap_app",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO scap_app",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
            "GRANT USAGE, SELECT ON SEQUENCES TO scap_app",
            "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_events FROM scap_app",
            "GRANT SELECT, INSERT ON TABLE audit_events TO scap_app",
            "REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_checkpoints FROM scap_app",
            "GRANT SELECT, INSERT ON TABLE audit_checkpoints TO scap_app",
            "GRANT CONNECT ON DATABASE " + quoted_db + " TO scap_auditor",
            "GRANT USAGE ON SCHEMA public TO scap_auditor",
            "GRANT SELECT ON TABLE audit_events TO scap_auditor",
            "GRANT SELECT ON TABLE audit_checkpoints TO scap_auditor",
        )
        with self.engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))

    def session(self) -> Generator[Session, None, None]:
        db = self.session_factory()
        try:
            yield db
        finally:
            db.close()
