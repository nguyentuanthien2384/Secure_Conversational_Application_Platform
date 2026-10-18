from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, database_url: str, *, runtime_limits: bool = False):
        """Create a database engine without connecting to PostgreSQL yet.

        Web runtimes opt into finite PostgreSQL pool, connect and SQL waits.
        Maintenance scripts retain their existing defaults, including for long
        migrations. The 30-second statement ceiling accommodates full audit
        history reads while still bounding stalled queries; lock waits are
        capped independently at five seconds. It is not a request deadline.
        """
        connect_args = (
            {"check_same_thread": False, "timeout": 10}
            if database_url.startswith("sqlite")
            else {}
        )
        pool_limits = {}
        if runtime_limits and make_url(database_url).get_backend_name() == "postgresql":
            # SQLAlchemy merges connect_args after URL driver parameters, so
            # runtime limits deliberately win URL timeout/options overrides.
            # SSL mode, certificate paths, credentials and other URL parameters
            # are passed through unchanged. No idle-transaction ceiling: an AI
            # call can hold an otherwise legitimate transaction while waiting.
            connect_args = {
                "connect_timeout": 5,
                "options": "-c statement_timeout=30000 -c lock_timeout=5000",
            }
            pool_limits = {"pool_size": 5, "max_overflow": 5, "pool_timeout": 5}
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args=connect_args,
            **pool_limits,
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
        auth_session_indexes = {
            index["name"] for index in inspector.get_indexes("auth_sessions")
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
            if "mfa_failed_attempts" not in columns:
                connection.execute(
                    text(
                        "ALTER TABLE users ADD COLUMN mfa_failed_attempts "
                        "INTEGER NOT NULL DEFAULT 0"
                    )
                )
            if "mfa_locked_until" not in columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN mfa_locked_until TIMESTAMP"))
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
            if "last_activity_at" not in auth_session_columns:
                # Match the model's timezone-aware type so PostgreSQL preserves
                # issued_at's instant even when the session timezone is not UTC.
                # Constant DDL per dialect (no f-string) keeps the SAST rule happy.
                if self.engine.dialect.name == "postgresql":
                    activity_ddl = (
                        "ALTER TABLE auth_sessions ADD COLUMN last_activity_at "
                        "TIMESTAMP WITH TIME ZONE"
                    )
                else:
                    activity_ddl = (
                        "ALTER TABLE auth_sessions ADD COLUMN last_activity_at DATETIME"
                    )
                connection.execute(text(activity_ddl))
                # Preserve a conservative existing timestamp rather than grant
                # every old session a new inactivity window at deployment.
                connection.execute(
                    text("UPDATE auth_sessions SET last_activity_at = issued_at")
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
            # Ứng dụng chạy dưới role ít quyền nên không được phép thực thi
            # CREATE INDEX trên bảng do role migration sở hữu. Migrate service
            # tạo index một lần; startup app chỉ kiểm tra và bỏ qua khi nó đã có.
            if "ix_auth_sessions_family_active" not in auth_session_indexes:
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

        self._upgrade_passkey_step_up()
        self._upgrade_phone_challenge_retention()

    def _upgrade_phone_challenge_retention(self) -> None:
        """Preserve SMS issuance budgets when expired bearer rows are pruned."""
        inspector = inspect(self.engine)
        columns = {
            column["name"]: column
            for column in inspector.get_columns("security_phone_challenges")
        }
        session_keys = [
            key for key in inspector.get_foreign_keys("security_phone_challenges")
            if key["constrained_columns"] == ["auth_session_id"]
        ]
        ready = (
            columns["auth_session_id"]["nullable"]
            and len(session_keys) == 1
            and session_keys[0]["referred_table"] == "auth_sessions"
            and session_keys[0]["referred_columns"] == ["jti"]
            and session_keys[0].get("options", {}).get("ondelete", "").upper() == "SET NULL"
        )
        expected_indexes = {
            "ix_security_phone_created": "created_at",
            "ix_security_phone_challenges_user_id": "user_id",
            "ix_security_phone_target_created": "phone_hash,created_at",
        }
        existing_indexes = {
            index["name"] for index in inspector.get_indexes("security_phone_challenges")
        }
        if ready and set(expected_indexes) <= existing_indexes:
            return
        with self.engine.begin() as connection:
            if not ready and self.engine.dialect.name == "sqlite":
                # SQLite cannot change a foreign-key action in place. Keep the
                # rebuild transactional even with sqlite3's legacy DDL mode.
                if not connection.connection.driver_connection.in_transaction:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                connection.exec_driver_sql("""
                    CREATE TABLE security_phone_challenges_retention_upgrade (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        user_id VARCHAR(36) NOT NULL,
                        auth_session_id VARCHAR(36),
                        phone_hash VARCHAR(64) NOT NULL,
                        phone_ciphertext TEXT NOT NULL,
                        phone_nonce VARCHAR(64) NOT NULL,
                        code_hash VARCHAR(64) NOT NULL,
                        attempts INTEGER NOT NULL,
                        expires_at DATETIME NOT NULL,
                        consumed_at DATETIME,
                        created_at DATETIME NOT NULL,
                        CONSTRAINT ck_security_phone_attempts CHECK (attempts >= 0 AND attempts <= 5),
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                        FOREIGN KEY(auth_session_id) REFERENCES auth_sessions(jti) ON DELETE SET NULL
                    )
                """)
                # A partially upgraded database may contain a dangling opaque
                # session ID. It no longer authorizes a proof, but the issuance
                # must remain in the quota window.
                connection.exec_driver_sql("""
                    INSERT INTO security_phone_challenges_retention_upgrade
                        (id,user_id,auth_session_id,phone_hash,phone_ciphertext,
                         phone_nonce,code_hash,attempts,expires_at,consumed_at,created_at)
                    SELECT id,user_id,
                           CASE WHEN auth_session_id IN (SELECT jti FROM auth_sessions)
                                THEN auth_session_id ELSE NULL END,
                           phone_hash,phone_ciphertext,phone_nonce,code_hash,attempts,
                           expires_at,consumed_at,created_at
                    FROM security_phone_challenges
                """)
                connection.exec_driver_sql("DROP TABLE security_phone_challenges")
                connection.exec_driver_sql(
                    "ALTER TABLE security_phone_challenges_retention_upgrade "
                    "RENAME TO security_phone_challenges"
                )
            elif not ready:
                quote = self.engine.dialect.identifier_preparer.quote
                for key in session_keys:
                    connection.exec_driver_sql(
                        "ALTER TABLE security_phone_challenges DROP CONSTRAINT " + quote(key["name"])
                    )
                connection.exec_driver_sql(
                    "ALTER TABLE security_phone_challenges ALTER COLUMN auth_session_id DROP NOT NULL"
                )
                connection.exec_driver_sql("""
                    UPDATE security_phone_challenges SET auth_session_id=NULL
                    WHERE auth_session_id IS NOT NULL
                      AND auth_session_id NOT IN (SELECT jti FROM auth_sessions)
                """)
                connection.exec_driver_sql(
                    "ALTER TABLE security_phone_challenges ADD CONSTRAINT "
                    "fk_security_phone_challenges_session_retention "
                    "FOREIGN KEY(auth_session_id) REFERENCES auth_sessions(jti) ON DELETE SET NULL"
                )
            for index_name, indexed_columns in expected_indexes.items():
                connection.exec_driver_sql(
                    f"CREATE INDEX IF NOT EXISTS {index_name} "
                    f"ON security_phone_challenges({indexed_columns})"
                )

    def _upgrade_passkey_step_up(self) -> None:
        """Keep short-lived ceremonies while adding exact-session step-up binding."""
        inspector = inspect(self.engine)
        columns = {column["name"] for column in inspector.get_columns("webauthn_challenges")}
        checks = inspector.get_check_constraints("webauthn_challenges")
        old_purpose = any(
            check.get("name") == "ck_webauthn_challenge_purpose"
            and "step_up" not in check.get("sqltext", "")
            for check in checks
        )
        if "auth_session_id" in columns and not old_purpose:
            return
        with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite" and old_purpose:
                # SQLite cannot replace CHECK constraints in place. Explicitly
                # begin before DDL as its legacy driver otherwise autocommits it.
                if not connection.connection.driver_connection.in_transaction:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")
                connection.exec_driver_sql("""
                    CREATE TABLE webauthn_challenges_step_up_upgrade (
                        id VARCHAR(36) NOT NULL PRIMARY KEY,
                        user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                        auth_session_id VARCHAR(36) REFERENCES auth_sessions(jti) ON DELETE CASCADE,
                        purpose VARCHAR(16) NOT NULL,
                        challenge VARCHAR(128) NOT NULL,
                        expires_at DATETIME NOT NULL,
                        consumed_at DATETIME,
                        created_at DATETIME NOT NULL,
                        CONSTRAINT ck_webauthn_challenge_purpose
                        CHECK (purpose IN ('register', 'authenticate', 'step_up'))
                    )
                """)
                source_session = "auth_session_id" if "auth_session_id" in columns else "NULL"
                connection.exec_driver_sql(
                    "INSERT INTO webauthn_challenges_step_up_upgrade "
                    "(id, user_id, auth_session_id, purpose, challenge, expires_at, consumed_at, created_at) "
                    "SELECT id, user_id, " + source_session + ", purpose, challenge, expires_at, consumed_at, created_at "
                    "FROM webauthn_challenges"
                )
                connection.exec_driver_sql("DROP TABLE webauthn_challenges")
                connection.exec_driver_sql("ALTER TABLE webauthn_challenges_step_up_upgrade RENAME TO webauthn_challenges")
                connection.exec_driver_sql("CREATE INDEX ix_webauthn_challenges_user_id ON webauthn_challenges(user_id)")
            else:
                if "auth_session_id" not in columns:
                    connection.execute(text(
                        "ALTER TABLE webauthn_challenges ADD COLUMN auth_session_id VARCHAR(36) "
                        "REFERENCES auth_sessions(jti) ON DELETE CASCADE"
                    ))
                if old_purpose:
                    connection.execute(text(
                        "ALTER TABLE webauthn_challenges DROP CONSTRAINT ck_webauthn_challenge_purpose"
                    ))
                    connection.execute(text(
                        "ALTER TABLE webauthn_challenges ADD CONSTRAINT ck_webauthn_challenge_purpose "
                        "CHECK (purpose IN ('register', 'authenticate', 'step_up'))"
                    ))

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
                "mfa_failed_attempts",
                "mfa_locked_until",
            },
            "auth_sessions": {
                "root_issued_at",
                "last_step_up_at",
                "last_activity_at",
                "session_family_id",
            },
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
            "webauthn_challenges": {"auth_session_id"},
            "security_phone_challenges": {"auth_session_id"},
            "intrusion_detections": {"payload_json"},
            "intrusion_sources": {"score_times_json", "last_seen_at", "blocked_until"},
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
        phone_columns = {
            column["name"]: column
            for column in inspector.get_columns("security_phone_challenges")
        }
        phone_session_keys = [
            key for key in inspector.get_foreign_keys("security_phone_challenges")
            if key["constrained_columns"] == ["auth_session_id"]
        ]
        if (
            not phone_columns["auth_session_id"]["nullable"]
            or len(phone_session_keys) != 1
            or phone_session_keys[0]["referred_table"] != "auth_sessions"
            or phone_session_keys[0]["referred_columns"] != ["jti"]
            or phone_session_keys[0].get("options", {}).get("ondelete", "").upper() != "SET NULL"
        ):
            raise RuntimeError(
                "Database schema chưa được migrate; cần giữ hạn mức SMS khi hết phiên đăng nhập."
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
