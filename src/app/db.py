from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, database_url: str):
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(
            database_url,
            pool_pre_ping=True,
            connect_args=connect_args,
        )
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
            "GRANT CONNECT ON DATABASE " + quoted_db + " TO scap_auditor",
            "GRANT USAGE ON SCHEMA public TO scap_auditor",
            "GRANT SELECT ON TABLE audit_events TO scap_auditor",
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
