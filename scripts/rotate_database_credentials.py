#!/usr/bin/env python3
"""Rotate PostgreSQL owner/runtime/auditor passwords from file-backed secrets."""

from __future__ import annotations

import os
import re

import psycopg
from psycopg import sql
from sqlalchemy.engine import make_url

from src.app.config import _read_secret_file, database_url_with_file_password

ROLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _required_secret(file_env: str) -> str:
    value = _read_secret_file(file_env)
    if value is None:
        raise RuntimeError(f"{file_env} is required for database credential rotation.")
    if len(value) < 32:
        raise RuntimeError(f"{file_env} must contain at least 32 characters.")
    return value


def main() -> None:
    database_url = database_url_with_file_password(os.getenv("DATABASE_URL", "").strip())
    parsed = make_url(database_url)
    owner_role = parsed.username or ""
    if not database_url.startswith(("postgresql://", "postgresql+")) or not ROLE_RE.fullmatch(
        owner_role
    ):
        raise RuntimeError("DATABASE_URL must identify the PostgreSQL owner role.")
    if owner_role in {"scap_app", "scap_auditor"}:
        raise RuntimeError("Credential rotation must connect with the database owner role.")

    new_owner_password = _required_secret("NEW_POSTGRES_PASSWORD_FILE")
    new_app_password = _required_secret("NEW_APP_DB_PASSWORD_FILE")
    new_auditor_password = _required_secret("NEW_AUDITOR_DB_PASSWORD_FILE")

    connect_args = parsed.translate_connect_args(username="user", database="dbname")
    connect_args.update(dict(parsed.query))
    with psycopg.connect(**connect_args) as connection:
        with connection.cursor() as cursor:
            # A failed ALTER ROLE must not echo its SQL literal into server
            # statement, duration, or error-statement logs.
            cursor.execute("SET LOCAL log_statement = 'none'")
            cursor.execute("SET LOCAL log_min_duration_statement = -1")
            cursor.execute("SET LOCAL log_min_error_statement = 'panic'")
            for role, password in (
                ("scap_app", new_app_password),
                ("scap_auditor", new_auditor_password),
                # Change the credential used by this transaction last.
                (owner_role, new_owner_password),
            ):
                cursor.execute(
                    sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
                        sql.Identifier(role),
                        sql.Literal(password),
                    )
                )
    print("Database owner, runtime and auditor credentials rotated successfully.")


if __name__ == "__main__":
    main()

