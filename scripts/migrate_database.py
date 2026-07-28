#!/usr/bin/env python3
"""Create/upgrade the schema with the owner account, then drop runtime grants."""

from __future__ import annotations

import os

from src.app import models as _models  # noqa: F401 - registers SQLAlchemy metadata
from src.app.db import Database


def main() -> None:
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url.startswith(("postgresql://", "postgresql+")):
        raise RuntimeError("Migration container requires an owner PostgreSQL DATABASE_URL.")
    database = Database(database_url)
    try:
        database.create_all()
        database.apply_postgres_least_privilege()
    finally:
        database.engine.dispose()
    print("Database migration and least-privilege grants completed.")


if __name__ == "__main__":
    main()
