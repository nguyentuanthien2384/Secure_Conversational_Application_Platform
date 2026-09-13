"""Run SCAP retention enforcement as a scheduler/Kubernetes CronJob command."""

from __future__ import annotations

import argparse
import json

from src.app.config import Settings
from src.app.db import Database
from src.app.retention import enforce_retention


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce SCAP retention policy")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--batch-size", type=int, default=500)
    args = parser.parse_args()
    settings = Settings.from_env()
    database = Database(settings.database_url)
    database.assert_schema_ready()
    with database.session_factory() as db:
        result = enforce_retention(
            db,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
            secure_retention_days=settings.secure_retention_days,
            confidential_retention_days=settings.confidential_retention_days,
        )
    print(json.dumps(result.as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
