from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from scripts.security_recovery_drill import (
    _MARKER,
    RecoveryDrillError,
    _online_backup,
    _snapshot_valid,
    main,
    run_recovery_drill,
)


def test_recovery_drill_verifies_crypto_revocation_and_cleans_synthetic_data(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.security_recovery_drill.tempfile.tempdir", str(tmp_path))
    report = run_recovery_drill()
    assert report["status"] == "passed"
    assert report["scope"] == "disposable_offline_sqlite_demo"
    checks = {check["name"]: check["passed"] for check in report["checks"]}
    assert len(checks) >= 25 and all(checks.values())
    assert len(checks) == len(report["checks"])
    assert checks["main_file_alone_misses_latest_commit"]
    assert checks["wrapped_keys_and_metadata_preserved"]
    assert checks["historical_and_current_key_epochs_present"]
    assert checks["snapshot_excludes_sample_plaintexts_kek_and_jwt_key"]
    assert checks["wrong_key_rejected"]
    assert checks["ciphertext_tamper_rejected"]
    assert checks["message_metadata_tamper_rejected"]
    assert checks["owner_metadata_tamper_rejected"]
    assert checks["wrapped_dek_tamper_rejected"]
    assert checks["kek_uri_tamper_rejected"]
    assert checks["kek_version_tamper_rejected"]
    assert checks["logged_out_session_blocked_after_restore"]
    assert checks["inactive_account_login_blocked_after_restore"]
    assert checks["inactive_account_token_blocked_after_restore"]
    assert checks["sealed_audit_chain_valid_after_restore"]
    assert report["keys_embedded_in_snapshot"] is False
    assert report["backup_seconds"] >= 0
    assert report["restore_and_verify_seconds"] > 0
    assert not list(tmp_path.glob("scap-recovery-drill-*"))
    encoded = json.dumps(report)
    assert "SYNTHETIC-ACCOUNT-SECRET" not in encoded
    assert "Bearer " not in encoded
    assert "wrapped_dek\":" not in encoded


def test_online_backup_includes_committed_wal_instead_of_only_main_file(tmp_path):
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    main_only_path = tmp_path / "main-only.db"
    with closing(sqlite3.connect(source_path)) as source:
        source.execute("PRAGMA journal_mode=WAL")
        source.execute("PRAGMA wal_autocheckpoint=0")
        source.execute("CREATE TABLE recovery_drill_marker (value TEXT NOT NULL)")
        source.execute("INSERT INTO recovery_drill_marker (value) VALUES (?)", (_MARKER,))
        source.commit()
        with closing(sqlite3.connect(source_path.as_uri() + "?immutable=1", uri=True)) as old:
            assert old.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='recovery_drill_marker'"
            ).fetchone() == (0,)
        main_only_path.write_bytes(source_path.read_bytes())
        assert not _snapshot_valid(main_only_path)
        _online_backup(source, backup_path)
    with closing(sqlite3.connect(backup_path)) as restored:
        assert restored.execute("SELECT value FROM recovery_drill_marker").fetchall() == [(_MARKER,)]
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert _snapshot_valid(backup_path)


def test_fresh_process_ignores_host_configuration_and_never_touches_existing_data(tmp_path):
    sentinel = tmp_path / "existing.db"
    untouched = b"Existing synthetic sentinel; never open or migrate this database."
    sentinel.write_bytes(untouched)
    (tmp_path / ".env").write_text(
        f"DATABASE_URL=sqlite:///{sentinel.as_posix()}\nAPP_ENV=production\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PYTHONUTF8": "1",
        "TEMP": str(tmp_path), "TMP": str(tmp_path), "TMPDIR": str(tmp_path),
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_ENV": "production", "SECURITY_PROFILE": "high", "KEY_PROVIDER": "vault",
        "APP_SECRET_KEY_FILE": str(tmp_path / "must-not-read-secret"),
        "GOOGLE_GENAI_API_KEY_FILE": str(tmp_path / "must-not-read-provider-key"),
        "GOOGLE_GENAI_API_KEY": "never-use-or-print-this-provider-secret",
        "VAULT_TOKEN_FILE": str(tmp_path / "must-not-read-vault-token"),
        "VAULT_ADDR": "https://example.invalid", "REDIS_URL": "redis://example.invalid",
        "SELF_BASE_URL": "https://example.invalid/never-use-this-api",
        "PUBLIC_BASE_URL": "https://example.invalid/never-use-this-url",
        "HTTP_PROXY": "http://example.invalid:9999",
    })
    result = subprocess.run(
        [sys.executable, "-m", "scripts.security_recovery_drill"], cwd=tmp_path,
        env=environment, capture_output=True, text=True, encoding="utf-8", timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == "passed" and all(check["passed"] for check in report["checks"])
    assert "never-use-or-print-this-provider-secret" not in result.stdout + result.stderr
    assert sentinel.read_bytes() == untouched
    assert not (tmp_path / "secure_chat.db").exists()
    assert not list(tmp_path.glob("scap-recovery-drill-*"))


def test_cli_hides_unexpected_error_details(monkeypatch, capsys):
    def fail():
        raise RuntimeError("never-print-private-key-or-token")

    monkeypatch.setattr("scripts.security_recovery_drill.run_recovery_drill", fail)
    assert main([]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "failed", "failed_check": "unexpected_drill_error",
    }


def test_cli_exits_nonzero_and_reports_failed_verification(monkeypatch, capsys):
    def fail():
        raise RecoveryDrillError("wrapped_keys_and_metadata_preserved")

    monkeypatch.setattr("scripts.security_recovery_drill.run_recovery_drill", fail)
    assert main([]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "status": "failed", "failed_check": "wrapped_keys_and_metadata_preserved",
    }
