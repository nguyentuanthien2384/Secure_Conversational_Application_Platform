"""The recruiter rehearsal uses a separate server and ignores real settings."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("vodozemac", reason="Requires the standalone E2EE client extra")


def test_two_client_rehearsal_ignores_existing_secrets_database_and_proxies(tmp_path):
    sentinel = tmp_path / "existing.db"
    original = b"Existing data must not be opened or changed."
    sentinel.write_bytes(original)
    (tmp_path / ".env").write_text(f"APP_ENV=production\nDATABASE_URL=sqlite:///{sentinel.as_posix()}\n")
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PYTHONUTF8": "1",
        "TEMP": str(tmp_path), "TMP": str(tmp_path), "TMPDIR": str(tmp_path),
        "APP_ENV": "production", "SECURITY_PROFILE": "high",
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_SECRET_KEY_FILE": str(tmp_path / "must-not-read-secret"),
        "CLAUDE_API_KEY": "never-print-provider-credential",
        "CLAUDE_API_KEY_FILE": str(tmp_path / "must-not-read-provider-file"),
        "SELF_BASE_URL": "https://example.invalid", "PUBLIC_BASE_URL": "https://example.invalid",
        "HTTP_PROXY": "http://example.invalid:9999", "HTTPS_PROXY": "http://example.invalid:9999",
    })
    result = subprocess.run([sys.executable, "-m", "scripts.demo_e2ee", "--check",
                             "--output-dir", str(tmp_path / "proof")], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, encoding="utf-8",
                            timeout=90, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "never-print-provider-credential" not in result.stdout + result.stderr
    report = json.loads((tmp_path / "proof/e2ee-demo.json").read_text())
    assert report["status"] == "pass"
    assert report["scope"] == "two_local_clients_and_separate_server_process"
    assert report["both_clients_decrypted"] and report["server_export_ciphertext_only"]
    assert report["plaintext_absent_from_server_export"] and report["cursor_replay_empty"]
    assert report["prekeys_refilled"] and not report["external_services_used"]
    assert sentinel.read_bytes() == original
    assert not list(tmp_path.glob("scap-e2ee-rehearsal-*"))
