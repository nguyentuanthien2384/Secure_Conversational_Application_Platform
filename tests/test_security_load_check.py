from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scripts.security_load_check import LocalServer, Sample, current_rss_bytes, summarize


def test_success_latency_is_separate_from_fast_rejections_and_private_payloads():
    result = summarize([
        Sample(200, 100, False, {"access_token": "never-print-token"}),
        Sample(201, 200, False, {"content": "never-print-content"}),
        Sample(503, 1, True), Sample(429, 2, True),
    ])
    assert result["success_latency"] == {"samples": 2, "p50_ms": 100, "p95_ms": 200}
    assert result["rejection_latency"] == {"samples": 2, "p50_ms": 1, "p95_ms": 2}
    assert result["retry_after_on_rejections"]
    assert "never-print" not in json.dumps(result)


def test_missing_retry_after_is_not_reported_as_successful_control():
    assert not summarize([Sample(503, 1, False)])["retry_after_on_rejections"]


@pytest.mark.parametrize("path", ["https://example.invalid/", "//example.invalid/", "/\r\nHost: evil"])
def test_request_cannot_redirect_the_harness_to_an_external_destination(path):
    server = LocalServer.__new__(LocalServer)
    with pytest.raises(ValueError):
        server.request("GET", path)


@pytest.mark.parametrize("slow", [False, True])
def test_total_request_ceiling_applies_before_connecting_including_slow_bodies(slow, monkeypatch):
    server = LocalServer.__new__(LocalServer)
    server.requests = 160
    server.deadline = time.monotonic() + 10
    monkeypatch.setattr("scripts.security_load_check.socket.create_connection", lambda *_a, **_k: pytest.fail("Connected past ceiling"))
    with pytest.raises(RuntimeError, match="safety ceiling"):
        server.slow_body() if slow else server.request("GET", "/api/health")


def test_remaining_deadline_limits_io_and_rejects_recovery_waits():
    server = LocalServer.__new__(LocalServer)
    server.deadline = time.monotonic() + .1
    assert 0 < server.timeout(7) <= .1
    with pytest.raises(RuntimeError, match="Recovery exceeds"):
        server.pause(2.1)
    server.deadline = time.monotonic() - 1
    with pytest.raises(RuntimeError, match="deadline"):
        server.timeout(7)


def test_rss_is_measured_for_the_current_process_or_explicitly_unavailable():
    rss = current_rss_bytes()
    if os.name == "nt" or Path("/proc/self/statm").exists():
        assert isinstance(rss, int) and rss > 0
    else:
        assert rss is None


def test_startup_resource_guard_stops_disposable_child_and_releases_handles(tmp_path, monkeypatch):
    existing = {child.pid for child in multiprocessing.active_children()}
    monkeypatch.setattr("scripts.security_load_check.MAX_RSS_BYTES", 1)
    with pytest.raises((RuntimeError, EOFError)):
        LocalServer(tmp_path, "capacity", time.monotonic() + 20)
    assert not [child for child in multiprocessing.active_children() if child.pid not in existing]
    assert not (tmp_path / "demo.db").exists()


def test_fresh_http_run_is_isolated_from_host_database_secrets_and_proxies(tmp_path):
    sentinel = tmp_path / "existing.db"
    original = b"Existing synthetic sentinel; must never open this file."
    sentinel.write_bytes(original)
    (tmp_path / ".env").write_text(f"DATABASE_URL=sqlite:///{sentinel.as_posix()}\nAPP_ENV=production\n", encoding="utf-8")
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]), "PYTHONUTF8": "1",
        "TEMP": str(tmp_path), "TMP": str(tmp_path), "TMPDIR": str(tmp_path),
        "APP_ENV": "production", "SECURITY_PROFILE": "high", "KEY_PROVIDER": "vault",
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_SECRET_KEY_FILE": str(tmp_path / "must-not-read-secret"),
        "GOOGLE_GENAI_API_KEY": "never-use-or-print-this-provider-secret",
        "GOOGLE_GENAI_API_KEY_FILE": str(tmp_path / "must-not-read-key"),
        "VAULT_ADDR": "https://example.invalid", "REDIS_URL": "redis://example.invalid",
        "SELF_BASE_URL": "https://example.invalid", "PUBLIC_BASE_URL": "https://example.invalid",
        "HTTP_PROXY": "http://example.invalid:9999", "ALL_PROXY": "http://example.invalid:9999",
    })
    output = tmp_path / "report"
    result = subprocess.run(
        [sys.executable, "-m", "scripts.security_load_check", "--quick", "--output-dir", str(output)],
        cwd=tmp_path, env=environment, capture_output=True, text=True, encoding="utf-8",
        timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads((output / "security-load.json").read_text(encoding="utf-8"))
    assert report["passed"] and all(phase["passed"] for phase in report["phases"])
    assert report["coverage"]["body_timeout"] == "skipped_quick"
    assert report["capacity_resources"]["peak_rss_bytes"] > 0
    assert report["capacity_resources"]["stop_reason"] is None
    assert report["safety"]["max_open_load_connections"] == 5
    encoded = json.dumps(report) + result.stdout + result.stderr
    assert "never-use-or-print-this-provider-secret" not in encoded
    assert "Bearer " not in encoded and "access_token" not in encoded
    assert sentinel.read_bytes() == original
    assert not (tmp_path / "secure_chat.db").exists()
    assert not list(tmp_path.glob("scap-load-check-*"))
