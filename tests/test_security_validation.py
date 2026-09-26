from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from xml.etree import ElementTree

import pytest

from scripts.validate_security import main
from src.app import security_validation as validation


@pytest.fixture(scope="module")
def validation_report():
    return validation.run_validation()


def test_full_feedback_loop_requires_correlated_sealed_evidence(validation_report):
    report = validation_report
    failures = [case for case in report["scenarios"] if case["status"] != "pass"]
    assert not failures, failures
    assert report["total_scenarios"] == 7
    assert report["temporary_database_cleaned"] is True
    request_ids = []
    for case in report["scenarios"]:
        assert case["checks"]
        for request in case["requests"]:
            request_ids.append(request["request_id"])
            assert request["latency_ms"] >= 0
            for evidence in request["audit_evidence"]:
                assert evidence["request_id"] == request["request_id"]
                assert evidence["sealed"]
            if request["expected_event"]:
                assert any(event["event_type"] == request["expected_event"] for event in request["audit_evidence"])
                assert request["audit_observation_latency_ms"] >= request["latency_ms"]
    assert len(request_ids) == len(set(request_ids))
    benign = next(case for case in report["scenarios"] if case["kind"] == "control")
    assert benign["mitre_technique"] is None
    assert all(event["event_type"] != "ids.signature" for request in benign["requests"] for event in request["audit_evidence"])


def test_missing_detection_evidence_fails_even_when_http_prevention_works(monkeypatch):
    # A detector may return the expected status while its audit pipeline is
    # broken. This regression must cause CI to fail rather than claim coverage.
    import src.app.main as application

    original = application.record_audit

    def missing_signature(db, request, event_type, **kwargs):
        if event_type != "ids.signature":
            return original(db, request, event_type, **kwargs)
        return None

    monkeypatch.setattr(application, "record_audit", missing_signature)
    report = validation.run_validation(["encoded-sqli"])
    assert report["failed_scenarios"] == 1
    scenario = report["scenarios"][0]
    assert [request["observed_status"] for request in scenario["requests"]] == [200, 403]
    assert any("correlated ids.signature" in check["name"] and not check["passed"] for check in scenario["checks"])


def test_runner_cleans_databases_and_sanitizes_unexpected_errors(monkeypatch):
    directories = []
    original = validation._settings

    def tracking_settings(directory):
        directories.append(directory)
        return original(directory)

    def fail_after_request(probe):
        probe.request("GET", "/api/health", expected_status=200)
        raise RuntimeError("DO-NOT-EXPORT-sensitive-request-content")

    case = replace(validation.SCENARIOS[0], exercise=fail_after_request)
    monkeypatch.setattr(validation, "SCENARIOS", (case,))
    monkeypatch.setattr(validation, "_settings", tracking_settings)
    report = validation.run_validation()
    assert report["failed_scenarios"] == 1
    assert report["scenarios"][0]["error_type"] == "RuntimeError"
    assert "DO-NOT-EXPORT" not in json.dumps(report)
    assert directories and all(not directory.exists() for directory in directories)


def test_json_junit_and_cli_exit_code_reflect_failure(tmp_path, monkeypatch, validation_report):
    report = json.loads(json.dumps(validation_report))
    report["status"] = "fail"
    report["failed_scenarios"] = 1
    report["passed_scenarios"] -= 1
    report["scenarios"][0]["status"] = "fail"
    report["scenarios"][0]["checks"][0]["passed"] = False
    monkeypatch.setattr("scripts.validate_security.run_validation", lambda _: report)
    assert main(["--output-dir", str(tmp_path)]) == 1
    saved = json.loads((tmp_path / "security-validation.json").read_text(encoding="utf-8"))
    assert saved["failed_scenarios"] == 1
    suite = ElementTree.parse(tmp_path / "security-validation.junit.xml").getroot()
    assert suite.attrib["failures"] == "1"
    assert len(suite.findall("testcase/failure")) == 1


def test_fresh_process_never_reads_env_file_or_opens_configured_database(tmp_path):
    sentinel = tmp_path / "production.db"
    original = b"This file must never be opened as a database"
    sentinel.write_bytes(original)
    (tmp_path / ".env").write_text(
        f"DATABASE_URL=sqlite:///{sentinel.as_posix()}\nAPP_ENV=production\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update({
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "DATABASE_URL": f"sqlite:///{sentinel.as_posix()}",
        "APP_SECRET_KEY_FILE": str(tmp_path / "must-not-read-secret"),
        "GOOGLE_GENAI_API_KEY_FILE": str(tmp_path / "must-not-read-api-key"),
    })
    result = subprocess.run(
        [sys.executable, "-m", "scripts.validate_security", "--scenario", "benign", "--output-dir", str(tmp_path / "reports")],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert sentinel.read_bytes() == original
    assert not (tmp_path / "secure_chat.db").exists()
    report = json.loads((tmp_path / "reports/security-validation.json").read_text(encoding="utf-8"))
    assert report["status"] == "pass"


def test_network_transport_is_blocked_and_global_settings_restored(tmp_path):
    import httpx

    from src.app.config import Settings

    before = Settings.from_env.__func__
    with validation._offline_factory(validation._settings(tmp_path)):
        with httpx.Client() as client:
            with pytest.raises(RuntimeError, match="Outbound HTTP is disabled"):
                client.get("https://example.invalid/")
    assert Settings.from_env.__func__ is before


def test_unknown_or_empty_scenario_set_is_rejected():
    with pytest.raises(ValueError):
        validation.run_validation(["unknown"])
    with pytest.raises(ValueError):
        validation.run_validation([])


def test_ci_runs_validator_and_uploads_evidence():
    workflow = Path(".github/workflows/security.yml").read_text(encoding="utf-8")
    assert "python -m scripts.validate_security" in workflow
    assert "reports/security-validation/security-validation.json" in workflow
    assert "reports/security-validation/security-validation.junit.xml" in workflow
