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
    assert report["total_scenarios"] == 11
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


def test_demo_proofs_distinguish_real_requests_from_synthetic_evidence(validation_report):
    by_id = {case["id"]: case for case in validation_report["scenarios"]}
    timeout = by_id["session-timeout"]
    assert [request["observed_status"] for request in timeout["requests"] if request["phase"] == "exercise"] == [200, 401, 401]
    assert timeout["observations"][0]["source"] == "temporary_session_timestamp_fixture"
    expired = [event for request in timeout["requests"] for event in request["audit_evidence"] if event["event_type"] == "auth.session.expired"]
    assert len(expired) == 2 and all(event["sealed"] for event in expired)

    dlp = by_id["encoded-dlp"]
    assert [request["observed_status"] for request in dlp["requests"] if request["phase"] == "exercise"] == [422, 201, 201]
    assert dlp["observations"][0]["source"] == "local_recording_provider"
    assert dlp["observations"][0]["provider_calls"] == 2
    assert dlp["observations"][0]["external_network_calls"] == 0

    correlations = by_id["auth-correlation"]["observations"]
    fixtures = [item for item in correlations if item["source"] == "synthetic_audit_fixture"]
    assert len(fixtures) == 7 and all(item["sealed"] for item in fixtures)
    assert len([item for item in fixtures if item["outcome"] == "failure"]) == 5
    findings = {item["code"]: item for item in correlations if item["source"] == "anomaly_api_over_synthetic_fixtures"}
    assert findings["IDS-DISTRIBUTED-BRUTEFORCE"]["source_count"] == 5
    assert findings["IDS-AUTH-SUCCESS-AFTER-FAILURES"]["evidence_event_id"] == fixtures[-1]["audit_id"]

    browser = by_id["browser-origin"]
    denials = [request for request in browser["requests"] if request["expected_status"] == 403]
    assert {request["path"] for request in denials} == {"/api/sessions", "/gradio_api/queue/join"}
    assert {item["request_id"] for item in browser["observations"]} == {request["request_id"] for request in denials}
    assert all(item["source"] == "in_process_security_telemetry" and item["event_type"] == "browser.origin.denied" for item in browser["observations"])


def test_new_report_fields_never_export_payloads_or_fixture_subjects(validation_report, tmp_path):
    import base64

    json_path, junit_path = validation.write_reports(validation_report, tmp_path)
    saved = json_path.read_text(encoding="utf-8") + junit_path.read_text(encoding="utf-8")
    private = [
        "password:validation-only-encoded-secret", "validation-person@example.com",
        "synthetic-validation-target", "192.0.2.", "https://untrusted.example",
        "Must never exist", "Allowed browser conversation", "Safe local provider response",
    ]
    for value in private:
        assert value not in saved
        assert base64.b64encode(value.encode()).decode("ascii") not in saved


def test_origin_prevention_without_correlated_telemetry_fails_validation(monkeypatch):
    from src.app.security import SlidingWindowRateLimiter

    original = SlidingWindowRateLimiter.allow

    def suppress_origin_telemetry(self, key, max_attempts, window_seconds):
        if key.startswith("browser-origin:"):
            return False, 60
        return original(self, key, max_attempts, window_seconds)

    # HTTP prevention still works when the audit limiter suppresses emission.
    # The proof must report the missing telemetry, not claim evidence delivery.
    monkeypatch.setattr(SlidingWindowRateLimiter, "allow", suppress_origin_telemetry)
    report = validation.run_validation(["browser-origin"])
    assert report["failed_scenarios"] == 1
    scenario = report["scenarios"][0]
    assert all(request["observed_status"] == request["expected_status"] for request in scenario["requests"])
    assert any("correlated security telemetry" in check["name"] and not check["passed"] for check in scenario["checks"])


def test_leaked_encoded_email_at_provider_boundary_fails_validation(monkeypatch):
    from src.app.dlp import DLPScanner

    original = DLPScanner.evaluate

    def broken_redaction(self, text, **kwargs):
        decision = original(self, text, **kwargs)
        if text.startswith("Contact ("):
            return replace(decision, output_text=text)
        return decision

    monkeypatch.setattr(DLPScanner, "evaluate", broken_redaction)
    report = validation.run_validation(["encoded-dlp"])
    assert report["failed_scenarios"] == 1
    assert any("no encoded email" in check["name"] and not check["passed"] for check in report["scenarios"][0]["checks"])


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
