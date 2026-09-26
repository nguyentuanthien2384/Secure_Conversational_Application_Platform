"""Repeatable, offline application security validation with correlated evidence.

This runner is intended for a dedicated CLI/CI process. Every scenario owns a
temporary SQLite database and an in-process TestClient; there is deliberately
no target URL, database URL, or production-settings option. ATT&CK labels are
limited analogies for the exercised application controls, not host coverage.
"""

from __future__ import annotations

import base64
import importlib
import json
import logging
import secrets
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from xml.etree import ElementTree

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from src.app.config import Settings
from src.app.ids import detect_anomalies
from src.app.models import AuditEvent, User


class ValidationFailure(RuntimeError):
    """A failed setup/check with a fixed, credential-free description."""


@dataclass(frozen=True)
class Scenario:
    identifier: str
    name: str
    kind: str
    technique: str | None
    scope: str
    exercise: Callable[[Probe], None]


class Probe:
    def __init__(self, app: Any, client: TestClient, run_id: str, scenario_id: str):
        self.app = app
        self.client = client
        self.prefix = f"sv-{run_id[:12]}-{scenario_id}"
        self.requests: list[dict[str, Any]] = []
        self.checks: list[dict[str, Any]] = []
        # Generated credentials never appear in reports or failure messages.
        self.password = "Validation-" + secrets.token_urlsafe(24) + "Aa1"

    def check(self, name: str, passed: bool) -> None:
        self.checks.append({"name": name, "passed": bool(passed)})

    def require(self, name: str, passed: bool) -> None:
        self.check(name, passed)
        if not passed:
            raise ValidationFailure(name)

    def request(
        self,
        method: str,
        path: str,
        *,
        expected_status: int,
        event: str | None = None,
        outcome: str | None = None,
        rule: str | None = None,
        phase: str = "exercise",
        token: str | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        request_id = f"{self.prefix}-{len(self.requests) + 1}"
        headers = {"X-Request-ID": request_id}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        started = time.perf_counter()
        response = self.client.request(method, path, headers=headers, **kwargs)
        latency_ms = (time.perf_counter() - started) * 1000
        with self.app.state.database.session_factory() as db:
            rows = db.scalars(
                select(AuditEvent)
                .where(AuditEvent.request_id == request_id)
                .order_by(AuditEvent.id)
            ).all()
            # Allow-list evidence fields: never export body, token, password,
            # free-form audit details, query strings, or user supplied values.
            evidence = [
                {
                    "audit_id": row.id,
                    "request_id": row.request_id,
                    "event_type": row.event_type,
                    "outcome": row.outcome,
                    "rule_id": row.target_id if row.event_type == "ids.signature" else None,
                    "sealed": bool(row.entry_hash),
                }
                for row in rows
            ]
        evidence_latency = (time.perf_counter() - started) * 1000 if evidence else None
        self.requests.append(
            {
                "request_id": request_id,
                "phase": phase,
                "method": method,
                "path": path.partition("?")[0],
                "expected_status": expected_status,
                "observed_status": response.status_code,
                "expected_event": event,
                "latency_ms": round(latency_ms, 3),
                "audit_observation_latency_ms": (
                    round(evidence_latency, 3) if evidence_latency is not None else None
                ),
                "audit_evidence": evidence,
            }
        )
        self.check(f"{request_id}: response status", response.status_code == expected_status)
        self.check(f"{request_id}: request correlation", response.headers.get("x-request-id") == request_id)
        if event:
            matches = [
                item for item in evidence
                if item["event_type"] == event
                and (outcome is None or item["outcome"] == outcome)
                and (rule is None or item["rule_id"] == rule)
            ]
            self.check(f"{request_id}: correlated {event} evidence", bool(matches))
            self.check(f"{request_id}: sealed evidence", bool(matches) and all(item["sealed"] for item in matches))
        return response

    def account(self, username: str, *, admin: bool = False) -> str:
        if admin:
            with self.app.state.database.session_factory() as db:
                db.add(User(username=username, password_hash=self.app.state.password_service.hash(self.password), role="admin"))
                db.commit()
        else:
            response = self.request(
                "POST", "/api/auth/register", expected_status=201,
                event="auth.register", outcome="success", phase="setup",
                json={"username": username, "password": self.password},
            )
            self.require("account setup completed", response.status_code == 201)
        response = self.request(
            "POST", "/api/auth/login", expected_status=200,
            event="auth.login", outcome="success", phase="setup",
            json={"username": username, "password": self.password},
        )
        self.require("login setup completed", response.status_code == 200)
        return response.json()["access_token"]


def _missing_auth(probe: Probe) -> None:
    probe.request("GET", "/api/sessions", expected_status=401, event="auth.access.denied", outcome="denied")


def _invalid_token(probe: Probe) -> None:
    probe.request("GET", "/api/auth/me", expected_status=401, event="auth.access.denied", outcome="denied", token="validation-invalid-token")


def _idor(probe: Probe) -> None:
    owner = probe.account("validation-owner")
    other = probe.account("validation-other")
    response = probe.request("POST", "/api/sessions", expected_status=201, token=owner, phase="setup", json={"title": "Validation private session"})
    probe.require("session setup completed", response.status_code == 201)
    session_id = response.json()["id"]
    for method, path in (("GET", f"/api/sessions/{session_id}/messages"), ("DELETE", f"/api/sessions/{session_id}")):
        probe.request(method, path, expected_status=404, token=other, event="authorization.denied", outcome="denied")
    response = probe.request("GET", f"/api/sessions/{session_id}", expected_status=200, token=owner, phase="control")
    probe.check("owner resource remains available after denied deletion", response.status_code == 200 and response.json().get("id") == session_id)


def _brute_force(probe: Probe) -> None:
    probe.account("validation-login")
    for attempt in range(6):
        response = probe.request(
            "POST", "/api/auth/login", expected_status=401 if attempt < 5 else 429,
            event="auth.login", outcome="failure" if attempt < 4 else "blocked",
            json={"username": "validation-login", "password": "Incorrect validation passphrase 2026"},
        )
        if attempt == 5:
            probe.check("throttled request advertises retry delay", response.headers.get("retry-after", "").isdigit())
    with probe.app.state.database.session_factory() as db:
        user = db.scalar(select(User).where(User.username == "validation-login"))
        probe.check("failed attempts persistently lock account", user is not None and user.failed_login_attempts == 5 and user.locked_until is not None)
        findings = detect_anomalies(db)
    probe.check("audit correlation detects brute force", any(finding.code == "IDS-BRUTEFORCE" and finding.count >= 5 for finding in findings))


def _encoded_injection(probe: Probe) -> None:
    # Fixed URL-only fixture; never executed against SQL or a remote service.
    path = "/api/health?q=1%2520UNION%2520SELECT%2520username"
    probe.request("GET", path, expected_status=200, event="ids.signature", rule="SQLI-001", outcome="denied")
    probe.request("GET", path, expected_status=403, event="ids.block", outcome="blocked")
    probe.check("signature is present in live IDS state", any(item["rule_id"] == "SQLI-001" for item in probe.app.state.intrusion_state.recent()))
    probe.check("IPS blocklist records source", bool(probe.app.state.intrusion_state.blocked_sources()))


def _benign_control(probe: Probe) -> None:
    token = probe.account("validation-benign")
    response = probe.request("GET", "/api/auth/me?note=selecting+a+meeting+time", expected_status=200, token=token, phase="control")
    probe.check("authenticated benign user identified", response.status_code == 200 and response.json().get("username") == "validation-benign")
    probe.check("benign request has protective headers", response.headers.get("x-content-type-options") == "nosniff" and response.headers.get("cache-control") == "no-store")
    probe.check("benign workflow produces no IDS false positive", not probe.app.state.intrusion_state.recent())
    probe.check("benign workflow produces no correlated denial", all(item["outcome"] == "success" for request in probe.requests for item in request["audit_evidence"]))


def _audit_tamper(probe: Probe) -> None:
    token = probe.account("validation-auditor", admin=True)
    clean = probe.request("GET", "/api/admin/audit/verify", expected_status=200, event="audit.chain.verify", outcome="success", token=token, phase="control")
    probe.require("clean audit chain verifies before mutation", clean.json().get("chain_intact") is True)
    with probe.app.state.database.session_factory() as db:
        event_id = db.scalar(select(AuditEvent.id).order_by(AuditEvent.id).limit(1))
        probe.require("temporary audit fixture exists", event_id is not None)
        # This database was constructed exclusively inside TemporaryDirectory.
        db.execute(update(AuditEvent).where(AuditEvent.id == event_id).values(outcome="failure"))
        db.commit()
    response = probe.request("GET", "/api/admin/audit/verify", expected_status=200, event="audit.chain.broken", outcome="failure", token=token)
    probe.check("tampering detected at changed row", response.json().get("chain_intact") is False and response.json().get("first_broken_id") == event_id)


SCENARIOS = (
    Scenario("missing-auth", "Unauthenticated access", "attack", None, "Authentication boundary; no ATT&CK technique asserted.", _missing_auth),
    Scenario("invalid-token", "Malformed bearer token", "attack", None, "Token verification boundary; no valid-account compromise asserted.", _invalid_token),
    Scenario("idor", "Cross-user resource access", "attack", None, "Application object authorization and denial evidence.", _idor),
    Scenario("brute-force", "Repeated failed passwords", "attack", "T1110.001", "Synthetic account password guessing and audit anomaly correlation.", _brute_force),
    Scenario("encoded-sqli", "Double-encoded injection signature", "attack", "T1190", "Application IDS signature and IPS prevention only; no exploitation proven.", _encoded_injection),
    Scenario("benign", "Benign authenticated control", "control", None, "False-positive control for a small fixed benign sample.", _benign_control),
    Scenario("audit-tamper", "Tampered audit fixture", "attack", "T1565.001", "Mutation of a temporary audit row; no host or production database access.", _audit_tamper),
)


def _settings(directory: Path) -> Settings:
    return Settings(
        environment="test", database_url=f"sqlite:///{directory / 'validation.db'}",
        secret_key=secrets.token_urlsafe(48),
        master_encryption_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        allow_demo_ai=True, google_genai_api_key="", password_breach_check=False,
        redis_url="", key_provider="local", audit_worm_endpoint="",
        bootstrap_admin_username="", bootstrap_admin_password="", seed_demo_data=False,
        siem_json_logs=False, retention_sweep_on_startup=False, docs_enabled=False,
        ids_enabled=True, ids_block_threshold=5, login_max_attempts=5,
    )


@contextmanager
def _offline_factory(settings: Settings) -> Iterator[Callable[..., Any]]:
    """Fence off HTTP transports and the module's legacy eager default app.

    TestClient uses its own transport. No mock replaces security controls. The
    Settings patch prevents main.py's import-time create_app() from reading
    .env, file-backed secrets, or a production database. Restore global logging
    state because create_app configures the shared SIEM logger.
    """
    logger = logging.getLogger("security.siem")
    original = (logger.disabled, logger.level, logger.propagate, list(logger.handlers))
    imported_here = "src.app.main" not in sys.modules
    module = None
    try:
        with (
            patch.object(Settings, "from_env", return_value=settings),
            patch.object(httpx.HTTPTransport, "handle_request", side_effect=RuntimeError("Outbound HTTP is disabled during validation")),
            patch.object(httpx.AsyncHTTPTransport, "handle_async_request", side_effect=RuntimeError("Outbound HTTP is disabled during validation")),
        ):
            module = importlib.import_module("src.app.main")
            yield module.create_app
    finally:
        if imported_here and module is not None:
            module.app.state.envelope_crypto_service.clear_cache()
            module.app.state.database.engine.dispose()
        for handler in logger.handlers:
            if handler not in original[3]:
                handler.close()
        logger.disabled, logger.level, logger.propagate, logger.handlers = original


def run_validation(scenario_ids: Sequence[str] | None = None) -> dict[str, Any]:
    """Run known offline scenarios and return sanitized, machine-readable evidence."""
    selected = set(scenario_ids) if scenario_ids is not None else {item.identifier for item in SCENARIOS}
    unknown = selected - {item.identifier for item in SCENARIOS}
    if unknown or not selected:
        raise ValueError("Select at least one known security validation scenario")
    run_id = uuid.uuid4().hex
    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="scap-security-validation-") as temporary:
        root = Path(temporary)
        with _offline_factory(_settings(root)) as create_app:
            for scenario in SCENARIOS:
                if scenario.identifier not in selected:
                    continue
                case_started = time.perf_counter()
                case_dir = root / scenario.identifier
                case_dir.mkdir()
                app = None
                probe = None
                error_type = None
                try:
                    app = create_app(_settings(case_dir))
                    with TestClient(app, raise_server_exceptions=True) as client:
                        probe = Probe(app, client, run_id, scenario.identifier)
                        scenario.exercise(probe)
                except Exception as exc:
                    # Exception strings may carry request/SQL data. A fixed
                    # error type plus failed named checks suffices for CI.
                    error_type = type(exc).__name__
                finally:
                    if app is not None:
                        app.state.envelope_crypto_service.clear_cache()
                        app.state.database.engine.dispose()
                checks = probe.checks if probe is not None else []
                passed = error_type is None and bool(checks) and all(item["passed"] for item in checks)
                results.append({
                    "id": scenario.identifier, "name": scenario.name,
                    "kind": scenario.kind, "mitre_technique": scenario.technique,
                    "scope": scenario.scope, "status": "pass" if passed else "fail",
                    "duration_ms": round((time.perf_counter() - case_started) * 1000, 3),
                    "checks": checks, "requests": probe.requests if probe is not None else [],
                    "error_type": error_type,
                })
    passed_count = sum(item["status"] == "pass" for item in results)
    return {
        "schema_version": 1, "run_id": run_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "validation_type": "isolated_application_security_validation",
        "scope": "In-process HTTP middleware, API authorization, temporary SQLite audit and IDS controls.",
        "not_covered": ["Production deployment", "External SIEM ingestion or alert delivery", "Operating-system ATT&CK telemetry", "Real exploit execution", "Statistical detection or false-positive rates"],
        "timing_definition": "latency_ms measures local request completion; audit_observation_latency_ms includes reading committed correlated evidence. Neither is external SIEM latency.",
        "temporary_database_cleaned": True,
        "total_scenarios": len(results), "passed_scenarios": passed_count,
        "failed_scenarios": len(results) - passed_count,
        "status": "pass" if passed_count == len(results) else "fail",
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "scenarios": results,
    }


def write_reports(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    """Write JSON evidence and JUnit failures without secrets or raw payloads."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "security-validation.json"
    junit_path = output_dir / "security-validation.junit.xml"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    suite = ElementTree.Element("testsuite", {
        "name": "scap.security-validation", "tests": str(report["total_scenarios"]),
        "failures": str(report["failed_scenarios"]), "errors": "0",
        "time": f"{report['duration_ms'] / 1000:.6f}",
    })
    for scenario in report["scenarios"]:
        case = ElementTree.SubElement(suite, "testcase", {
            "classname": "scap.security-validation", "name": scenario["id"],
            "time": f"{scenario['duration_ms'] / 1000:.6f}",
        })
        if scenario["status"] != "pass":
            failed = [item["name"] for item in scenario["checks"] if not item["passed"]]
            failure = ElementTree.SubElement(case, "failure", {"message": "Security control or correlated evidence missing"})
            failure.text = "\n".join(failed + ([scenario["error_type"]] if scenario["error_type"] else []))
    ElementTree.ElementTree(suite).write(junit_path, encoding="utf-8", xml_declaration=True)
    return json_path, junit_path
