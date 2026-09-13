from pathlib import Path

WORKFLOW = Path(".github/workflows/security.yml")


def test_vulnerability_scans_fail_for_every_high_or_critical_finding():
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "severity: HIGH,CRITICAL" in workflow
    assert 'exit-code: "1"' in workflow
    assert "ignore-unfixed" not in workflow


def test_semgrep_uses_a_checked_in_ruleset_and_pinned_cli():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    rules = Path(".semgrep.yml").read_text(encoding="utf-8")

    assert 'semgrep==1.172.0' in workflow
    assert "semgrep scan --config .semgrep.yml" in workflow
    assert "--config auto" not in workflow
    assert "scap.python.dynamic-code-execution" in rules
    assert "scap.python.tls-verification-disabled" in rules
    assert "scap.fastapi.wildcard-cors" in rules


def test_ci_validates_the_high_security_deployment_and_runtime():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    static_probe = Path("scripts/validate_high_security_deployment.sh").read_text(
        encoding="utf-8"
    )
    runtime_probe = Path("scripts/verify_high_security_app_runtime.sh").read_text(
        encoding="utf-8"
    )

    assert "deployment-config:" in workflow
    assert "scripts/validate_high_security_deployment.sh" in workflow
    assert "scripts/verify_high_security_app_runtime.sh secure-chat:ci" in workflow
    assert "docker compose" in static_probe
    assert "config --quiet" in static_probe
    assert "caddy validate" in static_probe
    assert "--read-only" in runtime_probe
    assert "--network none" in runtime_probe
    assert "NoNewPrivs" in runtime_probe
    assert "CapEff" in runtime_probe
    assert (
        "needs: [test, secret-scan, sast, filesystem-scan, image-scan, deployment-config]"
        in workflow
    )
