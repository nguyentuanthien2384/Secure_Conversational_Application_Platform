"""Restore shell orchestration only: fake Docker, HTTPS, and host cron."""

from __future__ import annotations

import pytest

from tests.test_remote_deploy_gate import deployment as deployment

ARCHIVE = "backups/20261017T030000Z"


def test_restore_migrates_and_quarantines_without_starting_public_services(deployment):
    result, logs = deployment(script="restore.sh", arguments=(ARCHIVE,))
    assert result.returncode == 0, result.stdout + result.stderr
    calls = logs["docker_log"]
    assert calls.index("stop caddy app") < calls.index("pg_restore")
    assert calls.index("pg_restore") < calls.index("run --rm --no-deps migrate\n")
    assert "-m scripts.quarantine_restored_database quarantine" in calls
    assert "up -d --no-build" not in calls
    assert not logs["curl_log"] and not logs["cron_log"]
    assert (deployment.project / "deploy/.restore-pending").read_text().strip() == "quarantined"
    assert "OFFLINE" in result.stdout


@pytest.mark.parametrize("scenario", [
    {"RESTORE_EXIT": 1}, {"MIGRATE_EXIT": 1}, {"QUARANTINE_EXIT": 1},
])
def test_restore_failure_stays_offline_and_requires_another_restore(deployment, scenario):
    result, logs = deployment(script="restore.sh", arguments=(ARCHIVE,), **scenario)
    assert result.returncode != 0
    assert "stop caddy app" in logs["docker_log"]
    assert "up -d --no-build" not in logs["docker_log"]
    assert "[OK]" not in result.stdout
    assert (deployment.project / "deploy/.restore-pending").read_text().strip() == "restoring"
    assert not logs["curl_log"] and not logs["cron_log"]


def test_restore_does_not_treat_database_unavailability_as_an_empty_database(deployment):
    result, logs = deployment(script="restore.sh", arguments=(ARCHIVE,), DB_READY_EXIT=1)
    assert result.returncode != 0
    assert "PostgreSQL chua san sang" in result.stderr
    assert "pg_restore" not in logs["docker_log"]
    assert not (deployment.project / "deploy/.restore-pending").exists()


def test_restore_requires_force_before_replacing_existing_users(deployment):
    result, logs = deployment(script="restore.sh", arguments=(ARCHIVE,), EXISTING_USERS=4)
    assert result.returncode != 0
    assert "DB dang co 4 nguoi dung" in result.stderr
    assert "pg_restore" not in logs["docker_log"]
    assert "stop caddy app" not in logs["docker_log"]


@pytest.mark.parametrize("marker", [None, "restoring"])
def test_review_commands_cannot_bypass_failed_or_missing_quarantine(deployment, marker):
    result, logs = deployment(script="restore.sh", arguments=("--resume-reviewed",), marker=marker)
    assert result.returncode != 0
    assert "Snapshot chua quarantine thanh cong" in result.stderr
    assert not any(logs.values())


def test_only_an_explicitly_named_reviewed_user_can_be_activated_while_offline(deployment):
    result, logs = deployment(script="restore.sh",
                              arguments=("--activate-reviewed-user", "reviewed.admin"),
                              marker="quarantined")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "activate-reviewed-user -- reviewed.admin" in logs["docker_log"]
    assert "up -d" not in logs["docker_log"]
    assert (deployment.project / "deploy/.restore-pending").exists()


def test_resume_requires_a_reviewed_active_admin(deployment):
    result, logs = deployment(script="restore.sh", arguments=("--resume-reviewed",),
                              marker="quarantined", REVIEWED_ADMINS=0)
    assert result.returncode != 0
    assert "it nhat mot admin" in result.stderr
    assert "up -d --no-build" not in logs["docker_log"]


def test_explicit_resume_runs_full_image_migration_readiness_and_tls_gate(deployment):
    result, logs = deployment(script="restore.sh", arguments=("--resume-reviewed",),
                              marker="quarantined")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "{{.Image}} {{.State.Status}} {{.State.ExitCode}}" in logs["docker_log"]
    assert "{{if .State.Health}}" in logs["docker_log"]
    assert "https://gate.invalid/api/health" in logs["curl_log"]
    assert not (deployment.project / "deploy/.restore-pending").exists()
    assert not (deployment.project / "deploy/.restore-reviewed").exists()


def test_failed_resume_restores_marker_and_stops_public_services(deployment):
    result, logs = deployment(script="restore.sh", arguments=("--resume-reviewed",),
                              marker="quarantined", STALE="app-container")
    assert result.returncode != 0
    assert "stop caddy app" in logs["docker_log"]
    assert "Readiness/deploy gate chua dat" in result.stderr
    assert (deployment.project / "deploy/.restore-pending").read_text().strip() == "quarantined"
    assert not logs["cron_log"]
