"""Exercise the deployment acceptance gate without Docker, network, or host cron."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _bash_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt":
        return f"/{value[0].lower()}{value[2:]}"
    return value


@pytest.fixture
def deployment(tmp_path):
    # Git Bash can execute the same wrappers as Linux; no WSL or Docker is needed.
    candidates = []
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            for parent in list(Path(git).resolve().parents)[:3]:
                candidates.append(parent / "bin/bash.exe")
        for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            directory = os.environ.get(variable)
            if directory:
                candidates.extend((Path(directory) / "Git/bin/bash.exe",
                                   Path(directory) / "Programs/Git/bin/bash.exe"))
    located = shutil.which("bash")
    if located:
        candidates.append(Path(located))
    bash = next((candidate for candidate in candidates
                 if candidate.is_file() and (os.name != "nt"
                     or (candidate.parent / "msys-2.0.dll").is_file()
                     or (candidate.parent.parent / "usr/bin/msys-2.0.dll").is_file())), None)
    if bash is None:
        pytest.skip("Bash is required to exercise the deployment script")

    project = tmp_path / "project"
    deploy = project / "deploy"
    deploy.mkdir(parents=True)
    (project / ".git").mkdir()
    for filename in ("remote-deploy.sh", "vps-compose.sh"):
        shutil.copyfile(ROOT / "deploy" / filename, deploy / filename)
    for filename in ("docker-compose.yml", "docker-compose.vps-demo.yml"):
        (project / filename).write_text("services: {}\n", encoding="utf-8")
    (deploy / ".env.vps").write_text(
        "SCAP_APP_IMAGE=scap-gate:test\nPUBLIC_DOMAIN=gate.invalid\nSCAP_EDGE_MODE=direct\n",
        encoding="utf-8",
    )
    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    wrappers = {
        "docker": r'''
printf '%s\n' "$*" >> "$SCAP_GATE_DOCKER_LOG"
case "$1" in
  image)
    [ "$2" = inspect ] || exit 91
    if [ "${3:-}" = --format ]; then
      case "$4" in
        '{{.Id}}') printf '%s\n' sha256:expected ;;
        '{{.Architecture}}') printf '%s\n' amd64 ;;
        *) exit 92 ;;
      esac
    fi
    ;;
  compose)
    shift
    while [ "$#" -gt 0 ]; do
      case "$1" in --env-file|-p|-f) shift 2 ;; *) break ;; esac
    done
    case "$1" in
      config|up|logs) exit 0 ;;
      ps)
        if [ "${2:-}" = --all ] && [ "${3:-}" = --quiet ]; then
          [ "${SCAP_GATE_MISSING:-}" != "$4" ] || exit 0
          printf '%s\n' "$4-container"
          if [ "$4" = app ] && [ "${SCAP_GATE_REPLICAS:-1}" = 2 ]; then
            printf '%s\n' app-second-container
          fi
        else
          printf '%s\n' 'Mock compose status'
        fi
        ;;
      *) exit 93 ;;
    esac
    ;;
  inspect)
    [ "$2" = --format ] || exit 94
    if [[ "$3" == *'.State.Health'* ]]; then
      if [ "$4" = app-second-container ]; then
        printf '%s\n' "${SCAP_GATE_SECOND_HEALTH:-healthy}"
      else
        printf '%s\n' "${SCAP_GATE_HEALTH:-healthy}"
      fi
    else
      image=sha256:expected
      case "$4" in
        migrate-container)
          [ "${SCAP_GATE_STALE:-}" != migrate ] || image=sha256:old
          printf '%s %s %s\n' "$image" "${SCAP_GATE_MIGRATE_STATE:-exited}" "${SCAP_GATE_MIGRATE_EXIT:-0}"
          ;;
        app-container|app-second-container)
          [ "${SCAP_GATE_STALE:-}" != "$4" ] || image=sha256:old
          printf '%s %s 0\n' "$image" "${SCAP_GATE_APP_STATE:-running}"
          ;;
        *) exit 95 ;;
      esac
    fi
    ;;
  *) exit 96 ;;
esac
''',
        "curl": r'''
printf '%s\n' "$*" >> "$SCAP_GATE_CURL_LOG"
exit "${SCAP_GATE_TLS_EXIT:-0}"
''',
        "python3": r'''
printf '%s\n' "$*" >> "$SCAP_GATE_PYTHON_LOG"
exit 0
''',
        "sleep": "exit 0\n",
        "uname": "printf '%s\\n' x86_64\n",
        "crontab": r'''
printf '%s\n' "$*" >> "$SCAP_GATE_CRON_LOG"
case "$1" in
  -l) printf '%s\n' '17 2 * * * echo preserved' ;;
  -) cat > "$SCAP_GATE_CRON_CONTENT" ;;
  *) exit 97 ;;
esac
''',
    }
    for name, content in wrappers.items():
        wrapper = mock_bin / name
        wrapper.write_text("#!/bin/bash\nset -eu\n" + content, encoding="utf-8", newline="\n")
        wrapper.chmod(0o700)

    def run(**scenario):
        environment = os.environ.copy()
        # Clear inherited test knobs; all observable writes stay in this fixture.
        for name in list(environment):
            if name.startswith("SCAP_GATE_"):
                environment.pop(name)
        environment["PATH"] = os.pathsep.join((str(bash.parent), environment["PATH"]))
        for name in ("DOCKER_LOG", "CURL_LOG", "PYTHON_LOG", "CRON_LOG", "CRON_CONTENT"):
            environment[f"SCAP_GATE_{name}"] = _bash_path(tmp_path / name.lower())
        environment.update({f"SCAP_GATE_{name}": str(value) for name, value in scenario.items()})
        result = subprocess.run(
            [
                str(bash), "--noprofile", "--norc", "-c",
                # Git Bash's launcher prepends its bundled curl/sleep to PATH.
                # Set precedence after startup and fail before the script unless
                # every sensitive command resolves to this fixture's wrapper.
                'export PATH="$1:$PATH"; '
                'for tool in docker curl python3 sleep crontab uname; do '
                '[ "$(command -v "$tool")" = "$1/$tool" ] || exit 98; '
                'done; source "$2"',
                _bash_path(deploy / "remote-deploy.sh"),
                _bash_path(mock_bin),
                _bash_path(deploy / "remote-deploy.sh"),
            ],
            cwd=project,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        logs = {
            name: (tmp_path / name).read_text(encoding="utf-8")
            if (tmp_path / name).exists() else ""
            for name in ("docker_log", "curl_log", "python_log", "cron_log", "cron_content")
        }
        return result, logs

    return run


def test_deploy_accepts_matching_images_completed_migration_and_both_health_checks(deployment):
    result, logs = deployment(REPLICAS=2)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[OK] App/migration dung image" in result.stdout
    assert "-m scripts.prepare_vps check --project ." in logs["python_log"]
    for container in ("migrate-container", "app-container", "app-second-container"):
        assert f"{{{{.Image}}}} {{{{.State.Status}}}} {{{{.State.ExitCode}}}} {container}" in logs["docker_log"]
    assert logs["docker_log"].count("{{if .State.Health}}") == 2
    assert logs["curl_log"].splitlines() == [
        "-fsS -o /dev/null --max-time 5 https://gate.invalid/api/health"
    ]
    # Both sides of the cron pipeline start independently.
    assert sorted(logs["cron_log"].splitlines()) == ["-", "-l"]
    assert "17 2 * * * echo preserved" in logs["cron_content"]
    assert "0 3 * * * bash " in logs["cron_content"]
    assert "/deploy/backup.sh >> " in logs["cron_content"]
    assert "image rm" not in logs["docker_log"]


@pytest.mark.parametrize("health", ["unhealthy", "starting", "missing", "unknown"])
def test_deploy_rejects_internal_health_failure_without_scheduling_backup(deployment, health):
    result, logs = deployment(HEALTH=health)
    assert result.returncode != 0
    assert "Deploy chua san sang" in result.stderr
    assert "[OK]" not in result.stdout
    assert logs["docker_log"].count("{{if .State.Health}}") == 30
    assert not logs["curl_log"]
    assert not logs["cron_log"]


def test_deploy_requires_every_app_replica_to_be_healthy(deployment):
    result, logs = deployment(REPLICAS=2, SECOND_HEALTH="unhealthy")
    assert result.returncode != 0
    assert "Deploy chua san sang" in result.stderr
    assert logs["docker_log"].count("{{if .State.Health}}") == 60
    assert not logs["curl_log"]
    assert not logs["cron_log"]


def test_deploy_rejects_tls_failure_without_weakening_certificate_verification(deployment):
    result, logs = deployment(TLS_EXIT=60)
    assert result.returncode != 0
    assert "Deploy chua san sang" in result.stderr
    assert len(logs["curl_log"].splitlines()) == 30
    assert all(line == "-fsS -o /dev/null --max-time 5 https://gate.invalid/api/health"
               for line in logs["curl_log"].splitlines())
    assert not logs["cron_log"]


@pytest.mark.parametrize("scenario, message", [
    ({"STALE": "migrate"}, "Container migrate khong dung image vua deploy"),
    ({"STALE": "app-container"}, "Container app khong dung image vua deploy"),
    ({"REPLICAS": 2, "STALE": "app-second-container"}, "Container app khong dung image vua deploy"),
    ({"MIGRATE_EXIT": 1}, "Migration that bai (ma loi 1)"),
    ({"MIGRATE_STATE": "running"}, "Container migrate co trang thai running, can exited"),
    ({"APP_STATE": "exited"}, "Container app co trang thai exited, can running"),
    ({"MISSING": "migrate"}, "Khong tim thay container migrate sau deploy"),
    ({"MISSING": "app"}, "Khong tim thay container app sau deploy"),
])
def test_deploy_rejects_stale_failed_or_missing_services_before_health_checks(
    deployment, scenario, message
):
    result, logs = deployment(**scenario)
    assert result.returncode != 0
    assert message in result.stderr
    assert "[OK]" not in result.stdout
    assert "{{if .State.Health}}" not in logs["docker_log"]
    assert not logs["curl_log"]
    assert not logs["cron_log"]
