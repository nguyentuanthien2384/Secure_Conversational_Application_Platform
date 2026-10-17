"""MLS command boundaries which do not require a native crypto runtime."""
from types import SimpleNamespace

import pytest

from clients.e2ee_client import ClientError, ClientPersistenceError
from clients.mls_chat import interact
from clients.mls_client import NativeMls


def test_mls_cli_prints_earlier_plaintext_before_mandatory_exit_on_save_failure(monkeypatch, capsys):
    client = SimpleNamespace(requires_restart=True)
    group = SimpleNamespace(client=client, last_receive_error="stopped", receive=lambda *a, **kw: [
        {"sender_device": "verified-device", "text": "Already saved message\x1b[2J"}])
    monkeypatch.setattr("builtins.input", lambda prompt: "receive 123e4567-e89b-12d3-a456-426614174000")
    with pytest.raises(ClientPersistenceError):
        interact(group)
    shown = capsys.readouterr().out
    assert "Already saved message" in shown
    assert "\x1b" not in shown and "\\u001b[2J" in shown


def test_native_helper_command_disables_network_logs_mounts_and_image_pulls():
    command = NativeMls().command
    for flag, value in (("--network", "none"), ("--log-driver", "none"),
                        ("--pull", "never"), ("--cap-drop", "ALL")):
        assert command[command.index(flag) + 1] == value
    assert "--read-only" in command
    assert not set(command) & {"--volume", "-v", "--mount", "--privileged", "--env", "-e"}


@pytest.mark.parametrize("endpoint", ["ssh://recruiter-vps", "tcp://192.0.2.10:2376"])
def test_remote_docker_context_is_rejected_before_private_state_enters_subprocess(monkeypatch, endpoint):
    calls = []

    def inspect_only(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=endpoint.encode())

    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setattr("clients.mls_client.subprocess.run", inspect_only)
    with pytest.raises(ClientError, match="local Docker socket"):
        NativeMls().call(op="send", state={"private": "must-not-leave-client"})
    assert len(calls) == 1 and "input" not in calls[0][1]
