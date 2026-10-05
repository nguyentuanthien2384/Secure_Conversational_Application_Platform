"""Secret files stay finite, handle-bound and safe across credential rotation."""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from src.app import secret_files
from src.app.audit_checkpoint import AuditCheckpointError, AuditCheckpointService
from src.app.config import _read_secret_file
from src.app.key_management import KeyProviderError, VaultTransitKeyProvider


def test_reader_keeps_raw_whitespace_and_supports_service_owned_regular_mounts(tmp_path):
    source = tmp_path / "mounted-token"
    source.write_bytes("  synthetic-token-é \r\n".encode())
    # The read policy intentionally does not demand process ownership/private
    # mode, unlike the private-write policy. Mounted service files may differ.
    if os.name != "nt":
        source.chmod(0o444)
    assert secret_files.read_secret_text(source) == "  synthetic-token-é \r\n"


def test_exact_byte_budget_succeeds_and_multibyte_overflow_is_rejected(tmp_path):
    source = tmp_path / "unicode-token"
    source.write_text("é" * 8, encoding="utf-8")
    assert secret_files.read_secret_text(source, max_bytes=16) == "é" * 8
    source.write_text("é" * 9, encoding="utf-8")
    with pytest.raises(secret_files.SecretFileTooLarge):
        secret_files.read_secret_text(source, max_bytes=16)


@pytest.mark.parametrize("budget", [0, -1, 16_385, True, 1.5, "4096"])
def test_reader_rejects_unbounded_or_invalid_byte_budgets(tmp_path, budget):
    with pytest.raises(ValueError):
        secret_files.read_secret_text(tmp_path / "unused", max_bytes=budget)


def test_file_growth_after_size_check_still_reads_only_cap_plus_one(tmp_path, monkeypatch):
    source = tmp_path / "growing-token"
    source.write_bytes(b"small")
    requests = []

    class GrowingReader:
        def __init__(self, stream):
            self.stream = stream

        def fileno(self):
            return self.stream.fileno()

        def read(self, size):
            requests.append(size)
            # Simulate a concurrently replaced writer growing the same file
            # after fstat; one unbounded read would now allocate all of it.
            with source.open("ab") as writer:
                writer.write(b"x" * 100_000)
            return self.stream.read(size)

    @contextmanager
    def opened(_path):
        with source.open("rb") as stream:
            yield GrowingReader(stream)

    monkeypatch.setattr(secret_files, "read_regular_file", opened)
    with pytest.raises(secret_files.SecretFileTooLarge):
        secret_files.read_secret_text(source, max_bytes=16)
    assert requests == [17]


@pytest.mark.parametrize("kind", ["missing", "directory", "invalid_utf8"])
def test_bad_inputs_have_fixed_errors_without_path_or_contents(tmp_path, kind):
    source = tmp_path / "private-operator-name"
    if kind == "directory":
        source.mkdir()
    elif kind == "invalid_utf8":
        source.write_bytes(b"synthetic-sensitive-token\xff")
    with pytest.raises(secret_files.SecretFileError) as caught:
        secret_files.read_secret_text(source)
    assert str(source) not in str(caught.value)
    assert "synthetic-sensitive-token" not in str(caught.value)


def test_hardlink_secret_is_rejected_without_mutating_either_entry(tmp_path):
    source = tmp_path / "original-token"
    source.write_bytes(b"synthetic-hardlinked-token")
    alias = tmp_path / "alias-token"
    os.link(source, alias)
    with pytest.raises(secret_files.SecretFileError):
        secret_files.read_secret_text(alias)
    assert source.read_bytes() == alias.read_bytes() == b"synthetic-hardlinked-token"


@pytest.mark.parametrize("linked_parent", [False, True])
def test_symlink_or_linked_parent_secret_is_rejected(tmp_path, linked_parent):
    directory = tmp_path / "target"
    directory.mkdir()
    source = directory / "token"
    source.write_bytes(b"synthetic-linked-token")
    alias = tmp_path / "linked"
    try:
        alias.symlink_to(directory if linked_parent else source, target_is_directory=linked_parent)
    except OSError:
        pytest.skip("This Windows account cannot create symbolic links.")
    path = alias / "token" if linked_parent else alias
    with pytest.raises(secret_files.SecretFileError):
        secret_files.read_secret_text(path)
    assert source.read_bytes() == b"synthetic-linked-token"


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO/device open policy.")
def test_fifo_and_device_are_rejected_without_waiting_for_a_writer(tmp_path):
    fifo = tmp_path / "token-fifo"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(secret_files.SecretFileError):
        secret_files.read_secret_text(fifo)
    with pytest.raises(secret_files.SecretFileError):
        secret_files.read_secret_text(Path("/dev/null"))
    assert time.monotonic() - started < 1


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace/device/reparse policy.")
@pytest.mark.parametrize("name", ["NUL", "CON", "COM1.txt", "token:stream", "token."])
def test_windows_device_or_ambiguous_paths_are_rejected_before_content_read(tmp_path, name):
    with pytest.raises(secret_files.SecretFileError):
        secret_files.read_secret_text(tmp_path / name)


def test_config_preserves_single_newline_and_existing_error_messages(tmp_path, monkeypatch):
    source = tmp_path / "config-token"
    monkeypatch.setenv("SCAP_SYNTHETIC_SECRET_FILE", str(source))
    source.write_bytes(b"synthetic-value\r\n")
    assert _read_secret_file("SCAP_SYNTHETIC_SECRET_FILE") == "synthetic-value"
    source.write_bytes(b"first\nsecond")
    with pytest.raises(RuntimeError, match="một dòng"):
        _read_secret_file("SCAP_SYNTHETIC_SECRET_FILE")
    source.write_bytes(b"x" * 16_385)
    with pytest.raises(RuntimeError, match="16 KiB"):
        _read_secret_file("SCAP_SYNTHETIC_SECRET_FILE")
    source.write_bytes(b"invalid\xff")
    with pytest.raises(RuntimeError, match="Không thể đọc secret file"):
        _read_secret_file("SCAP_SYNTHETIC_SECRET_FILE")


def _provider(kind: str, source: Path):
    if kind == "vault":
        return VaultTransitKeyProvider(
            address="https://vault.example.invalid", token_file=str(source), key_name="test-key",
        )
    return AuditCheckpointService(
        "synthetic-checkpoint-signing-key", endpoint="https://worm.example.invalid",
        token_file=str(source),
    )


@pytest.mark.parametrize("kind", ["vault", "worm"])
def test_workload_tokens_reread_atomic_replacements_and_keep_strip_normalization(tmp_path, kind):
    source = tmp_path / f"{kind}-token"
    source.write_bytes(b"  synthetic-first-token\r\n")
    provider = _provider(kind, source)
    assert provider._token() == "synthetic-first-token"
    replacement = tmp_path / "rotated-token"
    replacement.write_bytes(b" synthetic-rotated-token\n")
    os.replace(replacement, source)
    assert provider._token() == "synthetic-rotated-token"


@pytest.mark.parametrize("kind", ["vault", "worm"])
@pytest.mark.parametrize("payload", [b"x" * 4097, "é".encode() * 2049, b"line\nother", b"embedded\x00token", b"invalid\xff"])
def test_workload_token_validation_fails_closed_without_echoing_contents(tmp_path, kind, payload):
    source = tmp_path / f"{kind}-private-name"
    source.write_bytes(payload)
    error = KeyProviderError if kind == "vault" else AuditCheckpointError
    with pytest.raises(error) as caught:
        _provider(kind, source)
    assert str(source) not in str(caught.value)
    assert repr(payload[:20]) not in str(caught.value)


@pytest.mark.parametrize("payload", [b"x" * 4097, b"x" * 31, b"x" * 32 + b"\nother", b"x" * 32 + b"\x00", b"invalid\xff"])
def test_oidc_secret_rejects_invalid_bounded_inputs_before_proxy_access(settings, tmp_path, monkeypatch, payload):
    from src.app import main

    source = tmp_path / "oidc-token"
    source.write_bytes(payload)
    created_databases = []
    original_database = main.Database

    def database(*args, **kwargs):
        result = original_database(*args, **kwargs)
        created_databases.append(result)
        return result

    monkeypatch.setattr(main, "Database", database)
    # Validation must happen before mounting any proxy-authorized UI. Avoid
    # allocating a UI that cannot be mounted with the invalid credential.
    monkeypatch.setattr(main, "build_ui", lambda **_kwargs: object())
    configured = replace(settings, gradio_auth_mode="oidc", oidc_proxy_secret_file=str(source))
    try:
        with pytest.raises(RuntimeError) as caught:
            main.create_app(configured)
        assert str(source) not in str(caught.value)
        assert payload.decode("utf-8", errors="replace") not in str(caught.value)
    finally:
        for created in created_databases:
            created.engine.dispose()
