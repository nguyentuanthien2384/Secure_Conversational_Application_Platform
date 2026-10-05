"""Real temporary filesystem checks for owner-only storage and failure cleanup."""

from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from src.app import private_storage as storage
from src.app.private_storage import (
    PrivateStorageError,
    check_private_directory,
    check_private_file,
    create_private_directory,
    create_private_file,
    prepare_private_directory,
    read_regular_file,
)


def test_directory_is_private_before_first_file(tmp_path):
    directory = create_private_directory(tmp_path / "private")
    check_private_directory(directory)
    assert not list(directory.iterdir())
    with create_private_file(directory / "secret") as output:
        output.write(b"synthetic-secret")
    check_private_file(directory / "secret")
    assert (directory / "secret").read_bytes() == b"synthetic-secret"


def test_prepare_creates_missing_private_ancestors(tmp_path):
    directory = prepare_private_directory(tmp_path / "one" / "two" / "three")
    for part in (directory, directory.parent, directory.parent.parent):
        check_private_directory(part)
    assert prepare_private_directory(directory) == directory


def test_prepare_without_parents_checks_existing_private_directory(tmp_path):
    directory = prepare_private_directory(tmp_path / "private", parents=False)
    assert prepare_private_directory(directory, parents=False) == directory


def test_directory_creation_is_new_only(tmp_path):
    directory = create_private_directory(tmp_path / "private")
    marker = directory / "marker"
    with create_private_file(marker) as output:
        output.write(b"keep")
    with pytest.raises(FileExistsError):
        create_private_directory(directory)
    assert marker.read_bytes() == b"keep"


def test_file_creation_is_new_only(tmp_path):
    destination = tmp_path / "existing"
    destination.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        create_private_file(destination)
    assert destination.read_bytes() == b"keep"


@pytest.mark.parametrize("function", [create_private_directory, create_private_file])
def test_new_objects_require_existing_parent(tmp_path, function):
    with pytest.raises(FileNotFoundError):
        function(tmp_path / "missing" / "object")
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("function", [create_private_directory, create_private_file,
                                      prepare_private_directory, check_private_directory,
                                      check_private_file, read_regular_file])
def test_rejects_parent_traversal(tmp_path, function):
    with pytest.raises(PrivateStorageError):
        function(tmp_path / "child" / ".." / "unexpected")
    assert not (tmp_path / "unexpected").exists()


@pytest.mark.parametrize("function", [create_private_directory, create_private_file,
                                      prepare_private_directory, read_regular_file])
def test_rejects_nul_path_before_creation(tmp_path, function):
    with pytest.raises(PrivateStorageError):
        function(str(tmp_path / "unexpected") + "\x00suffix")
    assert not (tmp_path / "unexpected").exists()


def test_rejects_file_hardlinks(tmp_path):
    original = tmp_path / "original"
    linked = tmp_path / "linked"
    with create_private_file(original) as output:
        output.write(b"secret")
    os.link(original, linked)
    for candidate in (original, linked):
        with pytest.raises(PrivateStorageError):
            check_private_file(candidate)
        with pytest.raises(PrivateStorageError):
            read_regular_file(candidate)
    assert original.read_bytes() == b"secret"


def test_reader_uses_opened_version_when_file_rotates(tmp_path):
    destination = tmp_path / "credential"
    destination.write_bytes(b"old-version")
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"new-version")
    with read_regular_file(destination) as source:
        if os.name == "nt":
            # MoveFileEx cannot replace a destination while it is open, even
            # with delete sharing. Rotation completes between bounded reads.
            with pytest.raises(PermissionError):
                os.replace(replacement, destination)
        else:
            os.replace(replacement, destination)
        assert source.read() == b"old-version"
    if os.name == "nt":
        os.replace(replacement, destination)
    with read_regular_file(destination) as source:
        assert source.read() == b"new-version"


def test_reader_does_not_require_private_owner_permissions(tmp_path):
    destination = tmp_path / "credential"
    destination.write_bytes(b"service-managed")
    if os.name != "nt":
        destination.chmod(0o644)
    with read_regular_file(destination) as source:
        assert source.read() == b"service-managed"


def test_reader_rejects_directory(tmp_path):
    with pytest.raises((PrivateStorageError, PermissionError, IsADirectoryError)):
        read_regular_file(tmp_path)


def _symlink(target: Path, link: Path, *, directory: bool):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip("The Windows account cannot create symbolic links.")


def test_rejects_linked_ancestor_without_writing_target(tmp_path):
    actual = create_private_directory(tmp_path / "actual")
    alias = tmp_path / "alias"
    _symlink(actual, alias, directory=True)
    for function in (create_private_file, create_private_directory, prepare_private_directory):
        with pytest.raises(OSError):
            function(alias / "unexpected")
    assert not (actual / "unexpected").exists()


def test_rejects_linked_file_without_reading_target(tmp_path):
    actual = tmp_path / "actual"
    with create_private_file(actual) as output:
        output.write(b"private")
    alias = tmp_path / "alias"
    _symlink(actual, alias, directory=False)
    for function in (read_regular_file, check_private_file):
        with pytest.raises(OSError):
            function(alias)
    assert actual.read_bytes() == b"private"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions are distinct from Windows ACLs.")
def test_posix_objects_have_exact_owner_modes(tmp_path):
    directory = create_private_directory(tmp_path / "private")
    with create_private_file(directory / "secret"):
        pass
    assert directory.stat().st_mode & 0o777 == 0o700
    assert (directory / "secret").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions are distinct from Windows ACLs.")
def test_existing_broad_modes_are_rejected_without_repair(tmp_path):
    directory = tmp_path / "broad"
    directory.mkdir()
    directory.chmod(0o755)
    with pytest.raises(PrivateStorageError):
        prepare_private_directory(directory)
    assert directory.stat().st_mode & 0o777 == 0o755
    destination = directory / "secret"
    destination.write_bytes(b"keep")
    destination.chmod(0o644)
    with pytest.raises(PrivateStorageError):
        check_private_file(destination)
    assert destination.stat().st_mode & 0o777 == 0o644
    assert destination.read_bytes() == b"keep"


@pytest.mark.skipif(os.name == "nt", reason="FIFO behavior is a POSIX check.")
def test_reader_rejects_fifo_without_waiting_for_writer(tmp_path):
    destination = tmp_path / "pipe"
    os.mkfifo(destination, 0o600)
    with pytest.raises(PrivateStorageError):
        read_regular_file(destination)


@pytest.mark.skipif(os.name != "nt", reason="Inspect real Windows descriptors.")
def test_windows_actual_owner_and_protected_dacl(tmp_path):
    api = storage._windows()
    directory = create_private_directory(tmp_path / "private")
    destination = directory / "secret"
    with create_private_file(destination):
        pass
    for path, is_directory in ((directory, True), (destination, False)):
        handle = api.kernel.CreateFileW(str(path), api.READ_CONTROL, 3, None, 3,
                                        0x02200000, None)
        assert handle != api.invalid_handle
        try:
            owner, control, entries = api.acl_entries(handle)
            assert owner == api.current_sid()
            assert control & 0x1000  # SE_DACL_PROTECTED, inheritance disabled.
            assert {entry[3] for entry in entries} == {owner, "S-1-5-18"}
            assert all(entry[:3] == (0, 3 if is_directory else 0, 0x1F01FF)
                       for entry in entries)
        finally:
            api.kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name != "nt", reason="Windows paths include alternate data streams/devices.")
@pytest.mark.parametrize("suffix", ["secret:stream", "secret.", "secret ", "CON",
                                   "NUL.txt", "COM1.log", "LPT9", "COM¹.txt"])
def test_windows_rejects_ambiguous_names(tmp_path, suffix):
    with pytest.raises(PrivateStorageError):
        create_private_file(tmp_path / suffix)
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Windows network/device namespaces differ.")
@pytest.mark.parametrize("path", [r"\\server\share\secret", r"\\?\C:\secret",
                                 r"\\.\PIPE\secret"])
def test_windows_rejects_remote_and_device_namespaces(path):
    with pytest.raises(PrivateStorageError):
        create_private_file(path)


@pytest.mark.skipif(os.name != "nt", reason="Windows failure paths close/delete native objects.")
@pytest.mark.parametrize("kind", ["file", "directory"])
def test_windows_validation_failure_deletes_new_empty_object(tmp_path, monkeypatch, kind):
    api = storage._windows()

    def rejected(*_arguments, **_keywords):
        raise PrivateStorageError("Injected validation failure.")

    monkeypatch.setattr(api, "private", rejected)
    path = tmp_path / "new-object"
    with pytest.raises(PrivateStorageError):
        (create_private_file if kind == "file" else create_private_directory)(path)
    assert not path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows CRT transfers ownership of the native handle.")
def test_windows_descriptor_transfer_failure_closes_and_removes_file(tmp_path, monkeypatch):
    import msvcrt

    def rejected(*_arguments):
        raise OSError("Injected descriptor transfer failure.")

    monkeypatch.setattr(msvcrt, "open_osfhandle", rejected)
    with pytest.raises(OSError):
        create_private_file(tmp_path / "new-object")
    assert not (tmp_path / "new-object").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows existing ACLs must never be silently rewritten.")
def test_windows_existing_inherited_directory_is_rejected(tmp_path):
    directory = tmp_path / "legacy"
    directory.mkdir()
    with pytest.raises(PrivateStorageError):
        prepare_private_directory(directory)
    assert directory.exists()


@pytest.mark.skipif(os.name != "nt", reason="Build an intentionally weak Windows DACL only on test data.")
def test_windows_weak_creation_descriptor_fails_closed(tmp_path, monkeypatch):
    api = storage._windows()

    @contextmanager
    def weak_attributes(*, directory):
        sid = api.current_sid()
        descriptor = api.wt.LPVOID()
        flags = "OICI" if directory else ""
        # Two grants but Everyone replaces SYSTEM, so count alone cannot pass.
        api._require(api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{sid}D:P(A;{flags};FA;;;{sid})(A;{flags};FA;;;WD)",
            1, ctypes.byref(descriptor), None))
        attributes = api.SecurityAttributes(ctypes.sizeof(api.SecurityAttributes), descriptor, False)
        try:
            yield ctypes.byref(attributes)
        finally:
            api.kernel.LocalFree(descriptor)

    monkeypatch.setattr(api, "attributes", weak_attributes)
    with pytest.raises(PrivateStorageError):
        create_private_file(tmp_path / "new-object")
    assert not (tmp_path / "new-object").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows ancestor handles must prevent rename substitution.")
def test_windows_ancestor_is_pinned_during_creation(tmp_path, monkeypatch):
    directory = create_private_directory(tmp_path / "parent")
    api = storage._windows()
    original = api.attributes
    attempts = []

    @contextmanager
    def try_rename(*, directory):
        with pytest.raises(PermissionError):
            os.rename(tmp_path / "parent", tmp_path / "replaced")
        attempts.append(True)
        with original(directory=directory) as attributes:
            yield attributes

    monkeypatch.setattr(api, "attributes", try_rename)
    with create_private_file(directory / "secret") as output:
        output.write(b"private")
    assert attempts == [True]
    assert (directory / "secret").read_bytes() == b"private"


@pytest.mark.skipif(os.name != "nt", reason="Mapped Windows network drives must fail closed.")
@pytest.mark.parametrize("drive_type", [0, 1, 4, 5])
def test_windows_rejects_unavailable_remote_or_readonly_drives_before_creation(tmp_path, monkeypatch, drive_type):
    api = storage._windows()
    monkeypatch.setattr(api.kernel, "GetDriveTypeW", lambda _root: drive_type)
    with pytest.raises(PrivateStorageError):
        create_private_file(tmp_path / "not-created")
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(os.name != "nt", reason="Drive-relative Windows paths vary with process state.")
def test_windows_rejects_drive_relative_before_resolution():
    with pytest.raises(PrivateStorageError):
        create_private_file("C:relative-secret")


@pytest.mark.skipif(os.name != "nt", reason="Native handles must close even if deletion fails.")
def test_windows_failed_cleanup_still_closes_new_file_handle(tmp_path, monkeypatch):
    api = storage._windows()

    def failed_validation(*_arguments, **_keywords):
        raise PrivateStorageError("Synthetic validation failure.")

    def failed_delete(_handle):
        raise OSError("Synthetic deletion failure.")

    monkeypatch.setattr(api, "private", failed_validation)
    monkeypatch.setattr(api, "mark_delete", failed_delete)
    destination = tmp_path / "empty-private-file"
    with pytest.raises(OSError):
        create_private_file(destination)
    assert destination.read_bytes() == b""
    # A leaked exclusive native handle would prevent this deletion on Windows.
    destination.unlink()
    assert not destination.exists()
