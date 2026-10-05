"""Provision new local storage without exposing generated keys to a shell.

Existing configurations and databases are never changed or migrated. This
module intentionally does not import application settings or load ``.env``.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from src.app.private_storage import (
    PrivateStorageError,
    check_private_directory,
    create_private_directory,
    create_private_file,
    read_regular_file,
)

_MAX_TEMPLATE_BYTES = 64 * 1024
_REQUIRED_FIELDS = {
    "APP_ENV", "SECURITY_PROFILE", "KEY_PROVIDER", "APP_SECRET_KEY",
    "MASTER_ENCRYPTION_KEY", "DATABASE_URL", "MAIL_BACKEND", "MAIL_OUTBOX_DIR",
    "SEED_DEMO_DATA",
}
_ASSIGNMENT = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)")


class LocalStorageError(RuntimeError):
    """Provisioning needs an operator decision or a valid local template."""


def _metadata(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _ordinary(info) -> bool:
    return not stat.S_ISLNK(info.st_mode) and not (
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _project_path(project: str | Path) -> Path:
    path = Path(project)
    if ".." in path.parts:
        raise LocalStorageError("Use a project path without parent traversal.")
    if os.name == "nt" and path.drive and not path.root:
        raise LocalStorageError("Use an absolute or working-directory-relative project path.")
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        info = _metadata(component)
        if info is None or not _ordinary(info) or not stat.S_ISDIR(info.st_mode):
            raise LocalStorageError("The project must be an existing ordinary directory.")
    return path


def _existing_configuration(path: Path) -> bool:
    info = _metadata(path)
    if info is None:
        return False
    if not _ordinary(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise LocalStorageError("Existing .env must be an ordinary file; it was left unchanged.")
    # Metadata only: existing keys, configuration bytes and permissions stay intact.
    return True


def _read_template(path: Path) -> tuple[list[str], dict[str, str]]:
    before = _metadata(path)
    if before is None or not _ordinary(before) or not stat.S_ISREG(before.st_mode):
        raise LocalStorageError("A regular .env.example template is required.")
    if before.st_nlink != 1:
        raise LocalStorageError("The .env.example template must not be hard-linked.")
    with read_regular_file(path) as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise LocalStorageError("The .env.example template changed while being opened.")
        raw = stream.read(_MAX_TEMPLATE_BYTES + 1)
    if len(raw) > _MAX_TEMPLATE_BYTES:
        raise LocalStorageError("The .env.example template exceeds the size limit.")
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeError as exc:
        raise LocalStorageError("The .env.example template must contain UTF-8 text.") from exc
    if "\x00" in content or any(ord(character) < 32 and character not in "\r\n\t"
                               for character in content):
        raise LocalStorageError("The .env.example template contains invalid characters.")
    lines = content.splitlines()
    values: dict[str, str] = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if match is None or match[1] in values:
            raise LocalStorageError("The .env.example template has invalid or duplicate assignments.")
        values[match[1]] = match[2]
    if not _REQUIRED_FIELDS <= values.keys():
        raise LocalStorageError("The .env.example template is missing required local settings.")
    expected = {"APP_ENV": "development", "SECURITY_PROFILE": "standard",
                "KEY_PROVIDER": "local", "MAIL_BACKEND": "outbox"}
    if any(values[key] != value for key, value in expected.items()):
        raise LocalStorageError("The .env.example template must use the standard local profile.")
    if values["DATABASE_URL"] not in {
        "sqlite:///./secure_chat.db", "sqlite:///./local_data/secure_chat.db",
    }:
        raise LocalStorageError(
            "Custom database storage requires its matching configuration and keys; "
            "fresh local setup cannot replace its DATABASE_URL."
        )
    for key in ("APP_SECRET_KEY_FILE", "MASTER_ENCRYPTION_KEYS", "ACTIVE_KEY_VERSION"):
        if values.get(key, ""):
            raise LocalStorageError("The local template must not select pre-existing secret files or keys.")
    return lines, values


def _assert_no_database(project: Path) -> None:
    for directory in (project, project / "local_data"):
        for suffix in ("", "-wal", "-shm", "-journal"):
            if _metadata(directory / f"secure_chat.db{suffix}") is not None:
                raise LocalStorageError(
                    "An existing database was found without .env. Restore its matching configuration "
                    "and keys before setup; no new configuration or empty database was selected."
                )


def _prepare_directory(path: Path) -> None:
    try:
        create_private_directory(path)
    except FileExistsError:
        check_private_directory(path)


def initialize_local_project(project: str | Path) -> dict[str, str]:
    """Create a fresh private local configuration; never read an existing .env."""
    project_path = _project_path(project)
    configuration = project_path / ".env"
    if _existing_configuration(configuration):
        return {"status": "unchanged"}
    _assert_no_database(project_path)
    lines, _ = _read_template(project_path / ".env.example")
    data_directory = project_path / "local_data"
    _prepare_directory(data_directory)
    _prepare_directory(data_directory / "mail_outbox")
    # Recheck after preparing storage, before generating keys or writing anything.
    _assert_no_database(project_path)
    replacements = {
        "APP_SECRET_KEY": secrets.token_urlsafe(48),
        "MASTER_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        "DATABASE_URL": "sqlite:///./local_data/secure_chat.db",
        "MAIL_OUTBOX_DIR": "local_data/mail_outbox",
        "SEED_DEMO_DATA": "true",
    }
    output = []
    for line in lines:
        match = _ASSIGNMENT.fullmatch(line)
        output.append(f"{match[1]}={replacements[match[1]]}"
                      if match and match[1] in replacements else line)
    payload = ("\n".join(output) + "\n").encode("utf-8")
    created_identity = None
    try:
        with create_private_file(configuration) as stream:
            opened = os.fstat(stream.fileno())
            created_identity = opened.st_dev, opened.st_ino
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if _existing_configuration(configuration):
            return {"status": "unchanged"}
        raise
    except BaseException:
        current = _metadata(configuration)
        if current is not None and created_identity == (current.st_dev, current.st_ino):
            configuration.unlink()
        raise
    return {"status": "initialized", "storage": "local_data"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Prepare a fresh local project; preserve existing .env.")
    init.add_argument("--project", type=Path, default=Path.cwd())
    mkdir = commands.add_parser("mkdir", help="Create a NEW private directory under an existing parent.")
    mkdir.add_argument("--directory", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "mkdir":
            create_private_directory(arguments.directory)
            print("Created a new private directory. Existing directories were not changed.")
        else:
            report = initialize_local_project(arguments.project)
            if report["status"] == "unchanged":
                print("Existing .env preserved unchanged; no keys or data were read or migrated.")
            else:
                print("Created private .env and local_data storage with internally generated keys.")
        return 0
    except LocalStorageError as exc:
        print(f"Local setup failed: {exc}", file=sys.stderr)
    except FileExistsError:
        print("Local setup failed: the destination already exists; it was not changed.", file=sys.stderr)
    except (PrivateStorageError, OSError):
        print(
            "Local setup failed: storage permissions or path are unsafe. Use a NEW private directory "
            "with `python -m scripts.local_storage mkdir --directory PATH`; existing data was not changed.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
