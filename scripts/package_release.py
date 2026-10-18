"""Package public SCAP sources locally, without loading config or contacting a server.

``create`` writes a reproducible archive plus SHA-256 sidecar. After extracting
it, ``verify`` checks its file manifest before the operator adds private config.
This is a source release: Docker still builds the application at its destination.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

from src.app.private_storage import create_private_file, read_regular_file

ARCHIVE_ROOT = "scap-source"
MANIFEST = "RELEASE-MANIFEST.json"
_ROOT_FILES = frozenset({
    ".dockerignore", ".env.example", ".gitattributes", ".gitignore", ".python-version",
    ".semgrep.yml", ".trivyignore", "Caddyfile", "Caddyfile.shared-proxy", "Dockerfile",
    "Makefile", "pyproject.toml", "uv.lock", "README.md", "SECURITY.md", "SECURITY_REVIEW.md",
    "HUONG_DAN_CHAY.md", "HUONG_DAN_DOCKER.md", "run_app.py", "setup.ps1", "setup.sh",
    "docker-compose.yml", "docker-compose.local.yml", "docker-compose.high-security.yml",
    "docker-compose.repair.yml", "docker-compose.vps-demo.yml", "docker-compose.shared-proxy.yml",
    "docker-compose.security-channels.yml",
})
_SOURCE_DIRS = frozenset({"src", "scripts", "clients", "docs", "tests", ".github", "deploy"})
_SKIP_DIRS = frozenset({
    "__pycache__", "target", "node_modules", "out", "build", "dist", "secrets", "certs",
    "local_data", "client_data", "mail_outbox", "backups", "reports", "security-files",
})
_SUFFIXES = frozenset({
    ".py", ".js", ".cjs", ".css", ".html", ".md", ".yml", ".yaml", ".toml", ".lock",
    ".ps1", ".sh", ".sql", ".caddy", ".jpg", ".png", ".svg", ".rs",
})
_EXTRA_FILES = frozenset({
    "deploy/vps.env.example", "clients/mls_native/.dockerignore", "clients/mls_native/Dockerfile",
    "tests/fixtures/maxmind/source.json", "tests/fixtures/maxmind/GeoIP2-City-Test.mmdb",
    "tests/fixtures/maxmind/LICENSE-APACHE", "tests/fixtures/maxmind/LICENSE-MIT",
    "clients/mls_native/vendor/hpke-rs-libcrux/Cargo.toml.orig",
    "clients/mls_native/vendor/hpke-rs-libcrux/provenance.json",
    "clients/mls_native/vendor/hpke-rs-libcrux/.cargo_vcs_info.json",
})
_REQUIRED = frozenset({
    "Dockerfile", ".dockerignore", "pyproject.toml", "uv.lock", "README.md", "run_app.py",
    "docker-compose.yml", "docker-compose.vps-demo.yml", "docker-compose.security-channels.yml",
    "src/app/main.py", "scripts/migrate_database.py", "scripts/package_release.py",
    "scripts/prepare_vps.py", "deploy/vps-compose.sh", "deploy/remote-deploy.sh",
    "deploy/vps.env.example",
    "Caddyfile", "Caddyfile.shared-proxy", "docker-compose.shared-proxy.yml",
    "deploy/backup.sh", "deploy/restore.sh", "deploy/shared-proxy-site.caddy",
    "scripts/init_db_roles.sh", "scripts/db_least_privilege.sql",
})
_MAX_FILE = 10 * 1024 * 1024
_MAX_TOTAL = 64 * 1024 * 1024
_MAX_FILES = 5000


class ReleaseError(RuntimeError):
    """A source release cannot be built or checked safely."""


def _ordinary_directory(path: Path) -> None:
    information = path.lstat()
    if (not stat.S_ISDIR(information.st_mode)
            or getattr(information, "st_file_attributes", 0) & 0x400):
        raise ReleaseError("Source/output directories must be ordinary, unlinked directories.")


def _allowed(name: str) -> bool:
    """A narrow source allowlist, independent of Git and operator .gitignore rules."""
    path = PurePosixPath(name)
    if (str(path) != name or path.is_absolute() or "\\" in name or ":" in name
            or any(part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                   for part in path.parts)):
        return False
    if len(path.parts) == 1:
        return name in _ROOT_FILES
    if path.parts[0] not in _SOURCE_DIRS:
        return False
    if any(part.lower() in _SKIP_DIRS or (part.startswith(".") and part != ".github")
           for part in path.parts[:-1]):
        return False
    if name in _EXTRA_FILES or re.fullmatch(r"(?:LICENSE|NOTICE)(?:-[A-Za-z0-9.-]+)?", path.name):
        return True
    if path.name.startswith(".") or path.name.lower().endswith((".env", ".env.vps")):
        return False
    return path.suffix.lower() in _SUFFIXES


def _source_names(project: Path) -> list[str]:
    _ordinary_directory(project)
    names = [name for name in _ROOT_FILES if (project / name).exists()]
    for folder in sorted(_SOURCE_DIRS):
        directory = project / folder
        if not directory.exists():
            continue
        _ordinary_directory(directory)
        for parent, directories, files in os.walk(directory, followlinks=False):
            directories[:] = sorted(
                name for name in directories
                if name.lower() not in _SKIP_DIRS and not name.startswith(".")
            )
            for name in directories:
                _ordinary_directory(Path(parent) / name)
            names.extend(
                relative for name in sorted(files)
                if _allowed(relative := (Path(parent) / name).relative_to(project).as_posix())
            )
    if len(names) > _MAX_FILES or not _REQUIRED.issubset(names):
        raise ReleaseError("Source release is incomplete or exceeds the file limit.")
    return sorted(names)


def _read(path: Path, limit: int = _MAX_FILE) -> bytes:
    with read_regular_file(path) as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ReleaseError("Source release exceeds the size limit.")
    return payload


def _mode(name: str) -> int:
    return 0o755 if name.endswith(".sh") else 0o644


def _add(archive: tarfile.TarFile, name: str, payload: bytes, mode: int) -> None:
    metadata = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{name}")
    metadata.size = len(payload)
    metadata.mode = mode
    metadata.mtime = 0
    metadata.uid = metadata.gid = 0
    metadata.uname = metadata.gname = ""
    archive.addfile(metadata, io.BytesIO(payload))


def create_release(project: Path, output: Path) -> dict:
    """Read only public source candidates; never inspect private runtime paths."""
    project = Path(os.path.abspath(project))
    output = Path(os.path.abspath(output))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.tar\.gz", output.name):
        raise ReleaseError("Use an ordinary .tar.gz output filename.")
    checksum = output.with_name(output.name + ".sha256")
    if output.exists() or checksum.exists():
        raise ReleaseError("Release output already exists; choose a new filename.")
    contents, records, total = [], [], 0
    for name in _source_names(project):
        payload = _read(project / name)
        total += len(payload)
        if total > _MAX_TOTAL:
            raise ReleaseError("Source release exceeds the total size limit.")
        contents.append((name, payload))
        records.append({"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                        "mode": _mode(name)})
    manifest = json.dumps({"schema_version": 1, "archive_root": ARCHIVE_ROOT, "files": records},
                          sort_keys=True, indent=2).encode("utf-8") + b"\n"
    # Output contains public sources, so an existing output directory need not
    # have private ACLs. Exclusive private files still prevent accidental reuse.
    output.parent.mkdir(parents=True, exist_ok=True)
    _ordinary_directory(output.parent)
    created = []
    try:
        with create_private_file(output) as stream:
            created.append(output)
            with gzip.GzipFile(fileobj=stream, filename="", mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                    for name, payload in contents:
                        _add(archive, name, payload, _mode(name))
                    _add(archive, MANIFEST, manifest, 0o644)
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256(_read(output, _MAX_TOTAL)).hexdigest()
        with create_private_file(checksum) as stream:
            created.append(checksum)
            stream.write(f"{digest}  {output.name}\n".encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return {"archive": str(output), "sha256": digest, "files": len(records)}


def verify_release(project: Path) -> dict:
    """Verify bounded, allowlisted paths from the extracted release manifest."""
    project = Path(os.path.abspath(project))
    _ordinary_directory(project)
    try:
        manifest = json.loads(_read(project / MANIFEST, 2 * 1024 * 1024))
    except (ValueError, UnicodeError) as exc:
        raise ReleaseError("Release manifest is malformed.") from exc
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
            or manifest.get("archive_root") != ARCHIVE_ROOT
            or not isinstance(manifest.get("files"), list)
            or not 1 <= len(manifest["files"]) <= _MAX_FILES):
        raise ReleaseError("Release manifest is malformed.")
    names, total = set(), 0
    for entry in manifest["files"]:
        if (not isinstance(entry, dict) or not isinstance(name := entry.get("path"), str)
                or not _allowed(name) or name in names
                or type(entry.get("size")) is not int or not 0 <= entry["size"] <= _MAX_FILE
                or entry.get("mode") != _mode(name)
                or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ReleaseError("Release manifest contains an invalid source entry.")
        total += entry["size"]
        if total > _MAX_TOTAL:
            raise ReleaseError("Release manifest exceeds the size limit.")
        payload = _read(project / name)
        if len(payload) != entry["size"] or hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            raise ReleaseError("Release files do not match their manifest.")
        names.add(name)
    if not _REQUIRED.issubset(names):
        raise ReleaseError("Release manifest is incomplete.")
    return {"verified": True, "files": len(names)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create", allow_abbrev=False)
    create.add_argument("--project", type=Path, default=Path.cwd())
    create.add_argument("--output", type=Path)
    verify = commands.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--project", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            output = args.output or args.project / "deploy/out/scap-source-release.tar.gz"
            result = create_release(args.project, output)
        else:
            result = verify_release(args.project)
    except ReleaseError as exc:
        print(f"Source release failed: {exc}", file=sys.stderr)
        return 1
    except (OSError, tarfile.TarError):
        print("Source release failed: a required source/output is missing, linked or inaccessible.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
