"""Prepare a separate, private configuration for a NEW demo VPS deployment.

This tool never loads the local .env, contacts a server, starts Docker, migrates
data, or replaces existing keys. The readiness check prints field names only.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.app.private_storage import (
    PrivateStorageError,
    check_private_file,
    create_private_file,
    read_regular_file,
)

_MAX_BYTES = 64 * 1024
_ASSIGNMENT = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)")
_IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SAFE_SECRET = re.compile(r"[A-Za-z0-9_-]{32,128}")
_FIXED = {
    "COMPOSE_PROJECT_NAME": "scap-vps-demo",
    "SCAP_ENV_FILE": "./deploy/.env.vps",
    "APP_ENV": "production",
    "SECURITY_PROFILE": "standard",
    "KEY_PROVIDER": "local",
    "DATABASE_URL": "postgresql+psycopg://scap_app@db:5432/secure_chat",
    "REDIS_URL": "redis://redis:6379/0",
    "DOCS_ENABLED": "false",
    "SEED_DEMO_DATA": "false",
    "PASSWORD_BREACH_CHECK": "true",
    "GRADIO_AUTH_MODE": "application",
    "CSP_ALLOW_UNSAFE_EVAL": "false",
    "CSP_REPORT_ONLY": "false",
    "IDS_ENABLED": "true",
    "AUDIT_CHAIN_ENABLED": "true",
    "SIEM_JSON_LOGS": "true",
    "RETENTION_SWEEP_ON_STARTUP": "true",
}
_EMPTY = (
    "BOOTSTRAP_ADMIN_USERNAME", "BOOTSTRAP_ADMIN_PASSWORD", "APP_SECRET_KEY_FILE",
    "MASTER_ENCRYPTION_KEYS", "ACTIVE_KEY_VERSION", "DATABASE_PASSWORD_FILE",
    "REDIS_PASSWORD_FILE", "GOOGLE_GENAI_API_KEY_FILE", "VAULT_TOKEN_FILE",
    "OIDC_PROXY_SECRET_FILE", "AUDIT_WORM_TOKEN_FILE",
)
_IMAGES = ("BASE_IMAGE", "POSTGRES_IMAGE", "REDIS_IMAGE", "CADDY_IMAGE")
_PASSWORDS = ("POSTGRES_PASSWORD", "APP_DB_PASSWORD", "AUDITOR_DB_PASSWORD")
_LIMITS = {
    "REQUEST_MAX_CONCURRENT": (16, 64), "REQUEST_MAX_STREAMS": (4, 16),
    "REQUEST_IP_MAX_CONCURRENT": (16, 32), "REQUEST_IP_MAX_STREAMS": (4, 8),
    "PASSWORD_MAX_CONCURRENT": (1, 1), "AI_MAX_CONCURRENT": (1, 1),
    "AI_GLOBAL_MAX_ATTEMPTS": (1, 60), "AI_DAILY_MAX_ATTEMPTS": (1, 1000),
    "AI_MAX_OUTPUT_TOKENS": (128, 1024), "GRADIO_QUEUE_MAX_SIZE": (1, 16),
    "GRADIO_CONCURRENCY_LIMIT": (1, 2), "GRADIO_RETAINED_EVENTS": (1, 128),
    "GRADIO_STATE_CAPACITY": (1, 256), "UVICORN_LIMIT_CONCURRENCY": (32, 64),
    "UVICORN_BACKLOG": (16, 128), "UVICORN_KEEPALIVE_SECONDS": (1, 10),
    "UVICORN_SHUTDOWN_SECONDS": (10, 60), "GEMINI_TIMEOUT_SECONDS": (5, 25),
    "MAIL_MAX_PENDING": (1, 16),
}


class PreparationError(RuntimeError):
    """An operator must correct configuration; messages contain no secret values."""


def _project(value: str | Path) -> Path:
    path = Path(value)
    if ".." in path.parts or (os.name == "nt" and path.drive and not path.root):
        raise PreparationError("Use an ordinary project directory without parent traversal.")
    path = Path(os.path.abspath(path))
    if not path.is_dir():
        raise PreparationError("The project directory must already exist.")
    return path


def _read(path: Path, *, private: bool) -> tuple[list[str], dict[str, str]]:
    if private:
        check_private_file(path)
    with read_regular_file(path) as stream:
        payload = stream.read(_MAX_BYTES + 1)
    if len(payload) > _MAX_BYTES:
        raise PreparationError("Configuration exceeds the size limit.")
    try:
        content = payload.decode("utf-8-sig")
    except UnicodeError as exc:
        raise PreparationError("Configuration must be UTF-8 text.") from exc
    if any(ord(char) < 32 and char not in "\r\n" for char in content):
        raise PreparationError("Configuration contains invalid control characters.")
    lines = content.splitlines()
    values = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.fullmatch(line)
        if match is None or match[1] in values:
            raise PreparationError("Configuration has malformed or duplicate assignments.")
        name, value = match.groups()
        if value.startswith("'") and value.endswith("'") and "'" not in value[1:-1]:
            value = value[1:-1]
        elif any(char in value for char in "\"'$#\\") or value != value.strip():
            raise PreparationError(f"{name}: use a plain value or a single-quoted literal.")
        values[name] = value
    return lines, values


def _domain(value: str) -> bool:
    if value != value.lower() or len(value) > 253:
        return False
    parts = value.split(".")
    if len(parts) < 2 or not all(_LABEL.fullmatch(part) for part in parts):
        return False
    if parts[-1] in {"localhost", "local", "test", "invalid", "example"}:
        return False
    if any(value == name or value.endswith("." + name)
           for name in ("example.com", "example.net", "example.org")):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def _email(value: str) -> bool:
    if len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!+_-]+@[a-z0-9.-]+", value):
        return False
    return _domain(value.rsplit("@", 1)[1])


def initialize(project: str | Path, *, domain: str = "", email: str = "") -> str:
    """Create future deployment secrets once, only for a separate new database."""
    project_path = _project(project)
    target = project_path / "deploy" / ".env.vps"
    try:
        info = target.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            raise PreparationError("Existing deployment configuration must be an ordinary file.")
        return "unchanged"
    if domain and not _domain(domain):
        raise PreparationError("PUBLIC_DOMAIN: use a real lower-case DNS hostname.")
    if email and not _email(email):
        raise PreparationError("CADDY_EMAIL: use an email address on a real domain.")
    lines, values = _read(project_path / "deploy" / "vps.env.example", private=False)
    required = set(_FIXED) | set(_IMAGES) | set(_PASSWORDS) | {
        "APP_SECRET_KEY", "MASTER_ENCRYPTION_KEY", "PUBLIC_DOMAIN", "CADDY_EMAIL",
        "PUBLIC_BASE_URL", "ALLOWED_ORIGINS", "ALLOWED_HOSTS", "WEBAUTHN_RP_ID",
        "WEBAUTHN_ORIGINS", "SECURITY_TXT_EXPIRES",
    }
    if not required <= values.keys() or any(values.get(k) != v for k, v in _FIXED.items()):
        raise PreparationError("Deployment template must contain the safe VPS demo settings.")
    if any(values.get(k) for k in (*_EMPTY, *_IMAGES, *_PASSWORDS,
                                   "APP_SECRET_KEY", "MASTER_ENCRYPTION_KEY",
                                   "GOOGLE_GENAI_API_KEY", "SMTP_PASSWORD")):
        raise PreparationError("Deployment template must not contain credentials or image selections.")
    origin = f"https://{domain}" if domain else ""
    replacements = {
        "APP_SECRET_KEY": secrets.token_urlsafe(48),
        "MASTER_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
        **{name: secrets.token_urlsafe(40) for name in _PASSWORDS},
        "PUBLIC_DOMAIN": domain, "CADDY_EMAIL": email,
        "PUBLIC_BASE_URL": origin, "ALLOWED_ORIGINS": origin,
        "ALLOWED_HOSTS": f"{domain},127.0.0.1,localhost,::1" if domain else "",
        "WEBAUTHN_RP_ID": domain, "WEBAUTHN_ORIGINS": origin,
        "SECURITY_TXT_EXPIRES": (datetime.now(timezone.utc) + timedelta(days=180))
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    output = []
    for line in lines:
        match = _ASSIGNMENT.fullmatch(line)
        output.append(f"{match[1]}={replacements[match[1]]}"
                      if match and match[1] in replacements else line)
    # O_EXCL / CREATE_NEW, private ACL/mode applied before any secret byte is written.
    with create_private_file(target) as stream:
        stream.write(("\n".join(output) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    return "created"


def check(project: str | Path) -> list[str]:
    """Return bounded field-level issues without loading dotenv or echoing values."""
    _, values = _read(_project(project) / "deploy" / ".env.vps", private=True)
    issues = [f"{key}: required demo production setting."
              for key, expected in _FIXED.items() if values.get(key) != expected]
    issues.extend(f"{key}: leave empty in this profile." for key in _EMPTY if values.get(key))
    issues.extend(f"{key}: unsupported Compose override." for key in values
                  if key.startswith("COMPOSE_") and key != "COMPOSE_PROJECT_NAME")
    domain = values.get("PUBLIC_DOMAIN", "")
    if not _domain(domain):
        issues.append("PUBLIC_DOMAIN: a real DNS hostname is required.")
    else:
        origin = f"https://{domain}"
        expected = {
            "PUBLIC_BASE_URL": origin, "ALLOWED_ORIGINS": origin,
            "ALLOWED_HOSTS": f"{domain},127.0.0.1,localhost,::1",
            "WEBAUTHN_RP_ID": domain, "WEBAUTHN_ORIGINS": origin,
        }
        issues.extend(f"{key}: must match PUBLIC_DOMAIN."
                      for key, value in expected.items() if values.get(key) != value)
    if not _email(values.get("CADDY_EMAIL", "")):
        issues.append("CADDY_EMAIL: a real contact email is required.")
    for key in _IMAGES:
        if not _IMAGE.fullmatch(values.get(key, "")):
            issues.append(f"{key}: select a verified digest-pinned image.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9./_-]*:[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}",
                        values.get("SCAP_APP_IMAGE", "")):
        issues.append("SCAP_APP_IMAGE: an explicit application image tag is required.")
    if not _SAFE_SECRET.fullmatch(values.get("APP_SECRET_KEY", "")):
        issues.append("APP_SECRET_KEY: a generated strong secret is required.")
    for key in _PASSWORDS:
        if not _SAFE_SECRET.fullmatch(values.get(key, "")):
            issues.append(f"{key}: a generated URL-safe role password is required.")
    if len({values.get(key, "") for key in _PASSWORDS}) != len(_PASSWORDS):
        issues.append("POSTGRES_PASSWORD/APP_DB_PASSWORD/AUDITOR_DB_PASSWORD: use distinct secrets.")
    raw_key = values.get("MASTER_ENCRYPTION_KEY", "")
    try:
        decoded = base64.b64decode(raw_key, altchars=b"-_", validate=True)
        valid_key = len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode() == raw_key
    except ValueError:
        valid_key = False
    if not valid_key:
        issues.append("MASTER_ENCRYPTION_KEY: a canonical 32-byte base64 key is required.")
    try:
        expiry = datetime.strptime(values.get("SECURITY_TXT_EXPIRES", ""),
                                   "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if not now < expiry <= now + timedelta(days=365):
            raise ValueError
    except ValueError:
        issues.append("SECURITY_TXT_EXPIRES: choose a future UTC date within one year.")
    for key in ("ALLOW_DEMO_AI", "ALLOW_SELF_REGISTRATION"):
        if values.get(key) not in {"true", "false"}:
            issues.append(f"{key}: use true or false.")
    if values.get("ALLOW_DEMO_AI") == "false" and not values.get("GOOGLE_GENAI_API_KEY"):
        issues.append("GOOGLE_GENAI_API_KEY: required when offline demo AI is disabled.")
    for key, (minimum, maximum) in _LIMITS.items():
        try:
            if not minimum <= int(values.get(key, "")) <= maximum:
                raise ValueError
        except ValueError:
            issues.append(f"{key}: outside this small-VPS budget.")
    for key, expected in {"REDIS_MAXMEMORY": "96mb", "REDIS_MAXCLIENTS": "128"}.items():
        if values.get(key) != expected:
            issues.append(f"{key}: must match the bounded Redis container settings.")
    try:
        subnet = ipaddress.ip_network(values.get("SCAP_EDGE_SUBNET", ""))
        dynamic = ipaddress.ip_network(values.get("SCAP_EDGE_DYNAMIC_RANGE", ""))
        caddy = ipaddress.ip_address(values.get("SCAP_CADDY_IPV4", ""))
        if (subnet.version != 4 or dynamic.version != 4 or caddy.version != 4
                or not subnet.is_private or not dynamic.subnet_of(subnet)
                or caddy not in subnet or caddy in dynamic
                or caddy in {subnet.network_address, subnet.broadcast_address}):
            raise ValueError
    except ValueError:
        issues.append("SCAP_EDGE_SUBNET/SCAP_EDGE_DYNAMIC_RANGE/SCAP_CADDY_IPV4: invalid proxy network.")
    backend = values.get("MAIL_BACKEND")
    if backend not in {"disabled", "smtp"}:
        issues.append("MAIL_BACKEND: use disabled or smtp.")
    elif backend == "smtp":
        if not values.get("SMTP_HOST"):
            issues.append("SMTP_HOST: required for SMTP.")
        if values.get("SMTP_SECURITY") not in {"starttls", "ssl"}:
            issues.append("SMTP_SECURITY: TLS is required.")
        try:
            if not 1 <= int(values.get("SMTP_PORT", "")) <= 65535:
                raise ValueError
        except ValueError:
            issues.append("SMTP_PORT: invalid port.")
    if values.get("SMTP_PASSWORD_FILE"):
        issues.append("SMTP_PASSWORD_FILE: this profile has no secret-file mount.")
    # Host environment takes precedence over --env-file in Compose. Fail before
    # an accidental shell variable changes the selected database, image or host.
    issues.extend(f"{key}: conflicting shell environment; unset it before Compose."
                  for key, value in values.items() if key in os.environ
                  and os.environ[key] != value)
    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a separate private config once; never replace keys.")
    init.add_argument("--project", type=Path, default=Path.cwd())
    init.add_argument("--domain", default="")
    init.add_argument("--email", default="")
    verify = commands.add_parser("check", help="Check readiness without printing secrets or starting services.")
    verify.add_argument("--project", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            status = initialize(args.project, domain=args.domain, email=args.email)
            print(f"Deployment configuration {status}: deploy/.env.vps; local keys and data preserved.")
            print("For a NEW PostgreSQL deployment only. Run check before any server startup.")
            return 0
        issues = check(args.project)
        if issues:
            print("Deployment is pending; no services were started.")
            for issue in issues:
                print(f"- {issue}")
            return 2
        print("Configuration checks passed; DNS, server capacity and restore still require verification.")
        return 0
    except PreparationError as exc:
        print(f"VPS preparation failed: {exc}", file=sys.stderr)
    except (OSError, PrivateStorageError):
        print("VPS preparation failed: configuration missing, unsafe or inaccessible; no values shown.",
              file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
