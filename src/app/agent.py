"""Zero-trust execution boundary for the Secure AI Agent Platform.

This module deliberately does *not* give an LLM a shell, subprocess, socket, or
database handle.  An agent (and therefore its model output) is treated as an
untrusted planner.  Every proposed action is checked by a signed, short-lived
capability and then dispatched through a small allowlisted broker.

The built-in sandbox adapter is deny-by-default.  A production deployment must
replace it with a remote rootless-container/microVM runner; adding ``subprocess``
here would erase the security boundary this module is intended to demonstrate.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import jwt

from src.app.config import Settings

MAX_TOOL_OUTPUT_BYTES = 64 * 1024
MAX_FILE_WRITE_BYTES = 32 * 1024
MAX_SEARCH_RESULTS = 30
MAX_SEARCH_FILE_BYTES = 256 * 1024
VALID_SCOPES = frozenset(
    {
        "workspace:read",
        "workspace:write",
        "repo:read",
        "egress:inspect",
        "sandbox:execute",
    }
)
_SAFE_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")


class AgentPolicyError(PermissionError):
    """A requested agent action crossed a policy boundary."""


class AgentInputError(ValueError):
    """The tool input is malformed, too large, or ambiguous."""


@dataclass(frozen=True)
class ToolManifest:
    name: str
    version: str
    required_scope: str
    description: str
    timeout_seconds: int
    max_output_bytes: int = MAX_TOOL_OUTPUT_BYTES

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "required_scope": self.required_scope,
            "description": self.description,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
        }


BUILTIN_TOOLS: dict[str, ToolManifest] = {
    "workspace.list": ToolManifest(
        "workspace.list", "builtin@1", "workspace:read", "List the caller's isolated workspace.", 2
    ),
    "workspace.read": ToolManifest(
        "workspace.read", "builtin@1", "workspace:read", "Read one UTF-8 file in the caller's workspace.", 2
    ),
    "workspace.write": ToolManifest(
        "workspace.write", "builtin@1", "workspace:write", "Write one bounded UTF-8 file in the caller's workspace.", 2
    ),
    "repo.search": ToolManifest(
        "repo.search", "builtin@1", "repo:read", "Search an allowlisted source-tree view; secrets and Git metadata are excluded.", 3
    ),
    "egress.inspect": ToolManifest(
        "egress.inspect", "builtin@1", "egress:inspect", "Validate an outbound URL without performing a network request.", 2
    ),
    "sandbox.execute": ToolManifest(
        "sandbox.execute", "builtin@1", "sandbox:execute", "Request isolated code execution from an external sandbox runner.", 5
    ),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _derived_key(secret: str, label: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), label, hashlib.sha256).digest()


class CapabilityService:
    """Issue internal, short-lived, audience-bound capability JWTs.

    The token is never returned to the browser.  It exists so a future queue or
    remote runner can verify the same least-privilege grant independently of the
    web application's user JWT.
    """

    def __init__(self, secret: str, lifetime_seconds: int):
        self._key = _derived_key(secret, b"scap:agent-capability:v1")
        self.lifetime_seconds = lifetime_seconds

    def issue(self, user_id: str, scopes: Sequence[str]) -> str:
        now = _utcnow()
        payload = {
            "sub": user_id,
            "aud": "scap-agent-tool",
            "iat": now,
            "exp": now + timedelta(seconds=self.lifetime_seconds),
            "jti": str(uuid.uuid4()),
            "scopes": sorted(set(scopes)),
        }
        return jwt.encode(payload, self._key, algorithm="HS256")

    def verify(self, token: str, user_id: str) -> set[str]:
        try:
            claims = jwt.decode(token, self._key, algorithms=["HS256"], audience="scap-agent-tool")
        except jwt.PyJWTError as exc:
            raise AgentPolicyError("Capability token không hợp lệ hoặc đã hết hạn.") from exc
        if claims.get("sub") != user_id:
            raise AgentPolicyError("Capability token không thuộc về người dùng hiện tại.")
        scopes = claims.get("scopes")
        if not isinstance(scopes, list) or any(scope not in VALID_SCOPES for scope in scopes):
            raise AgentPolicyError("Capability token chứa scope không hợp lệ.")
        return set(scopes)


class Workspace:
    """Filesystem view rooted per user, with traversal and symlink escape checks."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()

    def _user_root(self, user_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f-]{36}", user_id):
            raise AgentPolicyError("Định danh workspace không hợp lệ.")
        path = (self.root / user_id).resolve()
        if not path.is_relative_to(self.root):  # defensive against future user-id format changes
            raise AgentPolicyError("Workspace vượt ra ngoài thư mục cho phép.")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def resolve(self, user_id: str, relative_path: str) -> Path:
        if not relative_path or len(relative_path) > 240 or "\x00" in relative_path:
            raise AgentInputError("Đường dẫn workspace không hợp lệ.")
        candidate_input = Path(relative_path)
        if candidate_input.is_absolute() or any(part in {"", ".", ".."} for part in candidate_input.parts):
            raise AgentPolicyError("Chỉ cho phép đường dẫn tương đối bên trong workspace.")
        if any(part.startswith(".") for part in candidate_input.parts):
            raise AgentPolicyError("Không cho phép truy cập tệp ẩn trong workspace.")
        user_root = self._user_root(user_id)
        candidate = (user_root / candidate_input).resolve()
        if not candidate.is_relative_to(user_root):
            raise AgentPolicyError("Đường dẫn đã thoát khỏi workspace.")
        return candidate

    def list(self, user_id: str) -> list[dict[str, Any]]:
        root = self._user_root(user_id)
        rows: list[dict[str, Any]] = []
        for item in sorted(root.iterdir(), key=lambda path: path.name.casefold()):
            if item.name.startswith("."):
                continue
            if item.is_symlink():
                rows.append({"name": item.name, "type": "symlink-blocked"})
            elif item.is_file():
                rows.append({"name": item.name, "type": "file", "size": item.stat().st_size})
            elif item.is_dir():
                rows.append({"name": item.name, "type": "directory"})
        return rows[:200]

    def read(self, user_id: str, relative_path: str) -> dict[str, Any]:
        path = self.resolve(user_id, relative_path)
        if path.is_symlink() or not path.is_file():
            raise AgentPolicyError("Chỉ được đọc tệp thông thường trong workspace.")
        if path.stat().st_size > MAX_TOOL_OUTPUT_BYTES:
            raise AgentInputError("Tệp vượt giới hạn đọc 64 KiB của tool.")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise AgentInputError("Tool chỉ đọc tệp UTF-8, không đọc binary.") from exc
        return {"path": relative_path, "content": content, "bytes": len(content.encode("utf-8"))}

    def write(self, user_id: str, relative_path: str, content: str) -> dict[str, Any]:
        if len(content.encode("utf-8")) > MAX_FILE_WRITE_BYTES:
            raise AgentInputError("Nội dung vượt giới hạn ghi 32 KiB của tool.")
        path = self.resolve(user_id, relative_path)
        if path.exists() and path.is_symlink():
            raise AgentPolicyError("Không cho phép ghi qua symbolic link.")
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.resolve().is_relative_to(self._user_root(user_id)):
            raise AgentPolicyError("Thư mục đích vượt ra ngoài workspace.")
        temporary = path.with_suffix(path.suffix + ".scap-tmp")
        with open(temporary, "x", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return {"path": relative_path, "bytes_written": len(content.encode("utf-8"))}


class SourceSearch:
    """Read-only, explicitly allowlisted project source search."""

    _ALLOWED_TOP_LEVEL = {"src", "tests", "scripts", "README.md", "pyproject.toml"}
    _ALLOWED_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".json", ".txt"}

    def __init__(self):
        self.root = Path(__file__).resolve().parents[2]

    def search(self, query: str) -> dict[str, Any]:
        cleaned = query.strip()
        if len(cleaned) < 3 or len(cleaned) > 100 or "\x00" in cleaned:
            raise AgentInputError("Từ khóa tìm kiếm phải dài 3–100 ký tự.")
        hits: list[dict[str, Any]] = []
        candidates: list[Path] = [self.root / "README.md", self.root / "pyproject.toml"]
        for directory in (self.root / "src", self.root / "tests", self.root / "scripts"):
            if directory.exists():
                candidates.extend(path for path in directory.rglob("*") if path.is_file())
        for path in candidates:
            try:
                relative = path.resolve().relative_to(self.root)
            except ValueError:
                continue
            if relative.parts[0] not in self._ALLOWED_TOP_LEVEL or path.suffix not in self._ALLOWED_SUFFIXES:
                continue
            if path.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(lines, start=1):
                if cleaned.casefold() in line.casefold():
                    hits.append(
                        {"path": str(relative).replace("\\", "/"), "line": line_number, "preview": line[:240]}
                    )
                    if len(hits) >= MAX_SEARCH_RESULTS:
                        return {"query": cleaned, "results": hits, "truncated": True}
        return {"query": cleaned, "results": hits, "truncated": False}


class EgressPolicy:
    """Validate destinations without making a network request.

    Actual HTTP fetching belongs behind a separate proxy that repeats this check
    at connect and on every redirect.  This local tool intentionally has no HTTP
    client, which makes SSRF impossible through the application process.
    """

    def __init__(self, allowed_hosts: Sequence[str]):
        self.allowed_hosts = {host.strip().lower().rstrip(".") for host in allowed_hosts if host.strip()}

    @staticmethod
    def _is_private(address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified

    def inspect(self, raw_url: str) -> dict[str, Any]:
        if len(raw_url) > 2048 or any(char in raw_url for char in "\r\n\x00"):
            raise AgentInputError("URL không hợp lệ.")
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise AgentPolicyError("Egress chỉ chấp nhận URL HTTPS không có user-info.")
        if parsed.port not in {None, 443}:
            raise AgentPolicyError("Egress chỉ cho phép cổng HTTPS mặc định.")
        host = parsed.hostname.lower().rstrip(".")
        normalized_url = urlunsplit(("https", host, parsed.path or "/", parsed.query, ""))
        try:
            if self._is_private(host):
                raise AgentPolicyError("Đích IP nội bộ/đặc biệt bị chặn để chống SSRF.")
        except ValueError:
            pass
        if host not in self.allowed_hosts:
            raise AgentPolicyError("Tên miền không nằm trong egress allowlist.")
        try:
            addresses = {entry[4][0] for entry in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise AgentPolicyError("Không phân giải được DNS của đích allowlist.") from exc
        if any(self._is_private(address) for address in addresses):
            raise AgentPolicyError("DNS của đích allowlist trỏ tới IP nội bộ/đặc biệt.")
        return {"url": normalized_url, "host": host, "resolved_addresses": sorted(addresses), "network_request": False}


class SandboxGateway:
    """Explicit production boundary; never falls back to local execution."""

    def execute(self, _: Mapping[str, Any]) -> dict[str, Any]:
        raise AgentPolicyError(
            "Sandbox runner chưa được cấu hình. Tool không bao giờ chạy lệnh trên tiến trình ứng dụng."
        )


class ToolBroker:
    def __init__(self, settings: Settings):
        self.capabilities = CapabilityService(settings.secret_key, settings.agent_capability_seconds)
        self.workspace = Workspace(settings.agent_workspace_root)
        self.source_search = SourceSearch()
        self.egress = EgressPolicy(settings.agent_egress_allowed_hosts)
        self.sandbox = SandboxGateway()
        self.max_tool_calls = settings.agent_max_tool_calls
        self._manifest_key = _derived_key(settings.secret_key, b"scap:tool-manifest:v1")

    def manifests(self) -> list[dict[str, Any]]:
        public = [manifest.public() for manifest in BUILTIN_TOOLS.values()]
        canonical = json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature = base64.urlsafe_b64encode(hmac.new(self._manifest_key, canonical, hashlib.sha256).digest()).decode("ascii")
        return [{**item, "manifest_signature": signature} for item in public]

    def execute(self, *, user_id: str, capability: str, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        manifest = BUILTIN_TOOLS.get(tool_name)
        if manifest is None or not _SAFE_TOOL_NAME.fullmatch(tool_name):
            raise AgentPolicyError("Tool không nằm trong allowlist manifest.")
        scopes = self.capabilities.verify(capability, user_id)
        if manifest.required_scope not in scopes:
            raise AgentPolicyError(f"Thiếu capability {manifest.required_scope} cho tool {tool_name}.")
        if tool_name == "workspace.list":
            return {"entries": self.workspace.list(user_id)}
        if tool_name == "workspace.read":
            return self.workspace.read(user_id, self._string(arguments, "path", maximum=240))
        if tool_name == "workspace.write":
            return self.workspace.write(
                user_id,
                self._string(arguments, "path", maximum=240),
                self._string(arguments, "content", maximum=MAX_FILE_WRITE_BYTES),
            )
        if tool_name == "repo.search":
            return self.source_search.search(self._string(arguments, "query", maximum=100))
        if tool_name == "egress.inspect":
            return self.egress.inspect(self._string(arguments, "url", maximum=2048))
        if tool_name == "sandbox.execute":
            return self.sandbox.execute(arguments)
        raise AgentPolicyError("Tool manifest không có handler.")

    @staticmethod
    def _string(arguments: Mapping[str, Any], name: str, *, maximum: int) -> str:
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            raise AgentInputError(f"Tool yêu cầu trường chuỗi {name}.")
        if len(value.encode("utf-8")) > maximum:
            raise AgentInputError(f"Trường {name} vượt giới hạn kích thước.")
        return value


class AgentOrchestrator:
    """Treat model-proposed calls as a plan, not authority."""

    def __init__(self, broker: ToolBroker):
        self.broker = broker

    def run(self, user_id: str, approved_scopes: Sequence[str], tool_calls: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        approved = sorted(set(approved_scopes))
        if any(scope not in VALID_SCOPES for scope in approved):
            raise AgentInputError("Yêu cầu chứa capability không được biết đến.")
        if len(tool_calls) > self.broker.max_tool_calls:
            raise AgentInputError("Vượt quá quota số tool call của một agent run.")
        capability = self.broker.capabilities.issue(user_id, approved)
        results: list[dict[str, Any]] = []
        denied = 0
        for call in tool_calls:
            tool_name = call.get("tool")
            arguments = call.get("arguments", {})
            if not isinstance(tool_name, str) or not isinstance(arguments, Mapping):
                results.append({"tool": str(tool_name)[:64], "status": "invalid", "detail": "Tool call không hợp lệ."})
                denied += 1
                continue
            try:
                output = self.broker.execute(
                    user_id=user_id, capability=capability, tool_name=tool_name, arguments=arguments
                )
                results.append({"tool": tool_name, "status": "success", "output": output})
            except (AgentPolicyError, AgentInputError) as exc:
                results.append({"tool": tool_name, "status": "denied", "detail": str(exc)})
                denied += 1
        return {
            "status": "completed" if denied == 0 else "completed_with_denials",
            "approved_scopes": approved,
            "results": results,
            "summary": {"tool_calls": len(tool_calls), "denied": denied, "capability_lifetime_seconds": self.broker.capabilities.lifetime_seconds},
        }
