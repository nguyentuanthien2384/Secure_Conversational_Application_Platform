from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
VALID_ROLES = {"user", "moderator", "admin"}

# NIST SP 800-63B-4 favours length and blocklists over composition rules. We require a
# long secret, accept passphrases up to 128 chars, and screen obvious weak/known tokens
# instead of forcing an uppercase/lowercase/digit mix.
PASSWORD_MIN_LENGTH = 15
WEAK_PASSWORDS = {
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "qwerty",
    "qwertyuiop",
    "letmein",
    "iloveyou",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "abc123",
    "secure-chat",
    "changeme",
    "111111",
    "000000",
    "passwordpassword",
    "correcthorsebatterystaple",
}


def _screen_password(value: str) -> str:
    value = unicodedata.normalize("NFC", value)
    if value.strip() != value:
        raise ValueError("Mật khẩu không được bắt đầu hoặc kết thúc bằng khoảng trắng.")
    lowered = value.lower()
    if lowered in WEAK_PASSWORDS:
        raise ValueError("Mật khẩu quá phổ biến hoặc dễ đoán.")
    return value


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip().lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Tên đăng nhập chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return _screen_password(value)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return RegisterRequest.validate_password(value)


class UserStatusUpdate(BaseModel):
    is_active: bool


class AIConsentUpdate(BaseModel):
    ai_data_consent: bool


class UserRoleUpdate(BaseModel):
    role: str = Field(min_length=1, max_length=16)

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in VALID_ROLES:
            raise ValueError(f"Role phải là một trong: {', '.join(sorted(VALID_ROLES))}.")
        return value


class AdminCreateUser(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)
    role: str = Field(default="user", min_length=1, max_length=16)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        value = value.strip().lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Tên đăng nhập chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang.")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return RegisterRequest.validate_password(value)

    @field_validator("role")
    @classmethod
    def validate_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in VALID_ROLES:
            raise ValueError(f"Role phải là một trong: {', '.join(sorted(VALID_ROLES))}.")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class MfaChallengeResponse(BaseModel):
    """Returned by /login when the account has MFA enabled and the password is correct.

    No access token is issued yet; the client must complete /mfa/verify with a
    time-based code (or a recovery code) using the short-lived ``mfa_token``.
    """

    mfa_required: bool = True
    mfa_token: str
    expires_in: int


class MfaEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaActivateRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        cleaned = value.strip().replace(" ", "")
        if not cleaned.isdigit():
            raise ValueError("Mã TOTP chỉ gồm chữ số.")
        return cleaned


class MfaActivateResponse(BaseModel):
    mfa_enabled: bool = True
    recovery_codes: list[str]


class MfaVerifyRequest(BaseModel):
    mfa_token: str = Field(min_length=1, max_length=4096)
    code: str = Field(min_length=6, max_length=32)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Mã xác thực không được để trống.")
        return cleaned


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=32)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Mã xác thực không được để trống.")
        return cleaned


class AuthSessionResponse(BaseModel):
    id: str
    issued_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    is_current: bool


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    role: str
    is_active: bool
    ai_data_consent: bool
    mfa_enabled: bool
    token_version: int
    created_at: datetime


class SessionCreate(BaseModel):
    title: str = Field(default="Cuộc hội thoại mới", min_length=1, max_length=120)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tiêu đề không được để trống.")
        return cleaned


class SessionUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=120)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tiêu đề không được để trống.")
        return cleaned


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    title: str
    created_at: datetime
    updated_at: datetime


class MessageSend(BaseModel):
    content: str = Field(min_length=1, max_length=4000)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Nội dung không được để trống.")
        if any(ch in cleaned for ch in ("\x00", "\r", "\x1f")):
            raise ValueError("Nội dung chứa ký tự điều khiển không hợp lệ.")
        return cleaned


class MessageResponse(BaseModel):
    id: int
    session_id: str
    role: str
    content: str
    created_at: datetime
    # Tên NHÓM dữ liệu mà lớp DLP đã che trước khi gửi sang AI bên ngoài
    # (ví dụ ["mật khẩu", "số thẻ"]). Chỉ chứa nhãn, tuyệt đối không chứa giá trị
    # gốc, nên an toàn để hiển thị trên giao diện và ghi vào audit log.
    dlp_redacted: list[str] = Field(default_factory=list)


class RawMessageResponse(BaseModel):
    id: int
    role: str
    ciphertext_preview: str
    nonce: str
    key_version: int
    created_at: datetime


class AuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: str | None
    event_type: str
    target_type: str | None
    target_id: str | None
    outcome: str
    ip_address: str | None
    request_id: str | None
    details_json: str
    created_at: datetime


class SecurityAlertResponse(BaseModel):
    code: str
    severity: str
    event_type: str
    count: int
    window_minutes: int
    message: str


class AgentToolCall(BaseModel):
    """An untrusted proposed tool call. The broker validates it again at execution."""

    tool: str = Field(min_length=2, max_length=64, pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentRunRequest(BaseModel):
    # This explicit list is the user approval boundary.  The model cannot add
    # scopes: the server converts this list to an internal capability token.
    approved_scopes: list[str] = Field(default_factory=list, max_length=8)
    tool_calls: list[AgentToolCall] = Field(min_length=1, max_length=8)

    @field_validator("approved_scopes")
    @classmethod
    def normalize_scopes(cls, value: list[str]) -> list[str]:
        cleaned = [scope.strip().lower() for scope in value]
        if any(not scope or len(scope) > 64 for scope in cleaned):
            raise ValueError("Capability scope không hợp lệ.")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("Không được cấp trùng capability scope.")
        return cleaned


class AgentToolResult(BaseModel):
    tool: str
    status: str
    detail: str | None = None
    output: dict[str, Any] | None = None


class AgentRunResponse(BaseModel):
    status: str
    approved_scopes: list[str]
    results: list[AgentToolResult]
    summary: dict[str, int]


class AgentToolManifestResponse(BaseModel):
    name: str
    version: str
    required_scope: str
    description: str
    timeout_seconds: int
    max_output_bytes: int
    manifest_signature: str


class AgentDocumentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=131072)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tiêu đề tài liệu không được để trống.")
        return cleaned


class AgentDocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    key_version: int
    created_at: datetime


class AgentRetrievalRequest(BaseModel):
    query: str = Field(min_length=3, max_length=200)


class AgentRetrievalHit(BaseModel):
    document_id: str
    title: str
    snippet: str
