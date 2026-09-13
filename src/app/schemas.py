from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
VALID_ROLES = {"user", "moderator", "admin"}
VALID_SECURITY_MODES = {"secure", "confidential", "private_e2ee"}
VALID_DATA_CLASSES = {
    "public",
    "internal",
    "confidential",
    "highly_confidential",
    "e2ee_private",
}

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


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str | None = Field(default=None, min_length=6, max_length=32)

    @field_validator("code")
    @classmethod
    def clean_code(cls, value: str | None) -> str | None:
        return value.strip() if value is not None else None


class StepUpResponse(BaseModel):
    verified_at: datetime
    valid_for_seconds: int


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
    ai_consent_at: datetime | None = None
    ai_consent_version: str | None = None
    mfa_enabled: bool
    token_version: int
    created_at: datetime


class SessionCreate(BaseModel):
    title: str = Field(default="Cuộc hội thoại mới", min_length=1, max_length=120)
    security_mode: str = "secure"
    data_classification: str = "internal"

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tiêu đề không được để trống.")
        return cleaned

    @field_validator("security_mode")
    @classmethod
    def validate_security_mode(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in VALID_SECURITY_MODES:
            raise ValueError("Chế độ bảo mật không hợp lệ.")
        return cleaned

    @field_validator("data_classification")
    @classmethod
    def validate_data_classification(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned not in VALID_DATA_CLASSES:
            raise ValueError("Phân loại dữ liệu không hợp lệ.")
        return cleaned

    @model_validator(mode="after")
    def align_private_mode(self) -> SessionCreate:
        if self.security_mode == "private_e2ee":
            self.data_classification = "e2ee_private"
        elif self.security_mode == "confidential" and self.data_classification in {
            "public",
            "internal",
        }:
            self.data_classification = "confidential"
        elif self.data_classification == "e2ee_private":
            raise ValueError("e2ee_private chỉ dùng với chế độ private_e2ee.")
        elif self.security_mode == "secure" and self.data_classification in {
            "confidential",
            "highly_confidential",
        }:
            raise ValueError("Dữ liệu nhạy cảm phải dùng chế độ confidential.")
        return self


class SessionUpdate(BaseModel):
    title: str = Field(min_length=1, max_length=120)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tiêu đề không được để trống.")
        return cleaned


class SessionSecurityUpdate(BaseModel):
    security_mode: str
    data_classification: str

    @field_validator("security_mode")
    @classmethod
    def validate_security_mode(cls, value: str) -> str:
        return SessionCreate.validate_security_mode(value)

    @field_validator("data_classification")
    @classmethod
    def validate_data_classification(cls, value: str) -> str:
        return SessionCreate.validate_data_classification(value)

    @model_validator(mode="after")
    def align_private_mode(self) -> SessionSecurityUpdate:
        if self.security_mode == "private_e2ee":
            self.data_classification = "e2ee_private"
        elif self.security_mode == "confidential" and self.data_classification in {
            "public",
            "internal",
        }:
            self.data_classification = "confidential"
        elif self.data_classification == "e2ee_private":
            raise ValueError("e2ee_private chỉ dùng với chế độ private_e2ee.")
        elif self.security_mode == "secure" and self.data_classification in {
            "confidential",
            "highly_confidential",
        }:
            raise ValueError("Dữ liệu nhạy cảm phải dùng chế độ confidential.")
        return self


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    title: str
    security_mode: str
    data_classification: str
    current_crypto_epoch: int
    crypto_suite: str
    retention_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class MessageSend(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    confirm_external_ai: bool = False

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
    crypto_epoch: int = 0
    encryption_scheme: str = "legacy-v1"
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


class E2eeChallengeResponse(BaseModel):
    id: str
    challenge: str
    expires_at: datetime


class E2eeDeviceRegisterRequest(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    challenge: str = Field(min_length=22, max_length=96)
    device_id: str = Field(min_length=36, max_length=36)
    display_name: str = Field(min_length=1, max_length=80)
    identity_key: str = Field(min_length=40, max_length=64)
    possession_signature: str = Field(min_length=80, max_length=128)
    signed_prekey: str = Field(min_length=40, max_length=512)
    signed_prekey_signature: str = Field(min_length=80, max_length=128)
    one_time_prekeys: list[str] = Field(default_factory=list, max_length=100)
    approver_device_id: str | None = Field(default=None, max_length=64)
    approval_signature: str | None = Field(default=None, max_length=128)

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if not cleaned:
            raise ValueError("Tên thiết bị không được để trống.")
        return cleaned

    @field_validator("challenge_id", "device_id")
    @classmethod
    def validate_uuid(cls, value: str) -> str:
        try:
            parsed = uuid.UUID(value)
        except ValueError as exc:
            raise ValueError("Định danh phải là UUID canonical.") from exc
        canonical = str(parsed)
        if canonical != value.lower():
            raise ValueError("Định danh phải là UUID canonical.")
        return canonical


class E2eeDeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_name: str
    fingerprint: str
    trust_state: str
    approved_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class E2eePreKeyBundleResponse(BaseModel):
    user_id: str
    device_id: str
    display_name: str
    fingerprint: str
    identity_key: str
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekey_id: str | None
    one_time_prekey: str | None


class E2eeEnvelopeSend(BaseModel):
    version: int = 1
    protocol: str
    recipient: str
    recipient_device_id: str | None = Field(default=None, max_length=64)
    epoch: int = Field(ge=0)
    client_message_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]*$",
    )
    sender_device_id: str = Field(min_length=1, max_length=64)
    message_kind: str = Field(default="application", pattern=r"^(application|commit|welcome)$")
    header: str = Field(min_length=2, max_length=25_000)
    ciphertext: str = Field(min_length=20, max_length=1_500_000)


class E2eeEnvelopeResponse(BaseModel):
    id: str
    session_id: str
    sender_device_id: str
    recipient_device_id: str | None
    protocol: str
    message_kind: str
    client_message_id: str
    header: str
    ciphertext: str
    group_epoch: int | None
    created_at: datetime


class E2eeMemberUpdate(BaseModel):
    username: str = Field(min_length=3, max_length=32)

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not USERNAME_RE.fullmatch(cleaned):
            raise ValueError("Tên đăng nhập không hợp lệ.")
        return cleaned


class ExportTicketResponse(BaseModel):
    download_url: str
    expires_at: datetime
