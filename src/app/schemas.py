from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import datetime
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
VALID_ROLES = {"user", "moderator", "admin"}
PageItem = TypeVar("PageItem")


class PageResponse(BaseModel, Generic[PageItem]):
    items: list[PageItem]
    total: int
    offset: int
    limit: int
    has_more: bool
    next_offset: int | None


VALID_SECURITY_MODES = {"secure", "confidential", "private_e2ee"}
VALID_DATA_CLASSES = {
    "public",
    "internal",
    "confidential",
    "highly_confidential",
    "e2ee_private",
}

# Explicit bidirectional embedding/override/isolate characters can make a URL
# or filename appear in a different order from the stored value ("Trojan
# Source" / visual phishing).  Do not reject ordinary Arabic/Hebrew text or the
# common LRM/RLM marks; only reject the high-risk directional controls which
# can open/close hidden direction scopes.
UNSAFE_BIDI_CONTROLS = frozenset(
    {
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    }
)


def _reject_unsafe_bidi_controls(value: str, *, field_label: str) -> str:
    if any(character in UNSAFE_BIDI_CONTROLS for character in value):
        raise ValueError(f"{field_label} chứa ký tự điều hướng Unicode không an toàn.")
    return value


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


class EmailUpdateRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class RecoveryCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class AccountEmailResponse(BaseModel):
    email: str | None
    verified_at: datetime | None
    pending_email: str | None
    delivery_available: bool


class PasswordResetRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=254)


class PasswordResetConfirm(BaseModel):
    identifier: str = Field(min_length=3, max_length=254)
    code: str = Field(min_length=6, max_length=32)
    new_password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, value: str) -> str:
        return RegisterRequest.validate_password(value)


class PasskeyCeremonyResponse(BaseModel):
    challenge_id: str
    public_key: dict


class PasskeyRegistrationVerify(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict
    name: str | None = Field(default=None, max_length=64)


class PasskeyAuthenticationVerify(BaseModel):
    challenge_id: str = Field(min_length=36, max_length=36)
    credential: dict


class PasskeyStepUpVerify(PasskeyAuthenticationVerify):
    """A WebAuthn assertion bound to the authenticated bearer session."""


class PasskeyResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    last_used_at: datetime | None
    backed_up: bool
    transports: list[str]


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
    # Browser-recognition token: send it back in X-SCAP-Device at the next
    # sign-in so the device is recognised. It never authorizes a request.
    device_token: str | None = None


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
    last_activity_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    is_current: bool


class SecurityActivityEventResponse(BaseModel):
    id: int
    created_at: datetime
    event_type: str
    title: str
    outcome: str
    outcome_label: str
    severity: Literal["info", "warning", "critical"]
    ip_address: str | None
    device: str | None
    by_administrator: bool


class PreviousSignInResponse(BaseModel):
    at: datetime
    ip_address: str | None
    device: str | None


class SecurityActivityResponse(BaseModel):
    previous_sign_in: PreviousSignInResponse | None
    failed_sign_ins_since_previous: int
    mfa_failures_since_previous: int
    new_device_sign_ins_since_previous: int
    events: list[SecurityActivityEventResponse]


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
        _reject_unsafe_bidi_controls(value, field_label="Tiêu đề")
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
        _reject_unsafe_bidi_controls(value, field_label="Tiêu đề")
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


MAX_CHAT_FILE_NAME_CHARS = 180
MAX_CHAT_FILE_CONTENT_CHARS = 30_000
ALLOWED_CHAT_FILE_EXTENSIONS: tuple[str, ...] = (
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl",
    ".xml", ".yaml", ".yml", ".log", ".ini", ".toml", ".cfg", ".conf",
    ".sql", ".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm",
    ".css", ".sh", ".bat", ".ps1", ".c", ".cpp", ".h", ".hpp",
    ".java", ".go", ".rs", ".rb", ".php", ".docx", ".pdf",
)


class MessageSend(BaseModel):
    content: str = Field(min_length=1, max_length=4000)
    confirm_external_ai: bool = False
    file_name: str | None = Field(default=None, max_length=MAX_CHAT_FILE_NAME_CHARS)
    file_content: str | None = Field(default=None, max_length=MAX_CHAT_FILE_CONTENT_CHARS)

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        _reject_unsafe_bidi_controls(value, field_label="Nội dung")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Nội dung không được để trống.")
        if any(ch in cleaned for ch in ("\x00", "\r", "\x1f")):
            raise ValueError("Nội dung chứa ký tự điều khiển không hợp lệ.")
        return cleaned

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _reject_unsafe_bidi_controls(value, field_label="Tên tệp đính kèm")
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Tên tệp đính kèm không được để trống.")
        if (
            "/" in cleaned
            or "\\" in cleaned
            or ".." in cleaned
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned)
        ):
            raise ValueError("Tên tệp đính kèm không hợp lệ.")
        lowered = cleaned.lower()
        matched_ext = next(
            (ext for ext in ALLOWED_CHAT_FILE_EXTENSIONS if lowered.endswith(ext)),
            None,
        )
        if matched_ext is None or len(cleaned) <= len(matched_ext):
            raise ValueError(
                "Định dạng tệp không được hỗ trợ. Hãy chọn tệp văn bản, dữ liệu, mã nguồn, .docx hoặc .pdf."
            )
        return cleaned

    @field_validator("file_content")
    @classmethod
    def validate_file_content(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _reject_unsafe_bidi_controls(value, field_label="Nội dung tệp đính kèm")
        normalized = value.replace("\r\n", "\n").replace("\r", "\n")
        if any((ord(ch) < 32 and ch not in ("\n", "\t")) or ord(ch) == 127 for ch in normalized):
            raise ValueError("Nội dung tệp đính kèm chứa ký tự điều khiển không hợp lệ.")
        cleaned = normalized.strip()
        if not cleaned:
            raise ValueError("Nội dung tệp đính kèm không được để trống.")
        return cleaned

    @model_validator(mode="after")
    def validate_file_attachment_pair(self) -> MessageSend:
        if (self.file_name is None) != (self.file_content is None):
            raise ValueError("Tệp đính kèm phải có đầy đủ cả tên tệp và nội dung tệp.")
        return self



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


class CryptoMessageCounts(BaseModel):
    """Disjoint counts of stored records, without reading their payloads."""

    total: int = Field(ge=0)
    envelope: int = Field(ge=0)
    legacy: int = Field(ge=0)
    e2ee: int = Field(ge=0)
    unknown: int = Field(ge=0)


class SessionCryptoInfoResponse(BaseModel):
    """Public encryption metadata; no key material or integrity claim."""

    session_id: str
    security_mode: Literal["secure", "confidential", "private_e2ee"]
    algorithm: Literal["AES-256-GCM", "client-controlled-e2ee"]
    key_bits: Literal[256] | None
    nonce_bits: Literal[96] | None
    tag_bits: Literal[128] | None
    current_crypto_epoch: int = Field(ge=0)
    key_provider: Literal["local", "vault", "aws-kms", "gcp-kms"] | None
    message_counts: CryptoMessageCounts
    e2ee_protocol_counts: dict[Literal["double-ratchet", "mls-rfc9420"], int]
    aad_fields: list[str]
    legacy_aad_fields: list[str]
    integrity_verification: Literal["not_performed"] = "not_performed"
    notes: list[
        Literal[
            "metadata_only_integrity_not_verified",
            "counts_are_stored_records",
            "server_can_decrypt_authorized_messages",
            "client_verifies_e2ee_ciphertexts",
            "legacy_messages_have_reduced_aad_binding",
            "unsupported_storage_format_present",
            "unexpected_ciphertext_storage_for_session_mode",
        ]
    ]


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


class E2eePreKeyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str = Field(min_length=36, max_length=36)
    challenge: str = Field(min_length=22, max_length=96)
    one_time_prekeys: list[str] = Field(default_factory=list, max_length=100)
    signed_prekey: str | None = Field(default=None, min_length=40, max_length=64)
    signed_prekey_signature: str | None = Field(default=None, min_length=80, max_length=128)
    update_signature: str = Field(min_length=80, max_length=128)

    @model_validator(mode="after")
    def complete_update(self):
        if bool(self.signed_prekey) != bool(self.signed_prekey_signature):
            raise ValueError("Signed prekey và chữ ký phải được cung cấp cùng nhau.")
        if not self.one_time_prekeys and self.signed_prekey is None:
            raise ValueError("Cần bổ sung prekey hoặc cập nhật signed prekey.")
        return self


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
