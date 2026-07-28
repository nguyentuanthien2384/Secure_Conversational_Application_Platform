from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from urllib.parse import urlparse

from dotenv import load_dotenv


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _keyring_env(name: str = "MASTER_ENCRYPTION_KEYS") -> dict[int, str]:
    """Parse ``v:key`` pairs used for encryption-key rotation.

    Format: ``MASTER_ENCRYPTION_KEYS=1:<base64>,2:<base64>``. Every listed key can
    decrypt; the highest version (or ACTIVE_KEY_VERSION) encrypts new data.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return {}
    keyring: dict[int, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        version, _, material = item.partition(":")
        if not material.strip():
            raise RuntimeError(f"{name} sai định dạng, cần 'version:base64key' (ví dụ '1:AAA...').")
        try:
            keyring[int(version)] = material.strip()
        except ValueError as exc:
            raise RuntimeError(f"{name}: version '{version}' phải là số nguyên.") from exc
    return keyring


def derive_demo_key(secret: str) -> str:
    """Derive a 256-bit development key and return URL-safe base64.

    Production deployments should set MASTER_ENCRYPTION_KEY explicitly.
    """
    digest = hashlib.sha256(("secure-chat:aes:" + secret).encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


@dataclass(frozen=True)
class Settings:
    app_name: str = "Secure Conversational Application Platform"
    environment: str = "development"
    database_url: str = "sqlite:///./secure_chat.db"
    # Development-only marker; the production guard below rejects it.
    secret_key: str = "development-only-change-me"  # nosec B105
    master_encryption_key: str = ""
    master_encryption_keys: tuple[tuple[int, str], ...] = ()
    active_key_version: int | None = None
    access_token_minutes: int = 30
    login_window_seconds: int = 300
    login_max_attempts: int = 5
    login_lockout_seconds: int = 900
    registration_window_seconds: int = 3600
    registration_max_attempts: int = 5
    message_window_seconds: int = 60
    message_max_attempts: int = 20
    # Issuer xuất hiện HAI lần trong otpauth URI (trong label và trong query),
    # nên tên dài đẩy mật độ QR lên đáng kể. Giữ ngắn; đây chỉ là nhãn hiển thị
    # trong ứng dụng xác thực và có thể đổi bất cứ lúc nào qua MFA_ISSUER.
    mfa_issuer: str = "SCAP"
    mfa_challenge_minutes: int = 5
    mfa_recovery_codes: int = 10
    mfa_window_seconds: int = 300
    mfa_max_attempts: int = 5
    redis_url: str = ""
    allowed_origins: tuple[str, ...] = ()
    allowed_hosts: tuple[str, ...] = ()
    max_sessions_per_user: int = 100
    csp_allow_unsafe_eval: bool = False
    password_min_length: int = 15
    password_breach_check: bool = False
    allow_demo_ai: bool = True
    google_genai_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash-lite"
    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = ""
    docs_enabled: bool = True
    seed_demo_data: bool = False
    ids_enabled: bool = True
    ids_block_threshold: int = 5
    ids_block_seconds: int = 900
    audit_chain_enabled: bool = True
    # Trần tuyệt đối cho một chuỗi phiên: dù gia hạn bao nhiêu lần, sau ngần
    # này giờ kể từ lần đăng nhập gốc vẫn phải xác thực lại từ đầu.
    session_absolute_hours: int = 8
    # Số lần được gọi /api/auth/refresh trong một cửa sổ, chống lạm dụng.
    refresh_window_seconds: int = 60
    refresh_max_attempts: int = 10
    siem_json_logs: bool = True
    password_change_max_attempts: int = 5
    password_change_window_seconds: int = 900

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        environment = os.getenv("APP_ENV", "development").strip().lower()
        database_url = os.getenv("DATABASE_URL", "sqlite:///./secure_chat.db")
        # Development-only marker; the production guard below rejects it.
        secret_key = os.getenv("APP_SECRET_KEY", "").strip() or "development-only-change-me"  # nosec B105
        master_key = os.getenv("MASTER_ENCRYPTION_KEY", "").strip()
        keyring = _keyring_env()
        if not master_key and not keyring and environment != "production":
            master_key = derive_demo_key(secret_key)
        active_version_raw = os.getenv("ACTIVE_KEY_VERSION", "").strip()
        active_version = int(active_version_raw) if active_version_raw else None

        if environment == "production":
            # This comparison is a guard, not a secret assignment.
            if secret_key == "development-only-change-me" or len(secret_key) < 32:  # nosec B105
                raise RuntimeError(
                    "APP_SECRET_KEY phải được đặt và dài tối thiểu 32 ký tự ở production."
                )
            if not master_key and not keyring:
                raise RuntimeError(
                    "MASTER_ENCRYPTION_KEY hoặc MASTER_ENCRYPTION_KEYS bắt buộc ở production."
                )
            if not os.getenv("REDIS_URL", "").strip():
                raise RuntimeError(
                    "REDIS_URL bắt buộc ở production để rate limit hoạt động đa instance."
                )
            if not _csv_env("ALLOWED_ORIGINS"):
                raise RuntimeError("ALLOWED_ORIGINS bắt buộc ở production.")
            if not _csv_env("ALLOWED_HOSTS"):
                raise RuntimeError(
                    "ALLOWED_HOSTS bắt buộc ở production (chống tấn công Host header)."
                )
            if _bool_env("DOCS_ENABLED", False):
                raise RuntimeError("DOCS_ENABLED phải tắt ở production.")
            if os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "").strip():
                raise RuntimeError(
                    "Không đặt BOOTSTRAP_ADMIN_PASSWORD ở production; tạo admin qua quy trình one-off."
                )
            if _bool_env("SEED_DEMO_DATA", False):
                raise RuntimeError(
                    "SEED_DEMO_DATA phải tắt ở production vì tài khoản mẫu có thông tin đăng nhập công khai."
                )
            if database_url.startswith(("postgresql://", "postgresql+")):
                runtime_user = urlparse(database_url).username
                if runtime_user in {"postgres", "secure_chat"}:
                    raise RuntimeError(
                        "DATABASE_URL production không được dùng tài khoản chủ/superuser; "
                        "hãy dùng vai trò runtime tối thiểu (ví dụ scap_app)."
                    )

        return cls(
            environment=environment,
            database_url=database_url,
            secret_key=secret_key,
            master_encryption_key=master_key,
            master_encryption_keys=tuple(sorted(keyring.items())),
            active_key_version=active_version,
            access_token_minutes=int(os.getenv("ACCESS_TOKEN_MINUTES", "30")),
            login_window_seconds=int(os.getenv("LOGIN_WINDOW_SECONDS", "300")),
            login_max_attempts=int(os.getenv("LOGIN_MAX_ATTEMPTS", "5")),
            login_lockout_seconds=int(os.getenv("LOGIN_LOCKOUT_SECONDS", "900")),
            registration_window_seconds=int(os.getenv("REGISTRATION_WINDOW_SECONDS", "3600")),
            registration_max_attempts=int(os.getenv("REGISTRATION_MAX_ATTEMPTS", "5")),
            message_window_seconds=int(os.getenv("MESSAGE_WINDOW_SECONDS", "60")),
            message_max_attempts=int(os.getenv("MESSAGE_MAX_ATTEMPTS", "20")),
            mfa_issuer=os.getenv("MFA_ISSUER", "SCAP").strip() or "SCAP",
            mfa_challenge_minutes=int(os.getenv("MFA_CHALLENGE_MINUTES", "5")),
            mfa_recovery_codes=int(os.getenv("MFA_RECOVERY_CODES", "10")),
            mfa_window_seconds=int(os.getenv("MFA_WINDOW_SECONDS", "300")),
            mfa_max_attempts=int(os.getenv("MFA_MAX_ATTEMPTS", "5")),
            redis_url=os.getenv("REDIS_URL", "").strip(),
            allowed_origins=_csv_env("ALLOWED_ORIGINS"),
            allowed_hosts=_csv_env("ALLOWED_HOSTS"),
            max_sessions_per_user=int(os.getenv("MAX_SESSIONS_PER_USER", "100")),
            csp_allow_unsafe_eval=_bool_env("CSP_ALLOW_UNSAFE_EVAL", False),
            password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "15")),
            password_breach_check=_bool_env("PASSWORD_BREACH_CHECK", False),
            allow_demo_ai=_bool_env("ALLOW_DEMO_AI", True),
            google_genai_api_key=os.getenv("GOOGLE_GENAI_API_KEY", ""),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite"),
            bootstrap_admin_username=os.getenv("BOOTSTRAP_ADMIN_USERNAME", ""),
            bootstrap_admin_password=os.getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
            docs_enabled=_bool_env("DOCS_ENABLED", environment != "production"),
            seed_demo_data=_bool_env("SEED_DEMO_DATA", False),
            ids_enabled=_bool_env("IDS_ENABLED", True),
            ids_block_threshold=int(os.getenv("IDS_BLOCK_THRESHOLD", "5")),
            ids_block_seconds=int(os.getenv("IDS_BLOCK_SECONDS", "900")),
            audit_chain_enabled=_bool_env("AUDIT_CHAIN_ENABLED", True),
            session_absolute_hours=int(os.getenv("SESSION_ABSOLUTE_HOURS", "8")),
            refresh_window_seconds=int(os.getenv("REFRESH_WINDOW_SECONDS", "60")),
            refresh_max_attempts=int(os.getenv("REFRESH_MAX_ATTEMPTS", "10")),
            siem_json_logs=_bool_env("SIEM_JSON_LOGS", True),
            password_change_max_attempts=int(os.getenv("PASSWORD_CHANGE_MAX_ATTEMPTS", "5")),
            password_change_window_seconds=int(os.getenv("PASSWORD_CHANGE_WINDOW_SECONDS", "900")),
        )
