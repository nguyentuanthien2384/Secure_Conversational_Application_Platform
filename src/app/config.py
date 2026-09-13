from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlparse, urlsplit, urlunsplit

from dotenv import load_dotenv
from sqlalchemy.engine import make_url


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(
        f"{name} phải là một giá trị boolean rõ ràng: true/false, yes/no, on/off hoặc 1/0."
    )


def _csv_env(name: str, default: str = "") -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _read_secret_file(file_env: str) -> str | None:
    """Read one bounded single-line secret without retaining it in the environment."""
    path_value = os.getenv(file_env, "").strip()
    if not path_value:
        return None
    path = Path(path_value)
    try:
        if path.stat().st_size > 16_384:
            raise RuntimeError(f"{file_env} vượt quá giới hạn 16 KiB.")
        value = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Không thể đọc secret file được chỉ định bởi {file_env}.") from exc
    value = value.removesuffix("\n").removesuffix("\r")
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        raise RuntimeError(f"{file_env} phải chứa đúng một secret khác rỗng trên một dòng.")
    return value


def _secret_setting(value_env: str, file_env: str) -> str:
    value = os.getenv(value_env, "").strip()
    file_value = _read_secret_file(file_env)
    if value and file_value is not None:
        raise RuntimeError(f"Chỉ cấu hình một trong {value_env} hoặc {file_env}.")
    return file_value if file_value is not None else value


def database_url_with_file_password(raw_url: str) -> str:
    """Inject the file-backed database password without exposing it in process env."""
    password = _read_secret_file("DATABASE_PASSWORD_FILE")
    if password is None:
        return raw_url
    try:
        parsed = make_url(raw_url)
    except Exception as exc:
        raise RuntimeError("DATABASE_URL không hợp lệ.") from exc
    if parsed.username is None:
        raise RuntimeError("DATABASE_URL cần username khi dùng DATABASE_PASSWORD_FILE.")
    if parsed.password not in (None, ""):
        raise RuntimeError(
            "Không nhúng password vào DATABASE_URL khi DATABASE_PASSWORD_FILE được đặt."
        )
    split = urlsplit(raw_url)
    if not split.hostname:
        raise RuntimeError("DATABASE_URL không hợp lệ.")
    host = split.hostname
    if ":" in host:
        host = f"[{host}]"
    if split.port is not None:
        host = f"{host}:{split.port}"
    netloc = f"{quote(parsed.username, safe='')}:{quote(password, safe='')}@{host}"
    return urlunsplit((split.scheme, netloc, split.path, split.query, split.fragment))


def _redis_url_with_file_password(raw_url: str) -> str:
    password = _read_secret_file("REDIS_PASSWORD_FILE")
    if password is None:
        return raw_url
    parsed = urlsplit(raw_url)
    if not parsed.hostname:
        raise RuntimeError("REDIS_URL không hợp lệ.")
    if parsed.password not in (None, ""):
        raise RuntimeError("Không nhúng password vào REDIS_URL khi REDIS_PASSWORD_FILE được đặt.")
    username = parsed.username or "default"
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    netloc = f"{quote(username, safe='')}:{quote(password, safe='')}@{host}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


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
    allow_self_registration: bool = True
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
    gemini_model: str = "gemini-flash-lite-latest"
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
    # High-assurance controls introduced by the security-upgrade report.
    security_profile: str = "standard"
    key_provider: str = "local"
    dek_cache_seconds: int = 60
    vault_addr: str = ""
    vault_token_file: str = ""
    vault_transit_mount: str = "transit"
    vault_transit_key: str = "scap-conversations"
    vault_namespace: str = ""
    vault_allow_insecure_http: bool = False
    aws_kms_key_id: str = ""
    aws_region: str = ""
    gcp_kms_key_name: str = ""
    step_up_minutes: int = 5
    max_messages_per_session: int = 10_000
    confidential_retention_days: int = 7
    secure_retention_days: int = 90
    ai_consent_version: str = "2026-09"
    dlp_custom_terms: tuple[str, ...] = ()
    csp_report_only: bool = True
    gradio_max_file_size: str = "5mb"
    gradio_auth_mode: str = "application"
    oidc_user_header: str = "x-auth-request-user"
    oidc_proxy_secret_header: str = "x-scap-proxy-secret"
    oidc_proxy_secret_file: str = ""
    audit_worm_endpoint: str = ""
    audit_worm_token_file: str = ""
    audit_checkpoint_interval: int = 100
    retention_sweep_on_startup: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        environment = os.getenv("APP_ENV", "development").strip().lower()
        if environment not in {"development", "test", "production"}:
            raise RuntimeError(
                "APP_ENV không hợp lệ; chỉ chấp nhận development, test hoặc production."
            )
        security_profile = os.getenv("SECURITY_PROFILE", "standard").strip().lower()
        if security_profile not in {"standard", "high"}:
            raise RuntimeError("SECURITY_PROFILE chỉ chấp nhận standard hoặc high.")
        key_provider = os.getenv("KEY_PROVIDER", "local").strip().lower()
        if key_provider not in {"local", "vault", "aws-kms", "gcp-kms"}:
            raise RuntimeError("KEY_PROVIDER chỉ chấp nhận local, vault, aws-kms hoặc gcp-kms.")
        raw_database_url = os.getenv("DATABASE_URL", "sqlite:///./secure_chat.db")
        database_url = database_url_with_file_password(raw_database_url)
        raw_redis_url = os.getenv("REDIS_URL", "").strip()
        redis_url = _redis_url_with_file_password(raw_redis_url)
        # Development-only marker; the production guard below rejects it.
        secret_key = (
            _secret_setting("APP_SECRET_KEY", "APP_SECRET_KEY_FILE")
            or "development-only-change-me"  # nosec B105
        )
        google_genai_api_key = _secret_setting(
            "GOOGLE_GENAI_API_KEY", "GOOGLE_GENAI_API_KEY_FILE"
        )
        master_key = os.getenv("MASTER_ENCRYPTION_KEY", "").strip()
        keyring = _keyring_env()
        if (
            not master_key
            and not keyring
            and environment != "production"
            and key_provider == "local"
        ):
            master_key = derive_demo_key(secret_key)
        active_version_raw = os.getenv("ACTIVE_KEY_VERSION", "").strip()
        active_version = int(active_version_raw) if active_version_raw else None

        if environment == "production":
            # This comparison is a guard, not a secret assignment.
            if secret_key == "development-only-change-me" or len(secret_key) < 32:  # nosec B105
                raise RuntimeError(
                    "APP_SECRET_KEY phải được đặt và dài tối thiểu 32 ký tự ở production."
                )
            if key_provider == "local" and not master_key and not keyring:
                raise RuntimeError(
                    "MASTER_ENCRYPTION_KEY hoặc MASTER_ENCRYPTION_KEYS bắt buộc ở production."
                )
            if not redis_url:
                raise RuntimeError(
                    "REDIS_URL bắt buộc ở production để rate limit hoạt động đa instance."
                )
            if not _csv_env("ALLOWED_ORIGINS"):
                raise RuntimeError("ALLOWED_ORIGINS bắt buộc ở production.")
            if not _csv_env("ALLOWED_HOSTS"):
                raise RuntimeError(
                    "ALLOWED_HOSTS bắt buộc ở production (chống tấn công Host header)."
                )
            if "*" in _csv_env("ALLOWED_ORIGINS") or "*" in _csv_env("ALLOWED_HOSTS"):
                raise RuntimeError(
                    "Production không cho phép wildcard trong origin/host allowlist."
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

            if security_profile == "high":
                if key_provider == "local":
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc dùng Vault hoặc managed KMS; "
                        "KEK không được nằm trong biến môi trường ứng dụng."
                    )
                if master_key or keyring:
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không nạp MASTER_ENCRYPTION_KEY(S) vào web runtime. "
                        "Hãy migrate dữ liệu cũ bằng maintenance job rồi gỡ khóa khỏi runtime."
                    )
                if not database_url.startswith(("postgresql://", "postgresql+")):
                    raise RuntimeError("SECURITY_PROFILE=high bắt buộc dùng PostgreSQL.")
                immutable_image = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
                mutable_images = [
                    name
                    for name in (
                        "BASE_IMAGE",
                        "POSTGRES_IMAGE",
                        "REDIS_IMAGE",
                        "CADDY_IMAGE",
                    )
                    if not immutable_image.fullmatch(os.getenv(name, "").strip())
                ]
                if mutable_images:
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc image pin theo name@sha256 cho: "
                        + ", ".join(mutable_images)
                    )
                if _bool_env("VAULT_ALLOW_INSECURE_HTTP", False):
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không cho phép VAULT_ALLOW_INSECURE_HTTP."
                    )
                if key_provider == "vault":
                    vault_url = urlparse(os.getenv("VAULT_ADDR", "").strip())
                    if vault_url.scheme.lower() != "https":
                        raise RuntimeError("SECURITY_PROFILE=high bắt buộc Vault dùng HTTPS.")

                database_query = parse_qsl(urlparse(raw_database_url).query, keep_blank_values=True)
                database_tls = [
                    value for name, value in database_query if name.lower() == "sslmode"
                ]
                if len(database_tls) != 1 or database_tls[0].lower() != "verify-full":
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc đúng một sslmode=verify-full cho PostgreSQL."
                    )
                parsed_redis = urlparse(raw_redis_url)
                redis_query = parse_qsl(parsed_redis.query, keep_blank_values=True)
                redis_tls = [
                    value for name, value in redis_query if name.lower() == "ssl_cert_reqs"
                ]
                redis_hostname = [
                    value for name, value in redis_query if name.lower() == "ssl_check_hostname"
                ]
                if (
                    parsed_redis.scheme.lower() != "rediss"
                    or len(redis_tls) != 1
                    or redis_tls[0].lower() != "required"
                    or len(redis_hostname) != 1
                    or redis_hostname[0].lower() not in {"1", "true", "yes", "on"}
                ):
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc Redis TLS (rediss:// và "
                        "một ssl_cert_reqs=required, ssl_check_hostname=true)."
                    )
                required_secret_files = (
                    "APP_SECRET_KEY_FILE",
                    "DATABASE_PASSWORD_FILE",
                    "REDIS_PASSWORD_FILE",
                )
                missing_secret_files = [
                    name for name in required_secret_files if not os.getenv(name, "").strip()
                ]
                if missing_secret_files:
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc secret file cho: "
                        + ", ".join(missing_secret_files)
                    )
                if (
                    os.getenv("APP_SECRET_KEY", "").strip()
                    or os.getenv("GOOGLE_GENAI_API_KEY", "").strip()
                    or urlparse(raw_database_url).password not in (None, "")
                    or urlparse(raw_redis_url).password not in (None, "")
                ):
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không cho phép secret nhúng trong environment/URL."
                    )
                if _bool_env("ALLOW_SELF_REGISTRATION", True):
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không cho phép tự đăng ký tài khoản; "
                        "hãy provision qua quản trị/IdP."
                    )
                required_controls = {
                    "IDS_ENABLED": _bool_env("IDS_ENABLED", True),
                    "AUDIT_CHAIN_ENABLED": _bool_env("AUDIT_CHAIN_ENABLED", True),
                    "SIEM_JSON_LOGS": _bool_env("SIEM_JSON_LOGS", True),
                    "PASSWORD_BREACH_CHECK": _bool_env("PASSWORD_BREACH_CHECK", False),
                }
                disabled = [name for name, enabled in required_controls.items() if not enabled]
                if disabled:
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không cho phép tắt: " + ", ".join(disabled)
                    )
                if _bool_env("ALLOW_DEMO_AI", False):
                    raise RuntimeError("SECURITY_PROFILE=high không cho phép ALLOW_DEMO_AI.")
                if not _bool_env("RETENTION_SWEEP_ON_STARTUP", True):
                    raise RuntimeError(
                        "SECURITY_PROFILE=high không cho phép tắt retention sweep khi khởi động."
                    )
                worm_endpoint = os.getenv("AUDIT_WORM_ENDPOINT", "").strip()
                worm_token_file = os.getenv("AUDIT_WORM_TOKEN_FILE", "").strip()
                if not worm_endpoint or not worm_token_file:
                    raise RuntimeError(
                        "SECURITY_PROFILE=high bắt buộc AUDIT_WORM_ENDPOINT và "
                        "AUDIT_WORM_TOKEN_FILE để neo audit ra hệ thống ngoài."
                    )

        if key_provider == "vault":
            if not os.getenv("VAULT_ADDR", "").strip():
                raise RuntimeError("VAULT_ADDR bắt buộc khi KEY_PROVIDER=vault.")
            if not os.getenv("VAULT_TOKEN_FILE", "").strip():
                raise RuntimeError("VAULT_TOKEN_FILE bắt buộc khi KEY_PROVIDER=vault.")
        elif key_provider == "aws-kms" and not os.getenv("AWS_KMS_KEY_ID", "").strip():
            raise RuntimeError("AWS_KMS_KEY_ID bắt buộc khi KEY_PROVIDER=aws-kms.")
        elif key_provider == "gcp-kms" and not os.getenv("GCP_KMS_KEY_NAME", "").strip():
            raise RuntimeError("GCP_KMS_KEY_NAME bắt buộc khi KEY_PROVIDER=gcp-kms.")

        numeric_limits = {
            "DEK_CACHE_SECONDS": int(os.getenv("DEK_CACHE_SECONDS", "60")),
            "STEP_UP_MINUTES": int(os.getenv("STEP_UP_MINUTES", "5")),
            "MAX_MESSAGES_PER_SESSION": int(os.getenv("MAX_MESSAGES_PER_SESSION", "10000")),
            "CONFIDENTIAL_RETENTION_DAYS": int(os.getenv("CONFIDENTIAL_RETENTION_DAYS", "7")),
            "SECURE_RETENTION_DAYS": int(os.getenv("SECURE_RETENTION_DAYS", "90")),
            "AUDIT_CHECKPOINT_INTERVAL": int(os.getenv("AUDIT_CHECKPOINT_INTERVAL", "100")),
        }
        if numeric_limits["DEK_CACHE_SECONDS"] < 0:
            raise RuntimeError("DEK_CACHE_SECONDS không được âm.")
        for name in (
            "STEP_UP_MINUTES",
            "MAX_MESSAGES_PER_SESSION",
            "CONFIDENTIAL_RETENTION_DAYS",
            "SECURE_RETENTION_DAYS",
            "AUDIT_CHECKPOINT_INTERVAL",
        ):
            if numeric_limits[name] <= 0:
                raise RuntimeError(f"{name} phải là số nguyên dương.")

        gradio_auth_mode = os.getenv("GRADIO_AUTH_MODE", "application").strip().lower()
        if gradio_auth_mode not in {"application", "oidc"}:
            raise RuntimeError("GRADIO_AUTH_MODE chỉ chấp nhận application hoặc oidc.")
        if security_profile == "high" and gradio_auth_mode != "oidc":
            raise RuntimeError(
                "SECURITY_PROFILE=high bắt buộc GRADIO_AUTH_MODE=oidc để bảo vệ route Gradio ở tầng HTTP."
            )
        oidc_proxy_secret_file = os.getenv("OIDC_PROXY_SECRET_FILE", "").strip()
        if gradio_auth_mode == "oidc" and not oidc_proxy_secret_file:
            raise RuntimeError(
                "OIDC_PROXY_SECRET_FILE bắt buộc ở chế độ OIDC; không tin cậy header proxy trần."
            )
        header_re = re.compile(r"^[a-z0-9-]{3,64}$")
        oidc_user_header = os.getenv("OIDC_USER_HEADER", "x-auth-request-user").strip().lower()
        oidc_proxy_secret_header = (
            os.getenv("OIDC_PROXY_SECRET_HEADER", "x-scap-proxy-secret").strip().lower()
        )
        if not header_re.fullmatch(oidc_user_header) or not header_re.fullmatch(
            oidc_proxy_secret_header
        ):
            raise RuntimeError("Tên header OIDC/proxy không hợp lệ.")

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
            allow_self_registration=_bool_env("ALLOW_SELF_REGISTRATION", True),
            message_window_seconds=int(os.getenv("MESSAGE_WINDOW_SECONDS", "60")),
            message_max_attempts=int(os.getenv("MESSAGE_MAX_ATTEMPTS", "20")),
            mfa_issuer=os.getenv("MFA_ISSUER", "SCAP").strip() or "SCAP",
            mfa_challenge_minutes=int(os.getenv("MFA_CHALLENGE_MINUTES", "5")),
            mfa_recovery_codes=int(os.getenv("MFA_RECOVERY_CODES", "10")),
            mfa_window_seconds=int(os.getenv("MFA_WINDOW_SECONDS", "300")),
            mfa_max_attempts=int(os.getenv("MFA_MAX_ATTEMPTS", "5")),
            redis_url=redis_url,
            allowed_origins=_csv_env("ALLOWED_ORIGINS"),
            allowed_hosts=_csv_env("ALLOWED_HOSTS"),
            max_sessions_per_user=int(os.getenv("MAX_SESSIONS_PER_USER", "100")),
            csp_allow_unsafe_eval=_bool_env("CSP_ALLOW_UNSAFE_EVAL", False),
            password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "15")),
            password_breach_check=_bool_env("PASSWORD_BREACH_CHECK", False),
            allow_demo_ai=_bool_env("ALLOW_DEMO_AI", True),
            google_genai_api_key=google_genai_api_key,
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest"),
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
            security_profile=security_profile,
            key_provider=key_provider,
            dek_cache_seconds=numeric_limits["DEK_CACHE_SECONDS"],
            vault_addr=os.getenv("VAULT_ADDR", "").strip(),
            vault_token_file=os.getenv("VAULT_TOKEN_FILE", "").strip(),
            vault_transit_mount=os.getenv("VAULT_TRANSIT_MOUNT", "transit").strip() or "transit",
            vault_transit_key=os.getenv("VAULT_TRANSIT_KEY", "scap-conversations").strip()
            or "scap-conversations",
            vault_namespace=os.getenv("VAULT_NAMESPACE", "").strip(),
            vault_allow_insecure_http=_bool_env("VAULT_ALLOW_INSECURE_HTTP", False),
            aws_kms_key_id=os.getenv("AWS_KMS_KEY_ID", "").strip(),
            aws_region=os.getenv("AWS_REGION", "").strip(),
            gcp_kms_key_name=os.getenv("GCP_KMS_KEY_NAME", "").strip(),
            step_up_minutes=numeric_limits["STEP_UP_MINUTES"],
            max_messages_per_session=numeric_limits["MAX_MESSAGES_PER_SESSION"],
            confidential_retention_days=numeric_limits["CONFIDENTIAL_RETENTION_DAYS"],
            secure_retention_days=numeric_limits["SECURE_RETENTION_DAYS"],
            ai_consent_version=os.getenv("AI_CONSENT_VERSION", "2026-09").strip() or "2026-09",
            dlp_custom_terms=_csv_env("DLP_CUSTOM_TERMS"),
            csp_report_only=_bool_env("CSP_REPORT_ONLY", True),
            gradio_max_file_size=os.getenv("GRADIO_MAX_FILE_SIZE", "5mb").strip() or "5mb",
            gradio_auth_mode=gradio_auth_mode,
            oidc_user_header=oidc_user_header,
            oidc_proxy_secret_header=oidc_proxy_secret_header,
            oidc_proxy_secret_file=oidc_proxy_secret_file,
            audit_worm_endpoint=os.getenv("AUDIT_WORM_ENDPOINT", "").strip(),
            audit_worm_token_file=os.getenv("AUDIT_WORM_TOKEN_FILE", "").strip(),
            audit_checkpoint_interval=numeric_limits["AUDIT_CHECKPOINT_INTERVAL"],
            retention_sweep_on_startup=_bool_env("RETENTION_SWEEP_ON_STARTUP", True),
        )
