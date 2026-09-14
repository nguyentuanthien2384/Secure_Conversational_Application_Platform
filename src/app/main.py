import hashlib
import json
import logging
import re
import secrets
import uuid
from collections.abc import Iterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from urllib.parse import unquote, urlsplit

import gradio as gr
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.audit import client_ip, record_audit, safe_user_agent
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.audit_checkpoint import AuditCheckpointError, AuditCheckpointService
from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.e2ee import (
    PROTOCOL_DOUBLE_RATCHET,
    PROTOCOL_MLS,
    E2EEValidationError,
    decode_base64_strict,
    encode_base64url,
    safety_fingerprint,
    validate_opaque_envelope,
    verify_device_approval,
    verify_device_possession,
    verify_ed25519_signature,
)
from src.app.envelope import EnvelopeCryptoService, EnvelopeEncryptionError
from src.app.gradio_ui import CUSTOM_CSS, THEME, build_ui
from src.app.ids import (
    DECOY_PATHS,
    SCANNER_AGENTS,
    Detection,
    IntrusionState,
    detect_anomalies,
    evidence_fingerprint,
    mitre_technique_for_rule,
    run_safe_detection_verification,
    scan_text,
)
from src.app.key_management import (
    AwsKmsKeyProvider,
    GcpKmsKeyProvider,
    KeyProvider,
    LocalAesKeyProvider,
    VaultTransitKeyProvider,
)
from src.app.models import (
    AuditEvent,
    AuthSession,
    ChatSession,
    ConversationMember,
    E2eeDevice,
    E2eeDeviceChallenge,
    E2eeEnvelope,
    E2eePreKey,
    MfaRecoveryCode,
    RevokedToken,
    SecureMessage,
    User,
)
from src.app.retention import enforce_retention
from src.app.schemas import (
    AdminCreateUser,
    AIConsentUpdate,
    AuditResponse,
    AuthSessionResponse,
    E2eeChallengeResponse,
    E2eeDeviceRegisterRequest,
    E2eeDeviceResponse,
    E2eeEnvelopeResponse,
    E2eeEnvelopeSend,
    E2eeMemberUpdate,
    E2eePreKeyBundleResponse,
    ExportTicketResponse,
    LoginRequest,
    MessageResponse,
    MessageSend,
    MfaActivateRequest,
    MfaActivateResponse,
    MfaChallengeResponse,
    MfaDisableRequest,
    MfaEnrollResponse,
    MfaVerifyRequest,
    PasswordChangeRequest,
    RawMessageResponse,
    RegisterRequest,
    SecurityAlertResponse,
    SessionCreate,
    SessionResponse,
    SessionSecurityUpdate,
    SessionUpdate,
    StepUpRequest,
    StepUpResponse,
    TokenResponse,
    UserResponse,
    UserRoleUpdate,
    UserStatusUpdate,
)
from src.app.security import (
    CryptoService,
    PasswordBreachCheckUnavailable,
    PasswordService,
    PwnedPasswordChecker,
    RedisSlidingWindowRateLimiter,
    SlidingWindowRateLimiter,
    TokenService,
    TotpService,
    generate_recovery_code,
)
from src.app.services import AIProviderError, AIService, ChatService, DLPPolicyViolation
from src.app.siem import configure_siem_logging, emit_security_event

logger = logging.getLogger("secure_chat")

bearer = HTTPBearer(auto_error=False)
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CSP_DIRECTIVE_RE = re.compile(r"^[a-z0-9-]{1,64}$")
DISABLED_GRADIO_UPLOAD_PATHS = frozenset(
    {"/gradio_api/upload", "/gradio_api/upload_progress"}
)


def _audit_safe_path(path: str) -> str:
    """Remove capability-bearing path segments before telemetry or IDS storage."""
    if path.startswith("/api/exports/"):
        return "/api/exports/[capability-redacted]"
    return path[:200]


def _is_disabled_gradio_file_request(path: str) -> bool:
    """Close Gradio file routes that this text-only application never uses.

    Gradio registers a generic upload API even when no File component exists.
    It can also proxy public HTTP(S) files through ``/gradio_api/file=...``.
    Neither capability belongs to SCAP's trust boundary: exports use the
    separate one-use streaming API and avatars/QR codes remain local files.
    Decode twice so a percent-encoded remote URL cannot bypass the decision.
    """
    normalized = path
    for _ in range(2):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    normalized = normalized.rstrip("/")
    lowered = normalized.lower()
    if lowered in DISABLED_GRADIO_UPLOAD_PATHS:
        return True
    file_prefix = next(
        (
            prefix
            for prefix in ("/gradio_api/file=", "/gradio_api/file/")
            if lowered.startswith(prefix)
        ),
        None,
    )
    if file_prefix is None:
        return False
    target = normalized[len(file_prefix) :].strip()
    parsed = urlsplit(target)
    return parsed.scheme.lower() in {"http", "https"} or target.startswith("//")


def _safe_csp_location(value: object) -> str:
    """Keep only a CSP keyword or URL origin; paths and queries may carry secrets."""
    raw = str(value or "").strip()[:2048]
    if raw in {"inline", "eval", "self", "data", "blob", "about"}:
        return raw
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return "other"
        host = parsed.hostname
        if ":" in host:
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme.lower()}://{host}{port}"
    except (TypeError, ValueError):
        return "other"


def _safe_csp_report(payload: object) -> dict[str, object] | None:
    """Normalize legacy and Reporting API CSP payloads into metadata-only fields."""
    candidate: object = payload
    if isinstance(payload, list):
        candidate = payload[0] if payload else None
    if not isinstance(candidate, dict):
        return None
    report = candidate.get("csp-report")
    if not isinstance(report, dict):
        report = candidate.get("body", candidate)
    if not isinstance(report, dict):
        return None

    def directive(*names: str) -> str:
        value = str(next((report[name] for name in names if name in report), "")).strip().lower()
        return value if CSP_DIRECTIVE_RE.fullmatch(value) else "unknown"

    status_code = report.get("status-code", report.get("statusCode"))
    safe_status = (
        status_code
        if isinstance(status_code, int)
        and not isinstance(status_code, bool)
        and 100 <= status_code <= 599
        else None
    )
    return {
        "effective_directive": directive("effective-directive", "effectiveDirective"),
        "violated_directive": directive("violated-directive", "violatedDirective"),
        "blocked_origin": _safe_csp_location(
            report.get("blocked-uri", report.get("blockedURL", ""))
        ),
        "document_origin": _safe_csp_location(
            report.get("document-uri", report.get("documentURL", ""))
        ),
        "status_code": safe_status,
    }


def _build_crypto_services(
    settings: Settings,
) -> tuple[CryptoService | None, KeyProvider, EnvelopeCryptoService]:
    """Build legacy decrypt support plus the selected external/local KEK provider."""
    encoded_keyring = dict(settings.master_encryption_keys)
    if settings.master_encryption_key:
        encoded_keyring.setdefault(1, settings.master_encryption_key)
    active_version = settings.active_key_version or (max(encoded_keyring) if encoded_keyring else 1)

    legacy_crypto = (
        CryptoService(keyring=encoded_keyring, active_key_version=active_version)
        if encoded_keyring
        else None
    )
    if settings.key_provider == "local":
        if not encoded_keyring:
            raise RuntimeError("Local key provider requires a configured keyring.")
        provider: KeyProvider = LocalAesKeyProvider.from_base64_keyring(
            encoded_keyring,
            active_version=active_version,
        )
    elif settings.key_provider == "vault":
        provider = VaultTransitKeyProvider(
            address=settings.vault_addr,
            token_file=settings.vault_token_file,
            key_name=settings.vault_transit_key,
            mount=settings.vault_transit_mount,
            namespace=settings.vault_namespace,
            allow_insecure_http=settings.vault_allow_insecure_http,
        )
    elif settings.key_provider == "aws-kms":
        provider = AwsKmsKeyProvider(
            key_id=settings.aws_kms_key_id,
            region=settings.aws_region,
        )
    else:
        provider = GcpKmsKeyProvider(key_name=settings.gcp_kms_key_name)

    envelope_crypto = EnvelopeCryptoService(
        provider,
        legacy_crypto=legacy_crypto,
        cache_ttl_seconds=settings.dek_cache_seconds,
    )
    return legacy_crypto, provider, envelope_crypto


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if any(
        value <= 0
        for value in (
            settings.access_token_minutes,
            settings.login_window_seconds,
            settings.login_max_attempts,
            settings.login_lockout_seconds,
            settings.registration_window_seconds,
            settings.registration_max_attempts,
            settings.message_window_seconds,
            settings.message_max_attempts,
        )
    ):
        raise ValueError("Security duration and rate-limit settings must be positive integers.")
    database = Database(settings.database_url)
    password_service = PasswordService()
    breach_checker = PwnedPasswordChecker(
        enabled=settings.password_breach_check,
        fail_closed=settings.security_profile == "high",
    )
    token_service = TokenService(settings.secret_key, settings.access_token_minutes)
    crypto_service, key_provider, envelope_crypto_service = _build_crypto_services(settings)
    limiter_type = RedisSlidingWindowRateLimiter if settings.redis_url else SlidingWindowRateLimiter
    limiter_args = (settings.redis_url,) if settings.redis_url else ()
    login_limiter = limiter_type(*limiter_args)
    registration_limiter = limiter_type(*limiter_args)
    message_limiter = limiter_type(*limiter_args)
    mfa_limiter = limiter_type(*limiter_args)
    password_change_limiter = limiter_type(*limiter_args)
    refresh_limiter = limiter_type(*limiter_args)
    totp_service = TotpService()
    chat_service = ChatService(envelope_crypto_service, AIService(settings))
    # Structured JSON security log on stdout for SIEM ingestion (Bài 7 §SIEM).
    configure_siem_logging(enabled=settings.siem_json_logs)
    # Application-layer IDS/IPS state (Bài 7 §7.3).
    intrusion_state = IntrusionState(
        block_threshold=settings.ids_block_threshold,
        block_seconds=settings.ids_block_seconds,
    )
    # HMAC key for the tamper-evident audit chain, derived from the app secret
    # with a distinct label so it is never the same key that signs JWTs.
    audit_key = derive_audit_key(settings.secret_key) if settings.audit_chain_enabled else None
    audit_checkpoint_service = (
        AuditCheckpointService(
            settings.secret_key,
            interval=settings.audit_checkpoint_interval,
            endpoint=settings.audit_worm_endpoint,
            token_file=settings.audit_worm_token_file,
            max_unanchored_events=settings.audit_max_unanchored_events,
        )
        if settings.audit_chain_enabled
        else None
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if settings.environment == "production" and settings.database_url.startswith(
            ("postgresql://", "postgresql+")
        ):
            database.assert_schema_ready()
        else:
            database.create_all()
        if settings.retention_sweep_on_startup:
            with database.session_factory() as retention_db:
                retention_result = enforce_retention(
                    retention_db,
                    secure_retention_days=settings.secure_retention_days,
                    confidential_retention_days=settings.confidential_retention_days,
                )
            envelope_crypto_service.clear_cache()
            if (
                retention_result.expired_sessions
                or retention_result.retention_deadlines_backfilled
            ):
                emit_security_event(
                    "retention.sweep",
                    details=retention_result.as_dict(),
                )
        if settings.bootstrap_admin_username and settings.bootstrap_admin_password:
            with database.session_factory() as db:
                username = settings.bootstrap_admin_username.strip().lower()
                existing = db.scalar(select(User).where(User.username == username))
                if existing is None:
                    admin = User(
                        username=username,
                        password_hash=password_service.hash(settings.bootstrap_admin_password),
                        role="admin",
                    )
                    db.add(admin)
                    db.commit()
        # Dữ liệu mẫu phục vụ demo/chấm bài: bật bằng SEED_DEMO_DATA=true trong .env.
        # Idempotent — không tạo trùng khi khởi động lại; tắt mặc định ở production.
        if settings.seed_demo_data:
            from src.app.demo_seed import seed_demo_data

            # Local demo cần có tín hiệu gần hiện tại để dashboard IDS (mặc
            # định quan sát 60 phút) không rỗng sau khi máy đã chạy lâu.
            if crypto_service is None:
                raise RuntimeError("Legacy demo seed requires an explicit migration key.")
            seed_demo_data(
                database,
                password_service,
                crypto_service,
                refresh_telemetry=True,
                log=logger.info,
            )
        yield
        envelope_crypto_service.clear_cache()
        database.engine.dispose()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description="Đồ án Bảo mật ứng dụng và hệ thống: chatbot đa người dùng, AES-GCM, RBAC và audit log.",
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url="/redoc" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.password_service = password_service
    app.state.token_service = token_service
    app.state.crypto_service = crypto_service
    app.state.key_provider = key_provider
    app.state.envelope_crypto_service = envelope_crypto_service
    app.state.totp_service = totp_service
    app.state.chat_service = chat_service
    app.state.intrusion_state = intrusion_state
    app.state.audit_key = audit_key
    app.state.audit_checkpoint_service = audit_checkpoint_service

    # Reject requests whose Host header is not explicitly allowed. This blocks
    # Host-header injection and DNS-rebinding attacks. Enabled whenever
    # ALLOWED_HOSTS is configured (mandatory in production, see config.py).
    if settings.allowed_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=list(settings.allowed_hosts),
        )

    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.allowed_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        )

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        supplied_request_id = request.headers.get("x-request-id", "")
        request_id = (
            supplied_request_id
            if REQUEST_ID_RE.fullmatch(supplied_request_id)
            else str(uuid.uuid4())
        )
        request.state.request_id = request_id

        if _is_disabled_gradio_file_request(request.url.path):
            # Return 404 rather than advertising an unused file-processing
            # surface. Do this before IDS/audit so attacker-controlled remote
            # URLs never enter telemetry and no network fetch can begin.
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={"detail": "File transfer is not available."},
                headers={
                    "X-Request-ID": request_id,
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "no-store",
                },
            )

        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > 1_048_576:
            return JSONResponse(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                content={"detail": "Request body vượt quá 1 MiB."},
                headers={"X-Request-ID": request_id},
            )

        # ── IDS/IPS: inspect before the request reaches any handler ──
        # Only the URL and headers are inspected here. The body is intentionally
        # NOT buffered: reading it in middleware would break streaming and give
        # an attacker a memory-amplification primitive. Body-level validation is
        # already handled structurally by Pydantic + the ORM.
        if settings.ids_enabled:
            source_ip = client_ip(request)
            safe_request_path = _audit_safe_path(request.url.path)
            blocked, retry_after = intrusion_state.is_blocked(source_ip)
            if blocked:
                emit_security_event(
                    "ids.block.enforced",
                    outcome="blocked",
                    source_ip=source_ip,
                    request_id=request_id,
                    details={"path": safe_request_path},
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Nguồn truy cập đang bị tạm chặn do hành vi bất thường."},
                    headers={"X-Request-ID": request_id, "Retry-After": str(retry_after)},
                )

            detections: list[Detection] = []
            surface = f"{safe_request_path}?{request.url.query}"
            for rule_id, severity, description, evidence in scan_text(surface):
                detections.append(
                    Detection(
                        rule_id=rule_id,
                        severity=severity,
                        engine="signature",
                        description=description,
                        source_ip=source_ip,
                        path=safe_request_path,
                        method=request.method,
                        evidence_sha256=evidence_fingerprint(evidence),
                        mitre_technique=mitre_technique_for_rule(rule_id),
                    )
                )
            user_agent = request.headers.get("user-agent", "")
            if SCANNER_AGENTS.search(user_agent):
                detections.append(
                    Detection(
                        rule_id="TOOL-001",
                        severity="medium",
                        engine="signature",
                        description="User-Agent của công cụ quét lỗ hổng tự động",
                        source_ip=source_ip,
                        path=safe_request_path,
                        method=request.method,
                        evidence_sha256=evidence_fingerprint(user_agent[:120]),
                    )
                )
            if DECOY_PATHS.search(request.url.path):
                detections.append(
                    Detection(
                        rule_id="RECON-001",
                        severity="medium",
                        engine="signature",
                        description="Dò đường dẫn nhạy cảm không tồn tại trên hệ thống này",
                        source_ip=source_ip,
                        path=safe_request_path,
                        method=request.method,
                        evidence_sha256=evidence_fingerprint(request.url.path[:120]),
                    )
                )

            if detections:
                newly_blocked = False
                for detection in detections:
                    newly_blocked = intrusion_state.record(detection) or newly_blocked
                with database.session_factory() as ids_db:
                    for detection in detections:
                        record_audit(
                            ids_db,
                            request,
                            "ids.signature",
                            outcome="blocked" if newly_blocked else "denied",
                            target_type="request",
                            target_id=detection.rule_id,
                            details={
                                "rule": detection.rule_id,
                                "severity": detection.severity,
                                "mitre_technique": detection.mitre_technique,
                                "path": detection.path,
                                "method": detection.method,
                                # Evidence can be attacker-controlled and may
                                # contain credentials. Keep only a correlation
                                # hash in the long-lived audit/SIEM stream.
                                "evidence_sha256": detection.evidence_sha256,
                            },
                        )
                    if newly_blocked:
                        record_audit(
                            ids_db,
                            request,
                            "ids.block",
                            outcome="blocked",
                            target_type="source_ip",
                            target_id=source_ip,
                            details={"block_seconds": settings.ids_block_seconds},
                        )
                if newly_blocked:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={
                            "detail": "Nguồn truy cập đang bị tạm chặn do hành vi bất thường."
                        },
                        headers={
                            "X-Request-ID": request_id,
                            "Retry-After": str(settings.ids_block_seconds),
                        },
                    )

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cache-Control"] = "no-store"
        path = request.url.path
        if path in {"/docs", "/redoc"}:
            # Swagger UI / ReDoc need an inline bootstrap script from a CDN.
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.redoc.ly; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        elif path.startswith("/api"):
            # The JSON API renders no markup, so it can ship a fully locked-down policy.
            csp = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        else:
            # Gradio demo UI. 'unsafe-eval' is dropped by default (CSP hardening phase 1) and
            # only re-enabled through CSP_ALLOW_UNSAFE_EVAL if a specific Gradio build needs it,
            # so the main origin no longer ships eval unconditionally. The UI deliberately avoids
            # gr.HTML for this reason: Gradio 6 compiles that component's markup with
            # new Function(), which this policy blocks — see _static_html in gradio_ui.py.
            # 'unsafe-inline' remains
            # pending a nonce/hash refactor (phase 2). object-src is locked to 'none'.
            script_eval = " 'unsafe-eval'" if settings.csp_allow_unsafe_eval else ""
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'unsafe-inline'{script_eval}; "
                "style-src 'self' 'unsafe-inline'; "
                "font-src 'self' data:; "
                "img-src 'self' data: blob:; "
                "connect-src 'self'; "
                "worker-src 'self' blob:; "
                "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        response.headers["Content-Security-Policy"] = csp
        if settings.csp_report_only and not path.startswith("/api"):
            # Observe whether the bundled Gradio release can run without inline
            # script before promoting this stricter policy to enforcement.
            report_policy = csp.replace(" 'unsafe-inline'", "").replace(" 'unsafe-eval'", "")
            response.headers["Content-Security-Policy-Report-Only"] = (
                report_policy + "; report-uri /api/security/csp-report"
            )
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.post("/api/security/csp-report", status_code=status.HTTP_204_NO_CONTENT)
    async def receive_csp_report(request: Request) -> Response:
        # CSP reports are generated before application login and therefore
        # cannot require bearer auth. Bound both request size and per-source
        # volume, then retain only origins/directive names—not URL paths,
        # queries, script samples, DOM snippets, or user content.
        allowed, _ = registration_limiter.allow(
            f"csp-report:{client_ip(request)}",
            max_attempts=30,
            window_seconds=60,
        )
        if not allowed:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16_384:
                return Response(status_code=status.HTTP_413_CONTENT_TOO_LARGE)
        try:
            payload = json.loads(body or b"{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        details = _safe_csp_report(payload)
        if details is not None:
            emit_security_event(
                "browser.csp.violation",
                outcome="denied",
                source_ip=client_ip(request),
                request_id=getattr(request.state, "request_id", None),
                details=details,
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Exception messages can contain SQL parameters, tokens, or provider
        # payloads. Retain only correlation + type in logs and return a generic
        # client response.
        logger.error(
            "Unhandled exception request_id=%s error_type=%s",
            getattr(request.state, "request_id", None),
            type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Đã xảy ra lỗi nội bộ. Hãy cung cấp request_id cho quản trị viên.",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    def get_db() -> Session:
        db = database.session_factory()
        try:
            yield db
        finally:
            db.close()

    def password_is_compromised(
        password: str,
        request: Request,
        db: Session,
        *,
        event_type: str,
        actor_id: str | None = None,
    ) -> bool:
        try:
            return breach_checker.is_compromised(password)
        except PasswordBreachCheckUnavailable as exc:
            record_audit(
                db,
                request,
                event_type,
                actor_id=actor_id,
                outcome="failure",
                details={"reason": "password_breach_check_unavailable"},
            )
            raise HTTPException(
                status_code=503,
                detail="Tạm thời chưa thể kiểm tra an toàn mật khẩu. Vui lòng thử lại sau.",
                headers={"Retry-After": "30"},
            ) from exc

    def as_utc(value: datetime) -> datetime:
        """Normalize timestamps returned by SQLite and timezone-aware databases."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def retained_session_clause(now: datetime | None = None):
        cutoff = now or utcnow()
        # A legacy NULL is an unknown/unenforced deadline, never an implicit
        # legal hold. The startup sweeper backfills/purges these rows, while
        # every access path fails closed if one is encountered meanwhile.
        return ChatSession.retention_expires_at > cutoff

    def sensitive_session_clause():
        return or_(
            ChatSession.security_mode.in_(("confidential", "private_e2ee")),
            ChatSession.data_classification.in_(
                ("confidential", "highly_confidential", "e2ee_private")
            ),
        )

    def session_is_sensitive(chat_session: ChatSession) -> bool:
        return chat_session.security_mode in {
            "confidential",
            "private_e2ee",
        } or chat_session.data_classification in {
            "confidential",
            "highly_confidential",
            "e2ee_private",
        }

    def has_active_sensitive_session(db: Session, user_id: str) -> bool:
        owned = db.scalar(
            select(ChatSession.id)
            .where(
                ChatSession.owner_id == user_id,
                retained_session_clause(),
                sensitive_session_clause(),
            )
            .limit(1)
        )
        if owned is not None:
            return True
        membership = db.scalar(
            select(ConversationMember.id)
            .join(ChatSession, ChatSession.id == ConversationMember.session_id)
            .where(
                ConversationMember.user_id == user_id,
                ConversationMember.removed_at.is_(None),
                retained_session_clause(),
                sensitive_session_clause(),
            )
            .limit(1)
        )
        return membership is not None

    def lock_user_row(
        db: Session,
        user: User,
        *,
        require_active: bool = True,
    ) -> User | None:
        """Acquire a portable transaction lock and refresh security state.

        PostgreSQL row locks are required in the high-security profile. A
        same-value UPDATE also serializes correctly on SQLite, where SELECT
        FOR UPDATE is ignored, so local/test deployments fail closed too.
        """

        conditions = [User.id == user.id]
        if require_active:
            conditions.append(User.is_active.is_(True))
        locked = db.execute(
            update(User)
            .where(*conditions)
            .values(token_version=User.token_version)
            .execution_options(synchronize_session=False)
        )
        if locked.rowcount != 1:
            return None
        db.refresh(user)
        return user

    def lock_auth_session_row(
        db: Session,
        jti: str,
        user_id: str,
    ) -> AuthSession | None:
        """Atomically claim one still-active bearer session for rotation/revocation.

        Both refresh and logout take the user lock first and this session lock
        second. The conditional same-value UPDATE works as a row lock on
        PostgreSQL and as a serialized writer claim on SQLite, while rechecking
        ``revoked_at`` after a concurrent request has committed.
        """
        claimed = db.execute(
            update(AuthSession)
            .where(
                AuthSession.jti == jti,
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
            )
            .values(revoked_at=AuthSession.revoked_at)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            return None
        auth_session = db.get(AuthSession, jti)
        if auth_session is None:
            return None
        db.refresh(auth_session)
        return auth_session

    def lock_chat_session_row(db: Session, chat_session: ChatSession) -> ChatSession | None:
        """Serialize policy, membership, epoch, and content mutations.

        Explicitly preserve ``updated_at`` to avoid firing SQLAlchemy's
        application-side on-update timestamp for this lock-only statement.
        """

        locked = db.execute(
            update(ChatSession)
            .where(ChatSession.id == chat_session.id)
            .values(
                current_crypto_epoch=ChatSession.current_crypto_epoch,
                updated_at=ChatSession.updated_at,
            )
            .execution_options(synchronize_session=False)
        )
        if locked.rowcount != 1:
            return None
        db.refresh(chat_session)
        return chat_session

    def revoke_active_e2ee_memberships(db: Session, user_id: str) -> tuple[int, int]:
        """Revoke memberships and advance each affected routing epoch once.

        The caller must hold the user's row lock. Member addition takes that
        same lock before a session lock, so the initial enumeration cannot miss
        a concurrently added membership.
        """

        session_ids = list(
            db.scalars(
                select(ConversationMember.session_id)
                .join(ChatSession, ChatSession.id == ConversationMember.session_id)
                .where(
                    ConversationMember.user_id == user_id,
                    ConversationMember.removed_at.is_(None),
                    ChatSession.security_mode == "private_e2ee",
                )
                .order_by(ConversationMember.session_id.asc())
            )
        )
        revoked = 0
        advanced_sessions = 0
        now = utcnow()
        for affected_session_id in session_ids:
            chat_session = db.get(ChatSession, affected_session_id)
            if chat_session is None or lock_chat_session_row(db, chat_session) is None:
                continue
            membership = db.scalar(
                select(ConversationMember)
                .where(
                    ConversationMember.session_id == affected_session_id,
                    ConversationMember.user_id == user_id,
                    ConversationMember.removed_at.is_(None),
                )
                .execution_options(populate_existing=True)
            )
            if membership is None or chat_session.security_mode != "private_e2ee":
                continue
            chat_session.current_crypto_epoch += 1
            membership.removed_epoch = chat_session.current_crypto_epoch
            membership.removed_at = now
            revoked += 1
            advanced_sessions += 1
        return revoked, advanced_sessions

    def reject_expired_session(
        chat_session: ChatSession,
        user: User,
        db: Session,
        request: Request,
    ) -> None:
        expires_at = chat_session.retention_expires_at
        if expires_at is not None and as_utc(expires_at) > utcnow():
            return
        session_id = chat_session.id
        security_mode = chat_session.security_mode
        db.delete(chat_session)
        db.commit()
        # The cache may still contain a plaintext DEK for the deleted row.
        envelope_crypto_service.clear_cache()
        record_audit(
            db,
            request,
            "chat.session.retention_expired",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
            details={"security_mode": security_mode, "deleted_on_access": True},
        )
        raise HTTPException(status_code=404, detail="Không tìm thấy phiên hội thoại.")

    def current_user(
        credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer)],
        db: Annotated[Session, Depends(get_db)],
    ) -> User:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Yêu cầu xác thực.")
        try:
            payload = token_service.decode(credentials.credentials)
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=401, detail="Token không hợp lệ hoặc đã hết hạn."
            ) from exc
        user = db.get(User, payload.get("sub"))
        auth_session = db.get(AuthSession, payload.get("jti"))
        if (
            user is None
            or not user.is_active
            or payload.get("ver") != user.token_version
            or auth_session is None
            or auth_session.user_id != user.id
            or auth_session.revoked_at is not None
            or db.get(RevokedToken, payload.get("jti")) is not None
        ):
            raise HTTPException(status_code=401, detail="Tài khoản không hợp lệ.")
        return user

    def admin_user(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Không đủ quyền truy cập.")
        if settings.security_profile == "high" and not user.mfa_enabled:
            raise HTTPException(status_code=403, detail="Tài khoản quản trị bắt buộc bật MFA.")
        return user

    def moderator_or_admin(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in ("moderator", "admin"):
            raise HTTPException(status_code=403, detail="Không đủ quyền truy cập.")
        if settings.security_profile == "high" and not user.mfa_enabled:
            raise HTTPException(status_code=403, detail="Tài khoản đặc quyền bắt buộc bật MFA.")
        return user

    def require_owned_session(
        session_id: str,
        user: User,
        db: Session,
        request: Request,
        *,
        for_update: bool = False,
        account_locked: bool = False,
    ) -> ChatSession:
        chat_session = chat_service.get_owned_session(db, user, session_id)
        if chat_session is None:
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="denied",
            )
            # Return 404 to reduce resource enumeration.
            raise HTTPException(status_code=404, detail="Không tìm thấy phiên hội thoại.")
        reject_expired_session(chat_session, user, db, request)

        # Mutations always lock the account before the conversation. This is
        # the common order used by MFA disable, suspension and E2EE lifecycle
        # operations, preventing both stale authorization and deadlocks.
        must_lock_user = not account_locked and (
            for_update
            or (settings.security_profile == "high" and session_is_sensitive(chat_session))
        )
        if must_lock_user and lock_user_row(db, user) is None:
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "account_state_changed"},
            )
            raise HTTPException(status_code=401, detail="Tài khoản không hợp lệ.")
        if for_update:
            if lock_chat_session_row(db, chat_session) is None:
                raise HTTPException(status_code=404, detail="Không tìm thấy phiên hội thoại.")
            # The row may have changed while this request waited for its lock.
            if chat_session.owner_id != user.id:
                raise HTTPException(status_code=404, detail="Không tìm thấy phiên hội thoại.")
            reject_expired_session(chat_session, user, db, request)
        if (
            settings.security_profile == "high"
            and session_is_sensitive(chat_session)
            and not user.mfa_enabled
        ):
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "sensitive_session_requires_mfa"},
            )
            raise HTTPException(
                status_code=403,
                detail="Hội thoại nhạy cảm bắt buộc tài khoản đã bật MFA.",
            )
        return chat_session

    def require_private_member_session(
        session_id: str,
        user: User,
        db: Session,
        request: Request,
    ) -> tuple[ChatSession, ConversationMember]:
        """Authorize one active member without revealing whether another session exists."""

        # Suspension/deletion lock the same account first, then every affected
        # conversation. Whichever transaction wins defines a clean boundary:
        # the request either completes before revocation or sees it afterwards.
        if lock_user_row(db, user) is None:
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="e2ee_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "account_state_changed"},
            )
            raise HTTPException(status_code=404, detail="Không tìm thấy phiên E2EE.")
        chat_session = db.get(ChatSession, session_id)
        if (
            chat_session is None
            or lock_chat_session_row(db, chat_session) is None
            or chat_session.security_mode != "private_e2ee"
        ):
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="e2ee_session",
                target_id=session_id,
                outcome="denied",
            )
            raise HTTPException(status_code=404, detail="Không tìm thấy phiên E2EE.")
        reject_expired_session(chat_session, user, db, request)

        # Re-query only after acquiring the session lock. ``populate_existing``
        # defeats the identity-map copy loaded before a concurrent removal.
        member = db.scalar(
            select(ConversationMember)
            .where(
                ConversationMember.session_id == session_id,
                ConversationMember.user_id == user.id,
                ConversationMember.removed_at.is_(None),
            )
            .execution_options(populate_existing=True)
        )
        if member is None:
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="e2ee_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "membership_revoked"},
            )
            raise HTTPException(status_code=404, detail="Không tìm thấy phiên E2EE.")
        if settings.security_profile == "high" and not user.mfa_enabled:
            record_audit(
                db,
                request,
                "authorization.denied",
                actor_id=user.id,
                target_type="e2ee_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "sensitive_session_requires_mfa"},
            )
            raise HTTPException(
                status_code=403,
                detail="Hội thoại E2EE bắt buộc tài khoản đã bật MFA.",
            )
        return chat_session, member

    # Gradio UI is mounted after all API routes are registered (see below).

    def revoke_all_auth_sessions(db: Session, user: User) -> None:
        """Invalidate every JWT for a user, including the requesting device."""
        now = utcnow()
        for auth_session in db.scalars(
            select(AuthSession).where(
                AuthSession.user_id == user.id,
                AuthSession.revoked_at.is_(None),
            )
        ):
            auth_session.revoked_at = now
        user.token_version += 1

    def issue_access_session(
        db: Session,
        request: Request,
        user: User,
        ip: str,
        *,
        root_issued_at: datetime | None = None,
        last_step_up_at: datetime | None = None,
        mark_step_up: bool = False,
    ) -> str:
        """Mint an access token and persist its server-side AuthSession record.

        Shared by password-only login and the MFA second step so both paths create
        an identical, revocable device session. ``root_issued_at`` is carried over
        by ``/api/auth/refresh`` so a renewed session keeps the timestamp of the
        original password (+ MFA) authentication, which is what the absolute
        session cap is measured against.
        """
        token = token_service.issue(user.id, user.username, user.role, user.token_version)
        token_payload = token_service.decode(token)
        issued_at = datetime.fromtimestamp(int(token_payload["iat"]), tz=timezone.utc)
        db.add(
            AuthSession(
                jti=str(token_payload["jti"]),
                user_id=user.id,
                issued_at=issued_at,
                expires_at=datetime.fromtimestamp(int(token_payload["exp"]), tz=timezone.utc),
                ip_address=ip,
                user_agent=safe_user_agent(request.headers.get("user-agent", "")),
                root_issued_at=root_issued_at or issued_at,
                last_step_up_at=issued_at if mark_step_up else last_step_up_at,
            )
        )
        return token

    def require_recent_step_up(
        credentials: HTTPAuthorizationCredentials,
        user: User,
        db: Session,
    ) -> AuthSession:
        try:
            payload = token_service.decode(credentials.credentials)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=401, detail="Token không hợp lệ.") from exc
        auth_session = db.get(AuthSession, str(payload["jti"]))
        if auth_session is None or auth_session.user_id != user.id:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ.")
        verified_at = auth_session.last_step_up_at
        if verified_at is None:
            raise HTTPException(
                status_code=403,
                detail="Cần xác thực lại trước thao tác nhạy cảm.",
                headers={"X-Step-Up-Required": "true"},
            )
        if verified_at.tzinfo is None:
            verified_at = verified_at.replace(tzinfo=timezone.utc)
        if utcnow() - verified_at > timedelta(minutes=settings.step_up_minutes):
            raise HTTPException(
                status_code=403,
                detail="Xác thực lại đã hết hạn; vui lòng xác minh mật khẩu/MFA.",
                headers={"X-Step-Up-Required": "true"},
            )
        return auth_session

    def load_mfa_secret(user: User) -> str | None:
        if not user.mfa_secret_ciphertext or not user.mfa_secret_nonce:
            return None
        return envelope_crypto_service.decrypt_user_secret(
            user,
            ciphertext_b64=user.mfa_secret_ciphertext,
            nonce_b64=user.mfa_secret_nonce,
            field=f"mfa:{user.id}",
        )

    def claim_mfa_account_version(db: Session, user: User, expected_version: int) -> bool:
        """Lock and re-check account state before consuming a challenge factor."""
        claimed = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.mfa_enabled.is_(True),
                User.token_version == expected_version,
            )
            # A same-value UPDATE is portable to SQLite and PostgreSQL and takes
            # the row lock needed to serialize against password/session resets.
            .values(token_version=expected_version)
            .execution_options(synchronize_session=False)
        )
        return claimed.rowcount == 1

    def consume_recovery_code(
        db: Session,
        user: User,
        candidate: str,
        *,
        expected_token_version: int | None = None,
    ) -> bool:
        """Match a submitted backup code against unused hashes; burn it if valid."""
        normalized = candidate.strip().lower().replace(" ", "")
        for record in db.scalars(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.used_at.is_(None),
            )
        ):
            if password_service.verify(record.code_hash, normalized):
                if expected_token_version is not None and not claim_mfa_account_version(
                    db, user, expected_token_version
                ):
                    return False
                consumed = db.execute(
                    update(MfaRecoveryCode)
                    .where(
                        MfaRecoveryCode.id == record.id,
                        MfaRecoveryCode.used_at.is_(None),
                    )
                    .values(used_at=utcnow())
                    .execution_options(synchronize_session=False)
                )
                if consumed.rowcount == 1:
                    return True
        return False

    def claim_totp_counter(
        db: Session,
        user: User,
        counter: int,
        *,
        expected_token_version: int | None = None,
    ) -> bool:
        """Atomically consume one TOTP time step across concurrent requests."""
        conditions = [
            User.id == user.id,
            User.mfa_enabled.is_(True),
            User.mfa_last_counter < counter,
        ]
        if expected_token_version is not None:
            conditions.append(User.token_version == expected_token_version)
        consumed = db.execute(
            update(User)
            .where(*conditions)
            .values(mfa_last_counter=counter)
            .execution_options(synchronize_session=False)
        )
        return consumed.rowcount == 1

    @app.get("/api/health")
    def health(db: Annotated[Session, Depends(get_db)]):
        # Deliberately minimal: an unauthenticated probe should confirm liveness
        # and nothing else. Leaking the environment name helps an attacker decide
        # whether guards such as DOCS_ENABLED or HSTS are active.
        db.scalar(select(func.count()).select_from(User))
        payload = {"status": "ok"}
        if settings.environment != "production":
            payload["environment"] = settings.environment
        return payload

    @app.post("/api/auth/register", response_model=UserResponse, status_code=201)
    def register(
        payload: RegisterRequest, request: Request, db: Annotated[Session, Depends(get_db)]
    ):
        allowed, retry_after = registration_limiter.allow(
            f"register:{client_ip(request)}",
            settings.registration_max_attempts,
            settings.registration_window_seconds,
        )
        if not allowed:
            record_audit(
                db,
                request,
                "auth.register",
                outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Too many account creation attempts. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        if not settings.allow_self_registration:
            record_audit(
                db,
                request,
                "auth.register",
                outcome="denied",
                details={"reason": "self_registration_disabled"},
            )
            raise HTTPException(
                status_code=403,
                detail="Hệ thống chỉ cho phép tài khoản được cấp bởi quản trị viên.",
            )
        if password_is_compromised(
            payload.password,
            request,
            db,
            event_type="auth.register",
        ):
            record_audit(
                db,
                request,
                "auth.register",
                outcome="failure",
                details={"reason": "breached_password"},
            )
            raise HTTPException(
                status_code=400,
                detail="Mật khẩu này đã xuất hiện trong dữ liệu rò rỉ công khai; hãy chọn mật khẩu khác.",
            )
        user = User(
            username=payload.username,
            password_hash=password_service.hash(payload.password),
            role="user",
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
        except IntegrityError as exc:
            db.rollback()
            record_audit(
                db,
                request,
                "auth.register",
                outcome="failure",
                details={"reason": "duplicate_or_invalid"},
            )
            raise HTTPException(
                status_code=409, detail="Không thể tạo tài khoản với thông tin này."
            ) from exc
        record_audit(
            db, request, "auth.register", actor_id=user.id, target_type="user", target_id=user.id
        )
        return user

    @app.post("/api/auth/login", response_model=None)
    def login(
        payload: LoginRequest, request: Request, db: Annotated[Session, Depends(get_db)]
    ) -> TokenResponse | MfaChallengeResponse:
        normalized_username = payload.username.strip().lower()
        ip = client_ip(request)
        limiter_keys = (f"login:account:{normalized_username}", f"login:ip:{ip}")
        attempts = [
            login_limiter.allow(key, settings.login_max_attempts, settings.login_window_seconds)
            for key in limiter_keys
        ]
        if not all(allowed for allowed, _ in attempts):
            retry_after = max(retry for allowed, retry in attempts if not allowed)
            record_audit(
                db,
                request,
                "auth.login",
                outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Thử đăng nhập quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )

        user = db.scalar(select(User).where(User.username == normalized_username))
        now = utcnow()
        locked = False
        if user is not None and user.locked_until is not None:
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > now:
                locked = True
            else:
                user.failed_login_attempts = 0
                user.locked_until = None
        # Verify an Argon2 hash even for an unknown username to reduce timing-based enumeration.
        password_matches = password_service.verify(
            user.password_hash if user is not None else password_service.dummy_hash,
            payload.password,
        )
        valid = user is not None and user.is_active and not locked and password_matches
        if not valid:
            outcome = "blocked" if locked else "failure"
            details = {"reason": "account_locked" if locked else "invalid_credentials"}
            if user is not None and user.is_active and not locked:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.login_max_attempts:
                    user.locked_until = now + timedelta(seconds=settings.login_lockout_seconds)
                    outcome = "blocked"
                    details = {"reason": "account_locked"}
                db.commit()
            record_audit(
                db,
                request,
                "auth.login",
                actor_id=user.id if user else None,
                outcome=outcome,
                details=details,
            )
            raise HTTPException(status_code=401, detail="Tên đăng nhập hoặc mật khẩu không hợp lệ.")

        if password_service.needs_rehash(user.password_hash):
            user.password_hash = password_service.hash(payload.password)
            db.commit()
        for key in limiter_keys:
            login_limiter.reset(key)
        user.failed_login_attempts = 0
        user.locked_until = None

        # Password proven. If MFA is on, stop here and return a short-lived
        # challenge instead of an access token; the session is created only after
        # the second factor is verified at /api/auth/mfa/verify.
        if user.mfa_enabled:
            challenge = token_service.issue_mfa_challenge(
                user.id,
                user.token_version,
                settings.mfa_challenge_minutes,
            )
            db.commit()
            record_audit(
                db,
                request,
                "auth.mfa.challenge",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
            )
            return MfaChallengeResponse(
                mfa_token=challenge,
                expires_in=settings.mfa_challenge_minutes * 60,
            )

        token = issue_access_session(db, request, user, ip, mark_step_up=True)
        db.commit()
        record_audit(
            db, request, "auth.login", actor_id=user.id, target_type="user", target_id=user.id
        )
        return TokenResponse(
            access_token=token,
            expires_in=settings.access_token_minutes * 60,
        )

    @app.post("/api/auth/mfa/verify", response_model=TokenResponse)
    def mfa_verify(
        payload: MfaVerifyRequest, request: Request, db: Annotated[Session, Depends(get_db)]
    ):
        ip = client_ip(request)
        try:
            challenge = token_service.decode_mfa_challenge(payload.mfa_token)
        except jwt.PyJWTError as exc:
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                outcome="failure",
                details={"reason": "bad_challenge"},
            )
            raise HTTPException(
                status_code=401, detail="Phiên xác thực hai lớp không hợp lệ hoặc đã hết hạn."
            ) from exc

        user_id = str(challenge["sub"])
        challenge_jti = str(challenge["jti"])
        if db.get(RevokedToken, challenge_jti) is not None:
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user_id,
                outcome="failure",
                details={"reason": "challenge_replayed"},
            )
            raise HTTPException(status_code=401, detail="Phiên xác thực hai lớp đã được sử dụng.")
        allowed, retry_after = mfa_limiter.allow(
            f"mfa:{user_id}", settings.mfa_max_attempts, settings.mfa_window_seconds
        )
        if not allowed:
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user_id,
                outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Thử mã xác thực quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )

        user = db.get(User, user_id)
        if (
            user is None
            or not user.is_active
            or challenge.get("ver") != user.token_version
            or not user.mfa_enabled
        ):
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user_id,
                outcome="failure",
                details={"reason": "account_state_changed"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được mã.")
        secret = load_mfa_secret(user)
        if secret is None:
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user_id,
                outcome="failure",
                details={"reason": "mfa_secret_unavailable"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được mã.")

        matched_counter = totp_service.verify(
            secret, payload.code, after_counter=user.mfa_last_counter
        )
        used_recovery = False
        if matched_counter is None:
            used_recovery = consume_recovery_code(
                db,
                user,
                payload.code,
                expected_token_version=int(challenge["ver"]),
            )
            if not used_recovery:
                db.commit()
                record_audit(
                    db,
                    request,
                    "auth.mfa.verify",
                    actor_id=user.id,
                    outcome="failure",
                    details={"reason": "invalid_code"},
                )
                raise HTTPException(status_code=401, detail="Không xác thực được mã.")
        else:
            if not claim_totp_counter(
                db,
                user,
                matched_counter,
                expected_token_version=int(challenge["ver"]),
            ):
                db.rollback()
                record_audit(
                    db,
                    request,
                    "auth.mfa.verify",
                    actor_id=user.id,
                    outcome="failure",
                    details={"reason": "code_replay"},
                )
                raise HTTPException(status_code=401, detail="Không xác thực được mã.")

        mfa_limiter.reset(f"mfa:{user_id}")
        db.add(
            RevokedToken(
                jti=challenge_jti,
                user_id=user.id,
                expires_at=datetime.fromtimestamp(int(challenge["exp"]), tz=timezone.utc),
                reason="mfa_challenge_used",
            )
        )
        try:
            db.flush()
        except IntegrityError as exc:
            # Two valid factors racing on one challenge must produce one login,
            # not an unhandled uniqueness error or two bearer sessions.
            db.rollback()
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "challenge_replayed"},
            )
            raise HTTPException(status_code=401, detail="Phiên MFA đã được sử dụng.") from exc
        token = issue_access_session(db, request, user, ip, mark_step_up=True)
        db.commit()
        record_audit(
            db,
            request,
            "auth.mfa.verify",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            details={"method": "recovery_code" if used_recovery else "totp"},
        )
        return TokenResponse(access_token=token, expires_in=settings.access_token_minutes * 60)

    @app.post("/api/auth/mfa/enroll", response_model=MfaEnrollResponse)
    def mfa_enroll(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        if user.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA đã được bật cho tài khoản này.")
        secret = totp_service.generate_secret()
        ciphertext, nonce = envelope_crypto_service.encrypt_user_secret(
            user,
            plaintext=secret,
            field=f"mfa:{user.id}",
        )
        # Store as pending (mfa_enabled stays False) until a valid code proves the
        # user copied the seed correctly into their authenticator app.
        user.mfa_secret_ciphertext = ciphertext
        user.mfa_secret_nonce = nonce
        db.commit()
        record_audit(
            db, request, "auth.mfa.enroll", actor_id=user.id, target_type="user", target_id=user.id
        )
        return MfaEnrollResponse(
            secret=secret,
            provisioning_uri=totp_service.provisioning_uri(
                secret, user.username, settings.mfa_issuer
            ),
        )

    @app.post("/api/auth/mfa/activate", response_model=MfaActivateResponse)
    def mfa_activate(
        payload: MfaActivateRequest,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        allowed, retry_after = mfa_limiter.allow(
            f"mfa-activate:{user.id}",
            settings.mfa_max_attempts,
            settings.mfa_window_seconds,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Thử kích hoạt MFA quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )
        if user.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA đã được bật.")
        secret = load_mfa_secret(user)
        if secret is None:
            raise HTTPException(status_code=409, detail="Chưa khởi tạo MFA. Gọi /enroll trước.")
        matched_counter = totp_service.verify(secret, payload.code)
        if matched_counter is None:
            record_audit(
                db,
                request,
                "auth.mfa.activate",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "invalid_code"},
            )
            raise HTTPException(status_code=400, detail="Mã TOTP không đúng.")

        activated = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.mfa_enabled.is_(False),
                User.mfa_last_counter < matched_counter,
            )
            .values(mfa_enabled=True, mfa_last_counter=matched_counter)
            .execution_options(synchronize_session=False)
        )
        if activated.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Mã TOTP đã được sử dụng.")
        # The conditional UPDATE deliberately bypasses ORM synchronization so
        # concurrent activation attempts cannot both win. Refresh before the
        # remaining ORM work to avoid carrying the pre-activation state.
        db.refresh(user)
        plain_codes = [generate_recovery_code() for _ in range(settings.mfa_recovery_codes)]
        db.add_all(
            MfaRecoveryCode(user_id=user.id, code_hash=password_service.hash(code))
            for code in plain_codes
        )
        # Force other devices to re-authenticate now that a second factor exists.
        revoke_all_auth_sessions(db, user)
        db.commit()
        mfa_limiter.reset(f"mfa-activate:{user.id}")
        record_audit(
            db, request, "auth.mfa.enabled", actor_id=user.id, target_type="user", target_id=user.id
        )
        return MfaActivateResponse(recovery_codes=plain_codes)

    @app.post("/api/auth/mfa/disable", status_code=204)
    def mfa_disable(
        payload: MfaDisableRequest,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        allowed, retry_after = mfa_limiter.allow(
            f"mfa-disable:{user.id}",
            settings.mfa_max_attempts,
            settings.mfa_window_seconds,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Thử tắt MFA quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )
        if not user.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA chưa được bật.")
        expected_token_version = user.token_version
        secret = load_mfa_secret(user)
        password_ok = password_service.verify(user.password_hash, payload.password)
        # Validate the password before attempting a recovery code. Otherwise an
        # attacker who knows a backup code could burn it even with a bad password.
        if not password_ok:
            db.commit()
            record_audit(
                db,
                request,
                "auth.mfa.disable",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được yêu cầu tắt MFA.")
        matched_counter = (
            totp_service.verify(secret, payload.code, after_counter=user.mfa_last_counter)
            if secret is not None
            else None
        )
        if matched_counter is not None:
            code_ok = claim_totp_counter(
                db,
                user,
                matched_counter,
                expected_token_version=expected_token_version,
            )
        else:
            code_ok = consume_recovery_code(
                db,
                user,
                payload.code,
                expected_token_version=expected_token_version,
            )
        if not code_ok:
            # A zero-row conditional update means another request consumed the
            # same TOTP time step (or already disabled MFA).
            db.rollback()
            record_audit(
                db,
                request,
                "auth.mfa.disable",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được yêu cầu tắt MFA.")

        # The factor claim above holds the user-row lock. Refresh before the
        # policy query so account changes and sensitive-session creation are
        # serialized with this decision. Rollback preserves the one-time factor
        # when policy (rather than bad credentials) denies the operation.
        db.refresh(user)
        if (
            not user.mfa_enabled
            or user.token_version != expected_token_version
            or (
                settings.security_profile == "high"
                and has_active_sensitive_session(db, user.id)
            )
        ):
            policy_denied = (
                user.mfa_enabled
                and user.token_version == expected_token_version
                and settings.security_profile == "high"
            )
            db.rollback()
            record_audit(
                db,
                request,
                "auth.mfa.disable",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                outcome="denied" if policy_denied else "failure",
                details={
                    "reason": "active_sensitive_session" if policy_denied else "state_changed"
                },
            )
            if policy_denied:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Không thể tắt MFA khi tài khoản còn tham gia hội thoại nhạy cảm; "
                        "hãy xóa, hạ cấp hoặc rời các hội thoại đó trước."
                    ),
                )
            raise HTTPException(status_code=409, detail="Trạng thái MFA vừa thay đổi; hãy thử lại.")

        disabled = db.execute(
            update(User)
            .where(
                User.id == user.id,
                User.mfa_enabled.is_(True),
                User.token_version == expected_token_version,
            )
            .values(
                mfa_enabled=False,
                mfa_secret_ciphertext=None,
                mfa_secret_nonce=None,
                mfa_last_counter=0,
            )
            .execution_options(synchronize_session=False)
        )
        if disabled.rowcount != 1:
            db.rollback()
            record_audit(
                db,
                request,
                "auth.mfa.disable",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "state_changed"},
            )
            raise HTTPException(status_code=409, detail="Trạng thái MFA vừa thay đổi; hãy thử lại.")
        db.refresh(user)
        for record in db.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)):
            db.delete(record)
        revoke_all_auth_sessions(db, user)
        db.commit()
        mfa_limiter.reset(f"mfa-disable:{user.id}")
        record_audit(
            db,
            request,
            "auth.mfa.disabled",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        return Response(status_code=204)

    @app.get("/api/auth/me", response_model=UserResponse)
    def me(user: Annotated[User, Depends(current_user)]):
        return user

    @app.post("/api/auth/step-up", response_model=StepUpResponse)
    def step_up_authentication(
        payload: StepUpRequest,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        """Re-prove password and, when enabled, MFA for sensitive operations."""
        allowed, retry_after = password_change_limiter.allow(
            f"step-up:{user.id}",
            settings.password_change_max_attempts,
            settings.password_change_window_seconds,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Xác thực lại quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )
        valid = password_service.verify(user.password_hash, payload.password)
        matched_counter: int | None = None
        used_recovery = False
        if valid and user.mfa_enabled:
            secret = load_mfa_secret(user)
            if secret is None or not payload.code:
                valid = False
            else:
                matched_counter = totp_service.verify(
                    secret,
                    payload.code,
                    after_counter=user.mfa_last_counter,
                )
                used_recovery = matched_counter is None and consume_recovery_code(
                    db, user, payload.code
                )
                valid = matched_counter is not None or used_recovery
                if matched_counter is not None and not claim_totp_counter(
                    db, user, matched_counter
                ):
                    valid = False
                    matched_counter = None
        if not valid:
            db.commit()
            record_audit(
                db,
                request,
                "auth.step_up",
                actor_id=user.id,
                outcome="failure",
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được yêu cầu.")

        token_payload = token_service.decode(credentials.credentials)
        auth_session = db.get(AuthSession, str(token_payload["jti"]))
        if auth_session is None or auth_session.user_id != user.id:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ.")
        verified_at = utcnow()
        auth_session.last_step_up_at = verified_at
        db.commit()
        password_change_limiter.reset(f"step-up:{user.id}")
        record_audit(
            db,
            request,
            "auth.step_up",
            actor_id=user.id,
            target_type="auth_session",
            target_id=auth_session.jti,
            details={"method": "recovery_code" if used_recovery else "password_mfa"},
        )
        return StepUpResponse(
            verified_at=verified_at,
            valid_for_seconds=settings.step_up_minutes * 60,
        )

    @app.patch("/api/auth/ai-consent", response_model=UserResponse)
    def update_ai_consent(
        payload: AIConsentUpdate,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        consent_version_changed = (
            payload.ai_data_consent and user.ai_consent_version != settings.ai_consent_version
        )
        if user.ai_data_consent != payload.ai_data_consent or consent_version_changed:
            user.ai_data_consent = payload.ai_data_consent
            user.ai_consent_at = utcnow() if payload.ai_data_consent else None
            user.ai_consent_version = (
                settings.ai_consent_version if payload.ai_data_consent else None
            )
            db.commit()
            db.refresh(user)
            record_audit(
                db,
                request,
                "privacy.ai_consent",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                details={
                    "consented": payload.ai_data_consent,
                    "policy_version": settings.ai_consent_version,
                },
            )
        return user

    @app.post("/api/auth/logout", status_code=204)
    def logout(
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        payload = token_service.decode(credentials.credentials)
        old_jti = str(payload["jti"])
        expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
        if lock_user_row(db, user) is None or payload.get("ver") != user.token_version:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ.")
        auth_session = lock_auth_session_row(db, old_jti, user.id)
        revoked_family = auth_session is None
        if revoked_family:
            # A refresh may have won after current_user validated the old token.
            # Revoke every descendant conservatively so a stolen bearer cannot
            # keep the session alive by racing the legitimate logout request.
            revoke_all_auth_sessions(db, user)
        else:
            auth_session.revoked_at = utcnow()
        if db.get(RevokedToken, old_jti) is None:
            db.add(
                RevokedToken(
                    jti=old_jti,
                    user_id=user.id,
                    expires_at=expires_at,
                    reason="logout_after_rotation" if revoked_family else "logout",
                )
            )
        db.commit()
        record_audit(
            db,
            request,
            "auth.logout",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            details={"scope": "all_sessions" if revoked_family else "current_session"},
        )
        return Response(status_code=204)

    @app.post("/api/auth/refresh", response_model=TokenResponse)
    def refresh_session(
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        """Xoay access token còn hiệu lực thành token mới (sliding session).

        Ba tính chất bảo mật cần nêu rõ trong báo cáo:

        1. **Xoay, không nhân bản.** jti cũ bị đưa vào denylist và AuthSession
           của nó bị thu hồi ngay, nên tại mỗi thời điểm một thiết bị chỉ có
           đúng một token sống. Nếu token cũ bị đánh cắp, nó chết ngay khi
           người dùng thật gia hạn.
        2. **Trần tuyệt đối.** Mốc ``root_issued_at`` được mang sang token mới,
           nên chuỗi gia hạn không thể vượt quá ``SESSION_ABSOLUTE_HOURS`` tính
           từ lần đăng nhập gốc. Không có ràng buộc này, sliding session biến
           một lần xác thực thành quyền truy cập vĩnh viễn.
        3. **Không hạ cấp yêu cầu xác thực.** Endpoint đòi một access token còn
           hiệu lực; token hết hạn không gia hạn được, và MFA challenge (audience
           khác) không bao giờ dùng được ở đây.
        """
        ip = client_ip(request)
        allowed, retry_after = refresh_limiter.allow(
            f"refresh:{user.id}", settings.refresh_max_attempts, settings.refresh_window_seconds
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Gia hạn phiên quá nhiều lần. Thử lại sau.",
                headers={"Retry-After": str(retry_after)},
            )

        payload = token_service.decode(credentials.credentials)
        old_jti = str(payload["jti"])
        if lock_user_row(db, user) is None or payload.get("ver") != user.token_version:
            raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ.")
        old_session = lock_auth_session_row(db, old_jti, user.id)
        if old_session is None or db.get(RevokedToken, old_jti) is not None:
            raise HTTPException(
                status_code=401,
                detail="Token đã được xoay hoặc thu hồi; vui lòng đăng nhập lại.",
            )

        root_issued_at = old_session.root_issued_at or old_session.issued_at
        if root_issued_at is not None and root_issued_at.tzinfo is None:
            root_issued_at = root_issued_at.replace(tzinfo=timezone.utc)

        now = utcnow()
        if root_issued_at is not None:
            age = now - root_issued_at
            if age > timedelta(hours=settings.session_absolute_hours):
                record_audit(
                    db,
                    request,
                    "auth.session.refresh",
                    actor_id=user.id,
                    outcome="denied",
                    target_type="user",
                    target_id=user.id,
                    details={"reason": "absolute_lifetime_exceeded"},
                )
                raise HTTPException(
                    status_code=401,
                    detail=(
                        f"Phiên đã vượt quá thời hạn tối đa "
                        f"{settings.session_absolute_hours} giờ. Vui lòng đăng nhập lại."
                    ),
                )

        token = issue_access_session(
            db,
            request,
            user,
            ip,
            root_issued_at=root_issued_at,
            last_step_up_at=old_session.last_step_up_at,
        )
        # Thu hồi token cũ SAU khi đã cấp token mới, trong cùng transaction.
        db.add(
            RevokedToken(
                jti=old_jti,
                user_id=user.id,
                expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc),
                reason="refresh",
            )
        )
        old_session.revoked_at = now
        db.commit()
        record_audit(
            db,
            request,
            "auth.session.refresh",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        return TokenResponse(
            access_token=token,
            expires_in=settings.access_token_minutes * 60,
        )

    @app.patch("/api/auth/password", status_code=204)
    def change_password(
        payload: PasswordChangeRequest,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        allowed, retry_after = password_change_limiter.allow(
            f"password-change:{user.id}",
            settings.password_change_max_attempts,
            settings.password_change_window_seconds,
        )
        if not allowed:
            record_audit(
                db,
                request,
                "auth.password_change",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Thử đổi mật khẩu quá nhiều lần.",
                headers={"Retry-After": str(retry_after)},
            )
        if not password_service.verify(user.password_hash, payload.current_password):
            record_audit(
                db,
                request,
                "auth.password_change",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                outcome="failure",
                details={"reason": "invalid_current_password"},
            )
            raise HTTPException(
                status_code=401, detail="Unable to change password with the supplied credentials."
            )
        if payload.current_password == payload.new_password:
            raise HTTPException(
                status_code=422, detail="New password must differ from the current password."
            )
        if password_is_compromised(
            payload.new_password,
            request,
            db,
            event_type="auth.password_change",
            actor_id=user.id,
        ):
            record_audit(
                db,
                request,
                "auth.password_change",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                outcome="failure",
                details={"reason": "breached_password"},
            )
            raise HTTPException(
                status_code=400,
                detail="Mật khẩu mới đã xuất hiện trong dữ liệu rò rỉ công khai; hãy chọn mật khẩu khác.",
            )
        user.password_hash = password_service.hash(payload.new_password)
        revoke_all_auth_sessions(db, user)
        db.commit()
        record_audit(
            db,
            request,
            "auth.password_change",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            details={"token_version": user.token_version},
        )
        return Response(status_code=204)

    @app.get("/api/auth/sessions", response_model=list[AuthSessionResponse])
    def list_auth_sessions(
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        current_jti = str(token_service.decode(credentials.credentials)["jti"])
        sessions = list(
            db.scalars(
                select(AuthSession)
                .where(
                    AuthSession.user_id == user.id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > utcnow(),
                )
                .order_by(AuthSession.issued_at.desc())
            )
        )
        return [
            AuthSessionResponse(
                id=session.jti,
                issued_at=session.issued_at,
                expires_at=session.expires_at,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
                is_current=session.jti == current_jti,
            )
            for session in sessions
        ]

    @app.delete("/api/auth/sessions/{session_jti}", status_code=204)
    def revoke_auth_session(
        session_jti: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        auth_session = db.get(AuthSession, session_jti)
        if (
            auth_session is None
            or auth_session.user_id != user.id
            or auth_session.revoked_at is not None
        ):
            raise HTTPException(status_code=404, detail="Login session was not found.")
        auth_session.revoked_at = utcnow()
        db.add(
            RevokedToken(
                jti=session_jti,
                user_id=user.id,
                expires_at=auth_session.expires_at,
                reason="session_revoke",
            )
        )
        db.commit()
        record_audit(
            db,
            request,
            "auth.session_revoke",
            actor_id=user.id,
            target_type="auth_session",
            target_id=session_jti,
        )
        return Response(status_code=204)

    @app.post("/api/auth/logout-all", status_code=204)
    def logout_all(
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        revoke_all_auth_sessions(db, user)
        db.commit()
        record_audit(
            db, request, "auth.logout_all", actor_id=user.id, target_type="user", target_id=user.id
        )
        return Response(status_code=204)

    @app.post("/api/sessions", response_model=SessionResponse, status_code=201)
    def create_session_endpoint(
        payload: SessionCreate,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        _, title_findings = chat_service.ai.redact_with_configured_policy(payload.title)
        if title_findings:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "sensitive_metadata",
                    "message": "Tiêu đề hội thoại không được chứa bí mật hoặc dữ liệu định danh.",
                    "categories": title_findings,
                },
            )
        if settings.security_profile == "high" and payload.security_mode in {
            "confidential",
            "private_e2ee",
        }:
            # Serialize against MFA disable. Refreshing after the lock prevents
            # a request authenticated just before MFA was disabled from creating
            # a new sensitive trust boundary.
            if lock_user_row(db, user) is None or not user.mfa_enabled:
                raise HTTPException(
                    status_code=403,
                    detail="Chế độ hội thoại nhạy cảm bắt buộc tài khoản đã bật MFA.",
                )
        # Cap the number of sessions per user so a single account cannot exhaust
        # database/storage resources by creating unlimited sessions.
        session_count = (
            db.scalar(
                select(func.count())
                .select_from(ChatSession)
                .where(ChatSession.owner_id == user.id)
                .where(retained_session_clause())
            )
            or 0
        )
        if session_count >= settings.max_sessions_per_user:
            record_audit(
                db,
                request,
                "chat.session.create",
                actor_id=user.id,
                outcome="blocked",
                details={"reason": "session_limit", "limit": settings.max_sessions_per_user},
            )
            raise HTTPException(
                status_code=409,
                detail=f"Đã đạt giới hạn {settings.max_sessions_per_user} phiên hội thoại. Vui lòng xóa bớt phiên cũ.",
            )
        retention_days = (
            settings.confidential_retention_days
            if payload.security_mode in {"confidential", "private_e2ee"}
            else settings.secure_retention_days
        )
        row = ChatSession(
            owner_id=user.id,
            title=payload.title,
            security_mode=payload.security_mode,
            data_classification=payload.data_classification,
            retention_expires_at=utcnow() + timedelta(days=retention_days),
            current_crypto_epoch=1 if payload.security_mode == "private_e2ee" else 0,
            crypto_suite=(
                "Double-Ratchet/MLS-client"
                if payload.security_mode == "private_e2ee"
                else "AES-256-GCM"
            ),
        )
        db.add(row)
        db.flush()
        if row.security_mode == "private_e2ee":
            db.add(
                ConversationMember(
                    session_id=row.id,
                    user_id=user.id,
                    role="owner",
                    joined_epoch=1,
                )
            )
        else:
            try:
                envelope_crypto_service.ensure_session_key(db, row)
            except EnvelopeEncryptionError as exc:
                db.rollback()
                raise HTTPException(
                    status_code=503,
                    detail="Không thể khởi tạo khóa hội thoại an toàn.",
                ) from exc
        db.commit()
        db.refresh(row)
        record_audit(
            db,
            request,
            "chat.session.create",
            actor_id=user.id,
            target_type="chat_session",
            target_id=row.id,
            details={
                "security_mode": row.security_mode,
                "data_classification": row.data_classification,
            },
        )
        return row

    @app.get("/api/sessions", response_model=list[SessionResponse])
    def list_sessions_endpoint(
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        stmt = (
            select(ChatSession)
            .where(ChatSession.owner_id == user.id, retained_session_clause())
            .order_by(ChatSession.updated_at.desc())
            .limit(100)
        )
        if settings.security_profile == "high" and not user.mfa_enabled:
            stmt = stmt.where(~sensitive_session_clause())
        return list(db.scalars(stmt))

    @app.get("/api/sessions/{session_id}", response_model=SessionResponse)
    def get_session_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        return require_owned_session(session_id, user, db, request)

    @app.patch("/api/sessions/{session_id}", response_model=SessionResponse)
    def rename_session_endpoint(
        session_id: str,
        payload: SessionUpdate,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        _, title_findings = chat_service.ai.redact_with_configured_policy(payload.title)
        if title_findings:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "sensitive_metadata",
                    "message": "Tiêu đề hội thoại không được chứa bí mật hoặc dữ liệu định danh.",
                    "categories": title_findings,
                },
            )
        row = require_owned_session(session_id, user, db, request, for_update=True)
        row.title = payload.title
        row.updated_at = utcnow()
        db.commit()
        db.refresh(row)
        record_audit(
            db,
            request,
            "chat.session.rename",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
            # Audit is long-lived and externally anchored; never duplicate
            # user-controlled conversation metadata into it.
            details={"title_length": len(payload.title)},
        )
        return row

    @app.patch("/api/sessions/{session_id}/security", response_model=SessionResponse)
    def update_session_security(
        session_id: str,
        payload: SessionSecurityUpdate,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        # The lock is acquired before checking content. Plaintext and E2EE send
        # paths take the same lock, so a trust-boundary transition can never
        # observe an empty conversation and then race a concurrent insert.
        row = require_owned_session(session_id, user, db, request, for_update=True)
        if (
            settings.security_profile == "high"
            and payload.security_mode in {"confidential", "private_e2ee"}
            and not user.mfa_enabled
        ):
            raise HTTPException(
                status_code=403,
                detail="Chế độ hội thoại nhạy cảm bắt buộc tài khoản đã bật MFA.",
            )
        has_messages = db.scalar(
            select(SecureMessage.id).where(SecureMessage.session_id == row.id).limit(1)
        )
        has_e2ee = db.scalar(
            select(E2eeEnvelope.id).where(E2eeEnvelope.session_id == row.id).limit(1)
        )
        mode_changed = row.security_mode != payload.security_mode
        if mode_changed and (has_messages is not None or has_e2ee is not None):
            raise HTTPException(
                status_code=409,
                detail="Không thể đổi trust boundary sau khi hội thoại đã có dữ liệu.",
            )
        if mode_changed and payload.security_mode == "private_e2ee":
            for key_epoch in list(row.key_epochs):
                db.delete(key_epoch)
            row.wrapped_dek = None
            row.kek_uri = None
            row.kek_version = None
            row.current_crypto_epoch = 1
            row.crypto_suite = "Double-Ratchet/MLS-client"
            if not any(member.user_id == user.id for member in row.members):
                db.add(
                    ConversationMember(
                        session_id=row.id,
                        user_id=user.id,
                        role="owner",
                        joined_epoch=1,
                    )
                )
        elif mode_changed:
            for member in list(row.members):
                db.delete(member)
            row.current_crypto_epoch = 0
            row.crypto_suite = "AES-256-GCM"
            row.security_mode = payload.security_mode
            envelope_crypto_service.ensure_session_key(db, row)

        row.security_mode = payload.security_mode
        row.data_classification = payload.data_classification
        retention_days = (
            settings.confidential_retention_days
            if row.security_mode in {"confidential", "private_e2ee"}
            else settings.secure_retention_days
        )
        policy_updated_at = utcnow()
        policy_deadline = policy_updated_at + timedelta(days=retention_days)
        # Editing labels or policy must never become an unprivileged retention
        # extension. A stricter mode may shorten the deadline; only a separate,
        # governed legal-hold workflow should ever extend it.
        row.retention_expires_at = (
            min(as_utc(row.retention_expires_at), policy_deadline)
            if row.retention_expires_at is not None
            else policy_deadline
        )
        row.updated_at = policy_updated_at
        db.commit()
        db.refresh(row)
        record_audit(
            db,
            request,
            "chat.session.security_policy",
            actor_id=user.id,
            target_type="chat_session",
            target_id=row.id,
            details={
                "security_mode": row.security_mode,
                "data_classification": row.data_classification,
            },
        )
        return row

    @app.delete("/api/sessions/{session_id}", status_code=204)
    def delete_session_endpoint(
        session_id: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        row = require_owned_session(session_id, user, db, request, for_update=True)
        # Zeroize cached plaintext key material on both sides of the cascade.
        envelope_crypto_service.clear_cache()
        try:
            db.delete(row)
            db.commit()
        finally:
            envelope_crypto_service.clear_cache()
        record_audit(
            db,
            request,
            "chat.session.delete",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
        )
        return Response(status_code=204)

    def stream_session_export(db: Session, row: ChatSession) -> Iterator[bytes]:
        """Yield a valid JSON export while holding at most one plaintext row.

        No plaintext export is ever written to the server filesystem. Private
        E2EE sessions export the opaque client ciphertext exactly as stored.
        """
        metadata = {
            "format": "scap-session-export-v2",
            "session_id": row.id,
            "title": row.title,
            "owner_id": row.owner_id,
            "security_mode": row.security_mode,
            "data_classification": row.data_classification,
            "created_at": row.created_at.isoformat(),
        }
        prefix = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))[:-1]
        yield (prefix + ',"messages":[').encode("utf-8")
        first = True
        if row.security_mode == "private_e2ee":
            last_created: datetime | None = None
            last_id = ""
            while True:
                stmt = (
                    select(E2eeEnvelope)
                    .where(E2eeEnvelope.session_id == row.id)
                    .order_by(E2eeEnvelope.created_at.asc(), E2eeEnvelope.id.asc())
                    .limit(100)
                )
                if last_created is not None:
                    stmt = stmt.where(
                        (E2eeEnvelope.created_at > last_created)
                        | ((E2eeEnvelope.created_at == last_created) & (E2eeEnvelope.id > last_id))
                    )
                page = list(db.scalars(stmt))
                if not page:
                    break
                for envelope in page:
                    item = {
                        "opaque_e2ee": True,
                        "id": envelope.id,
                        "sender_device_id": envelope.sender_device_id,
                        "recipient_device_id": envelope.recipient_device_id,
                        "protocol": envelope.protocol,
                        "message_kind": envelope.message_kind,
                        "client_message_id": envelope.client_message_id,
                        "epoch": envelope.group_epoch,
                        "header": envelope.header_b64,
                        "ciphertext": envelope.ciphertext_b64,
                        "created_at": envelope.created_at.isoformat(),
                    }
                    chunk = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                    yield (("" if first else ",") + chunk).encode("utf-8")
                    first = False
                last_created, last_id = page[-1].created_at, page[-1].id
        else:
            last_message_id = 0
            while True:
                page = list(
                    db.scalars(
                        select(SecureMessage)
                        .where(
                            SecureMessage.session_id == row.id,
                            SecureMessage.id > last_message_id,
                        )
                        .order_by(SecureMessage.id.asc())
                        .limit(100)
                    )
                )
                if not page:
                    break
                for message in page:
                    content = envelope_crypto_service.decrypt_message(db, row, message)
                    item = {
                        "role": message.role,
                        "content": content,
                        "created_at": message.created_at.isoformat(),
                    }
                    chunk = json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                    yield (("" if first else ",") + chunk).encode("utf-8")
                    first = False
                    # Reduce the lifetime of the plaintext reference before the
                    # next database page is loaded.
                    del content
                last_message_id = page[-1].id
        yield b"]}"

    def export_response(db: Session, row: ChatSession) -> StreamingResponse:
        filename = f"scap-export-{row.id}.json"
        return StreamingResponse(
            stream_session_export(db, row),
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store",
            },
        )

    @app.get("/api/sessions/{session_id}/export")
    def export_session_endpoint(
        session_id: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        row = require_owned_session(session_id, user, db, request, for_update=True)
        record_audit(
            db,
            request,
            "chat.session.export",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
            details={"streamed": True, "security_mode": row.security_mode},
        )
        return export_response(db, row)

    @app.post(
        "/api/sessions/{session_id}/export-ticket",
        response_model=ExportTicketResponse,
    )
    def create_export_ticket(
        session_id: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        """Issue a 60-second one-use browser download capability after step-up."""
        auth_session = require_recent_step_up(credentials, user, db)
        row = require_owned_session(session_id, user, db, request)
        ticket = token_service.issue_export_ticket(
            user.id,
            row.id,
            user.token_version,
            auth_session.jti,
            seconds=60,
        )
        claims = token_service.decode_export_ticket(ticket)
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        record_audit(
            db,
            request,
            "chat.session.export_ticket",
            actor_id=user.id,
            target_type="chat_session",
            target_id=row.id,
            details={"expires_in_seconds": 60},
        )
        return ExportTicketResponse(
            download_url=f"/api/exports/{ticket}",
            expires_at=expires_at,
        )

    @app.get("/api/exports/{ticket}")
    def consume_export_ticket(
        ticket: str,
        request: Request,
        db: Annotated[Session, Depends(get_db)],
    ):
        try:
            claims = token_service.decode_export_ticket(ticket)
        except jwt.PyJWTError as exc:
            raise HTTPException(status_code=404, detail="Vé tải xuống không hợp lệ.") from exc
        ticket_jti = str(claims["jti"])
        # Reuse the durable denylist as a one-time-token ledger. A row-level
        # insert/primary key makes simultaneous redemption fail closed.
        if db.get(RevokedToken, ticket_jti) is not None:
            raise HTTPException(status_code=410, detail="Vé tải xuống đã được sử dụng.")
        user = db.get(User, str(claims["sub"]))
        parent_jti = str(claims["parent_jti"])
        parent_session = db.get(AuthSession, parent_jti)
        parent_expiry = parent_session.expires_at if parent_session is not None else None
        if (
            user is None
            or not user.is_active
            or int(claims["ver"]) != user.token_version
            or parent_session is None
            or parent_session.user_id != user.id
            or parent_session.revoked_at is not None
            or parent_expiry is None
            or as_utc(parent_expiry) <= utcnow()
            or db.get(RevokedToken, parent_jti) is not None
        ):
            raise HTTPException(status_code=404, detail="Vé tải xuống không hợp lệ.")
        row = db.scalar(
            select(ChatSession).where(
                ChatSession.id == str(claims["sid"]),
                ChatSession.owner_id == str(claims["sub"]),
            )
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy dữ liệu xuất.")
        reject_expired_session(row, user, db, request)
        if (
            settings.security_profile == "high"
            and session_is_sensitive(row)
            and not user.mfa_enabled
        ):
            raise HTTPException(status_code=404, detail="Vé tải xuống không hợp lệ.")
        db.add(
            RevokedToken(
                jti=ticket_jti,
                user_id=str(claims["sub"]),
                expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc),
                reason="export_consumed",
            )
        )
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=410, detail="Vé tải xuống đã được sử dụng.") from exc
        record_audit(
            db,
            request,
            "chat.session.export_download",
            actor_id=str(claims["sub"]),
            target_type="chat_session",
            target_id=row.id,
            details={"streamed": True},
        )
        return export_response(db, row)

    @app.get("/api/sessions/{session_id}/messages", response_model=list[MessageResponse])
    def get_messages_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
        query: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    ):
        row = require_owned_session(session_id, user, db, request)
        try:
            return chat_service.list_messages(db, row, query=query)
        except PermissionError as exc:
            raise HTTPException(
                status_code=409,
                detail="Dùng API bản mã E2EE cho phiên Private E2EE.",
            ) from exc

    @app.get("/api/sessions/{session_id}/ciphertexts", response_model=list[RawMessageResponse])
    def get_ciphertexts_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row = require_owned_session(session_id, user, db, request)
        messages = list(
            db.scalars(
                select(SecureMessage)
                .where(SecureMessage.session_id == row.id)
                .order_by(SecureMessage.id.asc())
            )
        )
        return [
            RawMessageResponse(
                id=item.id,
                role=item.role,
                ciphertext_preview=item.ciphertext[:72]
                + ("…" if len(item.ciphertext) > 72 else ""),
                nonce=item.nonce,
                key_version=item.key_version,
                crypto_epoch=item.crypto_epoch,
                encryption_scheme=item.encryption_scheme,
                created_at=item.created_at,
            )
            for item in messages
        ]

    @app.post(
        "/api/sessions/{session_id}/messages", response_model=MessageResponse, status_code=201
    )
    def send_message_endpoint(
        session_id: str,
        payload: MessageSend,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row = require_owned_session(session_id, user, db, request, for_update=True)
        # Serialize index allocation and quota checks for a conversation. The
        # UNIQUE(session_id, message_index) constraint remains the final replay
        # barrier if two application instances race.
        existing_messages = (
            db.scalar(
                select(func.count())
                .select_from(SecureMessage)
                .where(SecureMessage.session_id == row.id)
            )
            or 0
        )
        if existing_messages + 2 > settings.max_messages_per_session:
            record_audit(
                db,
                request,
                "chat.message.send",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="blocked",
                details={
                    "reason": "message_quota",
                    "limit": settings.max_messages_per_session,
                },
            )
            raise HTTPException(status_code=409, detail="Phiên đã đạt giới hạn tin nhắn.")
        limiter_key = f"message:{user.id}"
        allowed, retry_after = message_limiter.allow(
            limiter_key,
            settings.message_max_attempts,
            settings.message_window_seconds,
        )
        if not allowed:
            record_audit(
                db,
                request,
                "chat.message.send",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Tần suất gửi tin nhắn quá cao.",
                headers={"Retry-After": str(retry_after)},
            )

        try:
            _, assistant_row, response_text, dlp_redacted = chat_service.chat(
                db,
                row,
                payload.content,
                allow_external_ai=(
                    user.ai_data_consent and user.ai_consent_version == settings.ai_consent_version
                ),
                confirm_external_ai=payload.confirm_external_ai,
                consent_since=user.ai_consent_at,
            )
        except DLPPolicyViolation as exc:
            record_audit(
                db,
                request,
                "dlp.policy",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="blocked" if exc.action.value != "confirm" else "denied",
                details={
                    "action": exc.action.value,
                    "categories": list(exc.categories),
                },
            )
            raise HTTPException(
                status_code=409 if exc.action.value == "confirm" else 422,
                detail={
                    "code": f"dlp_{exc.action.value}",
                    "message": str(exc),
                    "categories": list(exc.categories),
                },
            ) from exc
        except PermissionError as exc:
            record_audit(
                db,
                request,
                "chat.message.send",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "policy_or_consent_required"},
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except AIProviderError as exc:
            # Lỗi phía nhà cung cấp AI, không phải lỗi của người dùng: 503 kèm
            # Retry-After. `str(exc)` đã là thông điệp chung chung an toàn;
            # log máy chủ chỉ giữ loại lỗi và model, không giữ thông điệp SDK.
            record_audit(
                db,
                request,
                "chat.message.send",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="failure",
                details={"reason": "ai_provider_unavailable"},
            )
            raise HTTPException(
                status_code=503,
                detail=str(exc),
                headers={"Retry-After": "30"},
            ) from exc
        row.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            request,
            "chat.message.send",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
            details={
                "content_length": len(payload.content),
                "dlp_redacted": dlp_redacted,
            },
        )
        if dlp_redacted:
            # Sự kiện riêng để SIEM/IDS đếm được số lần DLP phải can thiệp.
            record_audit(
                db,
                request,
                "dlp.redacted",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                details={"categories": dlp_redacted},
            )
        return MessageResponse(
            id=assistant_row.id,
            session_id=session_id,
            role="assistant",
            content=response_text,
            created_at=assistant_row.created_at,
            dlp_redacted=dlp_redacted,
        )

    @app.get("/api/search/messages")
    def global_search_endpoint(
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
        q: Annotated[str, Query(min_length=1, max_length=120)],
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ):
        """Search decrypted message content across every session the caller owns.

        Decryption happens server-side per message; results never include other
        users' sessions because the query is scoped to ``owner_id``.
        """
        session_stmt = (
            select(ChatSession)
            .where(ChatSession.owner_id == user.id, retained_session_clause())
            .order_by(ChatSession.updated_at.desc())
            .limit(100)
        )
        if settings.security_profile == "high" and not user.mfa_enabled:
            session_stmt = session_stmt.where(~sensitive_session_clause())
        sessions = list(db.scalars(session_stmt))
        results: list[dict] = []
        for chat_session in sessions:
            if chat_session.security_mode == "private_e2ee":
                # The server has no plaintext index for E2EE conversations.
                continue
            for message in chat_service.list_messages(db, chat_session, query=q):
                results.append(
                    {
                        "session_id": chat_session.id,
                        "session_title": chat_session.title,
                        "message_id": message["id"],
                        "role": message["role"],
                        "content": message["content"],
                        "created_at": message["created_at"].isoformat(),
                    }
                )
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break
        record_audit(
            db,
            request,
            "chat.message.search",
            actor_id=user.id,
            details={"query_length": len(q), "results": len(results)},
        )
        return results

    # ------------------------------------------------------------------
    # Private E2EE control plane. The server stores public identity material,
    # one-time prekeys, membership metadata and opaque ciphertext only. Double
    # Ratchet / RFC 9420 MLS state and every private key remain in an audited
    # client implementation.

    @app.post("/api/e2ee/devices/challenge", response_model=E2eeChallengeResponse)
    def create_e2ee_device_challenge(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        raw_challenge = secrets.token_urlsafe(32)
        challenge_bytes = decode_base64_strict(
            raw_challenge,
            field="challenge",
            min_bytes=32,
            max_bytes=32,
        )
        expires_at = utcnow() + timedelta(minutes=5)
        challenge = E2eeDeviceChallenge(
            user_id=user.id,
            challenge_hash=hashlib.sha256(challenge_bytes).hexdigest(),
            expires_at=expires_at,
        )
        db.add(challenge)
        db.commit()
        db.refresh(challenge)
        record_audit(
            db,
            request,
            "e2ee.device.challenge",
            actor_id=user.id,
            target_type="e2ee_challenge",
            target_id=challenge.id,
            details={"expires_in_seconds": 300},
        )
        return E2eeChallengeResponse(
            id=challenge.id,
            challenge=raw_challenge,
            expires_at=expires_at,
        )

    @app.post("/api/e2ee/devices", response_model=E2eeDeviceResponse, status_code=201)
    def register_e2ee_device(
        payload: E2eeDeviceRegisterRequest,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        _, display_findings = chat_service.ai.redact_with_configured_policy(payload.display_name)
        if display_findings:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "sensitive_metadata",
                    "message": "Tên thiết bị không được chứa bí mật hoặc dữ liệu định danh.",
                    "categories": display_findings,
                },
            )
        now = utcnow()
        challenge = db.scalar(
            select(E2eeDeviceChallenge).where(
                E2eeDeviceChallenge.id == payload.challenge_id,
                E2eeDeviceChallenge.user_id == user.id,
            )
        )
        expires_at = challenge.expires_at if challenge is not None else None
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        try:
            challenge_bytes = decode_base64_strict(
                payload.challenge,
                field="challenge",
                min_bytes=16,
                max_bytes=64,
            )
        except E2EEValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if (
            challenge is None
            or challenge.consumed_at is not None
            or expires_at is None
            or expires_at <= now
            or not secrets.compare_digest(
                challenge.challenge_hash,
                hashlib.sha256(challenge_bytes).hexdigest(),
            )
        ):
            raise HTTPException(status_code=409, detail="Challenge không hợp lệ hoặc đã hết hạn.")

        # Burn atomically even on SQLite, where SELECT ... FOR UPDATE is a no-op.
        # This prevents two concurrent registrations from redeeming one proof.
        burned = db.execute(
            update(E2eeDeviceChallenge)
            .where(
                E2eeDeviceChallenge.id == challenge.id,
                E2eeDeviceChallenge.user_id == user.id,
                E2eeDeviceChallenge.challenge_hash == challenge.challenge_hash,
                E2eeDeviceChallenge.consumed_at.is_(None),
                E2eeDeviceChallenge.expires_at > now,
            )
            .values(consumed_at=now)
            .execution_options(synchronize_session=False)
        )
        if burned.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="Challenge đã được sử dụng.")
        if db.get(E2eeDevice, payload.device_id) is not None:
            record_audit(
                db,
                request,
                "e2ee.device.register",
                actor_id=user.id,
                outcome="denied",
                details={"reason": "duplicate_device_id"},
            )
            raise HTTPException(status_code=409, detail="Thiết bị đã tồn tại.")

        possession_ok = verify_device_possession(
            payload.identity_key,
            payload.possession_signature,
            account_id=user.id,
            device_id=payload.device_id,
            challenge_b64=payload.challenge,
        )
        try:
            identity_key = encode_base64url(
                decode_base64_strict(
                    payload.identity_key,
                    field="identity_key",
                    exact_bytes=32,
                )
            )
            signed_prekey_bytes = decode_base64_strict(
                payload.signed_prekey,
                field="signed_prekey",
                exact_bytes=32,
            )
            signed_prekey = encode_base64url(signed_prekey_bytes)
            prekeys = [
                encode_base64url(
                    decode_base64_strict(
                        item,
                        field="one_time_prekey",
                        exact_bytes=32,
                    )
                )
                for item in payload.one_time_prekeys
            ]
        except E2EEValidationError as exc:
            record_audit(
                db,
                request,
                "e2ee.device.register",
                actor_id=user.id,
                outcome="denied",
                details={"reason": "invalid_public_material"},
            )
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        prekey_signature_ok = verify_ed25519_signature(
            identity_key,
            payload.signed_prekey_signature,
            signed_prekey_bytes,
        )
        if not possession_ok or not prekey_signature_ok or len(set(prekeys)) != len(prekeys):
            record_audit(
                db,
                request,
                "e2ee.device.register",
                actor_id=user.id,
                outcome="denied",
                details={"reason": "invalid_public_key_proof"},
            )
            raise HTTPException(status_code=422, detail="Bằng chứng khóa công khai không hợp lệ.")

        trusted_devices = list(
            db.scalars(
                select(E2eeDevice).where(
                    E2eeDevice.user_id == user.id,
                    E2eeDevice.trust_state == "trusted",
                )
            )
        )
        approver: E2eeDevice | None = None
        if trusted_devices:
            if not payload.approver_device_id or not payload.approval_signature:
                record_audit(
                    db,
                    request,
                    "e2ee.device.register",
                    actor_id=user.id,
                    outcome="denied",
                    details={"reason": "trusted_device_approval_required"},
                )
                raise HTTPException(
                    status_code=403,
                    detail="Thiết bị mới phải được một thiết bị đã tin cậy phê duyệt.",
                )
            approver = next(
                (item for item in trusted_devices if item.id == payload.approver_device_id),
                None,
            )
            if approver is None or not verify_device_approval(
                approver.identity_key_b64,
                payload.approval_signature,
                account_id=user.id,
                approver_device_id=approver.id,
                new_device_id=payload.device_id,
                new_device_public_key_b64=identity_key,
                approval_challenge_b64=payload.challenge,
            ):
                record_audit(
                    db,
                    request,
                    "e2ee.device.register",
                    actor_id=user.id,
                    outcome="denied",
                    details={"reason": "invalid_device_approval"},
                )
                raise HTTPException(status_code=403, detail="Chữ ký phê duyệt không hợp lệ.")

        device = E2eeDevice(
            id=payload.device_id,
            user_id=user.id,
            display_name=payload.display_name,
            identity_key_b64=identity_key,
            signed_prekey_b64=signed_prekey,
            signed_prekey_signature_b64=payload.signed_prekey_signature,
            fingerprint=safety_fingerprint(identity_key),
            trust_state="trusted",
            approved_by_device_id=approver.id if approver is not None else None,
            approved_at=now,
        )
        db.add(device)
        db.add_all(
            E2eePreKey(
                device_id=device.id,
                key_id=str(uuid.uuid4()),
                public_key_b64=prekey,
            )
            for prekey in prekeys
        )
        try:
            db.commit()
            db.refresh(device)
        except IntegrityError as exc:
            db.rollback()
            consumed = db.get(E2eeDeviceChallenge, payload.challenge_id)
            if consumed is not None and consumed.consumed_at is None:
                consumed.consumed_at = now
                db.commit()
            raise HTTPException(status_code=409, detail="Khóa hoặc thiết bị đã tồn tại.") from exc
        record_audit(
            db,
            request,
            "e2ee.device.register",
            actor_id=user.id,
            target_type="e2ee_device",
            target_id=device.id,
            details={
                "trust_state": device.trust_state,
                "prekey_count": len(prekeys),
                "approved_by_existing_device": approver is not None,
            },
        )
        return device

    @app.get("/api/e2ee/devices", response_model=list[E2eeDeviceResponse])
    def list_e2ee_devices(
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        return list(
            db.scalars(
                select(E2eeDevice)
                .where(E2eeDevice.user_id == user.id)
                .order_by(E2eeDevice.created_at.asc())
            )
        )

    @app.delete("/api/e2ee/devices/{device_id}", status_code=204)
    def revoke_e2ee_device(
        device_id: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, user, db)
        if lock_user_row(db, user) is None:
            raise HTTPException(status_code=401, detail="Tài khoản không hợp lệ.")
        device = db.scalar(
            select(E2eeDevice)
            .where(E2eeDevice.id == device_id, E2eeDevice.user_id == user.id)
            .with_for_update()
        )
        if device is None or device.trust_state == "revoked":
            raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị.")
        trusted_count = (
            db.scalar(
                select(func.count())
                .select_from(E2eeDevice)
                .where(
                    E2eeDevice.user_id == user.id,
                    E2eeDevice.trust_state == "trusted",
                )
            )
            or 0
        )
        if trusted_count <= 1:
            raise HTTPException(
                status_code=409,
                detail="Không thể thu hồi thiết bị E2EE tin cậy cuối cùng.",
            )
        now = utcnow()
        device.trust_state = "revoked"
        device.revoked_at = now
        for prekey in db.scalars(
            select(E2eePreKey).where(
                E2eePreKey.device_id == device.id,
                E2eePreKey.consumed_at.is_(None),
            )
        ):
            prekey.consumed_at = now
        # Clients must publish a corresponding MLS commit. Incrementing the
        # server routing epoch prevents the revoked device from injecting data
        # under the old membership epoch.
        affected_session_ids = list(
            db.scalars(
                select(ConversationMember.session_id)
                .join(ChatSession, ChatSession.id == ConversationMember.session_id)
                .where(
                    ConversationMember.user_id == user.id,
                    ConversationMember.removed_at.is_(None),
                    ChatSession.security_mode == "private_e2ee",
                )
                .order_by(ConversationMember.session_id.asc())
            )
        )
        for affected_session_id in affected_session_ids:
            session = db.get(ChatSession, affected_session_id)
            if session is None or lock_chat_session_row(db, session) is None:
                continue
            # Membership may have been removed while this request waited for
            # the conversation lock. Only an active member changes the epoch.
            still_active = db.scalar(
                select(ConversationMember.id).where(
                    ConversationMember.session_id == session.id,
                    ConversationMember.user_id == user.id,
                    ConversationMember.removed_at.is_(None),
                )
            )
            if still_active is not None and session.security_mode == "private_e2ee":
                session.current_crypto_epoch += 1
        db.commit()
        record_audit(
            db,
            request,
            "e2ee.device.revoke",
            actor_id=user.id,
            target_type="e2ee_device",
            target_id=device.id,
        )
        return Response(status_code=204)

    @app.get(
        "/api/e2ee/users/{username}/prekey-bundle",
        response_model=E2eePreKeyBundleResponse,
    )
    def consume_prekey_bundle(
        username: str,
        request: Request,
        requester: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
        device_id: Annotated[str | None, Query(max_length=36)] = None,
    ):
        allowed, retry_after = message_limiter.allow(
            f"prekey:{requester.id}",
            settings.message_max_attempts,
            settings.message_window_seconds,
        )
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Tần suất lấy prekey quá cao.",
                headers={"Retry-After": str(retry_after)},
            )
        target = db.scalar(
            select(User).where(User.username == username.strip().lower(), User.is_active.is_(True))
        )
        if target is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy prekey bundle.")
        device_stmt = select(E2eeDevice).where(
            E2eeDevice.user_id == target.id,
            E2eeDevice.trust_state == "trusted",
        )
        if device_id:
            device_stmt = device_stmt.where(E2eeDevice.id == device_id)
        device = db.scalar(device_stmt.order_by(E2eeDevice.created_at.asc()).limit(1))
        if device is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy prekey bundle.")
        prekey: E2eePreKey | None = None
        # Conditional UPDATE makes the public one-time prekey single-use even
        # on SQLite, where row-level SELECT FOR UPDATE is not implemented.
        for _ in range(3):
            candidate = db.scalar(
                select(E2eePreKey)
                .where(
                    E2eePreKey.device_id == device.id,
                    E2eePreKey.consumed_at.is_(None),
                )
                .order_by(E2eePreKey.created_at.asc())
                .limit(1)
            )
            if candidate is None:
                break
            claimed = db.execute(
                update(E2eePreKey)
                .where(
                    E2eePreKey.id == candidate.id,
                    E2eePreKey.consumed_at.is_(None),
                )
                .values(
                    consumed_at=utcnow(),
                    consumed_by_user_id=requester.id,
                )
                .execution_options(synchronize_session=False)
            )
            if claimed.rowcount == 1:
                prekey = candidate
                break
            db.rollback()
        db.commit()
        record_audit(
            db,
            request,
            "e2ee.prekey.consume",
            actor_id=requester.id,
            target_type="e2ee_device",
            target_id=device.id,
            details={"one_time_prekey_available": prekey is not None},
        )
        return E2eePreKeyBundleResponse(
            user_id=target.id,
            device_id=device.id,
            display_name=device.display_name,
            fingerprint=device.fingerprint,
            identity_key=device.identity_key_b64,
            signed_prekey=device.signed_prekey_b64,
            signed_prekey_signature=device.signed_prekey_signature_b64,
            one_time_prekey_id=prekey.key_id if prekey is not None else None,
            one_time_prekey=prekey.public_key_b64 if prekey is not None else None,
        )

    @app.get("/api/sessions/{session_id}/e2ee/members")
    def list_e2ee_members(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row, _ = require_private_member_session(session_id, user, db, request)
        members = db.execute(
            select(ConversationMember, User)
            .join(User, User.id == ConversationMember.user_id)
            .where(ConversationMember.session_id == row.id)
            .order_by(ConversationMember.joined_at.asc())
        ).all()
        return [
            {
                "user_id": member.user_id,
                "username": member_user.username,
                "role": member.role,
                "joined_epoch": member.joined_epoch,
                "removed_epoch": member.removed_epoch,
                "active": member.removed_at is None,
            }
            for member, member_user in members
        ]

    @app.post("/api/sessions/{session_id}/e2ee/members", status_code=201)
    def add_e2ee_member(
        session_id: str,
        payload: E2eeMemberUpdate,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        owner: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, owner, db)
        target = db.scalar(
            select(User).where(User.username == payload.username, User.is_active.is_(True))
        )
        if target is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy người dùng.")
        # Membership addition participates in account suspension/deletion. Lock
        # both accounts in stable id order before locking the conversation so a
        # concurrently suspended target can never be added after the revocation
        # sweep has enumerated memberships.
        accounts = sorted({owner.id: owner, target.id: target}.values(), key=lambda item: item.id)
        for account in accounts:
            if lock_user_row(db, account) is None:
                raise HTTPException(status_code=404, detail="Không tìm thấy người dùng.")
        row = require_owned_session(
            session_id,
            owner,
            db,
            request,
            for_update=True,
            account_locked=True,
        )
        if row.security_mode != "private_e2ee":
            raise HTTPException(status_code=409, detail="Phiên này không ở chế độ Private E2EE.")
        membership = db.scalar(
            select(ConversationMember).where(
                ConversationMember.session_id == row.id,
                ConversationMember.user_id == target.id,
            )
        )
        if membership is not None and membership.removed_at is None:
            raise HTTPException(status_code=409, detail="Người dùng đã là thành viên.")
        row.current_crypto_epoch += 1
        if membership is None:
            membership = ConversationMember(
                session_id=row.id,
                user_id=target.id,
                role="member",
                joined_epoch=row.current_crypto_epoch,
            )
            db.add(membership)
        else:
            membership.joined_epoch = row.current_crypto_epoch
            membership.removed_epoch = None
            membership.removed_at = None
            membership.joined_at = utcnow()
        db.commit()
        record_audit(
            db,
            request,
            "e2ee.member.add",
            actor_id=owner.id,
            target_type="chat_session",
            target_id=row.id,
            details={"member_id": target.id, "epoch": row.current_crypto_epoch},
        )
        return {"member_id": target.id, "epoch": row.current_crypto_epoch}

    @app.delete("/api/sessions/{session_id}/e2ee/members/{username}", status_code=204)
    def remove_e2ee_member(
        session_id: str,
        username: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        owner: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, owner, db)
        row = require_owned_session(session_id, owner, db, request, for_update=True)
        if row.security_mode != "private_e2ee":
            raise HTTPException(status_code=409, detail="Phiên này không ở chế độ Private E2EE.")
        target = db.scalar(select(User).where(User.username == username.strip().lower()))
        if target is None or target.id == owner.id:
            raise HTTPException(status_code=404, detail="Không tìm thấy thành viên có thể xóa.")
        membership = db.scalar(
            select(ConversationMember).where(
                ConversationMember.session_id == row.id,
                ConversationMember.user_id == target.id,
                ConversationMember.removed_at.is_(None),
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy thành viên có thể xóa.")
        row.current_crypto_epoch += 1
        membership.removed_epoch = row.current_crypto_epoch
        membership.removed_at = utcnow()
        db.commit()
        record_audit(
            db,
            request,
            "e2ee.member.remove",
            actor_id=owner.id,
            target_type="chat_session",
            target_id=row.id,
            details={"member_id": target.id, "epoch": row.current_crypto_epoch},
        )
        return Response(status_code=204)

    def e2ee_envelope_response(item: E2eeEnvelope) -> E2eeEnvelopeResponse:
        return E2eeEnvelopeResponse(
            id=item.id,
            session_id=item.session_id,
            sender_device_id=item.sender_device_id,
            recipient_device_id=item.recipient_device_id,
            protocol=item.protocol,
            message_kind=item.message_kind,
            client_message_id=item.client_message_id,
            header=item.header_b64,
            ciphertext=item.ciphertext_b64,
            group_epoch=item.group_epoch,
            created_at=item.created_at,
        )

    @app.post(
        "/api/sessions/{session_id}/e2ee/envelopes",
        response_model=E2eeEnvelopeResponse,
        status_code=201,
    )
    def send_e2ee_envelope(
        session_id: str,
        payload: E2eeEnvelopeSend,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row, membership = require_private_member_session(session_id, user, db, request)
        sender_device = db.scalar(
            select(E2eeDevice).where(
                E2eeDevice.id == payload.sender_device_id,
                E2eeDevice.user_id == user.id,
                E2eeDevice.trust_state == "trusted",
            )
        )
        if sender_device is None:
            raise HTTPException(status_code=403, detail="Thiết bị gửi chưa được tin cậy.")
        if payload.epoch < membership.joined_epoch or payload.epoch != row.current_crypto_epoch:
            raise HTTPException(status_code=409, detail="Epoch E2EE không còn hiện hành.")

        expected_recipient: str
        recipient_device: E2eeDevice | None = None
        if payload.protocol == PROTOCOL_DOUBLE_RATCHET:
            if payload.message_kind != "application" or not payload.recipient_device_id:
                raise HTTPException(
                    status_code=422,
                    detail="Double Ratchet cần recipient_device_id và message_kind=application.",
                )
            expected_recipient = payload.recipient_device_id
        elif payload.protocol == PROTOCOL_MLS:
            if payload.message_kind == "welcome":
                if not payload.recipient_device_id:
                    raise HTTPException(
                        status_code=422,
                        detail="MLS welcome cần recipient_device_id.",
                    )
                expected_recipient = payload.recipient_device_id
            else:
                if payload.recipient_device_id is not None:
                    raise HTTPException(
                        status_code=422,
                        detail="MLS application/commit phải định tuyến tới session.",
                    )
                expected_recipient = row.id
        else:
            raise HTTPException(status_code=422, detail="Giao thức E2EE không được hỗ trợ.")

        if payload.recipient_device_id:
            recipient_device = db.scalar(
                select(E2eeDevice).where(
                    E2eeDevice.id == payload.recipient_device_id,
                    E2eeDevice.trust_state == "trusted",
                )
            )
            recipient_membership = (
                db.scalar(
                    select(ConversationMember).where(
                        ConversationMember.session_id == row.id,
                        ConversationMember.user_id == recipient_device.user_id,
                        ConversationMember.removed_at.is_(None),
                    )
                )
                if recipient_device is not None
                else None
            )
            if recipient_device is None or recipient_membership is None:
                raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị nhận.")

        try:
            envelope = validate_opaque_envelope(
                {
                    "version": payload.version,
                    "protocol": payload.protocol,
                    "recipient": payload.recipient,
                    "epoch": payload.epoch,
                    "client_message_id": payload.client_message_id,
                    "sender_device_id": payload.sender_device_id,
                    "header": payload.header,
                    "ciphertext": payload.ciphertext,
                },
                expected_recipient=expected_recipient,
            )
        except E2EEValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        envelope_count = (
            db.scalar(
                select(func.count())
                .select_from(E2eeEnvelope)
                .where(E2eeEnvelope.session_id == row.id)
            )
            or 0
        )
        if envelope_count >= settings.max_messages_per_session:
            raise HTTPException(status_code=409, detail="Phiên đã đạt giới hạn bản mã.")
        stored = E2eeEnvelope(
            session_id=row.id,
            sender_user_id=user.id,
            sender_device_id=sender_device.id,
            recipient_device_id=(recipient_device.id if recipient_device is not None else None),
            protocol=envelope.protocol,
            message_kind=payload.message_kind,
            client_message_id=envelope.client_message_id,
            replay_key=envelope.replay_key,
            header_b64=envelope.header_b64,
            ciphertext_b64=envelope.ciphertext_b64,
            group_epoch=envelope.epoch,
        )
        db.add(stored)
        row.updated_at = utcnow()
        try:
            db.commit()
            db.refresh(stored)
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Bản mã trùng hoặc đã được phát lại."
            ) from exc
        record_audit(
            db,
            request,
            "e2ee.envelope.send",
            actor_id=user.id,
            target_type="chat_session",
            target_id=row.id,
            details={
                "protocol": stored.protocol,
                "kind": stored.message_kind,
                "header_bytes": envelope.header_size,
                "ciphertext_bytes": envelope.ciphertext_size,
                "epoch": envelope.epoch,
            },
        )
        return e2ee_envelope_response(stored)

    @app.get(
        "/api/sessions/{session_id}/e2ee/envelopes",
        response_model=list[E2eeEnvelopeResponse],
    )
    def receive_e2ee_envelopes(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
        recipient_device_id: Annotated[str, Query(min_length=36, max_length=36)],
        after: Annotated[datetime | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 100,
    ):
        row, membership = require_private_member_session(session_id, user, db, request)
        device = db.scalar(
            select(E2eeDevice).where(
                E2eeDevice.id == recipient_device_id,
                E2eeDevice.user_id == user.id,
                E2eeDevice.trust_state == "trusted",
            )
        )
        if device is None:
            raise HTTPException(status_code=404, detail="Không tìm thấy thiết bị nhận.")
        stmt = (
            select(E2eeEnvelope)
            .where(
                E2eeEnvelope.session_id == row.id,
                E2eeEnvelope.group_epoch >= membership.joined_epoch,
                (
                    (E2eeEnvelope.recipient_device_id == device.id)
                    | (
                        (E2eeEnvelope.recipient_device_id.is_(None))
                        & (E2eeEnvelope.protocol == PROTOCOL_MLS)
                    )
                ),
            )
            .order_by(E2eeEnvelope.created_at.asc(), E2eeEnvelope.id.asc())
            .limit(limit)
        )
        if after is not None:
            stmt = stmt.where(E2eeEnvelope.created_at > after)
        return [e2ee_envelope_response(item) for item in db.scalars(stmt)]

    @app.get("/api/admin/audit", response_model=list[AuditResponse])
    def admin_audit(
        _: Annotated[User, Depends(moderator_or_admin)],
        db: Annotated[Session, Depends(get_db)],
        limit: int = 100,
    ):
        safe_limit = min(max(limit, 1), 500)
        return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(safe_limit)))

    @app.get("/api/admin/users", response_model=list[UserResponse])
    def admin_users(
        _: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        return list(db.scalars(select(User).order_by(User.created_at.desc()).limit(500)))

    @app.post("/api/admin/users", response_model=UserResponse, status_code=201)
    def admin_create_user(
        payload: AdminCreateUser,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, admin, db)
        if password_is_compromised(
            payload.password,
            request,
            db,
            event_type="admin.user_create",
            actor_id=admin.id,
        ):
            record_audit(
                db,
                request,
                "admin.user_create",
                actor_id=admin.id,
                outcome="failure",
                details={"reason": "breached_password"},
            )
            raise HTTPException(
                status_code=400,
                detail="Mật khẩu này đã xuất hiện trong dữ liệu rò rỉ; hãy chọn mật khẩu khác.",
            )
        user = User(
            username=payload.username,
            password_hash=password_service.hash(payload.password),
            role=payload.role,
        )
        db.add(user)
        try:
            db.commit()
            db.refresh(user)
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Không thể tạo tài khoản với thông tin này."
            ) from exc
        record_audit(
            db,
            request,
            "admin.user_create",
            actor_id=admin.id,
            target_type="user",
            target_id=user.id,
            # The immutable target id is sufficient for correlation; avoid
            # copying an account identifier into long-lived WORM audit data.
            details={"role": user.role},
        )
        return user

    @app.delete("/api/admin/users/{user_id}", status_code=204)
    def admin_delete_user(
        user_id: str,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, admin, db)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found.")
        if lock_user_row(db, target, require_active=False) is None:
            raise HTTPException(status_code=404, detail="User not found.")
        if target.id == admin.id:
            raise HTTPException(status_code=400, detail="Admin không thể tự xóa chính mình.")
        if target.role == "admin":
            raise HTTPException(status_code=400, detail="Không thể xóa tài khoản admin khác.")
        revoked_memberships, advanced_sessions = revoke_active_e2ee_memberships(db, target.id)
        # Lock every owned conversation before its cascade removes wrapped key
        # metadata. Content writers use the same account/session order.
        owned_session_ids = list(
            db.scalars(
                select(ChatSession.id)
                .where(ChatSession.owner_id == target.id)
                .order_by(ChatSession.id.asc())
            )
        )
        for owned_session_id in owned_session_ids:
            owned_session = db.get(ChatSession, owned_session_id)
            if owned_session is not None:
                lock_chat_session_row(db, owned_session)

        # A pre-delete wipe removes currently cached account/session DEKs; the
        # post-commit wipe catches any cache entry populated by an older in-flight
        # read before it observed the account lock.
        envelope_crypto_service.clear_cache()
        try:
            db.delete(target)
            db.commit()
        finally:
            envelope_crypto_service.clear_cache()
        record_audit(
            db,
            request,
            "admin.user_delete",
            actor_id=admin.id,
            target_type="user",
            target_id=user_id,
            details={
                "e2ee_memberships_revoked": revoked_memberships,
                "e2ee_epochs_advanced": advanced_sessions,
                "owned_sessions_deleted": len(owned_session_ids),
            },
        )
        return Response(status_code=204)

    @app.patch("/api/admin/users/{user_id}/role", response_model=UserResponse)
    def admin_change_role(
        user_id: str,
        payload: UserRoleUpdate,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, admin, db)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found.")
        if target.id == admin.id:
            raise HTTPException(
                status_code=400, detail="Admin không thể tự đổi role của chính mình."
            )
        old_role = target.role
        target.role = payload.role
        revoke_all_auth_sessions(db, target)
        db.commit()
        db.refresh(target)
        record_audit(
            db,
            request,
            "admin.user_role_change",
            actor_id=admin.id,
            target_type="user",
            target_id=user_id,
            details={"old_role": old_role, "new_role": payload.role},
        )
        return target

    @app.patch("/api/admin/users/{user_id}/status", response_model=UserResponse)
    def update_user_status(
        user_id: str,
        payload: UserStatusUpdate,
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        require_recent_step_up(credentials, admin, db)
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User account was not found.")
        if lock_user_row(db, target, require_active=False) is None:
            raise HTTPException(status_code=404, detail="User account was not found.")
        if target.id == admin.id and not payload.is_active:
            raise HTTPException(
                status_code=400, detail="The active administrator cannot lock itself."
            )
        revoked_memberships = 0
        advanced_sessions = 0
        if not payload.is_active:
            revoked_memberships, advanced_sessions = revoke_active_e2ee_memberships(
                db, target.id
            )
        if target.is_active != payload.is_active or revoked_memberships:
            status_changed = target.is_active != payload.is_active
            target.is_active = payload.is_active
            if status_changed:
                revoke_all_auth_sessions(db, target)
            db.commit()
            record_audit(
                db,
                request,
                "admin.user_status",
                actor_id=admin.id,
                target_type="user",
                target_id=target.id,
                details={
                    "is_active": target.is_active,
                    "token_version": target.token_version,
                    "e2ee_memberships_revoked": revoked_memberships,
                    "e2ee_epochs_advanced": advanced_sessions,
                },
            )
        return target

    @app.get("/api/admin/stats")
    def admin_stats(
        _: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        total_users = db.scalar(select(func.count()).select_from(User)) or 0
        active_users = (
            db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))) or 0
        )
        total_sessions = db.scalar(select(func.count()).select_from(ChatSession)) or 0
        total_messages = db.scalar(select(func.count()).select_from(SecureMessage)) or 0
        one_hour_ago = utcnow() - timedelta(hours=1)
        recent_login_failures = (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.event_type == "auth.login",
                    AuditEvent.outcome != "success",
                    AuditEvent.created_at >= one_hour_ago,
                )
            )
            or 0
        )
        recent_auth_denials = (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(
                    AuditEvent.event_type == "authorization.denied",
                    AuditEvent.created_at >= one_hour_ago,
                )
            )
            or 0
        )
        return {
            "total_users": total_users,
            "active_users": active_users,
            "total_sessions": total_sessions,
            "total_messages": total_messages,
            "recent_login_failures": recent_login_failures,
            "recent_auth_denials": recent_auth_denials,
        }

    @app.get("/api/admin/security-alerts", response_model=list[SecurityAlertResponse])
    def security_alerts(
        _: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
        window_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
        threshold: Annotated[int, Query(ge=1, le=100)] = 3,
    ):
        cutoff = utcnow() - timedelta(minutes=window_minutes)
        watched_events = ("auth.login", "authorization.denied", "chat.message.send")
        rows = db.execute(
            select(AuditEvent.event_type, AuditEvent.outcome, func.count(AuditEvent.id))
            .where(AuditEvent.created_at >= cutoff, AuditEvent.event_type.in_(watched_events))
            .group_by(AuditEvent.event_type, AuditEvent.outcome)
        ).all()
        alerts: list[SecurityAlertResponse] = []
        for event_type, outcome, count in rows:
            if outcome == "success" or count < threshold:
                continue
            severity = "high" if outcome == "blocked" else "medium"
            alerts.append(
                SecurityAlertResponse(
                    code=f"{event_type}.{outcome}",
                    severity=severity,
                    event_type=event_type,
                    count=count,
                    window_minutes=window_minutes,
                    message=f"{count} {event_type} events with outcome {outcome} in {window_minutes} minutes.",
                )
            )
        return alerts

    @app.get("/api/admin/audit/verify")
    def verify_audit_chain(
        admin: Annotated[User, Depends(admin_user)],
        request: Request,
        db: Annotated[Session, Depends(get_db)],
    ):
        """Recompute the audit hash chain and report the first broken link.

        This is the control that makes the audit trail *evidence*: if anyone with
        database access edits or deletes a row, verification fails here and the
        failure is itself audited.
        """
        if audit_key is None:
            raise HTTPException(
                status_code=409, detail="Audit chain đang tắt (AUDIT_CHAIN_ENABLED=false)."
            )
        # The verification itself must be auditable. Record it before walking
        # the chain so the returned result covers this action as well.
        record_audit(
            db,
            request,
            "audit.chain.verify",
            actor_id=admin.id,
            target_type="audit_event",
            outcome="success",
        )
        result = verify_chain(db, audit_key)
        if not result.intact:
            record_audit(
                db,
                request,
                "audit.chain.broken",
                actor_id=admin.id,
                outcome="failure",
                target_type="audit_event",
                target_id=str(result.first_broken_id),
                details={"reason": result.reason},
            )
        payload = result.as_dict()
        checkpoint_verification = (
            audit_checkpoint_service.verify_latest(db)
            if audit_checkpoint_service is not None
            else None
        )
        if checkpoint_verification is not None:
            payload.update(checkpoint_verification.as_dict())
            checkpoint_required = bool(settings.audit_worm_endpoint)
            payload["external_checkpoint_required"] = checkpoint_required
            checkpoint_coverage_intact = (
                checkpoint_verification.fully_anchored
                if checkpoint_required
                else checkpoint_verification.intact and checkpoint_verification.fresh
            )
            payload["high_assurance_intact"] = bool(
                result.intact and checkpoint_coverage_intact
            )
        payload["checked_at"] = utcnow().isoformat()
        payload["checked_by"] = admin.username
        return payload

    @app.post("/api/admin/audit/checkpoint")
    def create_audit_checkpoint(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials, Security(bearer)],
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if audit_checkpoint_service is None:
            raise HTTPException(status_code=409, detail="Audit chain đang tắt.")
        require_recent_step_up(credentials, admin, db)
        record_audit(
            db,
            request,
            "audit.checkpoint.request",
            actor_id=admin.id,
            target_type="audit_event",
        )
        try:
            checkpoint = audit_checkpoint_service.anchor(db)
        except AuditCheckpointError as exc:
            raise HTTPException(
                status_code=503,
                detail="Không thể neo chuỗi audit tới kho WORM.",
                headers={"Retry-After": "30"},
            ) from exc
        if checkpoint is None:
            raise HTTPException(status_code=409, detail="Chưa có audit event đã niêm phong.")
        return {
            "checkpoint_id": checkpoint.id,
            "last_event_id": checkpoint.last_event_id,
            "root_hash": checkpoint.root_hash,
            "externally_delivered": checkpoint.delivered_at is not None,
            "created_at": checkpoint.created_at,
        }

    @app.get("/api/admin/ids/detections")
    def ids_detections(
        _: Annotated[User, Depends(moderator_or_admin)],
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        """Recent signature-engine hits held in memory by the IPS."""
        return intrusion_state.recent(limit)

    @app.get("/api/admin/ids/anomalies")
    def ids_anomalies(
        _: Annotated[User, Depends(moderator_or_admin)],
        db: Annotated[Session, Depends(get_db)],
        window_minutes: Annotated[int, Query(ge=1, le=1440)] = 60,
    ):
        """Anomaly-engine findings correlated from the audit trail."""
        return [
            anomaly.as_dict() for anomaly in detect_anomalies(db, window_minutes=window_minutes)
        ]

    @app.post("/api/admin/ids/verify-detection")
    def verify_ids_detection(
        admin: Annotated[User, Depends(admin_user)],
        request: Request,
        db: Annotated[Session, Depends(get_db)],
    ):
        """Run the safe, deterministic Purple Team check for IDS signatures.

        This never sends a request to a target and never executes a command.
        It validates the application's T1190 signature controls only; the
        response names the boundary so it is not mistaken for a full pentest.
        """
        report = run_safe_detection_verification()
        outcome = "success" if report["missed_scenarios"] == 0 else "failure"
        record_audit(
            db,
            request,
            "ids.verification",
            actor_id=admin.id,
            target_type="mitre_technique",
            target_id="T1190",
            outcome=outcome,
            details={
                "technique": "T1190",
                "total_scenarios": report["total_scenarios"],
                "detected_scenarios": report["detected_scenarios"],
                "missed_scenarios": report["missed_scenarios"],
                "detection_rate": report["detection_rate"],
            },
        )
        report["checked_at"] = utcnow().isoformat()
        report["checked_by"] = admin.username
        return report

    @app.get("/api/admin/ids/blocklist")
    def ids_blocklist(_: Annotated[User, Depends(admin_user)]):
        return intrusion_state.blocked_sources()

    @app.delete("/api/admin/ids/blocklist/{source_ip}", status_code=204)
    def ids_unblock(
        source_ip: str,
        request: Request,
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        removed = intrusion_state.unblock(source_ip)
        record_audit(
            db,
            request,
            "ids.unblock",
            actor_id=admin.id,
            target_type="source_ip",
            target_id=source_ip,
            outcome="success" if removed else "failure",
        )
        if not removed:
            raise HTTPException(
                status_code=404, detail="Địa chỉ này không nằm trong danh sách chặn."
            )
        return Response(status_code=204)

    # The Gradio interface is the only supported web client. Keeping the former
    # static SPA alongside it duplicated authentication and security-sensitive
    # client code without serving the production workflow.
    gradio_demo = build_ui()
    gradio_auth_dependency = None
    if settings.gradio_auth_mode == "oidc":
        try:
            proxy_secret = Path(settings.oidc_proxy_secret_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Không đọc được bí mật xác thực reverse proxy OIDC.") from exc
        if len(proxy_secret) < 32 or len(proxy_secret) > 4096:
            raise RuntimeError("Bí mật reverse proxy OIDC phải dài 32-4096 ký tự.")

        def verified_proxy_identity(request: Request) -> str | None:
            supplied_secret = request.headers.get(settings.oidc_proxy_secret_header, "")
            identity = request.headers.get(settings.oidc_user_header, "").strip()
            if not supplied_secret or not secrets.compare_digest(
                supplied_secret,
                proxy_secret,
            ):
                return None
            if (
                not identity
                or len(identity) > 128
                or any(character in identity for character in ("\r", "\n", "\x00"))
            ):
                return None
            return identity

        gradio_auth_dependency = verified_proxy_identity

    # Gradio 6 supports these parameters. Security controls must fail closed if
    # an incompatible version is installed, rather than silently mounting an
    # unauthenticated or unlimited upload surface.
    app = gr.mount_gradio_app(
        app,
        gradio_demo,
        path="/",
        theme=THEME,
        css=CUSTOM_CSS,
        auth_dependency=gradio_auth_dependency,
        blocked_paths=["/app/.env", "/run/secrets", "/proc", "/sys", "/etc"],
        show_error=False,
        max_file_size=settings.gradio_max_file_size,
        enable_monitoring=False,
    )

    return app


app = create_app()
