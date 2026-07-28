import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

import gradio as gr
import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.audit import client_ip, record_audit
from src.app.audit_chain import derive_audit_key, verify_chain
from src.app.config import Settings
from src.app.db import Database, utcnow
from src.app.gradio_ui import build_ui
from src.app.ids import (
    DECOY_PATHS,
    SCANNER_AGENTS,
    Detection,
    IntrusionState,
    detect_anomalies,
    scan_text,
)
from src.app.models import (
    AuditEvent,
    AuthSession,
    ChatSession,
    MfaRecoveryCode,
    RevokedToken,
    SecureMessage,
    User,
)
from src.app.schemas import (
    AdminCreateUser,
    AIConsentUpdate,
    AuditResponse,
    AuthSessionResponse,
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
    SessionUpdate,
    TokenResponse,
    UserResponse,
    UserRoleUpdate,
    UserStatusUpdate,
)
from src.app.security import (
    CryptoService,
    PasswordService,
    PwnedPasswordChecker,
    RedisSlidingWindowRateLimiter,
    SlidingWindowRateLimiter,
    TokenService,
    TotpService,
    generate_recovery_code,
)
from src.app.services import AIService, ChatService
from src.app.siem import configure_siem_logging, emit_security_event

logger = logging.getLogger("secure_chat")

bearer = HTTPBearer(auto_error=False)
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


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
    breach_checker = PwnedPasswordChecker(enabled=settings.password_breach_check)
    token_service = TokenService(settings.secret_key, settings.access_token_minutes)
    crypto_service = CryptoService(
        settings.master_encryption_key,
        keyring=dict(settings.master_encryption_keys) or None,
        active_key_version=settings.active_key_version,
    )
    limiter_type = RedisSlidingWindowRateLimiter if settings.redis_url else SlidingWindowRateLimiter
    limiter_args = (settings.redis_url,) if settings.redis_url else ()
    login_limiter = limiter_type(*limiter_args)
    registration_limiter = limiter_type(*limiter_args)
    message_limiter = limiter_type(*limiter_args)
    mfa_limiter = limiter_type(*limiter_args)
    password_change_limiter = limiter_type(*limiter_args)
    refresh_limiter = limiter_type(*limiter_args)
    totp_service = TotpService()
    chat_service = ChatService(crypto_service, AIService(settings))
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

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if settings.environment == "production" and settings.database_url.startswith(
            ("postgresql://", "postgresql+")
        ):
            database.assert_schema_ready()
        else:
            database.create_all()
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

            seed_demo_data(database, password_service, crypto_service, log=logger.info)
        yield
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
    app.state.totp_service = totp_service
    app.state.chat_service = chat_service
    app.state.intrusion_state = intrusion_state
    app.state.audit_key = audit_key

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
            blocked, retry_after = intrusion_state.is_blocked(source_ip)
            if blocked:
                emit_security_event(
                    "ids.block.enforced",
                    outcome="blocked",
                    source_ip=source_ip,
                    request_id=request_id,
                    details={"path": request.url.path[:200]},
                )
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Nguồn truy cập đang bị tạm chặn do hành vi bất thường."},
                    headers={"X-Request-ID": request_id, "Retry-After": str(retry_after)},
                )

            detections: list[Detection] = []
            surface = f"{request.url.path}?{request.url.query}"
            for rule_id, severity, description, evidence in scan_text(surface):
                detections.append(
                    Detection(
                        rule_id=rule_id,
                        severity=severity,
                        engine="signature",
                        description=description,
                        source_ip=source_ip,
                        path=request.url.path[:200],
                        method=request.method,
                        evidence=evidence,
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
                        path=request.url.path[:200],
                        method=request.method,
                        evidence=user_agent[:120],
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
                        path=request.url.path[:200],
                        method=request.method,
                        evidence=request.url.path[:120],
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
                                "path": detection.path,
                                "method": detection.method,
                                "evidence": detection.evidence,
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
            # so the main origin no longer ships eval unconditionally. 'unsafe-inline' remains
            # pending a nonce/hash refactor (phase 2). object-src is locked to 'none'.
            script_eval = " 'unsafe-eval'" if settings.csp_allow_unsafe_eval else ""
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'unsafe-inline'{script_eval} https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
                "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:; "
                "img-src 'self' data: blob: https:; "
                "connect-src 'self' ws: wss:; "
                "worker-src 'self' blob:; "
                "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        response.headers["Content-Security-Policy"] = csp
        if settings.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Log server-side with request correlation, but never expose exception details to clients.
        logger.error(
            "Unhandled exception request_id=%s",
            getattr(request.state, "request_id", None),
            exc_info=(type(exc), exc, exc.__traceback__),
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
        return user

    def moderator_or_admin(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in ("moderator", "admin"):
            raise HTTPException(status_code=403, detail="Không đủ quyền truy cập.")
        return user

    def require_owned_session(
        session_id: str,
        user: User,
        db: Session,
        request: Request,
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
        return chat_session

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
                user_agent=request.headers.get("user-agent", "")[:256] or None,
                root_issued_at=root_issued_at or issued_at,
            )
        )
        return token

    def load_mfa_secret(user: User) -> str | None:
        if not user.mfa_secret_ciphertext or not user.mfa_secret_nonce:
            return None
        return crypto_service.decrypt_secret(
            user.mfa_secret_ciphertext, user.mfa_secret_nonce, context=f"mfa:{user.id}"
        )

    def consume_recovery_code(db: Session, user: User, candidate: str) -> bool:
        """Match a submitted backup code against unused hashes; burn it if valid."""
        normalized = candidate.strip().lower().replace(" ", "")
        for record in db.scalars(
            select(MfaRecoveryCode).where(
                MfaRecoveryCode.user_id == user.id,
                MfaRecoveryCode.used_at.is_(None),
            )
        ):
            if password_service.verify(record.code_hash, normalized):
                record.used_at = utcnow()
                return True
        return False

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
        if breach_checker.is_compromised(payload.password):
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
            challenge = token_service.issue_mfa_challenge(user.id, settings.mfa_challenge_minutes)
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

        token = issue_access_session(db, request, user, ip)
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
        secret = load_mfa_secret(user) if user is not None else None
        if user is None or not user.is_active or not user.mfa_enabled or secret is None:
            record_audit(
                db,
                request,
                "auth.mfa.verify",
                actor_id=user_id,
                outcome="failure",
                details={"reason": "not_enrolled"},
            )
            raise HTTPException(status_code=401, detail="Không xác thực được mã.")

        matched_counter = totp_service.verify(
            secret, payload.code, after_counter=user.mfa_last_counter
        )
        used_recovery = False
        if matched_counter is None:
            used_recovery = consume_recovery_code(db, user, payload.code)
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
            # Persist the accepted time counter so the same code cannot be replayed.
            user.mfa_last_counter = matched_counter

        mfa_limiter.reset(f"mfa:{user_id}")
        db.add(
            RevokedToken(
                jti=challenge_jti,
                user_id=user.id,
                expires_at=datetime.fromtimestamp(int(challenge["exp"]), tz=timezone.utc),
                reason="mfa_challenge_used",
            )
        )
        token = issue_access_session(db, request, user, ip)
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
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if user.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA đã được bật cho tài khoản này.")
        secret = totp_service.generate_secret()
        ciphertext, nonce = crypto_service.encrypt_secret(secret, context=f"mfa:{user.id}")
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

        plain_codes = [generate_recovery_code() for _ in range(settings.mfa_recovery_codes)]
        db.add_all(
            MfaRecoveryCode(user_id=user.id, code_hash=password_service.hash(code))
            for code in plain_codes
        )
        user.mfa_enabled = True
        user.mfa_last_counter = matched_counter
        # Force other devices to re-authenticate now that a second factor exists.
        revoke_all_auth_sessions(db, user)
        db.commit()
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
        if not user.mfa_enabled:
            raise HTTPException(status_code=409, detail="MFA chưa được bật.")
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
        code_ok = secret is not None and (
            totp_service.verify(secret, payload.code, after_counter=user.mfa_last_counter)
            is not None
            or consume_recovery_code(db, user, payload.code)
        )
        if not code_ok:
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

        user.mfa_enabled = False
        user.mfa_secret_ciphertext = None
        user.mfa_secret_nonce = None
        user.mfa_last_counter = 0
        for record in db.scalars(select(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id)):
            db.delete(record)
        revoke_all_auth_sessions(db, user)
        db.commit()
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

    @app.patch("/api/auth/ai-consent", response_model=UserResponse)
    def update_ai_consent(
        payload: AIConsentUpdate,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if user.ai_data_consent != payload.ai_data_consent:
            user.ai_data_consent = payload.ai_data_consent
            db.commit()
            db.refresh(user)
            record_audit(
                db,
                request,
                "privacy.ai_consent",
                actor_id=user.id,
                target_type="user",
                target_id=user.id,
                details={"consented": payload.ai_data_consent},
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
        expires_at = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
        db.add(
            RevokedToken(
                jti=str(payload["jti"]),
                user_id=user.id,
                expires_at=expires_at,
                reason="logout",
            )
        )
        auth_session = db.get(AuthSession, str(payload["jti"]))
        if auth_session is not None:
            auth_session.revoked_at = utcnow()
        db.commit()
        record_audit(
            db, request, "auth.logout", actor_id=user.id, target_type="user", target_id=user.id
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
        old_session = db.get(AuthSession, old_jti)

        root_issued_at = None
        if old_session is not None:
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

        token = issue_access_session(db, request, user, ip, root_issued_at=root_issued_at)
        # Thu hồi token cũ SAU khi đã cấp token mới, trong cùng transaction.
        db.add(
            RevokedToken(
                jti=old_jti,
                user_id=user.id,
                expires_at=datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc),
                reason="refresh",
            )
        )
        if old_session is not None:
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
        if breach_checker.is_compromised(payload.new_password):
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
        # Cap the number of sessions per user so a single account cannot exhaust
        # database/storage resources by creating unlimited sessions.
        session_count = (
            db.scalar(
                select(func.count()).select_from(ChatSession).where(ChatSession.owner_id == user.id)
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
        row = ChatSession(owner_id=user.id, title=payload.title)
        db.add(row)
        db.commit()
        db.refresh(row)
        record_audit(
            db,
            request,
            "chat.session.create",
            actor_id=user.id,
            target_type="chat_session",
            target_id=row.id,
        )
        return row

    @app.get("/api/sessions", response_model=list[SessionResponse])
    def list_sessions_endpoint(
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        stmt = (
            select(ChatSession)
            .where(ChatSession.owner_id == user.id)
            .order_by(ChatSession.updated_at.desc())
            .limit(100)
        )
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
        row = require_owned_session(session_id, user, db, request)
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
            details={"new_title": payload.title},
        )
        return row

    @app.delete("/api/sessions/{session_id}", status_code=204)
    def delete_session_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row = require_owned_session(session_id, user, db, request)
        db.delete(row)
        db.commit()
        record_audit(
            db,
            request,
            "chat.session.delete",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
        )
        return Response(status_code=204)

    @app.get("/api/sessions/{session_id}/export")
    def export_session_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        row = require_owned_session(session_id, user, db, request)
        messages = chat_service.list_messages(db, row)
        record_audit(
            db,
            request,
            "chat.session.export",
            actor_id=user.id,
            target_type="chat_session",
            target_id=session_id,
        )
        return {
            "session_id": row.id,
            "title": row.title,
            "owner_id": row.owner_id,
            "created_at": row.created_at.isoformat(),
            "messages": [
                {
                    "role": m["role"],
                    "content": m["content"],
                    "created_at": m["created_at"].isoformat(),
                }
                for m in messages
            ],
        }

    @app.get("/api/sessions/{session_id}/messages", response_model=list[MessageResponse])
    def get_messages_endpoint(
        session_id: str,
        request: Request,
        user: Annotated[User, Depends(current_user)],
        db: Annotated[Session, Depends(get_db)],
        query: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    ):
        row = require_owned_session(session_id, user, db, request)
        return chat_service.list_messages(db, row, query=query)

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
        row = require_owned_session(session_id, user, db, request)
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
                allow_external_ai=user.ai_data_consent,
            )
        except PermissionError as exc:
            record_audit(
                db,
                request,
                "chat.message.send",
                actor_id=user.id,
                target_type="chat_session",
                target_id=session_id,
                outcome="denied",
                details={"reason": "external_ai_consent_required"},
            )
            raise HTTPException(status_code=403, detail=str(exc)) from exc
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
        sessions = list(
            db.scalars(
                select(ChatSession)
                .where(ChatSession.owner_id == user.id)
                .order_by(ChatSession.updated_at.desc())
                .limit(100)
            )
        )
        results: list[dict] = []
        for chat_session in sessions:
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
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        if breach_checker.is_compromised(payload.password):
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
            details={"username": user.username, "role": user.role},
        )
        return user

    @app.delete("/api/admin/users/{user_id}", status_code=204)
    def admin_delete_user(
        user_id: str,
        request: Request,
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User not found.")
        if target.id == admin.id:
            raise HTTPException(status_code=400, detail="Admin không thể tự xóa chính mình.")
        if target.role == "admin":
            raise HTTPException(status_code=400, detail="Không thể xóa tài khoản admin khác.")
        username = target.username
        db.delete(target)
        db.commit()
        record_audit(
            db,
            request,
            "admin.user_delete",
            actor_id=admin.id,
            target_type="user",
            target_id=user_id,
            details={"deleted_username": username},
        )
        return Response(status_code=204)

    @app.patch("/api/admin/users/{user_id}/role", response_model=UserResponse)
    def admin_change_role(
        user_id: str,
        payload: UserRoleUpdate,
        request: Request,
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
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
        admin: Annotated[User, Depends(admin_user)],
        db: Annotated[Session, Depends(get_db)],
    ):
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="User account was not found.")
        if target.id == admin.id and not payload.is_active:
            raise HTTPException(
                status_code=400, detail="The active administrator cannot lock itself."
            )
        if target.is_active != payload.is_active:
            target.is_active = payload.is_active
            revoke_all_auth_sessions(db, target)
            db.commit()
            record_audit(
                db,
                request,
                "admin.user_status",
                actor_id=admin.id,
                target_type="user",
                target_id=target.id,
                details={"is_active": target.is_active, "token_version": target.token_version},
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
        payload["checked_at"] = utcnow().isoformat()
        payload["checked_by"] = admin.username
        return payload

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
    app = gr.mount_gradio_app(app, gradio_demo, path="/")

    return app


app = create_app()
