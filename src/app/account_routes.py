"""REST routes for recovery email, password reset and passkeys.

Registered from ``create_app`` with the shared authentication helpers, the
same way ``register_ui_session_routes`` is, so these flows go through the same
JWT, step-up, rate-limit and audit controls as every other endpoint.
"""

# No ``from __future__ import annotations`` here: FastAPI must evaluate the
# route annotations, which refer to dependency aliases local to the factory.
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timezone
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.account_recovery import (
    consume_code,
    issue_code,
    notify,
    send_code,
)
from src.app.account_security import describe_user_agent
from src.app.audit import client_ip, client_user_agent, record_audit
from src.app.config import Settings
from src.app.db import utcnow
from src.app.mailer import Mailer, mask_email, normalize_email
from src.app.models import AccountEmail, AccountRecoveryCode, User, WebAuthnCredential
from src.app.passkeys import PasskeyError, PasskeyService, clean_passkey_name, passkey_view
from src.app.schemas import (
    AccountEmailResponse,
    EmailUpdateRequest,
    PasskeyAuthenticationVerify,
    PasskeyCeremonyResponse,
    PasskeyRegistrationVerify,
    PasskeyResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    RecoveryCodeRequest,
    TokenResponse,
)
from src.app.security import PasswordService

RESET_ACCEPTED = {
    "status": "accepted",
    "message": "Nếu tài khoản có email khôi phục đã xác minh, mã đặt lại đã được gửi tới email đó.",
}


@dataclass(frozen=True)
class AccountRouteContext:
    settings: Settings
    get_db: Callable[..., Any]
    current_user: Callable[..., Any]
    bearer: HTTPBearer
    password_service: PasswordService
    mailer: Mailer
    passkeys: PasskeyService
    limiter: Any
    recovery_key: bytes
    require_recent_step_up: Callable[..., Any]
    revoke_all_auth_sessions: Callable[..., Any]
    lock_user_row: Callable[..., Any]
    password_is_compromised: Callable[..., bool]
    presented_device_id: Callable[..., str | None]
    sign_in_source: Callable[..., Any]
    finish_sign_in: Callable[..., TokenResponse]
    clear_login_throttle: Callable[[str, str], None]


def _as_utc(value):
    return value if value is None or value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def register_account_routes(app: FastAPI, ctx: AccountRouteContext) -> None:
    settings = ctx.settings
    DB = Annotated[Session, Depends(ctx.get_db)]
    CurrentUser = Annotated[User, Depends(ctx.current_user)]
    Credentials = Annotated[HTTPAuthorizationCredentials, Security(ctx.bearer)]

    def throttle(
        db: Session,
        request: Request,
        key: str,
        max_attempts: int,
        window_seconds: int,
        event_type: str,
        actor_id: str | None = None,
    ) -> None:
        allowed, retry_after = ctx.limiter.allow(key, max_attempts, window_seconds)
        if not allowed:
            record_audit(
                db, request, event_type, actor_id=actor_id, outcome="blocked",
                details={"reason": "rate_limit"},
            )
            raise HTTPException(
                status_code=429,
                detail="Thao tác quá nhiều lần; vui lòng thử lại sau.",
                headers={"Retry-After": str(retry_after)},
            )

    def require_mail() -> None:
        if not ctx.mailer.enabled:
            raise HTTPException(
                status_code=503, detail="Hệ thống chưa được cấu hình để gửi email."
            )

    def notify_user(db: Session, request: Request, user: User, kind: str, **kwargs) -> None:
        notify(
            db, ctx.mailer, user_id=user.id, username=user.username, kind=kind,
            ip=client_ip(request), **kwargs,
        )

    # ───────────────────────── recovery email ─────────────────────────

    def email_view(db: Session, user: User) -> AccountEmailResponse:
        record = db.get(AccountEmail, user.id)
        pending = db.scalars(
            select(AccountRecoveryCode)
            .where(
                AccountRecoveryCode.user_id == user.id,
                AccountRecoveryCode.purpose == "email_verify",
                AccountRecoveryCode.consumed_at.is_(None),
                AccountRecoveryCode.expires_at > utcnow(),
            )
            .order_by(AccountRecoveryCode.created_at.desc())
        ).first()
        return AccountEmailResponse(
            email=record.email if record else None,
            verified_at=_as_utc(record.verified_at) if record else None,
            pending_email=pending.target_email if pending else None,
            delivery_available=ctx.mailer.enabled,
        )

    @app.get("/api/auth/email", response_model=AccountEmailResponse)
    def get_account_email(user: CurrentUser, db: DB):
        return email_view(db, user)

    @app.post("/api/auth/email", response_model=AccountEmailResponse, status_code=202)
    def request_email_verification(
        payload: EmailUpdateRequest,
        request: Request,
        credentials: Credentials,
        user: CurrentUser,
        db: DB,
    ):
        """Send a code to a new address. Changing the recovery channel is a
        takeover vector, so it needs a recent password/MFA re-check."""
        ctx.require_recent_step_up(credentials, user, db)
        require_mail()
        normalized = normalize_email(payload.email)
        if normalized is None:
            raise HTTPException(status_code=422, detail="Địa chỉ email không hợp lệ.")
        throttle(db, request, f"email-verify:{user.id}", 5, 3600, "account.email.verification",
                 user.id)
        code = issue_code(
            db, ctx.recovery_key, user_id=user.id, purpose="email_verify", now=utcnow(),
            minutes=settings.password_reset_minutes, target_email=normalized,
        )
        db.commit()
        send_code(
            ctx.mailer, normalized, purpose="email_verify", username=user.username, code=code,
            minutes=settings.password_reset_minutes,
        )
        record_audit(
            db, request, "account.email.verification", actor_id=user.id, target_type="user",
            target_id=user.id, details={"email": mask_email(normalized)},
        )
        return email_view(db, user)

    @app.post("/api/auth/email/verify", response_model=AccountEmailResponse)
    def verify_account_email(
        payload: RecoveryCodeRequest, request: Request, user: CurrentUser, db: DB
    ):
        throttle(db, request, f"email-verify-code:{user.id}", 10, 3600, "account.email.verify",
                 user.id)
        now = utcnow()
        record = consume_code(
            db, ctx.recovery_key, user_id=user.id, purpose="email_verify", code=payload.code,
            now=now,
        )
        if record is None or not record.target_email:
            db.commit()  # keep the failed-attempt count
            record_audit(
                db, request, "account.email.verify", actor_id=user.id, outcome="failure",
                details={"reason": "invalid_code"},
            )
            raise HTTPException(status_code=400, detail="Mã không đúng hoặc đã hết hạn.")
        target = record.target_email
        existing = db.get(AccountEmail, user.id)
        previous = existing.email if existing is not None else None
        if existing is None:
            db.add(AccountEmail(user_id=user.id, email=target, normalized_email=target,
                                verified_at=now))
        else:
            existing.email = target
            existing.normalized_email = target
            existing.verified_at = now
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            # Shown only to someone who received the code at that address.
            raise HTTPException(
                status_code=409, detail="Email này đã được dùng cho một tài khoản khác."
            ) from exc
        record_audit(
            db, request, "account.email.verify", actor_id=user.id, target_type="user",
            target_id=user.id, details={"email": mask_email(target)},
        )
        if previous and previous != target:
            notify_user(db, request, user, "email_changed", to=previous)
        return email_view(db, user)

    @app.delete("/api/auth/email", status_code=204)
    def remove_account_email(
        request: Request, credentials: Credentials, user: CurrentUser, db: DB
    ):
        ctx.require_recent_step_up(credentials, user, db)
        record = db.get(AccountEmail, user.id)
        if record is None:
            raise HTTPException(status_code=404, detail="Tài khoản chưa có email khôi phục.")
        previous = record.email
        db.delete(record)
        db.execute(
            update(AccountRecoveryCode)
            .where(AccountRecoveryCode.user_id == user.id, AccountRecoveryCode.consumed_at.is_(None))
            .values(consumed_at=utcnow())
            .execution_options(synchronize_session=False)
        )
        db.commit()
        record_audit(
            db, request, "account.email.remove", actor_id=user.id, target_type="user",
            target_id=user.id,
        )
        notify_user(db, request, user, "email_changed", to=previous)
        return Response(status_code=204)

    # ───────────────────────── password reset ─────────────────────────

    def find_account(db: Session, identifier: str) -> User | None:
        normalized = normalize_email(identifier)
        if normalized is not None:
            record = db.scalar(
                select(AccountEmail).where(AccountEmail.normalized_email == normalized)
            )
            return db.get(User, record.user_id) if record is not None else None
        return db.scalar(select(User).where(User.username == identifier.strip().lower()))

    @app.post("/api/auth/password-reset/request", status_code=202)
    def request_password_reset(payload: PasswordResetRequest, request: Request, db: DB):
        """Always answers the same way, so it cannot be used to find accounts."""
        require_mail()
        ip = client_ip(request)
        throttle(db, request, f"reset-request:ip:{ip}", 5, 900, "auth.password_reset.request")
        user = find_account(db, payload.identifier)
        if user is None or not user.is_active:
            record_audit(
                db, request, "auth.password_reset.request", outcome="failure",
                details={"reason": "unknown_or_inactive_account"},
            )
            return RESET_ACCEPTED
        email = db.get(AccountEmail, user.id)
        allowed, _ = ctx.limiter.allow(f"reset-request:user:{user.id}", 3, 3600)
        if email is None or not allowed:
            record_audit(
                db, request, "auth.password_reset.request", actor_id=user.id, outcome="denied",
                details={"reason": "no_verified_email" if email is None else "rate_limit"},
            )
            return RESET_ACCEPTED
        code = issue_code(
            db, ctx.recovery_key, user_id=user.id, purpose="password_reset", now=utcnow(),
            minutes=settings.password_reset_minutes,
        )
        db.commit()
        send_code(
            ctx.mailer, email.email, purpose="password_reset", username=user.username, code=code,
            minutes=settings.password_reset_minutes,
        )
        record_audit(
            db, request, "auth.password_reset.request", actor_id=user.id, target_type="user",
            target_id=user.id, details={"email": mask_email(email.email)},
        )
        return RESET_ACCEPTED

    @app.post("/api/auth/password-reset/confirm", status_code=204)
    def confirm_password_reset(payload: PasswordResetConfirm, request: Request, db: DB):
        ip = client_ip(request)
        throttle(db, request, f"reset-confirm:ip:{ip}", 10, 900, "auth.password_reset")
        generic = HTTPException(
            status_code=400, detail="Mã không đúng, đã hết hạn, hoặc tài khoản không hợp lệ."
        )
        # Screen the new password first so a rejected choice does not burn the code.
        user = find_account(db, payload.identifier)
        if ctx.password_is_compromised(
            payload.new_password, request, db, event_type="auth.password_reset",
            actor_id=user.id if user else None,
        ):
            raise HTTPException(
                status_code=400,
                detail="Mật khẩu mới đã xuất hiện trong dữ liệu rò rỉ công khai; hãy chọn mật khẩu khác.",
            )
        if user is None or ctx.lock_user_row(db, user) is None:
            record_audit(
                db, request, "auth.password_reset", outcome="failure",
                details={"reason": "unknown_or_inactive_account"},
            )
            raise generic
        now = utcnow()
        record = consume_code(
            db, ctx.recovery_key, user_id=user.id, purpose="password_reset", code=payload.code,
            now=now,
        )
        if record is None:
            db.commit()  # keep the failed-attempt count
            record_audit(
                db, request, "auth.password_reset", actor_id=user.id, outcome="failure",
                details={"reason": "invalid_code"},
            )
            raise generic
        user.password_hash = ctx.password_service.hash(payload.new_password)
        # Proving the mailbox lifts a lockout, like self-service reset elsewhere.
        user.failed_login_attempts = 0
        user.locked_until = None
        ctx.revoke_all_auth_sessions(db, user)
        db.execute(
            update(AccountRecoveryCode)
            .where(
                AccountRecoveryCode.user_id == user.id,
                AccountRecoveryCode.purpose == "password_reset",
                AccountRecoveryCode.consumed_at.is_(None),
            )
            .values(consumed_at=now)
            .execution_options(synchronize_session=False)
        )
        db.commit()
        ctx.clear_login_throttle(user.username, ip)
        record_audit(
            db, request, "auth.password_reset", actor_id=user.id, target_type="user",
            target_id=user.id,
            details={"token_version": user.token_version, "mfa_still_required": user.mfa_enabled},
        )
        notify_user(db, request, user, "password_reset")
        return Response(status_code=204)

    # ───────────────────────── passkeys ─────────────────────────

    @app.get("/api/auth/passkeys", response_model=list[PasskeyResponse])
    def list_passkeys(user: CurrentUser, db: DB):
        rows = db.scalars(
            select(WebAuthnCredential)
            .where(WebAuthnCredential.user_id == user.id)
            .order_by(WebAuthnCredential.created_at.asc())
        )
        return [passkey_view(row) for row in rows]

    @app.post("/api/auth/passkeys/registration/options", response_model=PasskeyCeremonyResponse)
    def passkey_registration_options(
        request: Request, credentials: Credentials, user: CurrentUser, db: DB
    ):
        ctx.require_recent_step_up(credentials, user, db)
        throttle(db, request, f"passkey-register:{user.id}", 10, 3600, "auth.passkey.add", user.id)
        try:
            options = ctx.passkeys.registration_options(
                db, user_id=user.id, username=user.username, now=utcnow()
            )
        except PasskeyError as exc:
            raise HTTPException(
                status_code=409, detail="Tài khoản đã đạt số passkey tối đa."
            ) from exc
        db.commit()
        return PasskeyCeremonyResponse(
            challenge_id=options.challenge_id, public_key=options.public_key
        )

    @app.post(
        "/api/auth/passkeys/registration/verify", response_model=PasskeyResponse, status_code=201
    )
    def passkey_registration_verify(
        payload: PasskeyRegistrationVerify,
        request: Request,
        credentials: Credentials,
        user: CurrentUser,
        db: DB,
    ):
        ctx.require_recent_step_up(credentials, user, db)
        name = clean_passkey_name(
            payload.name, describe_user_agent(client_user_agent(request)) or "Passkey"
        )
        try:
            row = ctx.passkeys.verify_registration(
                db, user_id=user.id, challenge_id=payload.challenge_id,
                credential=payload.credential, name=name, now=utcnow(),
            )
        except PasskeyError as exc:
            db.commit()  # the challenge stays consumed
            record_audit(
                db, request, "auth.passkey.add", actor_id=user.id, outcome="failure",
                details={"reason": exc.reason},
            )
            raise HTTPException(status_code=400, detail="Không xác minh được passkey.") from exc
        db.commit()
        record_audit(
            db, request, "auth.passkey.add", actor_id=user.id, target_type="passkey",
            target_id=row.id, details={"name": row.name, "backed_up": row.backed_up},
        )
        notify_user(db, request, user, "passkey_added", device=row.name)
        return passkey_view(row)

    @app.delete("/api/auth/passkeys/{passkey_id}", status_code=204)
    def delete_passkey(
        passkey_id: str, request: Request, credentials: Credentials, user: CurrentUser, db: DB
    ):
        ctx.require_recent_step_up(credentials, user, db)
        row = db.get(WebAuthnCredential, passkey_id)
        if row is None or row.user_id != user.id:
            raise HTTPException(status_code=404, detail="Không tìm thấy passkey.")
        name = row.name
        db.delete(row)
        db.commit()
        record_audit(
            db, request, "auth.passkey.remove", actor_id=user.id, target_type="passkey",
            target_id=passkey_id, details={"name": name},
        )
        notify_user(db, request, user, "passkey_removed", device=name)
        return Response(status_code=204)

    @app.post(
        "/api/auth/passkeys/authentication/options", response_model=PasskeyCeremonyResponse
    )
    def passkey_authentication_options(request: Request, db: DB):
        throttle(db, request, f"passkey-auth:ip:{client_ip(request)}", 20, 300,
                 "auth.passkey.login")
        options = ctx.passkeys.authentication_options(db, now=utcnow())
        db.commit()
        return PasskeyCeremonyResponse(
            challenge_id=options.challenge_id, public_key=options.public_key
        )

    @app.post("/api/auth/passkeys/authentication/verify", response_model=TokenResponse)
    def passkey_authentication_verify(
        payload: PasskeyAuthenticationVerify, request: Request, db: DB
    ):
        """Passwordless sign-in. User verification on the authenticator plus
        possession of the key is two factors, so no TOTP step follows."""
        ip = client_ip(request)
        throttle(db, request, f"passkey-auth-verify:ip:{ip}", 10, 300, "auth.passkey.login")
        denied = HTTPException(status_code=401, detail="Không xác thực được passkey.")
        try:
            row = ctx.passkeys.verify_authentication(
                db, challenge_id=payload.challenge_id, credential=payload.credential, now=utcnow()
            )
        except PasskeyError as exc:
            db.commit()  # the challenge stays consumed
            record_audit(
                db, request, "auth.passkey.login", actor_id=exc.user_id, outcome="failure",
                details={"reason": exc.reason},
            )
            raise denied from exc
        user = db.get(User, row.user_id)
        if user is None or not user.is_active:
            db.commit()
            record_audit(
                db, request, "auth.passkey.login", actor_id=row.user_id, outcome="denied",
                details={"reason": "inactive_account"},
            )
            raise denied
        device_id = ctx.presented_device_id(request, user)
        source = ctx.sign_in_source(db, request, user.id, ip, device_id)
        return ctx.finish_sign_in(
            db, request, user, ip, source, device_id, event_type="auth.passkey.login",
            details={"passkey": row.id},
        )
