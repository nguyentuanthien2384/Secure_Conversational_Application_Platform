"""Opt-in security notification routes with exact-bearer and step-up guards."""

# Dependency aliases are local to the route factory; FastAPI resolves eagerly.
import hmac
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.app.audit import client_ip, record_audit
from src.app.db import utcnow
from src.app.models import SecurityPhone, SecurityPhoneChallenge, SecurityPushSubscription, User
from src.app.security_notifications import (
    SecurityNotifications,
    keyed_digest,
    mask_phone,
    normalize_phone,
    validate_subscription,
)


class PushKeys(BaseModel):
    model_config = ConfigDict(extra="forbid")
    p256dh: str = Field(min_length=80, max_length=100)
    auth: str = Field(min_length=20, max_length=30)


class PushSubscriptionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint: str = Field(min_length=20, max_length=2048)
    keys: PushKeys
    expirationTime: int | None = None  # Browser's standard toJSON field.


class PhoneRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phone: str = Field(min_length=9, max_length=16)


class PhoneVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=36, max_length=36)
    code: str = Field(min_length=1, max_length=16)


@dataclass(frozen=True)
class NotificationRouteContext:
    get_db: Callable[..., Any]
    current_user: Callable[..., Any]
    bearer: HTTPBearer
    lock_account_mutation: Callable[..., Any]
    limiter: Any
    notifications: SecurityNotifications
    recovery_key: bytes
    crypto: Any


def _as_utc(value):
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def register_notification_routes(app: FastAPI, ctx: NotificationRouteContext) -> None:
    DB = Annotated[Session, Depends(ctx.get_db)]
    CurrentUser = Annotated[User, Depends(ctx.current_user)]
    Credentials = Annotated[HTTPAuthorizationCredentials, Security(ctx.bearer)]
    notices = ctx.notifications

    def throttle(key: str, limit: int, seconds: int) -> None:
        allowed, retry = ctx.limiter.allow("notification:" + key, limit, seconds)
        if not allowed:
            raise HTTPException(429, "Thao tác thông báo quá nhiều lần; vui lòng thử lại sau.", headers={"Retry-After": str(retry)})

    def status(db: Session, user: User) -> dict[str, Any]:
        phone = db.get(SecurityPhone, user.id)
        destination = None
        if phone:
            value = ctx.crypto.decrypt_user_secret(
                user, ciphertext_b64=phone.phone_ciphertext, nonce_b64=phone.phone_nonce,
                field=f"security-phone:{user.id}",
            )
            destination = mask_phone(value)
        pending = db.scalar(select(SecurityPhoneChallenge).where(
            SecurityPhoneChallenge.user_id == user.id,
            SecurityPhoneChallenge.consumed_at.is_(None),
            SecurityPhoneChallenge.expires_at > utcnow(),
        ).order_by(SecurityPhoneChallenge.created_at.desc()).limit(1))
        return {
            "push": {
                "available": notices.push_enabled, "mode": notices.settings.push_backend,
                "application_server_key": notices.public_key if notices.push_enabled else None,
                "subscriptions": [{"id": row.id, "created_at": _as_utc(row.created_at).isoformat()} for row in db.scalars(select(SecurityPushSubscription).where(SecurityPushSubscription.user_id == user.id).order_by(SecurityPushSubscription.created_at, SecurityPushSubscription.id))],
            },
            "sms": {
                "available": notices.sms_enabled, "mode": notices.settings.sms_backend,
                "phone": destination, "verified_at": _as_utc(phone.verified_at).isoformat() if phone else None,
                "pending": {"challenge_id": pending.id, "expires_at": _as_utc(pending.expires_at).isoformat()} if pending else None,
            },
        }

    @app.get("/api/auth/notifications/status")
    def notification_status(user: CurrentUser, db: DB):
        return status(db, user)

    @app.post("/api/auth/notifications/push", status_code=201)
    def subscribe_push(payload: PushSubscriptionRequest, request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        if not notices.push_enabled:
            raise HTTPException(501, "Web Push chưa được cấu hình.")
        throttle("push:" + user.id, 20, 3600)
        ctx.lock_account_mutation(credentials, user, db, step_up=True)
        try:
            subscription = validate_subscription(payload.model_dump())
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        digest = keyed_digest(ctx.recovery_key, "push-endpoint", subscription["endpoint"])
        row = db.scalar(select(SecurityPushSubscription).where(SecurityPushSubscription.endpoint_hash == digest))
        if row and row.user_id != user.id:
            raise HTTPException(409, "Subscription đã được đăng ký; hãy hủy subscription trong trình duyệt trước.")
        if row is None:
            count = db.scalar(select(func.count()).select_from(SecurityPushSubscription).where(SecurityPushSubscription.user_id == user.id))
            if count >= 8:
                raise HTTPException(409, "Mỗi tài khoản chỉ được đăng ký tối đa 8 trình duyệt.")
            row = SecurityPushSubscription(id=str(uuid.uuid4()), user_id=user.id, endpoint_hash=digest)
            db.add(row)
        row.subscription_ciphertext, row.subscription_nonce = ctx.crypto.encrypt_user_secret(
            user, plaintext=json.dumps(subscription, separators=(",", ":")), field=f"security-push:{row.id}",
        )
        try:
            record_audit(db, request, "account.notifications.push.add", actor_id=user.id, target_type="push_subscription", target_id=row.id)
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Subscription đã được đăng ký; hãy thử lại.") from None
        return {"id": row.id, "mode": notices.settings.push_backend, "delivery": "not_sent"}

    @app.delete("/api/auth/notifications/push/{subscription_id}", status_code=204)
    def unsubscribe_push(subscription_id: str, request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        ctx.lock_account_mutation(credentials, user, db, step_up=True)
        row = db.get(SecurityPushSubscription, subscription_id)
        if row is None or row.user_id != user.id:
            raise HTTPException(404, "Không tìm thấy subscription.")
        db.delete(row)
        record_audit(db, request, "account.notifications.push.remove", actor_id=user.id, target_type="push_subscription", target_id=subscription_id)

    @app.delete("/api/auth/notifications/push", status_code=204)
    def unsubscribe_all_push(request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        ctx.lock_account_mutation(credentials, user, db, step_up=True)
        db.execute(delete(SecurityPushSubscription).where(SecurityPushSubscription.user_id == user.id))
        record_audit(db, request, "account.notifications.push.remove_all", actor_id=user.id)

    @app.post("/api/auth/notifications/phone/request", status_code=202)
    def request_phone(payload: PhoneRequest, request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        if not notices.sms_enabled:
            raise HTTPException(501, "SMS chưa được cấu hình.")
        phone = normalize_phone(payload.phone)
        if phone is None:
            raise HTTPException(422, "Nhập số điện thoại dạng quốc tế E.164, ví dụ +84901234567.")
        digest = keyed_digest(ctx.recovery_key, "phone-target", phone)
        throttle("phone-source:" + client_ip(request), 20, 3600)
        throttle("phone-target:" + digest, 3, 3600)
        throttle("phone-global", 200, 86400)
        auth_session = ctx.lock_account_mutation(credentials, user, db, step_up=True)
        now = utcnow()
        # The account lock serializes the durable per-owner budget, including
        # app restarts; the shared limiter covers cross-account target abuse.
        hour_count = db.scalar(select(func.count()).select_from(SecurityPhoneChallenge).where(SecurityPhoneChallenge.user_id == user.id, SecurityPhoneChallenge.created_at > now - timedelta(hours=1)))
        day_count = db.scalar(select(func.count()).select_from(SecurityPhoneChallenge).where(SecurityPhoneChallenge.user_id == user.id, SecurityPhoneChallenge.created_at > now - timedelta(days=1)))
        target_count = db.scalar(select(func.count()).select_from(SecurityPhoneChallenge).where(SecurityPhoneChallenge.phone_hash == digest, SecurityPhoneChallenge.created_at > now - timedelta(hours=1)))
        if hour_count >= 3 or day_count >= 10 or target_count >= 3:
            raise HTTPException(429, "Đã hết lượt xác minh SMS; vui lòng thử lại sau.", headers={"Retry-After": "3600"})
        db.execute(delete(SecurityPhoneChallenge).where(SecurityPhoneChallenge.user_id == user.id, SecurityPhoneChallenge.created_at <= now - timedelta(days=2), SecurityPhoneChallenge.expires_at <= now))
        db.execute(update(SecurityPhoneChallenge).where(SecurityPhoneChallenge.user_id == user.id, SecurityPhoneChallenge.consumed_at.is_(None)).values(consumed_at=now))
        challenge_id = str(uuid.uuid4())
        code = f"{secrets.randbelow(100_000_000):08d}"
        ciphertext, nonce = ctx.crypto.encrypt_user_secret(user, plaintext=phone, field=f"security-phone-challenge:{challenge_id}")
        challenge = SecurityPhoneChallenge(
            id=challenge_id, user_id=user.id, auth_session_id=auth_session.jti,
            phone_hash=digest, phone_ciphertext=ciphertext, phone_nonce=nonce,
            code_hash=keyed_digest(ctx.recovery_key, "phone-code:" + challenge_id, code),
            expires_at=now + timedelta(minutes=5), created_at=now,
        )
        db.add(challenge)
        record_audit(db, request, "account.notifications.phone.request", actor_id=user.id, details={"phone": mask_phone(phone)})
        try:
            delivery = notices.send_verification(phone, code)
        except Exception:
            # A committed issuance still consumes its budget. No usable code
            # is returned over HTTP, even if the provider rejected the SMS.
            raise HTTPException(503, "Chưa gửi được mã SMS; hãy thử lại sau.", headers={"Retry-After": "60"}) from None
        return {"challenge_id": challenge_id, "expires_at": challenge.expires_at, "delivery": delivery, "phone": mask_phone(phone)}

    @app.post("/api/auth/notifications/phone/verify")
    def verify_phone(payload: PhoneVerification, request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        throttle("phone-proof:" + user.id, 20, 3600)
        auth_session = ctx.lock_account_mutation(credentials, user, db, step_up=True)
        challenge = db.get(SecurityPhoneChallenge, payload.challenge_id)
        now = utcnow()
        valid = challenge is not None and challenge.user_id == user.id and challenge.auth_session_id == auth_session.jti and challenge.consumed_at is None and _as_utc(challenge.expires_at) > now
        if not valid:
            raise HTTPException(400, "Mã không đúng, khác phiên đăng nhập hoặc đã hết hạn.")
        challenge.attempts += 1
        candidate = keyed_digest(ctx.recovery_key, "phone-code:" + challenge.id, payload.code)
        if not hmac.compare_digest(candidate, challenge.code_hash):
            if challenge.attempts >= 5:
                challenge.consumed_at = now
            record_audit(db, request, "account.notifications.phone.verify", actor_id=user.id, outcome="failure", details={"reason": "invalid_code"})
            raise HTTPException(400, "Mã không đúng hoặc đã hết hạn.")
        phone = ctx.crypto.decrypt_user_secret(user, ciphertext_b64=challenge.phone_ciphertext, nonce_b64=challenge.phone_nonce, field=f"security-phone-challenge:{challenge.id}")
        challenge.consumed_at = now
        row = db.get(SecurityPhone, user.id)
        if row is None:
            row = SecurityPhone(user_id=user.id)
            db.add(row)
        row.phone_ciphertext, row.phone_nonce = ctx.crypto.encrypt_user_secret(user, plaintext=phone, field=f"security-phone:{user.id}")
        row.verified_at = now
        record_audit(db, request, "account.notifications.phone.verify", actor_id=user.id, details={"phone": mask_phone(phone)})
        return status(db, user)

    @app.delete("/api/auth/notifications/phone", status_code=204)
    def remove_phone(request: Request, credentials: Credentials, user: CurrentUser, db: DB):
        ctx.lock_account_mutation(credentials, user, db, step_up=True)
        db.execute(delete(SecurityPhone).where(SecurityPhone.user_id == user.id))
        # Opting out invalidates proofs and removes their encrypted destination,
        # but must not reset the durable hourly/day SMS issuance budget.
        db.execute(update(SecurityPhoneChallenge).where(SecurityPhoneChallenge.user_id == user.id).values(
            consumed_at=utcnow(), phone_ciphertext="", phone_nonce="", code_hash="0" * 64,
        ))
        record_audit(db, request, "account.notifications.phone.remove", actor_id=user.id)
