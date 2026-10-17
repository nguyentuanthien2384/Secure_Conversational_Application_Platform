"""Explicit, disabled-by-default configuration for optional security channels."""

from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from src.app.secret_files import read_secret_text


@dataclass(frozen=True)
class NotificationSettings:
    push_backend: str = "disabled"
    sms_backend: str = "disabled"
    outbox_dir: str = "data/security-notification-outbox"
    vapid_private_key: str = field(default="", repr=False)
    vapid_public_key: str = ""
    vapid_subject: str = ""
    twilio_account_sid: str = ""
    twilio_auth_token: str = field(default="", repr=False)
    twilio_from: str = ""

    @classmethod
    def from_env(cls, *, environment: str) -> NotificationSettings:
        push = os.getenv("PUSH_BACKEND", "disabled").strip().lower()
        sms = os.getenv("SMS_BACKEND", "disabled").strip().lower()
        if push not in {"disabled", "webpush", "outbox"}:
            raise RuntimeError("PUSH_BACKEND phải là disabled, webpush hoặc outbox.")
        if sms not in {"disabled", "twilio", "outbox"}:
            raise RuntimeError("SMS_BACKEND phải là disabled, twilio hoặc outbox.")
        if environment not in {"development", "test"} and "outbox" in {push, sms}:
            raise RuntimeError("Outbox thông báo chỉ dành cho development/test, không gửi thật.")
        private = public = subject = token = sid = sender = ""
        if push == "webpush":
            path = os.getenv("VAPID_PRIVATE_KEY_FILE", "").strip()
            if not path:
                raise RuntimeError("VAPID_PRIVATE_KEY_FILE bắt buộc khi bật Web Push.")
            try:
                key = serialization.load_pem_private_key(
                    read_secret_text(path, max_bytes=4096).encode("ascii"), password=None
                )
                if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
                    key.curve, ec.SECP256R1
                ):
                    raise ValueError("Wrong VAPID curve")
                private = base64.urlsafe_b64encode(
                    key.private_numbers().private_value.to_bytes(32, "big")
                ).decode("ascii").rstrip("=")
                public = base64.urlsafe_b64encode(key.public_key().public_bytes(
                    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
                )).decode("ascii").rstrip("=")
            except (OSError, ValueError, UnicodeError):
                raise RuntimeError("Khóa VAPID phải là PEM P-256 hợp lệ trong secret file.") from None
            subject = os.getenv("VAPID_SUBJECT", "").strip()
            if not re.fullmatch(r"mailto:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", subject):
                raise RuntimeError("VAPID_SUBJECT phải là địa chỉ liên hệ mailto hợp lệ.")
            try:
                import pywebpush  # noqa: F401 - optional backend must fail at startup
            except ImportError:
                raise RuntimeError("Web Push cần cài extra web-push trước khi khởi động.") from None
        if sms == "twilio":
            sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
            sender = os.getenv("TWILIO_FROM", "").strip()
            path = os.getenv("TWILIO_AUTH_TOKEN_FILE", "").strip()
            if not re.fullmatch(r"AC[0-9a-fA-F]{32}", sid) or not re.fullmatch(r"\+[1-9][0-9]{7,14}", sender) or not path:
                raise RuntimeError("Twilio cần ACCOUNT_SID, FROM dạng E.164 và AUTH_TOKEN_FILE.")
            try:
                token = read_secret_text(path, max_bytes=1024).strip()
            except OSError:
                raise RuntimeError("Không đọc được secret file của Twilio.") from None
            if not re.fullmatch(r"[A-Za-z0-9]{16,128}", token):
                raise RuntimeError("Twilio auth token không hợp lệ.")
        return cls(
            push_backend=push, sms_backend=sms,
            outbox_dir=os.getenv("NOTIFICATION_OUTBOX_DIR", "data/security-notification-outbox"),
            vapid_private_key=private, vapid_public_key=public, vapid_subject=subject,
            twilio_account_sid=sid, twilio_auth_token=token, twilio_from=sender,
        )
