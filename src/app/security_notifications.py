"""Optional, bounded post-commit security notices with fixed, non-sensitive text.

Provider acceptance never means the recipient read a message. Browser push
capabilities and verified phone numbers are encrypted using the account DEK.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import threading
from concurrent.futures import Future, ThreadPoolExecutor, wait
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import delete, select

from src.app.mailer import OutboxTransport
from src.app.models import SecurityPhone, SecurityPushSubscription, User
from src.app.notification_config import NotificationSettings

logger = logging.getLogger("secure_chat.notifications")
# Entries are event labels and descriptions, never authentication material.
EVENT_TEXT = dict([
    ("new_device", "Phat hien dang nhap tu thiet bi moi."),
    ("new_location", "Phat hien dang nhap tu khu vuc moi."),
    ("impossible_travel", "Phat hien dang nhap o cac khu vuc cach xa trong thoi gian ngan."),
    ("password_changed", "Mat khau tai khoan vua duoc thay doi."),
    ("password_reset", "Mat khau tai khoan vua duoc dat lai."),
    ("mfa_disabled", "Xac thuc hai lop vua bi tat."),
    ("email_changed", "Email khoi phuc vua duoc thay doi."),
    ("passkey_added", "Mot passkey moi vua duoc them."),
    ("passkey_removed", "Mot passkey vua bi xoa."),
    ("token_reuse", "Phat hien phien dang nhap bi dung lai; thiet bi da bi dang xuat."),
])
NOTICE_FOOTER = " Mo SCAP de kiem tra hoat dong bao mat."
_PUSH_HOSTS = frozenset({
    "fcm.googleapis.com", "updates.push.services.mozilla.com", "web.push.apple.com",
})


class NotificationUnavailable(RuntimeError):
    """Sanitized transport failure, separate from the completed account action."""


class SubscriptionExpired(NotificationUnavailable):
    pass


def normalize_phone(value: str) -> str | None:
    """Require international E.164 format rather than guessing a country."""
    return value if re.fullmatch(r"\+[1-9][0-9]{7,14}", value or "") else None


def mask_phone(value: str) -> str:
    return "••••" + value[-4:]


def keyed_digest(key: bytes, label: str, value: str) -> str:
    return hmac.new(key, f"scap-notifications:v1:{label}:{value}".encode(), hashlib.sha256).hexdigest()


def validate_push_endpoint(value: str) -> str:
    if not isinstance(value, str) or not 20 <= len(value) <= 2048 or any(
        ord(char) <= 32 or ord(char) >= 127 or char == "\\" for char in value
    ):
        raise ValueError("Push endpoint không hợp lệ.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https" or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment or parsed.query
            or not parsed.path.startswith("/") or not parsed.path.strip("/")
            or "%" in parsed.netloc or parsed.netloc.endswith(":")
            or not (host in _PUSH_HOSTS or host.endswith(".notify.windows.com"))
        ):
            raise ValueError("Unsupported push service")
    except ValueError:
        raise ValueError("Chỉ hỗ trợ endpoint HTTPS của FCM, Mozilla, Apple hoặc Windows Push.") from None
    return value


def _decode_key(value: str, length: int) -> bytes:
    if not isinstance(value, str) or len(value) != (length * 8 + 5) // 6 or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Push key không hợp lệ.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        raise ValueError("Push key không hợp lệ.") from None
    if len(decoded) != length or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("Push key không hợp lệ.")
    return decoded


def validate_subscription(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("keys"), dict):
        raise ValueError("Push subscription không hợp lệ.")
    endpoint = validate_push_endpoint(value.get("endpoint"))
    keys = value["keys"]
    point = _decode_key(keys.get("p256dh"), 65)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        raise ValueError("Push public key không hợp lệ.") from None
    _decode_key(keys.get("auth"), 16)
    return {"endpoint": endpoint, "keys": {"p256dh": keys["p256dh"], "auth": keys["auth"]}}


class _PinnedPushSession:
    """pywebpush adapter: public DNS, pinned address, verified original SNI.

    The HTTPS connection targets the resolved public address directly. Host
    and SNI retain the approved vendor hostname; DNS cannot be rebound between
    validation and connection. Redirects and proxy environment are disabled.
    """

    def __init__(self, stopped=None):
        self.stopped = stopped or (lambda: False)

    def post(self, url, *, data=None, headers=None, timeout=None, **kwargs):
        validate_push_endpoint(url)
        host = urlsplit(url).hostname
        try:
            ips = [str(ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]
            if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
                raise NotificationUnavailable("Push service DNS không an toàn.")
            if self.stopped():
                raise NotificationUnavailable("Dịch vụ thông báo đã dừng.")
            request_headers = dict(headers or {})
            request_headers["Host"] = host
            connection = http.client.HTTPSConnection(host, timeout=5.0, context=ssl.create_default_context())
            # Avoid HTTP-client URL logging: the path contains the capability.
            # Set the connected socket explicitly to avoid a second DNS query.
            raw_socket = socket.create_connection((ips[0], 443), timeout=5.0)
            try:
                connection.sock = connection._context.wrap_socket(raw_socket, server_hostname=host)
            except BaseException:
                raw_socket.close()
                raise
            try:
                connection.request("POST", urlsplit(url).path, body=data, headers=request_headers)
                response = connection.getresponse()
                body = response.read(4097)
                if len(body) > 4096:
                    raise NotificationUnavailable("Push response quá lớn.")
                from requests import Response
                result = Response()
                result.status_code = response.status
                result.reason = "Push response"
                result._content = body
                result.headers.update(response.headers)
                return result
            finally:
                connection.close()
        except (OSError, http.client.HTTPException, ValueError):
            raise NotificationUnavailable("Không kết nối được dịch vụ Push.") from None


class SecurityNotifications:
    def __init__(self, settings: NotificationSettings, session_factory, crypto, key: bytes, *, limiter=None):
        self.settings, self.session_factory, self.crypto, self.key = settings, session_factory, crypto, key
        self.limiter = limiter
        self.background = True
        self.public_key = settings.vapid_public_key
        if settings.push_backend == "outbox" and not self.public_key:
            # This demo-only key permits opt-in; the outbox contacts no server.
            self.public_key = base64.urlsafe_b64encode(ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )).decode().rstrip("=")
        self._outbox = OutboxTransport(settings.outbox_dir)
        self._executor: ThreadPoolExecutor | None = None
        self._pending: set[Future] = set()
        self._lock = threading.Lock()
        self._closed = False
        self._stop = threading.Event()
        self.push_transport = self._send_push
        self.sms_transport = self._send_sms

    @property
    def push_enabled(self) -> bool:
        return self.settings.push_backend != "disabled"

    @property
    def sms_enabled(self) -> bool:
        return self.settings.sms_backend != "disabled"

    def start(self) -> None:
        with self._lock:
            if self._closed and any(not future.done() for future in self._pending):
                raise NotificationUnavailable("Thông báo từ phiên chạy trước chưa dừng xong.")
            self._closed = False
            self._stop.clear()
            if (self.push_enabled or self.sms_enabled) and self._executor is None:
                self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="security-notice")

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._stop.set()
            executor, self._executor = self._executor, None
            pending = tuple(self._pending)
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        if pending:
            # Do not block shutdown indefinitely on an operating-system DNS
            # resolver. Workers recheck stop after resolution and before every
            # new provider/cleanup operation; active HTTPS calls have 5s waits.
            _done, outstanding = wait(pending, timeout=8.0)
            if outstanding:
                logger.warning("Security notices stopping (scope=active_delivery).")

    def _done(self, future: Future) -> None:
        with self._lock:
            self._pending.discard(future)

    def notify(self, *, user_id: str, kind: str) -> bool:
        if kind not in EVENT_TEXT or not (self.push_enabled or self.sms_enabled):
            return False
        if self._stop.is_set():
            return False
        if not self.background:
            self._deliver(user_id, kind)
            return True
        with self._lock:
            if self._closed or self._executor is None or len(self._pending) >= 32:
                logger.warning("Security notice not queued (scope=capacity).")
                return False
            future = self._executor.submit(self._deliver, user_id, kind)
            self._pending.add(future)
        future.add_done_callback(self._done)
        return True

    def _allow_notice(self, channel: str, user_id: str) -> bool:
        return self.limiter is None or self.limiter.allow(f"security-notice:{channel}:{user_id}", 10, 3600)[0]

    def _deliver(self, user_id: str, kind: str) -> None:
        try:
            if self._stop.is_set():
                return
            pushes, phone = [], None
            with self.session_factory() as db:
                user = db.get(User, user_id)
                if user is None or not user.is_active:
                    return
                if self.push_enabled and self._allow_notice("push", user_id):
                    for row in db.scalars(select(SecurityPushSubscription).where(SecurityPushSubscription.user_id == user_id).limit(8)):
                        try:
                            subscription = json.loads(self.crypto.decrypt_user_secret(
                                user, ciphertext_b64=row.subscription_ciphertext,
                                nonce_b64=row.subscription_nonce, field=f"security-push:{row.id}",
                            ))
                            pushes.append((row.id, validate_subscription(subscription)))
                        except Exception:
                            logger.warning("Security notice unavailable (scope=push_material).")
                if self.sms_enabled and self._allow_notice("sms", user_id):
                    row = db.get(SecurityPhone, user_id)
                    if row is not None:
                        try:
                            phone = self.crypto.decrypt_user_secret(
                                user, ciphertext_b64=row.phone_ciphertext, nonce_b64=row.phone_nonce,
                                field=f"security-phone:{user_id}",
                            )
                        except Exception:
                            logger.warning("Security notice unavailable (scope=sms_material).")
            payload = json.dumps({"title": "SCAP: Canh bao bao mat", "body": EVENT_TEXT[kind] + NOTICE_FOOTER}, separators=(",", ":"))
            for subscription_id, subscription in pushes:
                if self._stop.is_set():
                    return
                try:
                    self.push_transport(subscription, payload)
                except SubscriptionExpired:
                    if self._stop.is_set():
                        return
                    with self.session_factory() as db:
                        db.execute(delete(SecurityPushSubscription).where(SecurityPushSubscription.id == subscription_id, SecurityPushSubscription.user_id == user_id))
                        db.commit()
                except Exception:
                    logger.warning("Security notice unavailable (scope=push_delivery).")
            if not self._stop.is_set() and phone and normalize_phone(phone):
                try:
                    self.sms_transport(phone, "SCAP: " + EVENT_TEXT[kind] + NOTICE_FOOTER)
                except Exception:
                    logger.warning("Security notice unavailable (scope=sms_delivery).")
        except Exception:
            logger.warning("Security notice unavailable (scope=recipient_lookup).")

    def _write_outbox(self, channel: str, destination: str, body: str) -> str:
        message = EmailMessage()
        message["Subject"] = "SCAP DEMO ONLY - no message sent"
        message["X-SCAP-Channel"] = channel
        message.set_content(json.dumps({"channel": channel, "destination": destination, "body": body}, ensure_ascii=True))
        self._outbox.send(message)
        return "demo_outbox"

    def _send_push(self, subscription: dict[str, Any], body: str) -> str:
        if self._stop.is_set():
            raise NotificationUnavailable("Dịch vụ thông báo đã dừng.")
        if self.settings.push_backend == "outbox":
            return self._write_outbox("push", "browser-subscription", body)
        if self.settings.push_backend != "webpush":
            raise NotificationUnavailable("Web Push chưa được bật.")
        try:
            from pywebpush import WebPushException, webpush
            try:
                webpush(
                    subscription_info=validate_subscription(subscription), data=body,
                    vapid_private_key=self.settings.vapid_private_key,
                    vapid_claims={"sub": self.settings.vapid_subject},
                    requests_session=_PinnedPushSession(self._stop.is_set), timeout=5.0, ttl=300,
                )
            except WebPushException as exc:
                if getattr(exc, "status_code", None) in (404, 410) or getattr(getattr(exc, "response", None), "status_code", None) in (404, 410):
                    raise SubscriptionExpired("Push subscription đã hết hiệu lực.") from None
                raise NotificationUnavailable("Dịch vụ Push chưa chấp nhận thông báo.") from None
        except ImportError:
            raise NotificationUnavailable("Thiếu Web Push SDK.") from None
        return "provider_accepted"

    def _send_sms(self, phone: str, body: str) -> str:
        if self._stop.is_set():
            raise NotificationUnavailable("Dịch vụ thông báo đã dừng.")
        if normalize_phone(phone) is None or len(body) > 320:
            raise NotificationUnavailable("SMS không hợp lệ.")
        if self.settings.sms_backend == "outbox":
            return self._write_outbox("sms", phone, body)
        if self.settings.sms_backend != "twilio":
            raise NotificationUnavailable("SMS chưa được bật.")
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", self.settings.twilio_account_sid) or normalize_phone(self.settings.twilio_from) is None:
            raise NotificationUnavailable("Cấu hình dịch vụ SMS không hợp lệ.")
        # No user-controlled URL, redirects, proxy or credential-bearing logs.
        path = f"https://api.twilio.com/2010-04-01/Accounts/{self.settings.twilio_account_sid}/Messages.json"
        try:
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=5.0) as client:
                with client.stream("POST", path,
                    auth=(self.settings.twilio_account_sid, self.settings.twilio_auth_token),
                    data={"To": phone, "From": self.settings.twilio_from, "Body": body},
                ) as response:
                    if response.status_code != 201:
                        raise NotificationUnavailable("Dịch vụ SMS chưa chấp nhận thông báo.")
        except httpx.HTTPError:
            raise NotificationUnavailable("Không kết nối được dịch vụ SMS.") from None
        return "provider_accepted"

    def send_verification(self, phone: str, code: str) -> str:
        if not re.fullmatch(r"[0-9]{8}", code):
            raise NotificationUnavailable("Mã xác minh không hợp lệ.")
        return self.sms_transport(phone, f"SCAP: Ma xac minh so dien thoai {code}. Het han sau 5 phut. Khong chia se ma nay.")
