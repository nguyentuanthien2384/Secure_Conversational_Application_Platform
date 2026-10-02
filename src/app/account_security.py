"""Account protection modelled on large identity providers.

Three controls share one source of truth, the tamper-evident audit trail:

* **Smart lockout** (cf. Microsoft Entra ID): an address that already completed
  a sign-in for this account is *familiar*. Failures from unfamiliar addresses
  still lock the account, but they cannot lock the owner out of the networks
  they routinely use, so a stranger who knows a username no longer has a free
  denial-of-service.
* **New-device sign-in alerts** (cf. Google "New sign-in" notices): a completed
  sign-in from a browser/OS family never seen on this account raises
  ``auth.login.new_device`` for the user and the SIEM.
* **Security activity** (cf. GitHub security log): users can review their own
  sign-ins, failed attempts and account changes, including the attempts made
  by somebody else against their account.

Auth sessions are pruned on expiry for privacy, so history comes from audit
events, which already exist for every completed sign-in.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from src.app.models import AuditEvent

# Events that mark a *completed* sign-in. With MFA on, the password step only
# yields ``auth.mfa.challenge``; the session exists after ``auth.mfa.verify``.
SIGN_IN_EVENT_TYPES = ("auth.login", "auth.mfa.verify", "auth.passkey.login")
FAILED_OUTCOMES = ("failure", "blocked", "denied")
NEW_DEVICE_EVENT = "auth.login.new_device"
TOKEN_REUSE_EVENT = "auth.session.token_reuse"
_HISTORY_ROWS = 500

# Browser-recognition cookie (OWASP "device cookies"). API clients send the
# token they received at sign-in in this header; the UI forwards the cookie.
DEVICE_COOKIE_NAME = "scap_device"
DEVICE_TOKEN_HEADER = "X-SCAP-Device"
_DEVICE_TOKEN_RE = re.compile(r"^v1\.([A-Za-z0-9_-]{22})\.([0-9]{1,12})\.([A-Za-z0-9_-]{43})$")

ACCOUNT_EVENT_LABELS: dict[str, str] = {
    "auth.login": "Đăng nhập bằng mật khẩu",
    "auth.mfa.challenge": "Mật khẩu đúng, chờ mã 2FA",
    "auth.mfa.verify": "Xác minh 2FA khi đăng nhập",
    "auth.passkey.login": "Đăng nhập bằng passkey",
    NEW_DEVICE_EVENT: "Đăng nhập từ thiết bị mới",
    TOKEN_REUSE_EVENT: "Token cũ bị dùng lại — đã đăng xuất thiết bị đó",
    "auth.mfa.enabled": "Bật xác thực hai lớp",
    "auth.mfa.disable": "Yêu cầu tắt xác thực hai lớp",
    "auth.mfa.disabled": "Tắt xác thực hai lớp",
    "auth.password_change": "Đổi mật khẩu",
    "auth.password_reset.request": "Yêu cầu đặt lại mật khẩu qua email",
    "auth.password_reset": "Đặt lại mật khẩu qua email",
    "account.email.verify": "Xác minh email khôi phục",
    "account.email.remove": "Gỡ email khôi phục",
    "auth.passkey.add": "Thêm passkey",
    "auth.passkey.remove": "Xóa passkey",
    "auth.step_up": "Xác thực lại cho thao tác nhạy cảm",
    "auth.session_revoke": "Thu hồi một thiết bị",
    "auth.logout_all": "Đăng xuất mọi thiết bị",
    "e2ee.device.register": "Đăng ký thiết bị E2EE",
    "e2ee.device.revoke": "Thu hồi thiết bị E2EE",
}
ADMIN_EVENT_LABELS: dict[str, str] = {
    "admin.user_create": "Quản trị viên tạo tài khoản",
    "admin.user_role_change": "Quản trị viên đổi vai trò",
    "admin.user_status": "Quản trị viên đổi trạng thái tài khoản",
}
OUTCOME_LABELS = {
    "success": "Thành công",
    "failure": "Thất bại",
    "blocked": "Bị chặn",
    "denied": "Bị từ chối",
}

# Order matters: Edge/Opera/Samsung also announce "Chrome", iOS announces
# "Mac OS X" and Android announces "Linux".
_BROWSERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Edge", re.compile(r"\bEdg(?:e|A|iOS)?/")),
    ("Opera", re.compile(r"\bOPR/|\bOpera\b")),
    ("Samsung Internet", re.compile(r"\bSamsungBrowser/")),
    ("Firefox", re.compile(r"\b(?:Firefox|FxiOS)/")),
    ("Chrome", re.compile(r"\b(?:Chrome|CriOS|Chromium)/")),
    ("Safari", re.compile(r"\bVersion/[\d.]+.*\bSafari/")),
    ("curl", re.compile(r"^curl/")),
    ("Python", re.compile(r"python-(?:httpx|requests|urllib)|aiohttp|Python-urllib", re.I)),
)
_SYSTEMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Android", re.compile(r"\bAndroid\b")),
    ("iOS", re.compile(r"\b(?:iPhone|iPad|iPod)\b")),
    ("Windows", re.compile(r"\bWindows\b")),
    ("ChromeOS", re.compile(r"\bCrOS\b")),
    ("macOS", re.compile(r"\bMac OS X\b|\bMacintosh\b")),
    ("Linux", re.compile(r"\bLinux\b|\bX11\b")),
)
UNKNOWN = "Không rõ"


def device_family(user_agent: str | None) -> tuple[str, str]:
    """Reduce a User-Agent to (browser, OS) so version updates are not new devices."""
    value = user_agent or ""
    browser = next((name for name, pattern in _BROWSERS if pattern.search(value)), UNKNOWN)
    system = next((name for name, pattern in _SYSTEMS if pattern.search(value)), UNKNOWN)
    return browser, system


def describe_user_agent(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    browser, system = device_family(user_agent)
    if browser == UNKNOWN and system == UNKNOWN:
        return "Thiết bị không xác định"
    return f"{browser} · {system}"


class DeviceTokenService:
    """Signed, account-bound browser recognition tokens.

    ``v1.<device id>.<issued unix>.<HMAC>``. The account id is bound by the MAC
    but not written into the token. A valid token was minted at a completed
    sign-in of that same account, so it proves the browser has been here
    before — unlike a User-Agent string, which any client can copy. It is
    recognition evidence only and never authorizes a request.
    """

    def __init__(self, secret_key: str, max_age_days: int) -> None:
        self._key = hashlib.sha256(
            ("secure-chat:device-token:v1:" + secret_key).encode("utf-8")
        ).digest()
        self.max_age_seconds = max_age_days * 86_400

    def _mac(self, user_id: str, device_id: str, issued: str) -> str:
        digest = hmac.new(
            self._key, f"v1|{user_id}|{device_id}|{issued}".encode(), hashlib.sha256
        ).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    @staticmethod
    def new_device_id() -> str:
        return secrets.token_urlsafe(16)

    def issue(self, user_id: str, device_id: str, *, now: float | None = None) -> str:
        issued = str(int(time.time() if now is None else now))
        return f"v1.{device_id}.{issued}.{self._mac(user_id, device_id, issued)}"

    def verify(self, token: str | None, user_id: str, *, now: float | None = None) -> str | None:
        """Return the device id for a fresh token minted for ``user_id``."""
        match = _DEVICE_TOKEN_RE.fullmatch(token or "")
        if match is None:
            return None
        device_id, issued, mac = match.groups()
        if not hmac.compare_digest(mac, self._mac(user_id, device_id, issued)):
            return None
        age = (time.time() if now is None else now) - int(issued)
        if age < -300 or age > self.max_age_seconds:
            return None
        return device_id


def device_ref(device_id: str) -> str:
    """Short, non-reversible reference to a device id for audit details."""
    return hashlib.sha256(device_id.encode("ascii")).hexdigest()[:16]


@dataclass(frozen=True)
class SignInSource:
    """How a sign-in attempt relates to this account's completed sign-ins."""

    has_history: bool
    known_ip: bool
    known_device: bool
    # A valid device token for this account was presented.
    trusted_device: bool = False

    @property
    def familiar(self) -> bool:
        """Smart lockout: a known network or a browser recognised by its token."""
        return self.known_ip or self.trusted_device

    @property
    def classification(self) -> str:
        if not self.has_history:
            return "first_sign_in"
        if not self.known_device:
            return "new_device"
        if not self.known_ip:
            return "new_location"
        return "familiar"


def assess_sign_in_source(
    db: Session,
    user_id: str | None,
    ip: str,
    user_agent: str | None,
    *,
    now: datetime,
    history_days: int,
    device_id: str | None = None,
) -> SignInSource:
    """Compare a source with recent completed sign-ins of the same account.

    Device evidence, strongest first: a valid device token proves a known
    browser. Once an account has signed in with device tokens, a client that
    presents none is a new device whatever its User-Agent claims. Only accounts
    with no token history fall back to comparing browser/OS families.

    The query also runs for unknown usernames (matching nothing) so the work
    done does not reveal whether an account exists.
    """
    rows = db.execute(
        select(AuditEvent.ip_address, AuditEvent.user_agent, AuditEvent.details_json)
        .where(
            AuditEvent.actor_id == (user_id or ""),
            AuditEvent.event_type.in_(SIGN_IN_EVENT_TYPES),
            AuditEvent.outcome == "success",
            AuditEvent.created_at >= now - timedelta(days=history_days),
        )
        .order_by(AuditEvent.id.desc())
        .limit(_HISTORY_ROWS)
    ).all()
    if device_id is not None:
        known_device = True
    elif any("device_ref" in _parse_details(row.details_json) for row in rows):
        known_device = False
    else:
        family = device_family(user_agent)
        known_device = any(device_family(row.user_agent) == family for row in rows)
    return SignInSource(
        has_history=bool(rows),
        known_ip=any(row.ip_address == ip for row in rows),
        known_device=known_device,
        trusted_device=device_id is not None,
    )


def _parse_details(details_json: str | None) -> dict[str, Any]:
    try:
        value = json.loads(details_json or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _details(event: AuditEvent) -> dict[str, Any]:
    return _parse_details(event.details_json)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _severity(event: AuditEvent, by_administrator: bool) -> str:
    if event.event_type == TOKEN_REUSE_EVENT:
        return "critical"
    if event.event_type in (NEW_DEVICE_EVENT, "auth.password_reset", "account.email.remove") or (
        by_administrator
    ):
        return "warning"
    if event.event_type == "auth.mfa.verify" and event.outcome in FAILED_OUTCOMES:
        # The password was right; only the second factor stopped this attempt.
        return "critical"
    if event.outcome in FAILED_OUTCOMES:
        return "critical" if _details(event).get("reason") == "account_locked" else "warning"
    if event.event_type == "auth.mfa.disabled":
        return "warning"
    return "info"


def _title(event: AuditEvent) -> str:
    title = ACCOUNT_EVENT_LABELS.get(event.event_type) or ADMIN_EVENT_LABELS.get(
        event.event_type, event.event_type
    )
    details = _details(event)
    if event.event_type in SIGN_IN_EVENT_TYPES and event.outcome == "success":
        if details.get("sign_in_source") == "new_location":
            return f"{title} (địa chỉ mạng mới)"
    if details.get("reason") == "account_locked":
        return f"{title} — tài khoản đang tạm khóa với nguồn lạ"
    return title


def _event_view(event: AuditEvent, user_id: str) -> dict[str, Any]:
    by_administrator = event.event_type in ADMIN_EVENT_LABELS and event.actor_id != user_id
    return {
        "id": event.id,
        "created_at": _as_utc(event.created_at),
        "event_type": event.event_type,
        "title": _title(event),
        "outcome": event.outcome,
        "outcome_label": OUTCOME_LABELS.get(event.outcome, event.outcome),
        "severity": _severity(event, by_administrator),
        # An administrator's address and browser are not the account owner's
        # data; show that the action happened, not where it came from.
        "ip_address": None if by_administrator else event.ip_address,
        "device": None if by_administrator else describe_user_agent(event.user_agent),
        "by_administrator": by_administrator,
    }


def build_security_activity(
    db: Session,
    user_id: str,
    *,
    current_sign_in_at: datetime | None,
    limit: int,
) -> dict[str, Any]:
    """Assemble the caller's own security log plus a "since last visit" summary."""
    own_events = and_(
        AuditEvent.actor_id == user_id,
        AuditEvent.event_type.in_(tuple(ACCOUNT_EVENT_LABELS)),
    )
    admin_events = and_(
        AuditEvent.target_type == "user",
        AuditEvent.target_id == user_id,
        AuditEvent.event_type.in_(tuple(ADMIN_EVENT_LABELS)),
        AuditEvent.actor_id != user_id,
    )
    events = list(
        db.scalars(
            select(AuditEvent)
            .where(or_(own_events, admin_events))
            .order_by(AuditEvent.id.desc())
            .limit(limit)
        )
    )

    # The current session's audit row is written just after the session's
    # issue time, so anything strictly earlier is the previous visit.
    previous_query = select(AuditEvent).where(
        AuditEvent.actor_id == user_id,
        AuditEvent.event_type.in_(SIGN_IN_EVENT_TYPES),
        AuditEvent.outcome == "success",
    )
    if current_sign_in_at is not None:
        previous_query = previous_query.where(AuditEvent.created_at < current_sign_in_at)
    previous = db.scalars(previous_query.order_by(AuditEvent.id.desc()).limit(1)).first()

    def count_since(*conditions) -> int:
        query = select(func.count(AuditEvent.id)).where(
            AuditEvent.actor_id == user_id, *conditions
        )
        if previous is not None:
            query = query.where(AuditEvent.id > previous.id)
        return int(db.scalar(query) or 0)

    return {
        "previous_sign_in": (
            {
                "at": _as_utc(previous.created_at),
                "ip_address": previous.ip_address,
                "device": describe_user_agent(previous.user_agent),
            }
            if previous is not None
            else None
        ),
        "failed_sign_ins_since_previous": count_since(
            AuditEvent.event_type.in_(SIGN_IN_EVENT_TYPES),
            AuditEvent.outcome.in_(FAILED_OUTCOMES),
        ),
        "mfa_failures_since_previous": count_since(
            AuditEvent.event_type == "auth.mfa.verify",
            AuditEvent.outcome.in_(FAILED_OUTCOMES),
        ),
        "new_device_sign_ins_since_previous": count_since(
            AuditEvent.event_type == NEW_DEVICE_EVENT
        ),
        "events": [_event_view(event, user_id) for event in events],
    }
