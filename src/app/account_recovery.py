"""Email-based account recovery and security notifications.

Codes are what the user types from the email: 10 characters from a 31-symbol
alphabet without look-alikes (about 49 bits), valid for a few minutes, five
attempts at most, and superseded by any newer code for the same purpose.
Only an HMAC of the code is stored, keyed from the application secret with
its own label, so a database dump does not reveal usable codes.

A reset proves control of the verified mailbox only. It never disables
two-factor authentication: an account with TOTP still needs its code (or a
passkey) after the password is reset.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from src.app.mailer import Mailer, MailUnavailable
from src.app.models import AccountEmail, AccountRecoveryCode

CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
CODE_LENGTH = 10
MAX_CODE_ATTEMPTS = 5


def derive_recovery_code_key(secret_key: str) -> bytes:
    return hashlib.sha256(("secure-chat:account-recovery:v1:" + secret_key).encode("utf-8")).digest()


def _hash_code(key: bytes, code: str) -> str:
    return hmac.new(key, code.encode("ascii"), hashlib.sha256).hexdigest()


def normalize_code(value: str) -> str:
    return "".join((value or "").split()).replace("-", "").lower()[:32]


def format_code(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def issue_code(
    db: Session,
    key: bytes,
    *,
    user_id: str,
    purpose: str,
    now: datetime,
    minutes: int,
    target_email: str | None = None,
) -> str:
    """Create a code, retire older ones for the same purpose, return the plaintext."""
    db.execute(
        update(AccountRecoveryCode)
        .where(
            AccountRecoveryCode.user_id == user_id,
            AccountRecoveryCode.purpose == purpose,
            AccountRecoveryCode.consumed_at.is_(None),
        )
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    db.add(
        AccountRecoveryCode(
            user_id=user_id,
            purpose=purpose,
            code_hash=_hash_code(key, code),
            target_email=target_email,
            expires_at=now + timedelta(minutes=minutes),
            created_at=now,
        )
    )
    return code


def consume_code(
    db: Session, key: bytes, *, user_id: str, purpose: str, code: str, now: datetime
) -> AccountRecoveryCode | None:
    """Return the active record if ``code`` matches and burn it; count failures.

    The newest active code is the only candidate. Each wrong guess is counted
    on it and the fifth wrong guess retires it, so guessing across requests is
    bounded by issuance rate limits as well.
    """
    record = db.scalars(
        select(AccountRecoveryCode)
        .where(
            AccountRecoveryCode.user_id == user_id,
            AccountRecoveryCode.purpose == purpose,
            AccountRecoveryCode.consumed_at.is_(None),
        )
        .order_by(AccountRecoveryCode.created_at.desc())
        .limit(1)
    ).first()
    if record is None or _as_utc(record.expires_at) <= now:
        return None
    candidate = normalize_code(code)
    if len(candidate) != CODE_LENGTH or not hmac.compare_digest(
        _hash_code(key, candidate) if candidate.isascii() else "", record.code_hash
    ):
        record.attempts += 1
        if record.attempts >= MAX_CODE_ATTEMPTS:
            record.consumed_at = now
        return None
    claimed = db.execute(
        update(AccountRecoveryCode)
        .where(AccountRecoveryCode.id == record.id, AccountRecoveryCode.consumed_at.is_(None))
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    return record if claimed.rowcount == 1 else None


def verified_email(db: Session, user_id: str) -> AccountEmail | None:
    return db.get(AccountEmail, user_id)


# ── messages ──────────────────────────────────────────────────────────────────

_FOOTER = (
    "\n\nĐây là thư tự động về bảo mật tài khoản SCAP. Đừng chia sẻ mã trong thư với bất kỳ ai, "
    "kể cả người tự xưng là quản trị viên."
)


def send_code(mailer: Mailer, to: str, *, purpose: str, username: str, code: str, minutes: int) -> None:
    if purpose == "password_reset":
        subject = "Mã đặt lại mật khẩu"
        intro = (
            f"Có yêu cầu đặt lại mật khẩu cho tài khoản {username}. "
            "Nếu không phải bạn, hãy bỏ qua thư này; mật khẩu hiện tại vẫn giữ nguyên."
        )
    else:
        subject = "Mã xác minh email"
        intro = f"Nhập mã dưới đây trong tab Tài khoản để gắn email này với tài khoản {username}."
    body = f"{intro}\n\nMã: {format_code(code)}\nHiệu lực: {minutes} phút, tối đa {MAX_CODE_ATTEMPTS} lần nhập.{_FOOTER}"
    mailer.send(to, subject, body, template=purpose)


NOTICES = {
    "new_device": (
        "Đăng nhập từ thiết bị mới",
        "Tài khoản {username} vừa đăng nhập từ một thiết bị chưa từng thấy.\n"
        "Thời điểm (UTC): {when}\nThiết bị: {device}\nĐịa chỉ IP: {ip}\n\n"
        "Nếu là bạn, không cần làm gì. Nếu không, hãy đổi mật khẩu và thu hồi thiết bị "
        "trong tab Tài khoản ngay.",
    ),
    "password_changed": (
        "Mật khẩu đã được đổi",
        "Mật khẩu của tài khoản {username} vừa được đổi lúc {when} (UTC) từ IP {ip}. "
        "Mọi phiên đăng nhập cũ đã bị đăng xuất. Nếu không phải bạn, hãy dùng chức năng "
        "Quên mật khẩu và liên hệ quản trị viên.",
    ),
    "password_reset": (
        "Mật khẩu đã được đặt lại",
        "Mật khẩu của tài khoản {username} vừa được đặt lại qua email lúc {when} (UTC) từ IP {ip}. "
        "Mọi phiên đăng nhập cũ đã bị đăng xuất; xác thực hai lớp vẫn được giữ nguyên.",
    ),
    "mfa_disabled": (
        "Xác thực hai lớp đã bị tắt",
        "Xác thực hai lớp của tài khoản {username} vừa bị tắt lúc {when} (UTC) từ IP {ip}. "
        "Nếu không phải bạn, hãy đổi mật khẩu và bật lại 2FA ngay.",
    ),
    "email_changed": (
        "Email khôi phục đã thay đổi",
        "Email khôi phục của tài khoản {username} vừa được đổi hoặc gỡ lúc {when} (UTC) từ IP {ip}. "
        "Thư này được gửi tới địa chỉ cũ. Nếu không phải bạn, hãy liên hệ quản trị viên.",
    ),
    "passkey_added": (
        "Đã thêm passkey",
        "Một passkey mới ({device}) vừa được thêm vào tài khoản {username} lúc {when} (UTC) "
        "từ IP {ip}. Nếu không phải bạn, hãy xóa passkey đó và đổi mật khẩu.",
    ),
    "passkey_removed": (
        "Đã xóa passkey",
        "Passkey {device} vừa bị xóa khỏi tài khoản {username} lúc {when} (UTC) từ IP {ip}.",
    ),
    "token_reuse": (
        "Phát hiện phiên đăng nhập bị dùng lại",
        "Một token đăng nhập cũ của tài khoản {username} bị dùng lại lúc {when} (UTC) từ IP {ip}, "
        "dấu hiệu token có thể đã bị đánh cắp. Hệ thống đã đăng xuất thiết bị liên quan. "
        "Hãy đăng nhập lại và đổi mật khẩu nếu thấy bất thường.",
    ),
}


def notify(
    db: Session,
    mailer: Mailer,
    *,
    user_id: str,
    username: str,
    kind: str,
    ip: str,
    device: str | None = None,
    to: str | None = None,
) -> bool:
    """Send a security notice to the verified address (or ``to``); never raises."""
    if not mailer.enabled:
        return False
    address = to
    if address is None:
        record = verified_email(db, user_id)
        address = record.email if record is not None else None
    if not address:
        return False
    subject, template = NOTICES[kind]
    body = template.format(
        username=username,
        when=datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M"),
        ip=ip,
        device=device or "không xác định",
    )
    try:
        mailer.send(address, subject, body + _FOOTER, template=kind)
    except MailUnavailable:
        return False
    return True
