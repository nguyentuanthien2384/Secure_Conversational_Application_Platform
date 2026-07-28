"""Sinh dữ liệu mẫu cho nền tảng — dùng chung bởi scripts/seed_demo_data.py
và cơ chế auto-seed khi khởi động (biến môi trường SEED_DEMO_DATA=true).

Tạo 3 tài khoản demo (3 vai trò RBAC), các hội thoại đã mã hóa AES-256-GCM mà
nội dung giải thích chính cơ chế bảo mật của dự án, và chuỗi sự kiện audit mô
phỏng (brute-force, IDOR bị chặn) để bảng quản trị có dữ liệu.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import timedelta

from sqlalchemy import select

from src.app.db import Database, utcnow
from src.app.models import AuditEvent, ChatSession, SecureMessage, User
from src.app.security import CryptoService, PasswordService

# Mật khẩu chung cho các tài khoản demo — thỏa chính sách mật khẩu của dự án:
# >= 15 ký tự, không chứa chuỗi phổ biến, >= 5 ký tự khác nhau.
DEMO_PASSWORD = "Phenikaa-Vault#2026-Lab"

DEMO_USERS = (
    ("demo.user", "user"),
    ("demo.mod", "moderator"),
    ("demo.boss", "admin"),
)

# (tiêu đề, [(role, nội dung), ...]) — nội dung giải thích chính dự án này.
DEMO_CONVERSATIONS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Vì sao dùng AES-256-GCM?",
        [
            ("user", "Tin nhắn của tôi được lưu trong database như thế nào?"),
            (
                "assistant",
                "Mỗi tin nhắn được mã hóa bằng AES-256-GCM trước khi ghi xuống database. "
                "Hệ thống sinh một nonce 12 byte ngẫu nhiên cho từng tin nhắn, và AAD "
                "(Additional Authenticated Data) ràng buộc bản mã với session_id, vai trò "
                "và phiên bản khóa — vì vậy trong DB không tồn tại bất kỳ plaintext nào.",
            ),
            ("user", "AAD giúp ích gì? Không có nó thì sao?"),
            (
                "assistant",
                "AAD chống tấn công 'cắt-dán' bản mã: nếu kẻ tấn công có quyền ghi vào DB và "
                "sao chép ciphertext từ hội thoại này sang hội thoại khác (hoặc đổi vai trò "
                "user thành assistant), thao tác giải mã sẽ thất bại vì AAD không khớp, thay "
                "vì âm thầm giải mã thành nội dung sai ngữ cảnh. Bạn có thể tự kiểm chứng ở "
                "tab 'Dữ liệu mã hóa': mỗi dòng có nonce riêng và key version.",
            ),
        ],
    ),
    (
        "Argon2id và lưu mật khẩu",
        [
            ("user", "Mật khẩu của tôi có bị lưu trực tiếp không?"),
            (
                "assistant",
                "Không. Server chỉ lưu chuỗi băm Argon2id (time_cost=3, memory_cost=64MB). "
                "Argon2id là thuật toán thắng cuộc thi Password Hashing Competition, kháng "
                "cả tấn công GPU lẫn side-channel. Khi đăng nhập, server băm lại mật khẩu "
                "bạn nhập và so sánh — mật khẩu gốc không bao giờ được lưu.",
            ),
            ("user", "Nếu tôi nhập sai nhiều lần thì sao?"),
            (
                "assistant",
                "Có hai lớp bảo vệ: rate limiting theo cửa sổ trượt (theo cả tài khoản lẫn "
                "địa chỉ IP) và khóa tài khoản tạm thời sau khi vượt ngưỡng thất bại. Lỗi "
                "trả về luôn chung chung để không lộ tài khoản nào tồn tại — server còn băm "
                "một hash giả cho username không tồn tại nhằm chống dò theo thời gian phản hồi.",
            ),
        ],
    ),
    (
        "JWT và phiên đăng nhập",
        [
            ("user", "Access token của tôi sống được bao lâu?"),
            (
                "assistant",
                "Mặc định 30 phút. Token JWT chứa các claim exp, nbf, iat, jti, issuer và "
                "audience. Mỗi lần đăng nhập tạo một bản ghi phiên phía server gắn với jti — "
                "nhờ đó bạn có thể vào tab Tài khoản để xem và thu hồi từng thiết bị, hoặc "
                "đăng xuất tất cả.",
            ),
            ("user", "Đổi mật khẩu xong tôi bị văng ra, có phải lỗi không?"),
            (
                "assistant",
                "Đó là hành vi chủ đích: đổi mật khẩu, khóa tài khoản hoặc đổi vai trò đều "
                "thu hồi toàn bộ phiên đang tồn tại (tăng token_version). Nếu kẻ xấu đang "
                "giữ một token cũ thì token đó lập tức vô hiệu.",
            ),
        ],
    ),
    (
        "IDOR và phân quyền RBAC",
        [
            ("user", "Admin có đọc được tin nhắn của tôi không?"),
            (
                "assistant",
                "Không. API chat chỉ cho phép chủ sở hữu truy cập phiên của chính mình — kể "
                "cả admin cũng bị từ chối, để bảng quản trị không trở thành công cụ đọc "
                "trộm. Khi truy cập một session_id không thuộc về mình, server trả về 404 "
                "(thay vì 403) nhằm hạn chế dò tài nguyên, đồng thời ghi sự kiện "
                "authorization.denied vào nhật ký kiểm toán.",
            ),
        ],
    ),
]

FAKE_IPS = ("203.113.131.10", "14.161.20.88", "118.70.126.45", "42.114.53.201")


def seed_demo_data(
    database: Database,
    password_service: PasswordService,
    crypto_service: CryptoService,
    *,
    reset: bool = False,
    log=print,
) -> None:
    """Idempotent: tài khoản/hội thoại demo đã tồn tại sẽ được bỏ qua."""
    database.create_all()
    with database.session_factory() as db:
        if reset:
            removed = 0
            for username, _ in DEMO_USERS:
                user = db.scalar(select(User).where(User.username == username))
                if user is not None:
                    db.delete(user)  # cascade xóa hội thoại + tin nhắn
                    removed += 1
            db.query(AuditEvent).filter(AuditEvent.request_id.like("seed-%")).delete(
                synchronize_session=False
            )
            db.commit()
            log(f"[reset] Đã xóa {removed} tài khoản demo và audit mẫu cũ.")

        # ---------- 1. Người dùng ----------
        users: dict[str, User] = {}
        created_any = False
        for username, role in DEMO_USERS:
            existing = db.scalar(select(User).where(User.username == username))
            if existing is not None:
                users[username] = existing
                continue
            user = User(
                username=username,
                password_hash=password_service.hash(DEMO_PASSWORD),
                role=role,
                ai_data_consent=False,
                created_at=utcnow() - timedelta(days=random.randint(7, 30)),
            )
            db.add(user)
            users[username] = user
            created_any = True
            log(f"[user] Tạo {username} (role={role}).")
        db.commit()
        for user in users.values():
            db.refresh(user)

        # ---------- 2. Hội thoại + tin nhắn mã hóa ----------
        owner = users["demo.user"]
        has_sessions = (
            db.scalar(select(ChatSession.id).where(ChatSession.owner_id == owner.id).limit(1))
            is not None
        )
        if not has_sessions:
            base_time = utcnow() - timedelta(days=3)
            for idx, (title, turns) in enumerate(DEMO_CONVERSATIONS):
                session_row = ChatSession(
                    owner_id=owner.id,
                    title=title,
                    created_at=base_time + timedelta(hours=idx * 7),
                    updated_at=base_time + timedelta(hours=idx * 7 + 1),
                )
                db.add(session_row)
                db.flush()
                msg_time = session_row.created_at
                for role, content in turns:
                    ciphertext, nonce, key_version = crypto_service.encrypt(
                        content, session_row.id, role
                    )
                    msg_time += timedelta(minutes=random.randint(1, 4))
                    db.add(
                        SecureMessage(
                            session_id=session_row.id,
                            role=role,
                            ciphertext=ciphertext,
                            nonce=nonce,
                            key_version=key_version,
                            created_at=msg_time,
                        )
                    )
                log(f"[chat] “{title}” — {len(turns)} tin nhắn đã mã hóa.")
            db.commit()

        # ---------- 3. Sự kiện audit mô phỏng ----------
        if created_any or reset:

            def audit(minutes_ago, event, outcome, actor, ip, details, target=None):
                return AuditEvent(
                    actor_id=actor.id if actor else None,
                    event_type=event,
                    target_type=target[0] if target else None,
                    target_id=target[1] if target else None,
                    outcome=outcome,
                    ip_address=ip,
                    user_agent="Mozilla/5.0 (seed-demo)",
                    request_id="seed-" + uuid.uuid4().hex[:12],
                    details_json=json.dumps(details, ensure_ascii=False),
                    created_at=utcnow() - timedelta(minutes=minutes_ago),
                )

            events: list[AuditEvent] = []
            attacker_ip = FAKE_IPS[0]
            # Chuỗi brute-force trong 1 giờ gần nhất → kích hoạt cảnh báo an ninh.
            for i in range(6):
                events.append(
                    audit(
                        50 - i * 6,
                        "auth.login",
                        "failure",
                        users["demo.user"],
                        attacker_ip,
                        {"reason": "invalid_credentials"},
                    )
                )
            events.append(
                audit(
                    12,
                    "auth.login",
                    "blocked",
                    users["demo.user"],
                    attacker_ip,
                    {"reason": "rate_limit"},
                )
            )
            # Thử truy cập hội thoại của người khác (IDOR) → bị từ chối.
            for i in range(4):
                events.append(
                    audit(
                        30 - i * 5,
                        "authorization.denied",
                        "denied",
                        users["demo.mod"],
                        FAKE_IPS[1],
                        {"reason": "not_owner"},
                        target=("chat_session", uuid.uuid4().hex[:8]),
                    )
                )
            # Hoạt động bình thường rải trong vài ngày.
            for day in range(3):
                for username in ("demo.user", "demo.boss"):
                    actor = users[username]
                    events.append(
                        audit(
                            day * 1440 + random.randint(60, 600),
                            "auth.login",
                            "success",
                            actor,
                            random.choice(FAKE_IPS),
                            {},
                            target=("user", actor.id),
                        )
                    )
                    events.append(
                        audit(
                            day * 1440 + random.randint(30, 500),
                            "chat.message.send",
                            "success",
                            actor,
                            random.choice(FAKE_IPS),
                            {"content_length": random.randint(20, 300)},
                        )
                    )
            db.add_all(events)
            db.commit()
            log(f"[audit] Đã ghi {len(events)} sự kiện kiểm toán mô phỏng.")

    log("[seed] Dữ liệu mẫu sẵn sàng — mật khẩu chung: " + DEMO_PASSWORD)
