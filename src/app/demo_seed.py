"""Sinh dữ liệu mẫu cho nền tảng — dùng chung bởi scripts/seed_demo_data.py
và cơ chế auto-seed khi khởi động (biến môi trường SEED_DEMO_DATA=true).

Tạo 3 tài khoản demo chính theo RBAC, 8 tài khoản lab bổ sung, các hội thoại
đã mã hóa AES-256-GCM và chuỗi sự kiện audit mô phỏng (brute-force, IDOR bị
chặn) để dashboard có dữ liệu đủ cho buổi báo cáo.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from random import SystemRandom

from sqlalchemy import select

from src.app.audit_chain import derive_audit_key, seal_event
from src.app.db import Database, utcnow
from src.app.models import AuditEvent, ChatSession, SecureMessage, User
from src.app.security import CryptoService, PasswordService


def _seed_audit_key() -> bytes | None:
    """Khóa HMAC của hash chain, dẫn xuất từ cùng APP_SECRET_KEY mà server dùng.

    Trả về ``None`` khi chuỗi audit bị tắt, để seed vẫn chạy được trong lab.
    Phải là *cùng* khóa, nếu không mọi bản ghi mẫu sẽ báo entry_hash_mismatch.
    """
    from src.app.config import Settings

    settings = Settings.from_env()
    if not settings.audit_chain_enabled:
        return None
    return derive_audit_key(settings.secret_key)

# Passphrase công khai chỉ dành cho development; production cấm seed demo.
# Nó phải thỏa chính sách mật khẩu để phục vụ kiểm thử luồng đăng nhập.
DEMO_PASSPHRASE = "Phenikaa-Vault#2026-Lab"  # nosec B105
_DEMO_RANDOM = SystemRandom()

DEMO_USERS = (
    ("demo.user", "user"),
    ("demo.mod", "moderator"),
    ("demo.boss", "admin"),
)

# Các tài khoản phụ làm đầy bảng quản trị, kiểm tra phân trang/tìm kiếm và tạo
# phân bố dữ liệu thực tế hơn khi trình diễn. Chúng chỉ được sinh ở development
# (production bị Settings.from_env() từ chối SEED_DEMO_DATA=true).
SAMPLE_USERS = (
    ("lab.alice", "user"),
    ("lab.binh", "user"),
    ("lab.chi", "user"),
    ("lab.dung", "user"),
    ("lab.em", "user"),
    ("lab.giang", "user"),
    ("lab.hanh", "user"),
    ("lab.iris", "moderator"),
)
ALL_DEMO_USERS = DEMO_USERS + SAMPLE_USERS

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

# Các hội thoại ngắn cho moderator/admin và tài khoản thử nghiệm. Nội dung là
# mô tả kiểm soát bảo mật, không chứa mật khẩu, khóa hoặc thông tin cá nhân.
ROLE_CONVERSATIONS: dict[str, list[tuple[str, list[tuple[str, str]]]]] = {
    "demo.mod": [
        (
            "Rà soát audit log",
            [
                ("user", "Tôi cần xem các lần đăng nhập thất bại ở đâu?"),
                (
                    "assistant",
                    "Mở tab Nhật ký kiểm toán để xem event, outcome, IP và request ID. "
                    "Bản ghi được liên kết bằng chuỗi HMAC để phát hiện sửa đổi.",
                ),
            ],
        ),
        (
            "Triage cảnh báo IDS",
            [
                ("user", "Một địa chỉ IP bị chặn thì nên xử lý thế nào?"),
                (
                    "assistant",
                    "Kiểm tra chữ ký, thời điểm và chuỗi audit trước. Chỉ admin mới có thể "
                    "gỡ chặn sau khi xác nhận đây là false positive.",
                ),
            ],
        ),
    ],
    "demo.boss": [
        (
            "Báo cáo trạng thái bảo mật",
            [
                ("user", "Dashboard quản trị cho biết những gì?"),
                (
                    "assistant",
                    "Dashboard tổng hợp số người dùng, hội thoại, tin nhắn, đăng nhập lỗi "
                    "và các lần bị từ chối quyền trong cửa sổ quan sát.",
                ),
            ],
        ),
        (
            "Kiểm chứng MITRE T1190",
            [
                ("user", "Kết quả Hit/Miss có ý nghĩa gì?"),
                (
                    "assistant",
                    "Nó xác nhận các luật IDS nội bộ nhận diện được kịch bản an toàn cho "
                    "T1190. Đây không phải là kết luận thay thế pentest hoặc SIEM ngoài hệ thống.",
                ),
            ],
        ),
    ],
}

SAMPLE_CONVERSATIONS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Thực hành bảo vệ tài khoản",
        [
            ("user", "Tôi nên bật những lớp bảo vệ nào cho tài khoản?"),
            (
                "assistant",
                "Dùng mật khẩu dài, bật TOTP, không chia sẻ recovery code và thu hồi phiên "
                "trên thiết bị không còn sử dụng.",
            ),
        ],
    ),
    (
        "Dữ liệu được mã hóa",
        [
            ("user", "Tin nhắn có được lưu ở dạng rõ không?"),
            (
                "assistant",
                "Không. Nội dung được AES-256-GCM mã hóa trước khi ghi vào cơ sở dữ liệu; "
                "mỗi bản ghi có nonce riêng và AAD gắn với phiên hội thoại.",
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
    refresh_telemetry: bool = False,
    log=print,
) -> None:
    """Nạp dữ liệu demo, có thể làm mới telemetry hiển thị trên dashboard.

    Mặc định thao tác này idempotent: tài khoản, hội thoại và audit đã có sẽ
    không bị nhân bản. ``refresh_telemetry`` chỉ thêm 12 sự kiện gần hiện tại
    (brute-force và IDOR bị chặn) để cửa sổ IDS 60 phút luôn có kịch bản để
    trình diễn; không đụng đến dữ liệu hội thoại hay các sự kiện lịch sử.
    """
    database.create_all()
    with database.session_factory() as db:
        if reset:
            removed = 0
            for username, _ in ALL_DEMO_USERS:
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
        for username, role in ALL_DEMO_USERS:
            existing = db.scalar(select(User).where(User.username == username))
            if existing is not None:
                users[username] = existing
                continue
            user = User(
                username=username,
                password_hash=password_service.hash(DEMO_PASSPHRASE),
                role=role,
                ai_data_consent=False,
                created_at=utcnow() - timedelta(days=_DEMO_RANDOM.randint(7, 30)),
            )
            db.add(user)
            users[username] = user
            created_any = True
            log(f"[user] Tạo {username} (role={role}).")
        db.commit()
        for user in users.values():
            db.refresh(user)

        # ---------- 2. Hội thoại + tin nhắn mã hóa ----------
        # Có dữ liệu cho mỗi vai trò để kiểm tra RBAC, tìm kiếm tenant-scoped,
        # bảng quản trị và bản mã mà không cần tự nhập tay khi bảo vệ đồ án.
        conversations_by_user = {
            "demo.user": DEMO_CONVERSATIONS,
            "demo.mod": ROLE_CONVERSATIONS["demo.mod"],
            "demo.boss": ROLE_CONVERSATIONS["demo.boss"],
            **{username: SAMPLE_CONVERSATIONS for username, _ in SAMPLE_USERS},
        }
        base_time = utcnow() - timedelta(days=6)
        for owner_index, (username, conversations) in enumerate(conversations_by_user.items()):
            owner = users[username]
            has_sessions = (
                db.scalar(select(ChatSession.id).where(ChatSession.owner_id == owner.id).limit(1))
                is not None
            )
            if has_sessions:
                continue
            for idx, (title, turns) in enumerate(conversations):
                session_time = base_time + timedelta(hours=owner_index * 5 + idx * 2)
                session_row = ChatSession(
                    owner_id=owner.id,
                    title=title,
                    created_at=session_time,
                    updated_at=session_time + timedelta(minutes=len(turns) * 3),
                )
                db.add(session_row)
                db.flush()
                msg_time = session_row.created_at
                for role, content in turns:
                    ciphertext, nonce, key_version = crypto_service.encrypt(
                        content, session_row.id, role
                    )
                    msg_time += timedelta(minutes=_DEMO_RANDOM.randint(1, 4))
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
                log(f"[chat] {username} · “{title}” — {len(turns)} tin nhắn đã mã hóa.")
            db.commit()

        # ---------- 3. Sự kiện audit mô phỏng ----------
        # Khi cần trình diễn lại sau hơn 60 phút, chỉ làm mới cụm tín hiệu
        # vừa xảy ra. Không thêm lại lịch sử 7 ngày để số liệu không phình to
        # mỗi lần khởi động ứng dụng local.
        if created_any or reset or refresh_telemetry:

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
            # Ngưỡng IDS-IDOR-PROBE mặc định là 5, nên tạo đúng 5 lần bị chặn
            # để dashboard minh họa được cả kiểm soát BOLA/IDOR.
            for i in range(5):
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
            # Hoạt động bình thường rải trong nhiều ngày để dashboard có phân
            # bố dữ liệu thay vì chỉ một cụm sự kiện ở hiện tại. Phần lịch sử
            # chỉ sinh khi tạo lại dữ liệu, còn refresh chỉ sinh 12 tín hiệu
            # cần cho việc xem IDS ngay lúc đó.
            if created_any or reset:
                for day in range(7):
                    for username, _ in ALL_DEMO_USERS:
                        actor = users[username]
                        events.append(
                            audit(
                                day * 1440 + _DEMO_RANDOM.randint(60, 600),
                                "auth.login",
                                "success",
                                actor,
                                _DEMO_RANDOM.choice(FAKE_IPS),
                                {},
                                target=("user", actor.id),
                            )
                        )
                        events.append(
                            audit(
                                day * 1440 + _DEMO_RANDOM.randint(30, 500),
                                "chat.message.send",
                                "success",
                                actor,
                                _DEMO_RANDOM.choice(FAKE_IPS),
                                {"content_length": _DEMO_RANDOM.randint(20, 300)},
                            )
                        )
            # Trước đây các bản ghi này được INSERT trực tiếp, không đi qua
            # seal_event, nên entry_hash = NULL và GET /api/admin/audit/verify
            # báo "đã xác minh 97/120". Bây giờ mỗi bản ghi được niêm phong đúng
            # thứ tự id, nên chuỗi phủ 100% và trang Bảo mật hiển thị 120/120.
            audit_key = _seed_audit_key()
            if audit_key is None:
                log("[audit] AUDIT_CHAIN_ENABLED=false — bỏ qua niêm phong hash chain.")
                db.add_all(events)
                db.commit()
            else:
                for event in events:
                    seal_event(db, event, audit_key)
                    db.add(event)
                    # seal_event đọc hash của bản ghi cuối cùng trong DB, nên phải
                    # flush từng bản ghi để bản kế tiếp nối vào đúng mắt xích.
                    db.flush()
                db.commit()
            mode = "làm mới cảnh báo trong 60 phút" if refresh_telemetry and not (created_any or reset) else "tạo dữ liệu"
            log(f"[audit] Đã ghi {len(events)} sự kiện kiểm toán mô phỏng ({mode}, đã niêm phong).")

    log("[seed] Dữ liệu mẫu sẵn sàng — mật khẩu chung: " + DEMO_PASSPHRASE)
