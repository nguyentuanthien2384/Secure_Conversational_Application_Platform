#!/usr/bin/env python3
"""Dữ liệu mẫu "học được": mỗi bản ghi minh họa một cơ chế bảo mật của dự án.

Khác gì so với scripts/seed_demo_data.py?

  1. 5 tài khoản, mỗi tài khoản là một TRẠNG THÁI khác nhau: bình thường,
     moderator, admin, đã bật MFA (in ra cả secret TOTP để nạp vào
     Google Authenticator), và đang bị khóa do brute force.
  2. Hội thoại thuộc HAI chủ sở hữu khác nhau, nên có thể demo IDOR bằng
     session_id thật của người khác thay vì id bịa.
  3. Phiên thiết bị (auth_sessions) có cả phiên còn hiệu lực và phiên đã thu
     hồi, để tab "Thiết bị đăng nhập" và logout-all có dữ liệu.
  4. Nhật ký kiểm toán được NIÊM PHONG bằng đúng chuỗi băm HMAC của dự án
     (audit_chain.seal_event), nên GET /api/admin/audit/verify báo
     verified_events == total_events. Bản seed cũ chèn thẳng vào DB mà không
     niêm phong, khiến verify đếm được rất ít bản ghi đã xác minh.
  5. Kịch bản tấn công phân biệt brute force (1 tài khoản, nhiều mật khẩu) với
     password spraying (nhiều tài khoản, 1 mật khẩu) — đúng như engine bất
     thường trong src/app/ids.py phân loại.

Cách chạy (dùng cùng file .env với server, vì tin nhắn mã hóa bằng đúng
MASTER_ENCRYPTION_KEY mà server sẽ dùng để giải mã):

    uv run python scripts/seed_learning_data.py            # thêm dữ liệu
    uv run python scripts/seed_learning_data.py --reset     # xóa dữ liệu cũ rồi tạo lại
    uv run python scripts/seed_learning_data.py --wipe-audit  # xóa sạch audit trước

Trong Docker (script này không được COPY vào image, nên chạy từ host với
DATABASE_URL trỏ tới Postgres đã publish, hoặc dùng bản SQLite để học).
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from src.app.audit_chain import derive_audit_key, seal_event  # noqa: E402
from src.app.config import Settings  # noqa: E402
from src.app.db import Database, utcnow  # noqa: E402
from src.app.models import (  # noqa: E402
    AuditEvent,
    AuthSession,
    ChatSession,
    MfaRecoveryCode,
    SecureMessage,
    User,
)
from src.app.security import CryptoService, PasswordService, TotpService  # noqa: E402

# Thỏa chính sách mật khẩu: >= 15 ký tự, đủ đa dạng, không chứa chuỗi phổ biến.
LEARN_PASSWORD = "Phenikaa-Learn#2026-Lab"
TAG = "learn-"  # tiền tố request_id để có thể xóa lại đúng dữ liệu mẫu

# (username, role, ghi chú dạy điều gì)
LEARN_USERS: tuple[tuple[str, str, str], ...] = (
    ("learn.user", "user", "Người dùng thường — sở hữu 4 hội thoại, dùng để demo RBAC cấp thấp"),
    ("learn.mod", "moderator", "Moderator — có hội thoại RIÊNG, làm mục tiêu cho demo IDOR"),
    ("learn.boss", "admin", "Admin — thấy toàn bộ bảng quản trị, thống kê, cảnh báo"),
    ("learn.mfa", "user", "Đã bật 2FA TOTP — secret in ra cuối script để nạp vào app"),
    ("learn.locked", "user", "Đang bị khóa do brute force — demo account lockout"),
)

# Nội dung hội thoại giải thích chính các cơ chế của dự án.
CONVERSATIONS_USER: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "JWT mang những claim gì?",
        [
            ("user", "Token đăng nhập của tôi chứa thông tin gì, và vì sao cần nhiều claim thế?"),
            (
                "assistant",
                "Access token là JWT có exp (hết hạn), nbf (chưa hiệu lực trước mốc này), "
                "iat (thời điểm phát hành), jti (id duy nhất của token), iss và aud. "
                "jti là thứ cho phép thu hồi từng token cụ thể: khi bạn đăng xuất một "
                "thiết bị, jti đó được ghi vào bảng revoked_tokens, nên token vẫn còn "
                "hạn nhưng đã hết giá trị. Ngoài ra mỗi người dùng có token_version; "
                "đổi mật khẩu sẽ tăng số này lên và mọi token cũ mất hiệu lực cùng lúc.",
            ),
            ("user", "Vậy vì sao thời hạn chỉ 30 phút?"),
            (
                "assistant",
                "Vì chưa có refresh-token rotation. Token càng sống lâu thì cửa sổ mà "
                "một token bị đánh cắp còn dùng được càng rộng. 30 phút là đánh đổi giữa "
                "trải nghiệm và rủi ro — README mục 9 ghi rõ đây là giới hạn có chủ đích.",
            ),
        ],
    ),
    (
        "AAD trong AES-256-GCM để làm gì?",
        [
            ("user", "Tôi hiểu GCM mã hóa và xác thực. Nhưng AAD thêm vào để làm gì?"),
            (
                "assistant",
                "AAD (Associated Authenticated Data) là dữ liệu không được mã hóa nhưng "
                "ĐƯỢC xác thực. Ở đây AAD ràng buộc bản mã với session_id, vai trò của "
                "tin nhắn và phiên bản khóa. Hệ quả thực tế: nếu ai đó có quyền ghi DB và "
                "copy một dòng ciphertext từ hội thoại của người khác sang hội thoại của "
                "bạn, thì lúc giải mã, AAD không khớp và GCM báo lỗi xác thực thay vì trả "
                "về nội dung. Nếu không có AAD, thao tác copy đó sẽ thành công.",
            ),
            ("user", "Nonce có được phép lặp lại không?"),
            (
                "assistant",
                "Không, và đây là điểm chết người của GCM. Dùng lại một cặp (khóa, nonce) "
                "cho hai bản rõ khác nhau làm lộ XOR của hai bản rõ và cho phép giả mạo "
                "thẻ xác thực. Vì vậy mỗi tin nhắn sinh nonce 12 byte ngẫu nhiên riêng, "
                "lưu cùng dòng — bạn xem trực tiếp được ở tab Dữ liệu mã hóa.",
            ),
        ],
    ),
    (
        "Chuỗi băm audit chống giả mạo thế nào?",
        [
            ("user", "Một bảng log mà admin DB sửa được thì có ý nghĩa gì không?"),
            (
                "assistant",
                "Đúng là gần như không, nên dự án dùng hash chain: mỗi bản ghi lưu "
                "entry_hash = HMAC-SHA256(khóa, prev_hash || nội dung bản ghi). Sửa một "
                "dòng ở giữa làm mọi hash phía sau sai, và verify chỉ ra đúng id đầu tiên "
                "bị gãy. Khóa HMAC dẫn xuất từ APP_SECRET_KEY với nhãn riêng, không nằm "
                "trong database — nên người chỉ có quyền SQL có thể XÓA nhưng không thể "
                "GIẢ MẠO một chuỗi hợp lệ.",
            ),
            (
                "user",
                "Còn lớp nào nữa không, hay chỉ dựa vào hash?",
            ),
            (
                "assistant",
                "Có lớp thứ hai ở tầng database: vai trò runtime scap_app bị REVOKE "
                "UPDATE, DELETE, TRUNCATE trên bảng audit_events, chỉ còn SELECT và "
                "INSERT. Hash chain PHÁT HIỆN việc sửa đổi, còn phân quyền NGĂN CHẶN nó "
                "ngay từ đầu. Hai lớp bổ sung cho nhau, đúng nguyên tắc defense in depth.",
            ),
        ],
    ),
    (
        "DLP che dữ liệu nhạy cảm trước khi gửi ra ngoài",
        [
            ("user", "Nếu tôi vô tình dán số thẻ vào chat thì sao?"),
            (
                "assistant",
                "Lớp DLP quét bản rõ và che các mẫu nhạy cảm TRƯỚC khi nội dung được gửi "
                "tới nhà cung cấp AI bên ngoài. Bản gốc vẫn được lưu mã hóa trong DB của "
                "bạn, chỉ phần đi ra ngoài bị che. Khi có gì bị che, giao diện hiện banner "
                "cảnh báo và một sự kiện dlp.redacted được ghi vào nhật ký.",
            ),
            (
                "user",
                "Nghe nói lớp này từng bị lỗi?",
            ),
            (
                "assistant",
                "Có, và đó là lỗi đáng nhớ nhất của dự án: regex bị escape hai lần trong "
                "chuỗi raw nên không khớp gì cả — lớp DLP trông như đang hoạt động nhưng "
                "thực tế không che gì. Nó chỉ lộ ra khi có test kiểm tra đầu ra thật. Bài "
                "học: một kiểm soát bảo mật không có test là một kiểm soát chưa tồn tại.",
            ),
        ],
    ),
]

CONVERSATIONS_MOD: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Hội thoại riêng của moderator (mục tiêu IDOR)",
        [
            ("user", "Hội thoại này thuộc learn.mod. Dùng nó để thử tấn công IDOR."),
            (
                "assistant",
                "Chính xác. Hãy đăng nhập bằng learn.user, lấy session_id của hội thoại "
                "này rồi gọi GET /api/chat/sessions/{id}/messages. Máy chủ kiểm tra quyền "
                "sở hữu trên từng phiên nên sẽ trả 403 hoặc 404 thay vì nội dung, và ghi "
                "một sự kiện authorization.denied kèm id bị nhắm tới. Đó là cách chống "
                "IDOR/BOLA: không bao giờ tin id do client gửi lên.",
            ),
        ],
    ),
]

FAKE_IPS = ("203.0.113.24", "198.51.100.77", "192.0.2.140", "203.0.113.9")
UA_DESKTOP = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36"
UA_MOBILE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) Mobile/15E148 Safari/604.1"
UA_ATTACK = "python-requests/2.32.3"


def main() -> None:  # noqa: C901 - script tuần tự, đọc từ trên xuống dễ hơn là tách hàm
    reset = "--reset" in sys.argv
    wipe_audit = "--wipe-audit" in sys.argv

    settings = Settings.from_env()
    database = Database(settings.database_url)
    passwords = PasswordService()
    crypto = CryptoService(
        settings.master_encryption_key,
        keyring=dict(settings.master_encryption_keys) or None,
        active_key_version=settings.active_key_version,
    )
    totp = TotpService()
    audit_key = derive_audit_key(settings.secret_key) if settings.audit_chain_enabled else None

    database.create_all()
    notes: list[str] = []

    with database.session_factory() as db:
        # ───────────────── 0. Dọn dữ liệu cũ ─────────────────
        if wipe_audit:
            removed = db.query(AuditEvent).delete(synchronize_session=False)
            db.commit()
            print(f"[wipe] Đã xóa {removed} bản ghi audit — chuỗi băm bắt đầu lại từ genesis.")

        if reset:
            gone = 0
            for username, _role, _why in LEARN_USERS:
                user = db.scalar(select(User).where(User.username == username))
                if user is not None:
                    db.delete(user)  # cascade: hội thoại, tin nhắn, phiên, mã khôi phục
                    gone += 1
            killed = (
                db.query(AuditEvent)
                .filter(AuditEvent.request_id.like(TAG + "%"))
                .delete(synchronize_session=False)
            )
            db.commit()
            print(f"[reset] Đã xóa {gone} tài khoản và {killed} bản ghi audit mẫu.")
            if killed and not wipe_audit:
                notes.append(
                    "Vừa XÓA bản ghi audit ở giữa chuỗi. Nếu verify báo chain_intact=false, "
                    "đó là KIỂM SOÁT ĐANG HOẠT ĐỘNG ĐÚNG, không phải lỗi. Muốn chuỗi sạch "
                    "hoàn toàn, chạy lại kèm --wipe-audit."
                )

        # ───────────────── 1. Tài khoản ─────────────────
        users: dict[str, User] = {}
        created_any = False
        for username, role, _why in LEARN_USERS:
            existing = db.scalar(select(User).where(User.username == username))
            if existing is not None:
                users[username] = existing
                continue
            user = User(
                username=username,
                password_hash=passwords.hash(LEARN_PASSWORD),
                role=role,
                ai_data_consent=(username == "learn.user"),
                created_at=utcnow() - timedelta(days=21),
            )
            db.add(user)
            users[username] = user
            created_any = True
            print(f"[user] Tạo {username} (role={role}).")
        db.commit()
        for user in users.values():
            db.refresh(user)

        if not created_any and not reset:
            print("[skip] Tài khoản mẫu đã tồn tại. Dùng --reset để tạo lại từ đầu.")
            _print_tour(None, notes)
            return

        # ───────────────── 2. Trạng thái đặc biệt ─────────────────
        # 2a. Tài khoản đang bị khóa do đăng nhập sai quá ngưỡng.
        locked = users["learn.locked"]
        locked.failed_login_attempts = settings.login_max_attempts
        locked.locked_until = utcnow() + timedelta(seconds=settings.login_lockout_seconds)

        # 2b. Tài khoản đã bật 2FA. Secret được mã hóa tại chỗ, AAD ràng buộc
        #     theo user id (context="mfa:<id>") giống hệt luồng thật trong main.py.
        mfa_user = users["learn.mfa"]
        mfa_secret = totp.generate_secret()
        ciphertext, nonce = crypto.encrypt_secret(mfa_secret, context=f"mfa:{mfa_user.id}")
        mfa_user.mfa_secret_ciphertext = ciphertext
        mfa_user.mfa_secret_nonce = nonce
        mfa_user.mfa_enabled = True
        recovery_plain = [uuid.uuid4().hex[:10].upper() for _ in range(3)]
        for code in recovery_plain:
            db.add(MfaRecoveryCode(user_id=mfa_user.id, code_hash=passwords.hash(code)))
        db.commit()
        print(f"[mfa] Đã bật 2FA cho {mfa_user.username} + {len(recovery_plain)} mã khôi phục.")

        # ───────────────── 3. Hội thoại mã hóa ─────────────────
        idor_target: str | None = None
        plan = (
            (users["learn.user"], CONVERSATIONS_USER),
            (users["learn.mod"], CONVERSATIONS_MOD),
        )
        for owner, conversations in plan:
            has_any = (
                db.scalar(select(ChatSession.id).where(ChatSession.owner_id == owner.id).limit(1))
                is not None
            )
            if has_any:
                continue
            base = utcnow() - timedelta(days=6)
            for idx, (title, turns) in enumerate(conversations):
                session_row = ChatSession(
                    owner_id=owner.id,
                    title=title,
                    created_at=base + timedelta(hours=idx * 9),
                    updated_at=base + timedelta(hours=idx * 9 + 1),
                )
                db.add(session_row)
                db.flush()  # cần id để đưa vào AAD
                if owner.username == "learn.mod":
                    idor_target = session_row.id
                stamp = session_row.created_at
                for role, content in turns:
                    ct, nc, kv = crypto.encrypt(content, session_row.id, role)
                    stamp += timedelta(minutes=3)
                    db.add(
                        SecureMessage(
                            session_id=session_row.id,
                            role=role,
                            ciphertext=ct,
                            nonce=nc,
                            key_version=kv,
                            created_at=stamp,
                        )
                    )
                print(f"[chat] {owner.username}: “{title}” — {len(turns)} tin đã mã hóa.")
            db.commit()

        if idor_target is None:
            row = db.scalar(
                select(ChatSession).where(ChatSession.owner_id == users["learn.mod"].id).limit(1)
            )
            idor_target = row.id if row is not None else uuid.uuid4().hex[:8]

        # ───────────────── 4. Phiên thiết bị ─────────────────
        if not db.scalar(
            select(AuthSession.jti).where(AuthSession.user_id == users["learn.user"].id).limit(1)
        ):
            now = utcnow()
            devices = (
                (UA_DESKTOP, FAKE_IPS[0], None, 20),
                (UA_MOBILE, FAKE_IPS[1], None, 6),
                (UA_ATTACK, FAKE_IPS[2], now - timedelta(hours=30), 34),
            )
            for ua, ip, revoked, hours_ago in devices:
                issued = now - timedelta(hours=hours_ago)
                db.add(
                    AuthSession(
                        jti=str(uuid.uuid4()),
                        user_id=users["learn.user"].id,
                        issued_at=issued,
                        expires_at=issued
                        + timedelta(minutes=max(settings.access_token_minutes, 30)),
                        revoked_at=revoked,
                        ip_address=ip,
                        user_agent=ua,
                    )
                )
            db.commit()
            print("[device] 3 phiên thiết bị (1 đã thu hồi) cho learn.user.")

        # ───────────────── 5. Nhật ký kiểm toán ─────────────────
        # Xây danh sách rồi SẮP XẾP THEO THỜI GIAN trước khi chèn: chuỗi băm đi
        # theo id tăng dần, nên id phải cùng thứ tự với created_at, nếu không
        # verify sẽ báo gãy vì lý do không phải tấn công.
        drafts: list[tuple[int, dict]] = []

        def ev(minutes_ago: int, event_type: str, outcome: str, **kw) -> None:
            drafts.append((minutes_ago, {"event_type": event_type, "outcome": outcome, **kw}))

        u_user, u_mod, u_boss = users["learn.user"], users["learn.mod"], users["learn.boss"]
        u_mfa, u_locked = users["learn.mfa"], users["learn.locked"]

        # 5a. Hoạt động bình thường rải trong 5 ngày (đường nền để so sánh).
        for day in range(5, 0, -1):
            base = day * 1440
            for actor in (u_user, u_boss, u_mod):
                ev(base + 300, "auth.login", "success", actor=actor, ip=FAKE_IPS[0])
                ev(base + 280, "chat.message.send", "success", actor=actor, ip=FAKE_IPS[0],
                   details={"content_length": 120 + day * 7})
                ev(base + 120, "auth.logout", "success", actor=actor, ip=FAKE_IPS[0])

        # 5b. Đăng ký + bật 2FA (vòng đời MFA đầy đủ).
        ev(4300, "auth.register", "success", actor=u_mfa, ip=FAKE_IPS[1])
        ev(4200, "auth.mfa.enroll", "success", actor=u_mfa, ip=FAKE_IPS[1])
        ev(4190, "auth.mfa.activate", "success", actor=u_mfa, ip=FAKE_IPS[1],
           details={"recovery_codes": len(recovery_plain)})
        ev(2000, "auth.mfa.challenge", "success", actor=u_mfa, ip=FAKE_IPS[1])
        ev(1999, "auth.mfa.verify", "failure", actor=u_mfa, ip=FAKE_IPS[1],
           details={"reason": "code_replay"})
        ev(1998, "auth.mfa.verify", "success", actor=u_mfa, ip=FAKE_IPS[1])

        # 5c. PASSWORD SPRAYING: một IP, MỘT mật khẩu, NHIỀU tài khoản.
        for i, victim in enumerate((u_user, u_mod, u_boss, u_mfa, u_locked)):
            ev(700 - i * 3, "auth.login", "failure", actor=victim, ip=FAKE_IPS[3],
               ua=UA_ATTACK, details={"reason": "invalid_credentials", "pattern": "spraying"})
        ev(680, "ids.signature", "detected", ip=FAKE_IPS[3], ua=UA_ATTACK,
           details={"signature": "auth_anomaly", "verdict": "password_spraying", "score": 4})

        # 5d. BRUTE FORCE: một IP, MỘT tài khoản, nhiều mật khẩu -> lockout.
        for i in range(settings.login_max_attempts + 1):
            ev(240 - i * 8, "auth.login", "failure", actor=u_locked, ip=FAKE_IPS[2],
               ua=UA_ATTACK, details={"reason": "invalid_credentials", "attempt": i + 1})
        ev(180, "auth.login", "blocked", actor=u_locked, ip=FAKE_IPS[2], ua=UA_ATTACK,
           details={"reason": "account_locked", "lockout_seconds": settings.login_lockout_seconds})

        # 5e. Trinh sát bằng chữ ký tấn công -> IDS chặn nguồn.
        for i, probe in enumerate(("sqli_union", "path_traversal", "xss_script_tag")):
            ev(150 - i * 4, "ids.signature", "detected", ip=FAKE_IPS[2], ua=UA_ATTACK,
               details={"signature": probe, "score": 3})
        ev(135, "ids.block", "blocked", ip=FAKE_IPS[2], ua=UA_ATTACK, target=("source_ip", FAKE_IPS[2]),
           details={"score": settings.ids_block_threshold + 4,
                    "block_seconds": settings.ids_block_seconds})
        ev(100, "ids.block.enforced", "blocked", ip=FAKE_IPS[2], ua=UA_ATTACK,
           target=("source_ip", FAKE_IPS[2]), details={"path": "/api/chat/sessions"})

        # 5f. IDOR nhắm vào hội thoại THẬT của learn.mod -> bị từ chối.
        for i in range(3):
            ev(90 - i * 6, "authorization.denied", "denied", actor=u_user, ip=FAKE_IPS[0],
               target=("chat_session", idor_target), details={"reason": "not_owner"})

        # 5g. DLP che dữ liệu trước khi gửi ra nhà cung cấp AI.
        ev(70, "dlp.redacted", "success", actor=u_user, ip=FAKE_IPS[0],
           details={"patterns": ["credit_card", "email"], "redactions": 2})

        # 5h. Phản ứng sự cố: thu hồi phiên, đổi mật khẩu, đổi vai trò.
        ev(55, "auth.session_revoke", "success", actor=u_user, ip=FAKE_IPS[0],
           target=("auth_session", str(uuid.uuid4())), details={"reason": "unknown_device"})
        ev(50, "auth.password_change", "success", actor=u_user, ip=FAKE_IPS[0],
           details={"token_version_bumped": True})
        ev(45, "auth.logout_all", "success", actor=u_user, ip=FAKE_IPS[0],
           details={"sessions_revoked": 3})
        ev(30, "admin.user_role_change", "success", actor=u_boss, ip=FAKE_IPS[0],
           target=("user", u_mod.id), details={"from": "user", "to": "moderator"})
        ev(20, "admin.user_status", "success", actor=u_boss, ip=FAKE_IPS[0],
           target=("user", u_locked.id), details={"is_active": True, "unlocked": True})
        ev(10, "chat.message.search", "success", actor=u_user, ip=FAKE_IPS[0],
           details={"query_length": 6, "matches": 3})

        # Chèn theo đúng thứ tự thời gian và niêm phong từng bản ghi.
        drafts.sort(key=lambda item: -item[0])
        sealed = 0
        for minutes_ago, spec in drafts:
            actor = spec.get("actor")
            target = spec.get("target")
            row = AuditEvent(
                actor_id=actor.id if actor is not None else None,
                event_type=spec["event_type"],
                target_type=target[0] if target else None,
                target_id=target[1] if target else None,
                outcome=spec["outcome"],
                ip_address=spec.get("ip"),
                user_agent=spec.get("ua", UA_DESKTOP),
                request_id=TAG + uuid.uuid4().hex[:12],
                details_json=json.dumps(spec.get("details", {}), ensure_ascii=False),
                created_at=utcnow() - timedelta(minutes=minutes_ago),
            )
            if audit_key is not None:
                # seal_event đọc hash của bản ghi cuối trong DB, nên phải flush
                # từng dòng để dòng sau nối đúng vào dòng trước.
                seal_event(db, row, audit_key)
                sealed += 1
            db.add(row)
            db.flush()
        db.commit()
        print(f"[audit] Đã ghi {len(drafts)} sự kiện" + (f", niêm phong {sealed}." if sealed else "."))

        _print_tour(
            {
                "idor_target": idor_target,
                "mfa_user": mfa_user.username,
                "mfa_secret": mfa_secret,
                "recovery": recovery_plain,
                "locked_user": u_locked.username,
                "sealed": sealed,
            },
            notes,
        )


def _print_tour(info: dict | None, notes: list[str]) -> None:
    line = "─" * 68
    print(f"\n{line}\nTÀI KHOẢN MẪU — mật khẩu chung: {LEARN_PASSWORD}\n{line}")
    for username, role, why in LEARN_USERS:
        print(f"  {username:<14} {role:<10} {why}")

    if info:
        print(f"\n{line}\n2FA — nạp vào Google Authenticator / Authy\n{line}")
        print(f"  Tài khoản  : {info['mfa_user']}")
        print(f"  Secret     : {info['mfa_secret']}   (base32, nhập tay vào app)")
        print(f"  Mã khôi phục: {', '.join(info['recovery'])}")
        print("  Chỉ in ra một lần — trong DB chỉ có bản băm Argon2id của mã khôi phục.")

        print(f"\n{line}\nLỘ TRÌNH TÌM HIỂU — làm theo thứ tự này\n{line}")
        steps = [
            ("Mã hóa at-rest",
             "Đăng nhập learn.user → tab Dữ liệu mã hóa. Mỗi dòng có ciphertext, "
             "nonce riêng và key_version. Không dòng nào đọc được."),
            ("AAD ràng buộc",
             "Mở hội thoại “AAD trong AES-256-GCM để làm gì?” — nội dung tự giải thích "
             "vì sao copy ciphertext sang hội thoại khác sẽ thất bại."),
            ("IDOR bị chặn",
             f"Vẫn là learn.user, gọi GET /api/chat/sessions/{info['idor_target']}/messages "
             "(hội thoại này thuộc learn.mod) → 403/404 + audit authorization.denied."),
            ("Account lockout",
             f"Đăng nhập {info['locked_user']} bằng mật khẩu đúng → vẫn bị từ chối vì đang "
             "trong thời gian khóa. Thông báo lỗi giữ nguyên dạng chung, không tiết lộ "
             "tài khoản có tồn tại hay không."),
            ("2FA hai bước",
             f"Đăng nhập {info['mfa_user']} → nhập mã 6 số từ app. Thử nhập lại đúng mã "
             "vừa dùng → bị từ chối vì chống replay."),
            ("Brute force vs spraying",
             "Đăng nhập learn.boss → tab Quản trị. Nhật ký có hai cụm tấn công khác nhau: "
             "một IP dò nhiều mật khẩu trên 1 tài khoản, và một IP thử 1 mật khẩu trên 5 "
             "tài khoản. Engine bất thường phân loại chúng khác nhau."),
            ("IDS/IPS",
             "Cùng tab, tìm ids.signature rồi ids.block: điểm rủi ro tích lũy vượt ngưỡng "
             "nên nguồn bị chặn có thời hạn."),
            ("Audit chain",
             "Gọi GET /api/admin/audit/verify → verified_events nên bằng total_events. "
             "Sau đó sửa tay một dòng audit bằng psql rồi gọi lại → chain_intact=false "
             "kèm first_broken_id đúng dòng vừa sửa."),
            ("Phân quyền 3 cấp",
             "Đăng nhập learn.mod: thấy nhật ký kiểm toán nhưng KHÔNG thấy quản lý người "
             "dùng. learn.user không thấy cả hai. Cùng một API, ba kết quả."),
            ("Thiết bị đăng nhập",
             "learn.user → tab Tài khoản: 3 phiên, 1 đã thu hồi. Thu hồi một phiên rồi "
             "thử dùng lại token của phiên đó."),
        ]
        for i, (title, body) in enumerate(steps, 1):
            print(f"\n  {i:>2}. {title}\n      {body}")

    if notes:
        print(f"\n{line}\nLƯU Ý\n{line}")
        for note in notes:
            print(f"  ! {note}")
    print()


if __name__ == "__main__":
    main()
