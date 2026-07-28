"""Test hồi quy cho ba lỗi được sửa ngày 28/07/2026.

Mỗi test ở đây tương ứng một lỗi có thật đã quan sát được trên giao diện đang
chạy, không phải test lý thuyết:

1. Trang Bảo mật báo "Đã xác minh 97/120 bản ghi" nhưng vẫn hiện ✅ nguyên vẹn.
2. Mã QR 2FA hiện ra nhưng điện thoại không quét được.
3. Đồng hồ đếm ngược về 0 mà giao diện không phản ứng gì.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text

from src.app.audit_chain import (
    GENESIS_HASH,
    derive_audit_key,
    reseal_unsealed,
    seal_event,
    verify_chain,
)
from src.app.db import utcnow
from src.app.models import AuditEvent
from src.app.security import TotpService

# ────────────────── Lỗi 1: chuỗi băm audit ──────────────────

AUDIT_KEY = derive_audit_key("khoa-bi-mat-du-dai-cho-test-1234567890")


@pytest.fixture()
def clean_audit(client, db_session):
    """Xoá nhật ký do quá trình khởi động ứng dụng sinh ra.

    Các test dưới đây tự niêm phong bản ghi bằng AUDIT_KEY riêng, nên phải bắt
    đầu từ bảng rỗng để chuỗi khớp từ GENESIS_HASH.
    """
    db_session.execute(text("DELETE FROM audit_events"))
    db_session.commit()
    return db_session


def _event(db, n: int, *, sealed: bool = True) -> AuditEvent:
    event = AuditEvent(
        actor_id=f"user-{n}",
        event_type="auth.login",
        outcome="success",
        details_json="{}",
        created_at=utcnow() - timedelta(minutes=100 - n),
    )
    if sealed:
        seal_event(db, event, AUDIT_KEY)
    db.add(event)
    db.flush()
    return event


def test_bo_trong_entry_hash_khong_con_duoc_bao_la_nguyen_ven(clean_audit, db_session):
    """Lỗ hổng gốc: NULL entry_hash từng khiến verify_chain trả về intact=True.

    Kịch bản tấn công: kẻ có quyền UPDATE sửa nội dung một bản ghi rồi xoá
    entry_hash của nó và của mọi bản ghi phía sau. Bản cũ khởi động lại chuỗi ở
    mỗi dòng NULL và vẫn báo "Chuỗi nguyên vẹn" — toàn bộ cơ chế chống giả mạo
    bị vô hiệu bằng một câu lệnh SQL.
    """
    for i in range(5):
        _event(db_session, i)
    db_session.commit()

    assert verify_chain(db_session, AUDIT_KEY).intact is True

    # Kẻ tấn công sửa bản ghi #3 rồi bôi trắng hash của nó và các bản sau.
    db_session.execute(
        text("UPDATE audit_events SET actor_id = 'ke-tan-cong' WHERE id = 3")
    )
    db_session.execute(text("UPDATE audit_events SET entry_hash = NULL WHERE id >= 3"))
    db_session.commit()

    result = verify_chain(db_session, AUDIT_KEY)
    assert result.intact is False, "NULL entry_hash phải bị coi là mất bảo vệ"
    assert result.unsealed == 3
    assert result.first_unsealed_id == 3
    assert result.reason == "unsealed_events"
    assert result.coverage < 1.0


def test_ban_ghi_bi_sua_van_bi_phat_hien(clean_audit, db_session):
    """Trường hợp cơ bản: sửa nội dung mà giữ nguyên hash thì chuỗi phải gãy."""
    for i in range(4):
        _event(db_session, i)
    db_session.commit()

    db_session.execute(text("UPDATE audit_events SET outcome = 'failure' WHERE id = 2"))
    db_session.commit()

    result = verify_chain(db_session, AUDIT_KEY)
    assert result.intact is False
    assert result.first_broken_id == 2
    assert result.reason == "entry_hash_mismatch"


def test_reseal_va_duoc_khoang_trong_o_cuoi(clean_audit, db_session):
    """Bản ghi chưa niêm phong ở cuối bảng (do demo_seed cũ) thì vá được."""
    for i in range(3):
        _event(db_session, i)
    for i in range(3, 6):
        _event(db_session, i, sealed=False)
    db_session.commit()

    before = verify_chain(db_session, AUDIT_KEY)
    assert before.unsealed == 3 and before.intact is False

    assert reseal_unsealed(db_session, AUDIT_KEY) == 3

    after = verify_chain(db_session, AUDIT_KEY)
    assert after.intact is True
    assert after.verified == after.total == 6
    assert after.unsealed == 0


def test_reseal_tu_choi_khoang_trong_o_giua(clean_audit, db_session):
    """Khoảng trống ở giữa chuỗi phải bị từ chối, không được tự động vá.

    Vá chỗ giữa buộc phải băm lại các bản ghi đã niêm phong phía sau, tức là
    xoá bỏ chính bằng chứng mà chuỗi sinh ra để giữ. Đây phải là một sự cố cần
    điều tra, không phải một lệnh bảo trì.
    """
    _event(db_session, 0)
    _event(db_session, 1, sealed=False)
    _event(db_session, 2)
    db_session.commit()

    with pytest.raises(ValueError, match="nằm giữa chuỗi"):
        reseal_unsealed(db_session, AUDIT_KEY)


def test_chuoi_rong_va_ban_ghi_dau_tien(clean_audit, db_session):
    """Bản ghi đầu tiên phải trỏ về GENESIS_HASH."""
    assert verify_chain(db_session, AUDIT_KEY).intact is True
    first = _event(db_session, 0)
    db_session.commit()
    assert first.prev_hash == GENESIS_HASH
    assert verify_chain(db_session, AUDIT_KEY).verified == 1


def test_moi_ban_ghi_do_ung_dung_sinh_ra_deu_duoc_niem_phong(client, db_session):
    """Bất biến: không đường ghi nhật ký nào được bỏ qua seal_event.

    Đây chính là lỗi đã tạo ra con số 97/120 — demo_seed.py INSERT thẳng 23 sự
    kiện mà không niêm phong, nên 23 dòng đó có entry_hash = NULL.
    """
    client.post(
        "/api/auth/register",
        json={"username": "kiem.tra.audit", "password": "Correct Horse Battery1"},
    )
    client.post(
        "/api/auth/login",
        json={"username": "kiem.tra.audit", "password": "Correct Horse Battery1"},
    )
    client.post(
        "/api/auth/login",
        json={"username": "kiem.tra.audit", "password": "mat-khau-sai-hoan-toan"},
    )

    total, unsealed = db_session.execute(
        text(
            "SELECT COUNT(*), SUM(CASE WHEN entry_hash IS NULL THEN 1 ELSE 0 END) "
            "FROM audit_events"
        )
    ).one()
    assert total > 0, "Đăng ký/đăng nhập phải sinh ra bản ghi kiểm toán"
    assert (unsealed or 0) == 0, f"Còn {unsealed} bản ghi audit chưa được niêm phong"


# ────────────────── Lỗi 2: mã QR của 2FA ──────────────────

# Dung lượng byte-mode ở mức sửa lỗi M (ISO/IEC 18004), dùng để suy ra kích
# thước QR mà không cần cài thư viện qrcode trong test.
_CAP_M_BYTE = {1: 14, 2: 26, 3: 42, 4: 62, 5: 84, 6: 106, 7: 122, 8: 152, 9: 180}


def _qr_modules(uri: str) -> int:
    for version, capacity in sorted(_CAP_M_BYTE.items()):
        if len(uri) <= capacity:
            return 17 + 4 * version
    raise AssertionError("URI quá dài cho bảng dung lượng trong test")


def test_uri_compact_bo_cac_tham_so_mac_dinh():
    """SHA1/6/30 là mặc định của Key Uri Format nên không cần ghi ra.

    Ba tham số này thêm ~40 ký tự, đủ để đẩy QR từ version 5 lên version 9.
    """
    service = TotpService()
    uri = service.provisioning_uri("A" * 32, "learn.boss", "SCAP")
    assert "algorithm=" not in uri
    assert "digits=" not in uri
    assert "period=" not in uri
    assert uri.startswith("otpauth://totp/")
    assert "secret=" + "A" * 32 in uri
    assert "issuer=SCAP" in uri


def test_uri_van_ghi_tham_so_khi_khac_mac_dinh():
    """Bỏ tham số khác mặc định sẽ khiến ứng dụng xác thực tính sai mã."""
    service = TotpService(digits=8, period=60)
    uri = service.provisioning_uri("A" * 32, "learn.boss", "SCAP")
    assert "digits=8" in uri
    assert "period=60" in uri


def test_qr_du_thua_de_quet_duoc():
    """Mã QR phải đủ thưa để camera điện thoại đọc được từ màn hình.

    Ngưỡng thực nghiệm là khoảng 5 pixel/module. Cấu hình cũ (URI 154 ký tự,
    border=2, ảnh 342px bị co xuống 220px) chỉ đạt 3,86 px/module nên không
    quét được. Test này khoá lại cấu hình mới.
    """
    from src.app.gradio_ui import QR_DISPLAY_PX

    uri = TotpService().provisioning_uri(
        "C5UX4UFTYZRJ7H7UYRVN3WFDISWKPFKL", "learn.boss", "SCAP"
    )
    assert len(uri) <= 100, f"URI dài {len(uri)} ký tự — QR sẽ quá dày"

    border = 4  # quiet zone tối thiểu theo ISO/IEC 18004
    total_modules = _qr_modules(uri) + 2 * border
    px_per_module = QR_DISPLAY_PX / total_modules
    assert px_per_module >= 5.0, (
        f"Chỉ {px_per_module:.2f} px/module — quá dày để quét"
    )


def test_issuer_ngan_de_qr_khong_phinh():
    """Issuer xuất hiện hai lần trong URI nên tên dài làm QR dày lên đáng kể."""
    service = TotpService()
    ngan = service.provisioning_uri("A" * 32, "learn.boss", "SCAP")
    dai = service.provisioning_uri("A" * 32, "learn.boss", "Secure Chat Course")
    assert _qr_modules(ngan) < _qr_modules(dai)


# ────────────────── Lỗi 3: hết hạn phiên ──────────────────


def test_refresh_xoay_jti_va_thu_hoi_token_cu(client, auth_headers):
    """Gia hạn phải xoay token; token cũ phải chết ngay lập tức."""
    old = auth_headers["Authorization"].split()[1]

    response = client.post("/api/auth/refresh", headers=auth_headers)
    assert response.status_code == 200
    new = response.json()["access_token"]
    assert new != old, "refresh phải cấp token mới, không trả lại token cũ"

    # Token mới dùng được.
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {new}"}).status_code == 200
    # Token cũ đã bị thu hồi — đây là điểm mấu chốt: nếu token cũ vẫn sống thì
    # mỗi lần gia hạn lại nhân đôi số token hợp lệ đang lưu hành.
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {old}"}).status_code == 401


def test_refresh_can_token_hop_le(client):
    """Không có token, hoặc token rác, thì không gia hạn được."""
    assert client.post("/api/auth/refresh").status_code in (401, 403)
    assert (
        client.post(
            "/api/auth/refresh", headers={"Authorization": "Bearer khong-phai-token"}
        ).status_code
        == 401
    )


def test_refresh_bi_chan_boi_tran_tuyet_doi(client, auth_headers, db_session):
    """Sliding session không được biến một lần đăng nhập thành quyền vĩnh viễn."""
    from src.app.models import AuthSession

    session = db_session.query(AuthSession).filter(AuthSession.revoked_at.is_(None)).first()
    assert session is not None
    # Đẩy mốc đăng nhập gốc lùi quá trần 8 giờ.
    session.root_issued_at = utcnow() - timedelta(hours=9)
    db_session.commit()

    response = client.post("/api/auth/refresh", headers=auth_headers)
    assert response.status_code == 401
    assert "đăng nhập lại" in response.json()["detail"]


def test_refresh_giu_moc_phien_goc(client, auth_headers, db_session):
    """Token mới phải kế thừa root_issued_at, không được reset đồng hồ."""
    from src.app.models import AuthSession

    original = db_session.query(AuthSession).filter(AuthSession.revoked_at.is_(None)).first()
    root = original.root_issued_at or original.issued_at

    response = client.post("/api/auth/refresh", headers=auth_headers)
    assert response.status_code == 200

    db_session.expire_all()
    renewed = (
        db_session.query(AuthSession)
        .filter(AuthSession.revoked_at.is_(None))
        .order_by(AuthSession.issued_at.desc())
        .first()
    )
    assert renewed.jti != original.jti
    delta = abs((renewed.root_issued_at - root).total_seconds())
    assert delta < 1.0, "root_issued_at bị reset — trần tuyệt đối sẽ vô tác dụng"


def test_refresh_duoc_ghi_vao_nhat_ky(client, auth_headers, db_session):
    """Mọi lần gia hạn phải để lại vết trong nhật ký kiểm toán."""
    client.post("/api/auth/refresh", headers=auth_headers)
    count = db_session.execute(
        text("SELECT COUNT(*) FROM audit_events WHERE event_type = 'auth.session.refresh'")
    ).scalar()
    assert count >= 1
