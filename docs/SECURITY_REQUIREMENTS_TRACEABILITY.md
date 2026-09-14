# Truy vết yêu cầu nâng cấp

Tài liệu này ánh xạ các nhóm yêu cầu trong báo cáo nâng cấp vào mã, kiểm thử và
cổng vận hành. “Có trong repository” không đồng nghĩa “đã đạt production”: các
điều kiện cần hạ tầng/tổ chức được ghi riêng để tránh tuyên bố quá mức.

| Nhóm yêu cầu | Hiện thực trong repository | Bằng chứng tự động | Điều kiện ngoài repository |
|---|---|---|---|
| Envelope encryption | `key_management.py`, `envelope.py`, per-session DEK, AAD theo message UUID/index/epoch, cache TTL/zeroize | `test_envelope_and_audit.py` | Vault/KMS policy, workload identity, HSM/KMS SLA |
| Migration/rotation | `migrate_envelope_encryption.py`, `rewrap_deks.py`; không tạo plaintext file | unit/integration crypto tests | maintenance window, backup/restore, key-destruction approval |
| Export an toàn | `StreamingResponse`, paging từng dòng, step-up, ticket 60 giây single-use gắn phiên đăng nhập; không ghi plaintext temp/token vào access log | `test_high_security_features.py` | endpoint HTTPS, browser/endpoint monitoring |
| Xác thực/phiên | Argon2id, lockout/rate limit, MFA chống replay, JWT có server-side session; token rotation giữ `session_family_id`, nên logout/thu hồi thiết bị bắt cả successor sinh đồng thời; thao tác phá hủy phiên cần recent step-up | auth/MFA/step-up và deterministic concurrency tests | IdP/OIDC gateway, chính sách vòng đời tài khoản và giám sát đăng nhập thực tế |
| DLP chính thức | Unicode normalization, detectors Việt Nam/secret/health/card, allow/redact/confirm/block/local-only, output scan | `test_dlp_policy.py` | từ điển thật, rule tuning, vendor DPA/data residency |
| Consent AI | timestamp + policy version, chỉ giải mã context sau consent/DLP pass, tối đa 8 message; high profile chỉ nhận provider credential từ file và reference overlay mặc định tắt cloud AI | API/provider/config tests | nội dung thông báo pháp lý, paid/ZDR/DPA/data-residency được phê duyệt |
| Private E2EE server | device challenge, possession/approval proof, trusted-device list, prekey một lần, membership epoch, opaque envelopes, replay UNIQUE; đình chỉ/xóa thành viên thu hồi membership và tăng epoch nguyên tử | `test_e2ee_core.py`, `test_high_security_features.py`, `test_security_lifecycle.py` | client Double Ratchet/MLS đã audit và interop/pentest |
| Gradio/HTTP | API JWT/RBAC, high profile OIDC proxy gate + tắt tự đăng ký, upload cap, chặn đường dẫn hệ thống/secret, tắt error/monitoring/analytics, CSP enforce + stricter report-only có endpoint metadata-only | hardening/UI tests | OIDC IdP/proxy thật, nonce/hash CSP nếu Gradio hỗ trợ |
| Audit/WORM | HMAC chain, externally deliverable signed/idempotent checkpoints, đo chính xác tail chưa neo/freshness; high profile thử neo từng sự kiện, startup/readiness fail-closed và không tuyên bố high-assurance khi còn tail, append-only DB grants | audit/checkpoint freshness + readiness tests | WORM/retention-lock receiver, routing loại instance 503, SOC alert/rule ownership; không có distributed transaction giữa nghiệp vụ và WORM |
| Retention | mode-specific expiry, policy edit không được gia hạn, backfill deadline legacy từ thời điểm tạo, startup/on-access sweep fail-closed, xóa wrapped DEK và metadata phiên đăng nhập hết hạn | `test_envelope_and_audit.py` | backup/snapshot lifecycle và legal hold |
| Supply chain | frozen `uv.lock`, SHA-pinned actions, SAST/secret/dependency/image scan, CycloneDX SBOM, attestation | GitHub workflow | pin digest mọi image, protected branch, registry signature enforcement |
| Runtime hardening | fail-closed high profile, TLS xác minh CA cho PostgreSQL/Redis/Vault, trusted hosts/CORS, Caddy TLS, read-only/cap-drop/resource limits, DB least privilege, DLP scrub cho metadata audit/SIEM không biết trước | config/security tests + container integration | mTLS nội bộ nếu threat model yêu cầu, orchestrator policies, load/chaos tests |
| Atomic security lifecycle | lock account→session nhất quán; mọi thao tác gửi/đổi mode/MFA/member re-check policy sau lock; xóa tài khoản dọn session và DEK cache | `test_security_lifecycle.py` với ba race test xác định | PostgreSQL load/chaos test trên topology production |
| Privacy/DPIA | data inventory, purpose/minimization, mode-specific retention, rights workflow, processor/transfer và DPIA release gate trong `PRIVACY_DATA_INVENTORY.md` | consent/retention/export tests | controller/legal-basis, DPA/BAA, supplier facts, owner approval và data-subject SLA |
| IR/DR/governance | runbook high-security, key/DLP/device/audit procedures | tài liệu review | tabletop, restore drill, pentest/Red Team, owner/SLA |

## Trạng thái tuyên bố

- Có thể trình diễn và kiểm thử ngay: secure/confidential server-side, envelope
  encryption local test provider, DLP, step-up/export streaming, E2EE server
  boundary, audit checkpoint local, retention và CI definitions.
- Chỉ đạt high-security sau cấu hình ngoài: KMS/Vault thật, OIDC gateway, WORM
  sink, PostgreSQL/Redis/TLS, digest đã xác minh và bằng chứng vận hành.
- Chỉ được tuyên bố E2EE hoàn chỉnh sau khi một client thật dùng thư viện Double
  Ratchet/MLS đã audit vượt qua test vectors/interoperability và pentest. Không
  có private-key/ratchet implementation tùy biến trong server là chủ đích an
  toàn, không phải phần bị bỏ quên.
