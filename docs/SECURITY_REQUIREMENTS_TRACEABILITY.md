# Truy vết yêu cầu nâng cấp

Tài liệu này ánh xạ các nhóm yêu cầu trong báo cáo nâng cấp vào mã, kiểm thử và
cổng vận hành. “Có trong repository” không đồng nghĩa “đã đạt production”: các
điều kiện cần hạ tầng/tổ chức được ghi riêng để tránh tuyên bố quá mức.

| Nhóm yêu cầu | Hiện thực trong repository | Bằng chứng tự động | Điều kiện ngoài repository |
|---|---|---|---|
| Envelope encryption | `key_management.py`, `envelope.py`, per-session DEK, AAD theo message UUID/index/epoch, cache TTL/zeroize | `test_envelope_and_audit.py` | Vault/KMS policy, workload identity, HSM/KMS SLA |
| Migration/rotation | `migrate_envelope_encryption.py`, `rewrap_deks.py`; không tạo plaintext file | unit/integration crypto tests | maintenance window, backup/restore, key-destruction approval |
| Export an toàn | `StreamingResponse`, paging từng dòng, step-up, ticket 60 giây single-use gắn phiên đăng nhập; không ghi plaintext temp/token vào access log | `test_high_security_features.py` | endpoint HTTPS, browser/endpoint monitoring |
| DLP chính thức | Unicode normalization, detectors Việt Nam/secret/health/card, allow/redact/confirm/block/local-only, output scan | `test_dlp_policy.py` | từ điển thật, rule tuning, vendor DPA/data residency |
| Consent AI | timestamp + policy version, chỉ giải mã context sau consent/DLP pass, tối đa 8 message | API/provider tests | nội dung thông báo pháp lý được phê duyệt |
| Private E2EE server | device challenge, possession/approval proof, trusted-device list, prekey một lần, membership epoch, opaque envelopes, replay UNIQUE | `test_e2ee_core.py`, `test_high_security_features.py` | client Double Ratchet/MLS đã audit và interop/pentest |
| Gradio/HTTP | API JWT/RBAC, high profile OIDC proxy gate + tắt tự đăng ký, upload cap, CSP enforce + stricter report-only, headers | hardening/UI tests | OIDC IdP/proxy thật, nonce/hash CSP nếu Gradio hỗ trợ |
| Audit/WORM | HMAC chain, externally deliverable signed checkpoints, local+anchor verification, append-only DB grants | audit tests | WORM/retention-lock receiver, SOC alert/rule ownership |
| Retention | mode-specific expiry, startup sweep, xóa khi truy cập sau hạn, scheduler command, wrapped-DEK deletion | retention tests | backup/snapshot lifecycle và legal hold |
| Supply chain | frozen `uv.lock`, SHA-pinned actions, SAST/secret/dependency/image scan, CycloneDX SBOM, attestation | GitHub workflow | pin digest mọi image, protected branch, registry signature enforcement |
| Runtime hardening | fail-closed high profile, Redis, trusted hosts/CORS, Caddy TLS, read-only/cap-drop/resource limits, DB least privilege | config/security tests | TLS/mTLS nội bộ, orchestrator policies, load/chaos tests |
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
