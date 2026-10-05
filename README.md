# 🛡️ Secure Conversational Application Platform (SCAP)

**Demo đồ án trên máy cá nhân:** sau khi đã cài thư viện, chạy
`.\.venv\Scripts\python.exe -m scripts.demo_local` rồi mở <http://127.0.0.1:8000>.
Lượt demo có SQLite và khóa tạm riêng, tự nạp tài khoản mẫu và dùng AI ngoại tuyến;
không cần máy chủ, Docker, API key hoặc sửa `.env`. Xem
[hướng dẫn chạy](HUONG_DAN_CHAY.md) và [kịch bản 6/12 phút](docs/DEMO_SCRIPT.md).

**Thực hành ANM theo hai tài liệu Word:** tab **Thực hành ANM** dành cho
moderator/admin có 11 bài mạng, hệ điều hành, bảo mật ứng dụng và xử lý sự cố.
Chạy `.\.venv\Scripts\python.exe -m scripts.practice_lab` để xuất báo cáo kiểm
chứng theo 5 giai đoạn cùng PCAP DNS/TCP/HTTP tổng hợp cho Wireshark. Hồ sơ
sự cố gắn với audit thực có lịch sử điều tra và kết luận. Xem
[hướng dẫn thực hành và phạm vi đã kiểm chứng](docs/PRACTICAL_ANM.md).

Đợt phát triển theo báo cáo Vũ Văn Mạnh bổ sung kiểm soát body/URI thực nhận,
IDS xử lý mã hoá nhiều lớp, bằng chứng từ chối xác thực/phân quyền, bộ kiểm chứng
bảo mật API/audit/IDS và tác vụ bảo mật định kỳ. Xem
[hướng dẫn bảo mật và tự động hoá](docs/SECURITY_AUTOMATION.md) để chạy kiểm chứng,
bật lịch kiểm tra và đối chiếu từng thay đổi với nội dung PDF.

Đợt nâng cấp tiếp theo bổ sung thời hạn không hoạt động của phiên, DLP kiểm tra
mã hóa nhiều lớp, tương quan đăng nhập phân tán và chặn yêu cầu trình duyệt từ
nguồn không tin cậy. Xem [nguồn tham khảo và cách vận hành](docs/ADVANCED_SECURITY.md).

Đợt bảo vệ tài khoản sửa lỗi mọi người dùng giao diện chung một IP loopback (một người
đăng nhập sai có thể làm cả hệ thống nhận 429, một tìm kiếm độc hại làm IDS chặn tất cả),
không xóa bộ đếm theo IP khi đăng nhập thành công, và bổ sung smart lockout, cảnh báo
thiết bị mới, trang hoạt động bảo mật cho người dùng. Đợt sau đó bổ sung **passkey
(WebAuthn)** đăng nhập không mật khẩu, **khôi phục mật khẩu qua email** đã xác minh,
**phát hiện dùng lại token đã xoay** (RFC 9700) và **cookie nhận diện thiết bị** (OWASP).
Xem [bảo vệ tài khoản](docs/ACCOUNT_PROTECTION.md).

Đợt đối chiếu với `secret-weather-vault.zip` bổ sung ràng buộc mã khôi phục với
mật khẩu/email hiện tại, bảo vệ giao dịch đăng nhập/đổi mật khẩu khi reset đồng
thời, kiểm tra passkey sai định dạng, JSON/header chặt chẽ, cache khóa gắn metadata
và phản hồi lỗi không kèm dữ liệu nhạy cảm cho cả REST API lẫn Gradio. Xem
[kết quả đối chiếu, thay đổi và giới hạn vận hành](SECURITY_REVIEW.md#5-đối-chiếu-với-secret-weather-vaultzip--04102026).

> **Đồ án môn học:** Bảo mật Ứng dụng và Hệ thống
> **Kiến trúc:** FastAPI + Gradio 6 + envelope encryption (Vault/KMS) + DLP phân loại + E2EE ciphertext relay + audit anchor/WORM + IDS/IPS

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.140%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Gradio](https://img.shields.io/badge/Gradio-6.x-orange.svg)](https://gradio.app/)
[![Security](https://img.shields.io/badge/Security-Argon2id%20%7C%20AES--256--GCM%20%7C%20TOTP%20%7C%20HMAC--Chain-brightgreen.svg)]()
[![CI](https://img.shields.io/badge/CI-pytest%20%7C%20ruff%20%7C%20bandit%20%7C%20pip--audit%20%7C%20gitleaks%20%7C%20semgrep%20%7C%20trivy-informational.svg)](.github/workflows/security.yml)

---

## 📋 Mục lục

1. [Tổng quan dự án](#1-tổng-quan-dự-án)
2. [Bản đồ mã nguồn](#2-bản-đồ-mã-nguồn)
3. [Kiến trúc & luồng xử lý](#3-kiến-trúc--luồng-xử-lý)
4. [Các lớp bảo vệ (đối chiếu với mã nguồn)](#4-các-lớp-bảo-vệ-đối-chiếu-với-mã-nguồn)
5. [Giao diện Gradio](#5-giao-diện-gradio)
6. [Danh mục REST API](#6-danh-mục-rest-api)
7. [Chạy nhanh trên máy cá nhân](#7-chạy-nhanh-trên-máy-cá-nhân)
8. [Tài khoản demo & dữ liệu mẫu](#8-tài-khoản-demo--dữ-liệu-mẫu)
9. [Chạy bằng Docker](#9-chạy-bằng-docker)
10. [Kiểm thử, CI/CD & đánh giá an ninh](#10-kiểm-thử-cicd--đánh-giá-an-ninh)
11. [Vận hành: xoay khóa, migration, phục hồi audit](#11-vận-hành-xoay-khóa-migration-phục-hồi-audit)
12. [Cấu hình qua biến môi trường](#12-cấu-hình-qua-biến-môi-trường)
13. [Cấu trúc thư mục](#13-cấu-trúc-thư-mục)
14. [Giới hạn có chủ đích](#14-giới-hạn-có-chủ-đích)

---

## 1. Tổng quan dự án

**SCAP** là nền tảng trò chuyện AI đa người dùng, viết để minh họa một chuỗi kiểm soát
an ninh đầy đủ chứ không chỉ một tính năng đơn lẻ: xác thực mạnh (Argon2id + TOTP),
phân quyền RBAC kèm kiểm tra quyền sở hữu, mã hóa nội dung khi lưu trữ (AES-256-GCM
có AAD), DLP trước khi gửi dữ liệu ra nhà cung cấp AI bên ngoài, IDS/IPS tầng ứng dụng,
và nhật ký kiểm toán chống giả mạo bằng chuỗi băm HMAC.

Bản nâng cấp bổ sung ba trust boundary (`secure`, `confidential`,
`private_e2ee`), DEK riêng cho từng hội thoại được Vault/KMS bọc, AAD ràng buộc
từng message, export streaming không tạo tệp plaintext tạm, consent AI phiên bản
hóa, DLP chính thức, device/prekey/replay control cho E2EE, retention và audit
checkpoint ngoài hệ thống, cùng TLS xác minh CA cho kết nối nội bộ ở high profile. Xem [hướng dẫn triển khai bảo mật cao](docs/HIGH_SECURITY_DEPLOYMENT.md),
[hợp đồng E2EE client](docs/E2EE_CLIENT_CONTRACT.md),
[data inventory/DPIA baseline](docs/PRIVACY_DATA_INVENTORY.md) và
[bảng truy vết yêu cầu](docs/SECURITY_REQUIREMENTS_TRACEABILITY.md).

> `SECURITY_PROFILE=high` là guard fail-closed, không phải nhãn chứng nhận. E2EE
> hoàn chỉnh còn cần client dùng thư viện Double Ratchet/RFC 9420 MLS đã kiểm
> toán; repository này chủ đích chỉ cung cấp server ciphertext boundary.

Toàn bộ ứng dụng là **một tiến trình FastAPI duy nhất** ([src/app/main.py](src/app/main.py)).
Giao diện Gradio được `mount` vào chính ứng dụng đó tại `/`, và bản thân UI **gọi ngược lại
REST API qua HTTP** ([src/app/gradio_ui.py](src/app/gradio_ui.py)) — nghĩa là mọi thao tác
trên giao diện đều đi qua đúng lớp JWT, RBAC, rate limit và audit như một client bên ngoài.
Không có đường tắt nào từ UI xuống thẳng cơ sở dữ liệu.

Launcher `scripts.demo_local` chạy **SQLite + rate limiter in-memory + AI demo ngoại tuyến**
trong môi trường tạm sau khi đã cài thư viện. Cách chạy thông thường qua `run_app.py` đọc
cấu hình riêng; guard production (`APP_ENV=production`) yêu cầu hạ tầng và bí mật tương ứng.

---

## 2. Bản đồ mã nguồn

| File | Trách nhiệm |
| :--- | :--- |
| [src/app/main.py](src/app/main.py) | Tạo app, middleware bảo mật (security headers/CSP/IDS), toàn bộ route REST, mount Gradio |
| [src/app/config.py](src/app/config.py) | `Settings` đọc từ biến môi trường + **guard production** (từ chối khởi động nếu cấu hình yếu) |
| [src/app/security.py](src/app/security.py) | `PasswordService` (Argon2id), `TokenService` (JWT), `CryptoService` (AES-256-GCM + key ring), `TotpService` (TOTP tự cài đặt), `PwnedPasswordChecker`, hai bản rate limiter |
| [src/app/key_management.py](src/app/key_management.py) | Adapter Local/Vault Transit/AWS KMS/GCP KMS để sinh, unwrap và rewrap DEK |
| [src/app/envelope.py](src/app/envelope.py) | DEK riêng từng hội thoại/tài khoản, AAD canonical theo message, cache DEK ngắn hạn |
| [src/app/e2ee.py](src/app/e2ee.py) | Xác minh Ed25519, canonical JSON, fingerprint và validation opaque envelope; không giữ khóa riêng |
| [src/app/dlp.py](src/app/dlp.py) | Detector + policy allow/redact/confirm/block/local-only độc lập với provider |
| [src/app/services.py](src/app/services.py) | Tích hợp DLP, consent/context minimization, AIService và ChatService |
| [src/app/ids.py](src/app/ids.py) | IDS/IPS: engine `signature` (SQLi/XSS/traversal/scanner UA) + engine `anomaly` (dò trên chính audit log), trạng thái chặn nguồn |
| [src/app/audit.py](src/app/audit.py) | Ghi sự kiện audit, xác định IP nguồn (kể cả IP trình duyệt do UI ký HMAC) |
| [src/app/account_security.py](src/app/account_security.py) | Smart lockout, cookie nhận diện thiết bị, cảnh báo thiết bị mới, nhật ký hoạt động bảo mật |
| [src/app/passkeys.py](src/app/passkeys.py) | Passkey/WebAuthn: challenge một lần, UV bắt buộc, kiểm tra origin/RP ID, phát hiện nhân bản |
| [src/app/account_recovery.py](src/app/account_recovery.py) | Mã khôi phục qua email (HMAC, giới hạn lần thử) và mẫu email cảnh báo bảo mật |
| [src/app/account_routes.py](src/app/account_routes.py) | Endpoint email khôi phục, quên mật khẩu và passkey |
| [src/app/mailer.py](src/app/mailer.py) | Gửi email nền qua SMTP (TLS bắt buộc) hoặc outbox `.eml` cho demo |
| [src/app/audit_chain.py](src/app/audit_chain.py) | Chuỗi băm chống giả mạo: `entry_hash = HMAC-SHA256(key, prev_hash ‖ canonical(entry))` |
| [src/app/audit_checkpoint.py](src/app/audit_checkpoint.py) | Ký mốc cuối chuỗi và giao qua HTTPS tới WORM/SIEM ngoài máy chủ |
| [src/app/retention.py](src/app/retention.py) | Retention theo mode, không gia hạn ngầm, xóa wrapped DEK và metadata phiên hết hạn |
| [src/app/siem.py](src/app/siem.py) | Xuất sự kiện an ninh ra stdout dạng JSON một dòng (ECS-like) cho SIEM |
| [src/app/models.py](src/app/models.py) | ORM tài khoản, hội thoại, audit, `SecurityIncident`, `IncidentEvidence` và `IncidentTransition` |
| [src/app/schemas.py](src/app/schemas.py) | Pydantic request/response, ràng buộc đầu vào |
| [src/app/db.py](src/app/db.py) | Engine/session SQLAlchemy, `create_all`, `assert_schema_ready` |
| [src/app/gradio_ui.py](src/app/gradio_ui.py) | Toàn bộ giao diện (theme, CSS, 8 tab) — chỉ nói chuyện với API qua `httpx` |
| [src/app/demo_seed.py](src/app/demo_seed.py) | Sinh tài khoản/hội thoại mẫu (idempotent) |
| [src/core/ai_core/gemini_ai.py](src/core/ai_core/gemini_ai.py) | Wrapper mỏng quanh SDK `google-genai` |

> **Lưu ý khi đọc báo cáo:** DLP nằm ở `services.py`, IDS nằm ở `ids.py` — `security.py`
> chỉ chứa các primitive mật mã/xác thực. Ba thứ này cố ý tách rời nhau.

---

## 3. Kiến trúc & luồng xử lý

```text
┌──────────────────────────────────────────────────────────────────┐
│  Trình duyệt  →  Gradio SPA (mount tại "/", src/app/gradio_ui)   │
│  UI gọi REST API qua httpx: không có lối đi tắt xuống CSDL       │
└─────────────────────────────┬────────────────────────────────────┘
                              │ HTTPS (Caddy, chỉ ở production)
┌─────────────────────────────▼────────────────────────────────────┐
│  MIDDLEWARE — src/app/main.py                                    │
│   • TrustedHost (chống Host header injection / DNS rebinding)    │
│   • CORS (allowlist, allow_credentials=False)                    │
│   • Giới hạn body 1 MiB, chuẩn hóa X-Request-ID                  │
│   • IDS/IPS: quét URL + header, chặn nguồn khi vượt ngưỡng       │
│   • Security headers + CSP theo từng nhóm đường dẫn              │
└─────────────────────────────┬────────────────────────────────────┘
┌─────────────────────────────▼────────────────────────────────────┐
│  XÁC THỰC & PHÂN QUYỀN                                           │
│   • Argon2id (t=3, m=64 MiB, p=4) + hash giả chống enumeration   │
│   • TOTP RFC 6238 hai bước + recovery code dùng một lần          │
│   • JWT HS256 (iss/aud/jti/ver) + AuthSession phía server        │
│   • RBAC user/moderator/admin + kiểm tra quyền sở hữu từng phiên │
└─────────────────────────────┬────────────────────────────────────┘
┌─────────────────────────────▼────────────────────────────────────┐
│  DLP — src/app/services.py                                       │
│   Phân loại và áp dụng chính sách che/xác nhận/chặn gửi;         │
│   secret, private key và số thẻ không được gửi sang AI ngoài    │
└─────────────────────────────┬────────────────────────────────────┘
┌─────────────────────────────▼────────────────────────────────────┐
│  LƯU TRỮ & KIỂM TOÁN                                             │
│   • DEK AES-256-GCM riêng/session, bọc bởi Vault/KMS             │
│   • AAD = owner/session/message UUID/index/role/crypto epoch     │
│   • Private E2EE: chỉ public key/prekey/opaque ciphertext        │
│   • audit HMAC chain + checkpoint HTTPS tới WORM/SIEM            │
└──────────────────────────────────────────────────────────────────┘
```

### Luồng một tin nhắn

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng (Gradio)
    participant API as FastAPI
    participant IDS as IDS/IPS + Rate limiter
    participant DLP as DLP (services.py)
    participant AI as Gemini / Demo AI
    participant DB as CSDL (SQLite/Postgres)
    participant AUD as Audit chain (HMAC)

    U->>API: POST /api/auth/login (username + password)
    API->>DB: Argon2id verify, kiểm tra khóa tài khoản
    alt Tài khoản bật 2FA
        API-->>U: mfa_token ngắn hạn (aud=secure-chat-mfa)
        U->>API: POST /api/auth/mfa/verify (TOTP hoặc recovery code)
    end
    API->>DB: Tạo AuthSession (jti, root_issued_at)
    API->>AUD: auth.login / auth.mfa.verify
    API-->>U: access_token (JWT HS256, mặc định 30 phút)

    U->>API: POST /api/sessions/{id}/messages
    API->>IDS: Quét chữ ký + rate limit theo user
    API->>DB: Kiểm tra quyền sở hữu phiên (sai → 404, không phải 403)
    API->>DLP: Kiểm tra prompt và chính sách theo mode/classification
    alt Nhánh AI ngoài thiếu consent hoặc policy chặn
        API-->>U: Từ chối; không gọi provider, không lưu tin nhắn
    else Được xử lý
        alt AI ngoại tuyến
            DLP->>AI: Bản xem trước đã che (không ra Internet)
        else AI bên ngoài được consent và policy cho phép
            DLP->>AI: Prompt và ngữ cảnh được phép, đã che dữ liệu
        end
        AI-->>API: Phản hồi (503 + Retry-After nếu provider lỗi)
        API->>DLP: Kiểm tra phản hồi provider trước khi lưu/hiển thị
        API->>DB: Mã hóa AES-256-GCM cả câu hỏi lẫn câu trả lời
        API->>AUD: chat.message.send (+ dlp.redacted nếu có che)
        API-->>U: Nội dung trả lời + danh mục dữ liệu đã che
    end
```

---

## 4. Các lớp bảo vệ (đối chiếu với mã nguồn)

### 4.1 Xác thực & quản lý phiên
- **Argon2id** `time_cost=3, memory_cost=64 MiB, parallelism=4`; đăng nhập với username không
  tồn tại vẫn verify một hash giả để giảm rò rỉ qua thời gian phản hồi.
- **Khóa tài khoản**: quá `LOGIN_MAX_ATTEMPTS` lần sai → khóa `LOGIN_LOCKOUT_SECONDS`.
- **Rate limit hai chiều**: theo *tài khoản* và theo *IP* — chặn cả brute force lẫn password spraying.
  Đăng nhập thành công chỉ hoàn lại suất của chính nó trên bucket IP, không xóa các lần sai trước đó.
- **Smart lockout**: khóa do nhiều lần sai chỉ áp dụng với nguồn lạ; địa chỉ đã từng đăng nhập
  thành công có bucket riêng nên người lạ không thể khóa chủ tài khoản khỏi mạng quen.
- **IP/UA thật của trình duyệt sau UI**: UI ký `HMAC-SHA256` lên IP và User-Agent của trình duyệt;
  API chỉ tin khi chữ ký đúng và còn hạn 60 giây, nên rate limit, IDS và audit tách biệt từng người dùng.
- **Passkey (WebAuthn/FIDO2)**: đăng nhập không mật khẩu, chống phishing vì chữ ký gắn với origin;
  bắt buộc xác minh người dùng (PIN/sinh trắc), challenge dùng một lần, phát hiện authenticator nhân bản
  qua bộ đếm. Chỉ lưu public key. Trình duyệt yêu cầu tên miền: demo mở bằng `http://localhost:8000`.
- **Khôi phục mật khẩu qua email đã xác minh**: mã 10 ký tự, 15 phút, tối đa 5 lần nhập, chỉ lưu HMAC;
  phản hồi giống hệt nhau dù tài khoản có tồn tại hay không. Đặt lại mật khẩu thu hồi mọi phiên nhưng
  **không** tắt 2FA. Đổi email khôi phục cần xác thực lại và báo về địa chỉ cũ.
- **Phát hiện dùng lại token đã xoay** (RFC 9700 §4.14.2): token cũ quay lại sau 30 giây ân hạn ⇒ thu hồi
  cả họ phiên của thiết bị đó, cảnh báo `auth.session.token_reuse` (T1550.001). UI tự dùng token mới nhất
  nên tab cũ không bị nhận nhầm là kẻ trộm.
- **Cookie nhận diện thiết bị** (OWASP device cookie): token HMAC gắn với tài khoản, HttpOnly, SameSite=Strict.
  Khi tài khoản đã dùng cơ chế này, client không có token là thiết bị mới dù User-Agent giống hệt.
- **Email cảnh báo bảo mật**: thiết bị mới, đổi/đặt lại mật khẩu, tắt 2FA, đổi email, thêm/xóa passkey,
  token bị dùng lại. Gửi nền (SMTP + TLS bắt buộc) để thời gian phản hồi không lộ thông tin.
- **Cảnh báo thiết bị mới & hoạt động bảo mật**: đăng nhập từ trình duyệt/hệ điều hành chưa từng thấy
  sinh `auth.login.new_device`; người dùng xem lần đăng nhập trước, số lần thất bại, số lần đúng mật khẩu
  nhưng sai 2FA và thao tác của quản trị viên trên tài khoản mình.
- **TOTP (RFC 6238)** cài đặt trực tiếp bằng thư viện chuẩn để báo cáo giải thích được HOTP/TOTP;
  lưu `mfa_last_counter` để một mã đã dùng không thể replay trong cùng bước thời gian.
- **Recovery code** chỉ lưu hash Argon2id, dùng một lần.
- **JWT HS256** có `iss`/`aud`/`jti`/`ver`; mỗi token gắn một bản ghi `AuthSession` phía server.
  Token được xoay vẫn giữ `session_family_id`, nên thao tác thu hồi thiết bị bắt được cả token kế
  nhiệm vừa sinh đồng thời mà không đăng xuất các thiết bị khác; `logout-all` thu hồi toàn tài khoản.
- **Trần phiên tuyệt đối**: `root_issued_at` được mang qua mỗi lần `/api/auth/refresh`, vượt
  `SESSION_ABSOLUTE_HOURS` (mặc định 8h) thì buộc đăng nhập lại — sliding session không thành vĩnh viễn.
- **Hết hạn khi không hoạt động**: `last_activity_at` được kiểm tra ở server cho mọi bearer request;
  `SESSION_IDLE_MINUTES` (mặc định 30 phút) không bị kéo dài bằng polling `/me` hoặc refresh nền.
  API quản lý phiên trả cả thời điểm hoạt động cuối và hai deadline để người dùng thu hồi thiết bị đúng lúc.
- **Mật khẩu** tối thiểu 15 ký tự (NIST 800-63B ưu tiên độ dài); tùy chọn đối chiếu HIBP bằng
  k-anonymity. Standard profile có thể fail-open khi HIBP mất mạng; high profile bắt buộc fail-closed.

### 4.2 Mã hóa dữ liệu khi lưu trữ
- Mọi tin nhắn lưu dưới dạng **AES-256-GCM**, nonce 96-bit ngẫu nhiên cho từng bản ghi.
- Mỗi session có **DEK 256-bit riêng**; CSDL chỉ giữ wrapped DEK + KEK URI/version.
  High profile bắt buộc Vault/managed KMS và từ chối master key trong web runtime.
- **AAD canonical** ràng buộc owner, session, message UUID, message index, role và crypto epoch;
  hoán đổi hai ciphertext cùng role trong cùng session cũng thất bại xác thực.
- Bí mật TOTP dùng DEK riêng theo user và AAD namespace riêng nên không thể hoán đổi với message.
- Xoay KEK dùng rewrap không giải mã lại nội dung; script migration chuyển dòng legacy từng dòng
  trong RAM và không tạo plaintext file.

### 4.3 DLP trước khi ra khỏi biên tin cậy
Áp dụng ở [src/app/dlp.py](src/app/dlp.py) và [src/app/services.py](src/app/services.py) cho **cả prompt lẫn phản hồi**, và trả về
*tên danh mục* đã che (không bao giờ trả lại giá trị gốc) để UI và audit log hiển thị an toàn.
Scanner cũng giải mã có giới hạn URL-percent, HTML entity và Base64 nhiều lớp chỉ trong vùng kiểm tra;
mọi span được ánh xạ về chuỗi gốc để che cả dạng mã hóa. Vượt ngân sách kiểm tra chuyển sang
`inspection_limit` (highly confidential) và fail-closed thay vì âm thầm cho dữ liệu đi qua.
Ngoài ra dữ liệu người dùng được bọc trong JSON `UNTRUSTED_USER_DATA_JSON` kèm system instruction
để giảm rủi ro prompt injection. Việc gọi AI ngoài **chỉ xảy ra khi người dùng bật đồng ý**
(`PATCH /api/auth/ai-consent`); consent có timestamp/policy version và context chỉ lấy tối đa tám
message sau thời điểm consent. Policy hỗ trợ allow/redact/confirm/block/local-only; Private E2EE
không bao giờ gọi AI phía server.

### 4.4 IDS/IPS tầng ứng dụng
- Engine **signature**: 10 nhóm luật (SQLi, XSS, path traversal, command injection, SSTI,
  Log4Shell, NoSQL injection), nhận diện User-Agent công cụ quét và các đường dẫn "mồi".
- Engine **anomaly**: soi chính bảng `audit_events` để phát hiện credential stuffing, brute force
  một tài khoản, password guessing phân tán qua nhiều IP, chuỗi thất bại rồi đăng nhập thành công,
  và chuỗi từ chối quyền liên tiếp (dấu hiệu dò IDOR). Tương quan chạy trong SQL, chỉ giữ ID bằng chứng,
  số nguồn và nhãn ATT&CK; tác vụ định kỳ phát cảnh báo quan sát, không tự khóa người dùng.
- Điểm rủi ro tích lũy (high=3 / medium=2 / low=1); vượt `IDS_BLOCK_THRESHOLD` thì **chặn nguồn**
  `IDS_BLOCK_SECONDS` và trả 403 kèm `Retry-After`.
- IDS quét URL/header; lớp giới hạn yêu cầu riêng chỉ giữ tối đa 1 MiB body trong
  RAM trước khi phân tích. Phản hồi streaming không bị buffer.
- Yêu cầu trình duyệt thay đổi trạng thái phải vượt qua kiểm tra `Origin` và
  `Sec-Fetch-Site`, kể cả các route Gradio; nguồn chéo phải có trong `ALLOWED_ORIGINS`.

### 4.5 Audit chống giả mạo & SIEM
- `entry_hash = HMAC-SHA256(audit_key, prev_hash ‖ canonical(entry))`, `audit_key` dẫn xuất từ
  `APP_SECRET_KEY` với nhãn riêng (tách khóa khỏi khóa ký JWT) và **không nằm trong CSDL**.
- Sửa/xóa một dòng làm gãy toàn bộ chuỗi phía sau; kiểm chứng bằng `GET /api/admin/audit/verify`
  hoặc nút *Xác minh chuỗi* trên tab Bảo mật.
- Song song, mỗi sự kiện được in ra stdout dạng JSON một dòng cho Loki/ELK/Splunk/Wazuh.
- Checkpoint ký `last_event_id + root_hash` được đẩy qua HTTPS tới WORM. Đây là mốc ngoài máy
  chủ để phát hiện cả việc xóa phần đuôi; API verify đo cả số sự kiện chưa neo/freshness và chỉ
  trả `high_assurance_intact=true` khi checkpoint đáp ứng đầy đủ ngưỡng của hồ sơ triển khai.

### 4.6 Kiểm chứng Purple Team an toàn (MITRE ATT&CK)
- Mỗi phát hiện chữ ký ứng dụng đều gắn `mitre_technique: T1190` khi phù hợp, nên bản ghi
  audit và JSON SIEM có thể được lọc/đối soát theo kỹ thuật ATT&CK.
- Admin có thể gọi `POST /api/admin/ids/verify-detection` hoặc nút *Chạy kiểm chứng Hit/Miss*
  tại tab **Bảo mật**. Bộ kiểm chứng chạy hoàn toàn trong tiến trình (không có HTTP, shell,
  database mutation ngoài audit result), đo Hit/Miss cho SQLi, XSS, path traversal và command
  injection, rồi ghi tỉ lệ phát hiện vào audit/SIEM.
- Kết quả chỉ xác nhận engine chữ ký T1190, không phải kết luận "an toàn tuyệt đối" và không
  thay thế pentest, telemetry hệ điều hành, hay xác minh pipeline ELK/Wazuh bên ngoài.

### 4.7 Cứng hóa tầng HTTP
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Permissions-Policy`, `Cache-Control: no-store`, HSTS ở production, và **CSP tách theo nhóm đường dẫn**:
`/api/*` dùng `default-src 'none'`; `/docs`, `/redoc` nới đúng phần Swagger cần; UI Gradio bỏ
`'unsafe-eval'` theo mặc định (bật lại có chủ đích bằng `CSP_ALLOW_UNSAFE_EVAL`).
UI dùng nonce mới cho mỗi phản hồi và chỉ cấp cho bootstrap đã xác minh của Gradio;
`script-src` không còn `unsafe-inline`, thuộc tính chạy JavaScript bị chặn. CSS inline
vẫn được cho phép để giao diện hoạt động. Host local mặc định chỉ nhận loopback;
header đổi origin của thư viện và chức năng deep-link lưu trạng thái đã bị vô hiệu hóa.

Email có hàng đợi hữu hạn và outbox có trần tệp/dung lượng. Công cụ
`python -m scripts.secure_backup` sao lưu SQLite mã hóa và phục hồi vào **tệp mới**,
thu hồi phiên/mã một lần và khóa tài khoản mặc định. Xem quy trình và giới hạn trong
[hướng dẫn vận hành](docs/security/availability.md#sao-lưu-sqlite-mã-hóa-và-phục-hồi-offline).

---

## 5. Giao diện Gradio

Theme `gr.themes.Soft` — emerald/slate, font `Be Vietnam Pro`, font mono `IBM Plex Mono` cho
dữ liệu mật mã, cột nội dung giới hạn 1400px, có token màu riêng cho dark mode.

| Tab | Nội dung | Quyền |
| :--- | :--- | :--- |
| **Trò chuyện** | Danh sách phiên (tạo/đổi tên/xóa/xuất JSON), khung chat có avatar, cảnh báo DLP | mọi vai trò |
| **Dữ liệu mã hóa** | Soi bản mã AES-256-GCM thật của từng tin nhắn (ciphertext, nonce, key version) | mọi vai trò |
| **Tìm kiếm** | Tìm toàn cục trên các phiên *thuộc sở hữu người gọi* (giải mã phía server) | mọi vai trò |
| **Tài khoản** | Đổi mật khẩu kèm thanh đo độ mạnh, bật/tắt 2FA (QR + recovery code), đồng ý gửi dữ liệu cho AI, quản lý & thu hồi thiết bị, hoạt động bảo mật gần đây | mọi vai trò |
| **Quản trị** | Thống kê hệ thống, tạo/xóa người dùng, đổi vai trò, khóa/mở khóa tài khoản | admin |
| **Nhật ký kiểm toán** | Bảng `audit_events` gần nhất | moderator, admin |
| **Bảo mật** | Phát hiện IDS & bất thường; **admin thêm**: xác minh chuỗi audit, danh sách chặn (gỡ chặn được) | moderator (một phần), admin |

Tab *Bảo mật* nạp bốn khối độc lập, mỗi khối bọc lỗi riêng, nên moderator thiếu quyền ở một khối
vẫn xem được ba khối còn lại thay vì trắng cả màn hình.

Thanh trên cùng hiển thị username, vai trò, `jti` của phiên và **đồng hồ đếm ngược hạn token**.
Trang đăng nhập là luồng hai bước: mật khẩu → mã TOTP (hoặc recovery code).

> Giao diện tránh dùng `gr.HTML` một cách có chủ đích: Gradio 6 biên dịch markup của component
> đó bằng `new Function()`, thứ mà CSP không có `'unsafe-eval'` sẽ chặn.

---

## 6. Danh mục REST API

Tài liệu tương tác: `/docs` và `/redoc` (tự tắt khi `APP_ENV=production`).

### Xác thực
| Method | Đường dẫn | Ghi chú |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Rate limit theo IP; mật khẩu ≥ `PASSWORD_MIN_LENGTH` |
| `POST` | `/api/auth/login` | Trả `access_token`, **hoặc** `mfa_token` nếu tài khoản bật 2FA |
| `POST` | `/api/auth/mfa/verify` | Bước hai: mã TOTP hoặc recovery code |
| `POST` | `/api/auth/mfa/enroll` · `/activate` · `/disable` | Ghi danh (QR + secret), kích hoạt, tắt 2FA |
| `POST` | `/api/auth/step-up` | Xác minh lại password + MFA trước export/device/key operation |
| `GET` | `/api/auth/me` | Hồ sơ người gọi |
| `PATCH` | `/api/auth/ai-consent` | Bật/tắt đồng ý gửi nội dung cho AI bên ngoài |
| `PATCH` | `/api/auth/password` | Đổi mật khẩu (có rate limit riêng) |
| `POST` | `/api/auth/refresh` | Xoay token, giữ `root_issued_at` để áp trần phiên |
| `POST` | `/api/auth/logout` · `/logout-all` | Thu hồi họ token hiện tại / mọi phiên; `logout-all` cần recent step-up |
| `GET`/`DELETE` | `/api/auth/sessions[/{jti}]` | Liệt kê / thu hồi cả họ token của thiết bị; `DELETE` cần recent step-up |
| `GET` | `/api/auth/security-activity` | Nhật ký bảo mật của chính người gọi + tóm tắt kể từ lần đăng nhập trước |
| `GET`/`POST`/`DELETE` | `/api/auth/email` · `POST /api/auth/email/verify` | Email khôi phục: gửi mã tới địa chỉ mới (cần step-up), xác minh, gỡ |
| `POST` | `/api/auth/password-reset/request` · `/confirm` | Quên mật khẩu: luôn trả 202 giống nhau; xác nhận bằng mã email + mật khẩu mới |
| `GET`/`DELETE` | `/api/auth/passkeys[/{id}]` | Liệt kê / xóa passkey (xóa cần step-up) |
| `POST` | `/api/auth/passkeys/registration/options` · `/verify` | Tạo passkey (cần step-up) |
| `POST` | `/api/auth/passkeys/authentication/options` · `/verify` | Đăng nhập bằng passkey, không cần mật khẩu/TOTP |

### Hội thoại
| Method | Đường dẫn | Ghi chú |
| :--- | :--- | :--- |
| `POST`/`GET` | `/api/sessions` | Tạo / liệt kê phiên của chính mình |
| `GET`/`PATCH`/`DELETE` | `/api/sessions/{id}` | Truy cập sai chủ sở hữu → **404** (giảm enumeration) |
| `GET` | `/api/sessions/{id}/messages` | Nội dung đã giải mã |
| `GET` | `/api/sessions/{id}/ciphertexts` | Bản mã thô + nonce + key version |
| `PATCH` | `/api/sessions/{id}/security` | Chọn secure/confidential/private_e2ee trước khi có dữ liệu |
| `GET` | `/api/sessions/{id}/export` | Stream JSON trực tiếp, không tạo plaintext temp; cần recent step-up |
| `POST` | `/api/sessions/{id}/export-ticket` | Vé tải 60 giây single-use, ràng buộc phiên đăng nhập cha |
| `POST` | `/api/sessions/{id}/messages` | Gửi tin nhắn; 403 nếu chưa đồng ý AI, 503 + `Retry-After` nếu provider lỗi |
| `GET` | `/api/search/messages` | Tìm kiếm toàn cục trong phạm vi sở hữu |

### Private E2EE control plane
| Method | Đường dẫn | Ghi chú |
| :--- | :--- | :--- |
| `POST`/`GET`/`DELETE` | `/api/e2ee/devices[/challenge][/{id}]` | Proof Ed25519, trusted-device approval, revoke |
| `GET` | `/api/e2ee/users/{username}/prekey-bundle` | Tiêu thụ one-time public prekey trong transaction |
| `GET`/`POST`/`DELETE` | `/api/sessions/{id}/e2ee/members[/{username}]` | Membership + routing epoch cho MLS |
| `GET`/`POST` | `/api/sessions/{id}/e2ee/envelopes` | Relay opaque Double Ratchet/MLS ciphertext + replay guard |

### Quản trị & giám sát
| Method | Đường dẫn | Quyền |
| :--- | :--- | :--- |
| `GET` | `/api/admin/audit` | moderator, admin |
| `GET` | `/api/admin/ids/detections` · `/ids/anomalies` | moderator, admin |
| `POST` | `/api/admin/ids/verify-detection` | admin — kiểm chứng Hit/Miss T1190 an toàn |
| `GET`/`POST`/`DELETE` | `/api/admin/users[/{id}]` | admin |
| `PATCH` | `/api/admin/users/{id}/role` · `/status` | admin |
| `GET` | `/api/admin/stats` · `/security-alerts` | admin |
| `GET` | `/api/admin/audit/verify` | admin — xác minh chuỗi HMAC |
| `POST` | `/api/admin/audit/checkpoint` | admin + step-up — ký/giao mốc chuỗi tới WORM |
| `GET`/`DELETE` | `/api/admin/ids/blocklist[/{ip}]` | admin |

### Thực hành và hồ sơ sự cố

Moderator/admin dùng `GET /api/admin/practice/catalog` để đọc bài thực hành;
`GET`/`POST` `/api/admin/incidents` để liệt kê/tạo hồ sơ; `GET`/`PATCH`
`/api/admin/incidents/{id}` để đọc và chuyển trạng thái. Hồ sơ dùng 1–20 audit
ID đã kiểm chứng, cập nhật theo phiên bản và có audit niêm phong. Phạm vi,
quy trình và kết quả lab nằm trong [hướng dẫn thực hành](docs/PRACTICAL_ANM.md).
| `GET` | `/api/health` | công khai, cố ý tối giản |
| `GET` | `/api/ready` | công khai, readiness DB + WORM trong high profile |

> Admin **không** đọc được nội dung hội thoại của người khác qua API: `ChatService.get_owned_session`
> luôn lọc theo `owner_id`, kể cả với vai trò admin. Đây là lựa chọn thiết kế, không phải thiếu sót.

---

## 7. Chạy nhanh trên máy cá nhân

Yêu cầu: **Python 3.10+** và các thư viện trong `uv.lock`. Từ thư mục dự án,
nếu chưa có `.venv`, cài một lần bằng `uv sync --frozen --group dev` (cần mạng).
Sau đó dùng PowerShell:

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_local --check
.\.venv\Scripts\python.exe -m scripts.demo_local
```

- **Giao diện:** <http://127.0.0.1:8000>
- **OpenAPI / Swagger:** <http://127.0.0.1:8000/docs>

`--check` kiểm tra sẵn sàng rồi thoát, không mở cổng. `--port 8080` đổi cổng nếu cần.
Trên macOS/Linux dùng `./.venv/bin/python`. Launcher lắng nghe trên loopback, bỏ qua
`.env`, dùng SQLite/khóa tạm mới mỗi lần, tự seed và ép AI ngoại tuyến. Dừng bằng `Ctrl+C`;
khởi động lại là lượt demo mới, không xóa hoặc thay đổi cơ sở dữ liệu đang có của dự án.

Để cài đặt local lưu dữ liệu lâu dài, dùng `setup.ps1` trên Windows hoặc `setup.sh`
trên Linux/macOS. Với cài đặt mới, scripts tạo `.env` có quyền riêng trước khi ghi
khóa và đặt DB/outbox trong `local_data/` có ACL/mode riêng. `.env` đã tồn tại được
giữ nguyên; thiếu cấu hình nhưng còn DB sẽ bị từ chối sinh khóa mới. Cách tạo kho
private, xử lý outbox cũ và backup/restore nằm trong
[hướng dẫn lưu trữ local](docs/security/availability.md#kho-dữ-liệu-local-và-tệp-bí-mật).

**Passkey và email trong demo:** mở bằng <http://localhost:8000> (trình duyệt không cho passkey
trên địa chỉ IP như `127.0.0.1`). Mã xác minh email và mã đặt lại mật khẩu được ghi thành file `.eml`
trong thư mục `outbox` mà launcher in ra lúc khởi động; mở bằng trình soạn thảo hoặc ứng dụng thư.

Bot `[DEMO AI]` cho xem nội dung đã qua DLP. Nó không gọi AI ngoài nên không chứng minh
nhánh đồng thuận/chặn gửi/kiểm tra phản hồi provider. Runner bật consent rồi kiểm chứng
chặn secret mã hóa, che email và lọc phản hồi với nhà cung cấp giả lập; nhánh thiếu consent
được kiểm tra trong bộ pytest. Không cần khóa API:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate_security
```

JSON/JUnit được lưu trong `reports/security-validation/`. Đây là kiểm chứng ứng dụng
trên môi trường tạm, không phải thử tấn công giao diện đang trình chiếu.

Tài liệu đi kèm: [HUONG_DAN_CHAY.md](HUONG_DAN_CHAY.md) (từng bước đến lúc demo được),
[HUONG_DAN_DOCKER.md](HUONG_DAN_DOCKER.md), [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) (kịch bản bảo vệ đồ án).

---

## 8. Tài khoản demo & dữ liệu mẫu

Launcher nạp sẵn dữ liệu mẫu. Mật khẩu chung: **`Phenikaa-Vault#2026-Lab`**.

- `demo.user` (`user`): trò chuyện, xem bản mã, tìm kiếm, MFA và thiết bị.
- `demo.mod` (`moderator`): thêm nhật ký kiểm toán, phát hiện IDS và bất thường.
- `demo.boss` (`admin`): thêm thống kê, quản lý người dùng, danh sách chặn và xác minh audit.

Có thêm 8 tài khoản `lab.*` và tổng cộng 24 hội thoại. Các sự kiện seed đều là mô phỏng,
bao gồm chuỗi thất bại từ nhiều IP rồi đăng nhập thành công để trình diễn tương quan.
Không dùng sự kiện seed làm bằng chứng rằng một tấn công thật đã xảy ra hoặc đã bị chặn.

Muốn làm lại bài demo, dừng và chạy lại launcher. Các công cụ
[seed_demo_data.py](scripts/seed_demo_data.py) và
[seed_learning_data.py](scripts/seed_learning_data.py) vẫn dành cho môi trường cấu hình
riêng; không cần chạy chúng hoặc dùng `--reset` cho lượt demo tạm.

---

## 9. Chạy bằng Docker

### 9.1 Bản production (cần tên miền thật)

[docker-compose.yml](docker-compose.yml) là cấu hình production đầy đủ — 5 service, phân đoạn
mạng, PostgreSQL ba vai trò quyền tối thiểu, Caddy tự xin chứng chỉ Let's Encrypt:

| Service | Image | Mạng | Vai trò |
| :--- | :--- | :--- | :--- |
| `db` | postgres:17-alpine | `backend` (internal) | scram-sha-256, log connection + DDL |
| `redis` | redis:7.4-alpine | `backend` | rate limiter dùng chung, read-only + tmpfs |
| `migrate` | build `.` | `backend` | chạy một lần: tạo schema rồi hạ quyền |
| `app` | build `.` | `backend` + `edge` | FastAPI + Gradio, chạy bằng role `scap_app` (không có DDL) |
| `caddy` | caddy:2.10-alpine | `edge` | reverse proxy HTTPS, service **duy nhất** publish 80/443 |

```bash
cp .env.example .env
# Bắt buộc: POSTGRES_PASSWORD, APP_DB_PASSWORD, AUDITOR_DB_PASSWORD, PUBLIC_DOMAIN, CADDY_EMAIL
docker compose up --build -d
```

Cứng hóa hạ tầng: mọi container `cap_drop: ALL` + `no-new-privileges`, `read_only` rootfs với
tmpfs cho `/tmp`, `pids_limit`/`mem_limit`/`ulimits` chống cạn kiệt tài nguyên, mạng `backend`
đặt `internal: true` nên Postgres và Redis không có đường ra Internet.

### 9.2 Bản demo trên laptop (không cần tên miền)

[docker-compose.local.yml](docker-compose.local.yml) là lớp phủ tắt Caddy và publish thẳng cổng app:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build
```

Lớp phủ bind cổng app vào `127.0.0.1` và dùng `--no-proxy-headers`; header
`X-Forwarded-For` do client gửi không chọn được IP nguồn của rate limit/IDS/audit.
Cấu hình này dành cho local/demo; production dùng Caddy và IP proxy tin cậy cụ thể.

---

## 10. Kiểm thử, CI/CD & đánh giá an ninh

### 10.1 Chạy tại máy

```bash
uv run python -m pytest --cov=src.app --cov-report=term-missing   # toàn bộ test phải pass
uv run ruff check src tests scripts
uv run bandit -r src/app -ll -ii
uv run pip-audit
bash scripts/run_zap_baseline.sh http://127.0.0.1:8000            # DAST (cần Docker)
```

Bộ test ([tests/](tests/)) không chỉ kiểm chức năng mà kiểm **chính các kiểm soát an ninh**:

| File | Trọng tâm |
| :--- | :--- |
| [tests/test_api_security.py](tests/test_api_security.py) | RBAC, IDOR, rate limit, thu hồi token |
| [tests/test_account_protection.py](tests/test_account_protection.py) | IP/UA ký từ UI, chống spraying, smart lockout, thiết bị mới, hoạt động bảo mật |
| [tests/test_passkeys.py](tests/test_passkeys.py) | WebAuthn với authenticator phần mềm thật (ES256/CBOR): UV, origin giả, replay, nhân bản |
| [tests/test_account_recovery.py](tests/test_account_recovery.py) | Email khôi phục, đặt lại mật khẩu, chống dò tài khoản, email cảnh báo |
| [tests/test_token_reuse_and_devices.py](tests/test_token_reuse_and_devices.py) | Dùng lại token đã xoay, cookie thiết bị, tab cũ của UI |
| [tests/test_account_ui.py](tests/test_account_ui.py) | Callback Gradio cho passkey, email khôi phục, quên mật khẩu |
| [tests/test_security_v2.py](tests/test_security_v2.py) | DLP, security headers, audit chain, IDS |
| [tests/test_crypto.py](tests/test_crypto.py) | AES-GCM, ràng buộc AAD |
| [tests/test_mfa.py](tests/test_mfa.py) | TOTP, chống replay, recovery code |
| [tests/test_hardening.py](tests/test_hardening.py) | Guard production, trần phiên, CSP |
| [tests/test_ai_provider_errors.py](tests/test_ai_provider_errors.py) | Lỗi provider → 503, không rò rỉ chi tiết |
| [tests/test_gemini_integration.py](tests/test_gemini_integration.py) | Timeout/retry Gemini, phản hồi rỗng/bị chặn, consent và xác nhận dữ liệu mật trên UI |
| [tests/test_fixes_2026_07.py](tests/test_fixes_2026_07.py) | Regression cho từng lỗi đã sửa |
| [tests/test_ui_wiring.py](tests/test_ui_wiring.py) | UI gọi đúng API, không đi tắt |
| [tests/test_e2ee_core.py](tests/test_e2ee_core.py) | Canonical JSON, Ed25519 proofs, fingerprint, opaque envelope |
| [tests/test_high_security_features.py](tests/test_high_security_features.py) | E2EE routes, prekey một lần, replay guard, streaming export |
| [tests/test_envelope_and_audit.py](tests/test_envelope_and_audit.py) | Per-session DEK/AAD swap, rewrap, audit anchor, retention |
| [tests/test_security_lifecycle.py](tests/test_security_lifecycle.py) | Thu hồi E2EE, xóa tài khoản và khóa giao dịch chống race condition ở ranh giới bảo mật |
| [tests/test_database_rotation.py](tests/test_database_rotation.py) | Xoay mật khẩu Postgres bằng file secret, không lộ qua argv/log |
| [tests/test_supply_chain_ci.py](tests/test_supply_chain_ci.py) | Cổng image digest, Semgrep cục bộ, Trivy/SBOM và probe runtime CI |

### 10.2 Pipeline GitHub Actions

[.github/workflows/security.yml](.github/workflows/security.yml) chạy sáu cổng kiểm tra trên mỗi
push vào `main` và mỗi pull request; bước attestation chỉ chạy sau khi toàn bộ cổng đạt:

| Job | Nội dung | Chặn merge khi |
| :--- | :--- | :--- |
| `test` | `uv lock --check` → pytest + coverage → ruff → bandit → `uv export` → pip-audit | test đỏ, lint đỏ, hoặc dependency có CVE |
| `secret-scan` | gitleaks trên **toàn bộ lịch sử** (`fetch-depth: 0`) | có secret bị commit |
| `sast` | Semgrep CLI pin phiên bản với bộ luật `.semgrep.yml` đã review trong repository | phát hiện mẫu mã nguy hiểm |
| `filesystem-scan` | Trivy quét cây mã + sinh SBOM CycloneDX | có CVE HIGH/CRITICAL, kể cả chưa có bản vá |
| `image-scan` | Build Docker image, chạy probe quyền/secret rồi Trivy quét **chính image đó** + SBOM | runtime probe lỗi hoặc có CVE HIGH/CRITICAL |
| `deployment-config` | Render high-security Compose, kiểm tra shell và validate Caddy bằng image pin digest | cấu hình triển khai/edge không hợp lệ |

Artifact tải về được: `coverage.xml`, `reports-bandit.json`, `reports-pip-audit.json`,
`sbom-source.cdx.json`, `sbom-image.cdx.json`.

> `pip-audit` chạy trên bản export `--no-dev` của `uv.lock`, nên **sàn phiên bản trong
> `pyproject.toml` là một kiểm soát an ninh**: hạ sàn xuống bản dính CVE sẽ làm đỏ CI.
> Ví dụ `cryptography>=50.0.0` đang giữ ở đó vì PYSEC-2026-3552.

Xem thêm [SECURITY.md](SECURITY.md) (chính sách báo lỗi) và
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) (biên bản tự rà soát).

---

## 11. Vận hành: xoay khóa, migration, phục hồi audit

| Việc cần làm | Lệnh |
| :--- | :--- |
| Sinh secret mới | `uv run python scripts/generate_secrets.py` |
| Tạo/cập nhật schema | `uv run python scripts/migrate_database.py` |
| Xoay khóa mã hóa | `uv run python scripts/rotate_encryption_key.py` (đặt `MASTER_ENCRYPTION_KEYS` + `ACTIVE_KEY_VERSION` trước) |
| Migrate legacy sang envelope | `uv run python scripts/migrate_envelope_encryption.py --dry-run` rồi chạy thật |
| Rewrap DEK sau khi xoay KEK | `uv run python scripts/rewrap_deks.py --dry-run` rồi chạy thật |
| Xoay mật khẩu ba role Postgres | `uv run python scripts/rotate_database_credentials.py` với current/new password file — xem runbook high-security |
| Enforce retention | `uv run python scripts/enforce_retention.py --dry-run` rồi chạy theo scheduler |
| Nối lại chuỗi audit sau sự cố | `uv run python scripts/repair_audit_chain.py` — xem [docker-compose.repair.yml](docker-compose.repair.yml) |
| Cấp quyền tối thiểu cho Postgres | [scripts/db_least_privilege.sql](scripts/db_least_privilege.sql), chạy tự động bởi [scripts/init_db_roles.sh](scripts/init_db_roles.sh) |
| Kiểm tra nhanh các bản vá | `bash kiem-tra-ban-va.sh` |

Quy trình xoay khóa được thiết kế để **không downtime**: liệt kê mọi khóa từng dùng trong
`MASTER_ENCRYPTION_KEYS`, trỏ `ACTIVE_KEY_VERSION` vào khóa mới, chạy script re-encrypt, xác minh,
rồi mới gỡ khóa cũ khỏi danh sách.

---

## 12. Cấu hình qua biến môi trường

Lớp bảo vệ quá tải dùng ngân sách hữu hạn trước khi đọc/parse body: mặc định
32 yêu cầu xử lý và 16 luồng SSE trên mỗi worker, tối đa 8 yêu cầu và 2 luồng
SSE từ cùng IP. Redis chia sẻ hạn mức theo IP/toàn hệ thống giữa các worker.
Argon2 chỉ chạy 2 tác vụ đồng thời; Gradio chờ tối đa 32 sự kiện và không cho
API đồng bộ bỏ qua hàng đợi. AI giới hạn 2 lời gọi đồng thời, 60 lời gọi/phút,
1.000 lời gọi trong 24 giờ trượt và 1.024 output token/lời gọi. Các giá trị này
là ngân sách khởi điểm, phải điều chỉnh bằng đo tải trên môi trường triển khai;
giới hạn AI không thay thế hạn mức thanh toán của nhà cung cấp.

Quản trị viên xem bộ đếm của worker tại `GET /api/admin/availability`.
Tab Quản trị có thống kê HTTP cửa sổ 60 giây và cảnh báo khi quá tải, lỗi,
phản hồi chậm hoặc ngân sách tài nguyên đang đầy. Các phép đo có nhãn cố định,
không giữ URL/IP/body/token và không tự kết luận có tấn công DDoS.
Các biến `REQUEST_*`, `AUTH_GLOBAL_MAX_ATTEMPTS`, `PASSWORD_MAX_CONCURRENT`,
`AI_*`, `READINESS_*`, `GRADIO_QUEUE_MAX_SIZE`, `GRADIO_CONCURRENCY_LIMIT` cùng
quy trình vận hành nằm trong [hướng dẫn chống quá tải](docs/security/availability.md).
Máy local vẫn dùng hồ sơ development; trước khi mở Internet cần lớp chống
DDoS/WAF ở biên, khóa truy cập origin và hoàn tất cấu hình production/high.

Hai công cụ local dựng dữ liệu tạm riêng để kiểm chứng qua HTTP thật và
diễn tập khôi phục, không dùng DB/secret hoặc AI trả phí của bạn:

```powershell
.\.venv\Scripts\python.exe -m scripts.security_load_check
.\.venv\Scripts\python.exe -m scripts.security_recovery_drill
```

Load check xuất `reports/security-load-local/security-load.json`; recovery
drill xuất JSON ra stdout. Xem phạm vi và giới hạn phép đo trong hướng dẫn trên.

Toàn bộ biến và giải thích nằm trong [.env.example](.env.example). Những nhóm đáng chú ý:

| Nhóm | Biến tiêu biểu |
| :--- | :--- |
| Hồ sơ/KMS | `SECURITY_PROFILE`, `KEY_PROVIDER`, `VAULT_*`, `AWS_KMS_KEY_ID`, `GCP_KMS_KEY_NAME`, `DEK_CACHE_SECONDS` |
| Bí mật local/legacy | `APP_SECRET_KEY`, `MASTER_ENCRYPTION_KEY`, `MASTER_ENCRYPTION_KEYS`, `ACTIVE_KEY_VERSION` |
| Hạ tầng | `DATABASE_URL`, `REDIS_URL`, `ALLOWED_ORIGINS`, `ALLOWED_HOSTS`, `PUBLIC_DOMAIN` |
| Phiên & token | `ACCESS_TOKEN_MINUTES`, `SESSION_IDLE_MINUTES`, `SESSION_ABSOLUTE_HOURS`, `REFRESH_WINDOW_SECONDS`, `REFRESH_MAX_ATTEMPTS`, `SIGN_IN_HISTORY_DAYS`, `TOKEN_REUSE_GRACE_SECONDS`, `DEVICE_TOKEN_DAYS` |
| Email bảo mật | `MAIL_BACKEND` (`outbox`/`smtp`/`disabled`), `MAIL_OUTBOX_DIR`, `MAIL_FROM`, `SMTP_*`, `PASSWORD_RESET_MINUTES` |
| Passkey | `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGINS` |
| Hạn mức/retention | `MAX_SESSIONS_PER_USER`, `MAX_MESSAGES_PER_SESSION`, `SECURE_RETENTION_DAYS`, `CONFIDENTIAL_RETENTION_DAYS` |
| Chống lạm dụng | `LOGIN_*`, `ALLOW_SELF_REGISTRATION`, `REGISTRATION_*`, `MESSAGE_*`, `PASSWORD_CHANGE_*` |
| 2FA | `MFA_ISSUER`, `MFA_CHALLENGE_MINUTES`, `MFA_RECOVERY_CODES`, `MFA_*_ATTEMPTS` |
| IDS/Audit/SIEM | `IDS_*`, `AUDIT_CHAIN_ENABLED`, `AUDIT_WORM_*`, `AUDIT_CHECKPOINT_INTERVAL`, `AUDIT_MAX_UNANCHORED_EVENTS`, `SIEM_JSON_LOGS` |
| UI/SSO | `GRADIO_AUTH_MODE`, `OIDC_*`, `GRADIO_MAX_FILE_SIZE`, `CSP_*` |
| AI/DLP | `GOOGLE_GENAI_API_KEY`, `GEMINI_MODEL`, `GEMINI_TIMEOUT_SECONDS`, `ALLOW_DEMO_AI`, `AI_CONSENT_VERSION`, `DLP_CUSTOM_TERMS` |

Đặt `APP_ENV=production` sẽ kích hoạt các guard trong [src/app/config.py](src/app/config.py):
ứng dụng **từ chối khởi động** nếu thiếu `APP_SECRET_KEY` đủ mạnh, thiếu khóa mã hóa, thiếu
`REDIS_URL` / `ALLOWED_ORIGINS` / `ALLOWED_HOSTS`, còn bật `DOCS_ENABLED` hay `SEED_DEMO_DATA`,
có đặt `BOOTSTRAP_ADMIN_PASSWORD`, hoặc `DATABASE_URL` dùng tài khoản chủ của Postgres.
High profile còn bắt buộc KMS/Vault, PostgreSQL, OIDC gate, WORM audit, kiểm tra mật khẩu
rò rỉ fail-closed, MFA cho tài khoản đặc quyền/hội thoại nhạy cảm, tắt tự đăng ký và từ
chối master key legacy trong web runtime. Nó cũng từ chối Vault qua HTTP, PostgreSQL
không `sslmode=verify-full`, hoặc Redis không dùng `rediss://` với xác minh chứng chỉ.

---

## 13. Cấu trúc thư mục

```text
Secure_Conversational_Application_Platform/
├── .github/workflows/security.yml   # CI: test + 4 lớp quét an ninh
├── src/
│   ├── app/
│   │   ├── main.py                  # FastAPI app, middleware, toàn bộ route, mount Gradio
│   │   ├── config.py                # Settings + guard production
│   │   ├── security.py              # Argon2id, JWT, AES-256-GCM, TOTP, rate limiter
│   │   ├── key_management.py        # Vault/AWS/GCP/local KEK provider
│   │   ├── envelope.py              # Per-session DEK + message-bound AAD
│   │   ├── e2ee.py                  # Public proof/opaque ciphertext boundary
│   │   ├── dlp.py                   # Formal detector/policy engine
│   │   ├── services.py              # AI/DLP/Chat integration
│   │   ├── ids.py                   # IDS/IPS: signature + anomaly engine
│   │   ├── audit.py                 # Ghi sự kiện audit
│   │   ├── audit_chain.py           # Chuỗi băm HMAC-SHA256 chống giả mạo
│   │   ├── audit_checkpoint.py      # External WORM anchors
│   │   ├── retention.py             # Retention/cryptographic erasure
│   │   ├── siem.py                  # Log JSON một dòng cho SIEM
│   │   ├── models.py                # ORM SQLAlchemy
│   │   ├── schemas.py               # Pydantic schema
│   │   ├── db.py                    # Engine/session, kiểm tra schema
│   │   ├── gradio_ui.py             # Giao diện Gradio 6 (theme, CSS, 8 tab)
│   │   ├── demo_seed.py             # Dữ liệu mẫu idempotent
│   │   └── ui_assets/               # Ảnh tĩnh của giao diện
│   ├── core/ai_core/gemini_ai.py    # Wrapper SDK google-genai
├── tests/                           # Kiểm thử API, crypto, DLP, E2EE, audit, hardening
├── scripts/                         # secret, migration, rotate key, seed, repair, ZAP
├── docs/DEMO_SCRIPT.md              # Kịch bản demo trước hội đồng
├── reports/                         # Kết quả kiểm thử lưu lại
├── Dockerfile                       # Base image pin được bằng digest, chạy user không phải root
├── docker-compose.yml               # Production: db + redis + migrate + app + caddy
├── docker-compose.local.yml         # Lớp phủ demo trên laptop (tắt Caddy)
├── docker-compose.high-security.yml # Vault/OIDC/WORM + TLS DB/Redis guard overlay
├── docker-compose.repair.yml        # Cụm phục hồi chuỗi audit
├── Caddyfile                        # TLS, security header biên, /.well-known/security.txt
├── HUONG_DAN_CHAY.md                # Hướng dẫn chạy chi tiết
├── HUONG_DAN_DOCKER.md              # Hướng dẫn Docker từng bước
├── SECURITY.md / SECURITY_REVIEW.md # Chính sách & biên bản tự rà soát
├── pyproject.toml / uv.lock         # Dependency khóa phiên bản (tái lập được)
└── Makefile                         # install / run / test / security / docker
```

---

## 14. Giới hạn có chủ đích

1. **Khóa audit vẫn nằm cùng tiến trình.** High profile đã đưa KEK hội thoại ra Vault/KMS,
   nhưng khóa ký JWT/audit dẫn xuất từ app secret vẫn nằm trong web process. Checkpoint ngoài
   WORM phát hiện rollback sau khi giao; full host compromise trước khi giao vẫn còn rủi ro.
2. **CSP còn cho phép CSS inline.** Script đã dùng nonce và chặn handler inline;
   style runtime của Gradio cần allowance riêng. Adapter kiểm tra mẫu bootstrap
   và từ chối phiên bản không tương thích; phải kiểm thử lại khi nâng Gradio.
3. **IDS chữ ký là phòng thủ chiều sâu, không phải kiểm soát chính.** Truy vấn tham số hóa
   của SQLAlchemy là biện pháp chính chống SQL injection trong các luồng đã triển khai;
   engine signature phát hiện dấu hiệu nghi vấn và có thể bị né bằng mã hóa/obfuscation.
4. **Rate limiter in-memory chỉ đúng cho một tiến trình.** Nhiều worker bắt buộc dùng Redis —
   guard production đã ép điều này.
5. **E2EE cần client riêng đã audit.** Server đã có public-key/prekey/membership/ciphertext relay
   và replay guard nhưng cố ý không tự viết Double Ratchet/MLS. Chưa được tuyên bố E2EE production
   khi chưa có client, interop vectors và pentest độc lập.
6. **Dịch vụ ngoài chưa được provision bởi repository.** Adapter/guard cho KMS, OIDC proxy và
   WORM đã có, nhưng IAM, retention lock, IdP policy, alerting, DPA và Red Team là cổng vận hành.
7. **Chưa kèm file LICENSE.** Đây là đồ án môn học; hãy thêm `LICENSE` trước khi công bố lại
   dưới một giấy phép cụ thể.
