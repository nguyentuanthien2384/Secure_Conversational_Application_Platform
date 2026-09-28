# 🛡️ Phân tích dự án SCAP — Hiểu từ gốc rễ

> **Cập nhật lần cuối:** 2026-09-28
>
> Tài liệu này mô tả tổng quan kiến trúc, tính năng và cách các thành phần liên kết.
> Khi sửa hoặc phát triển thêm, hãy cập nhật tài liệu này cho phù hợp.

---

## Mục lục

1. [Dự án này làm về cái gì?](#1-dự-án-này-làm-về-cái-gì)
2. [Vòng đời của một tin nhắn](#2-vòng-đời-của-một-tin-nhắn)
3. [Chi tiết từng tính năng](#3-chi-tiết-từng-tính-năng)
   - [3.1 Xác thực & Quản lý phiên](#31--xác-thực--quản-lý-phiên)
   - [3.2 Mã hóa dữ liệu](#32--mã-hóa-dữ-liệu)
   - [3.3 DLP — Chống rò rỉ dữ liệu](#33--dlp--chống-rò-rỉ-dữ-liệu)
   - [3.4 IDS/IPS — Phát hiện & ngăn chặn xâm nhập](#34--idsips--phát-hiện--ngăn-chặn-xâm-nhập)
   - [3.5 Audit — Nhật ký kiểm toán chống giả mạo](#35--audit--nhật-ký-kiểm-toán-chống-giả-mạo)
   - [3.6 Giao diện Gradio (7 tab)](#36--giao-diện-gradio-7-tab)
4. [Mối quan hệ giữa các tính năng](#4-mối-quan-hệ-giữa-các-tính-năng)
5. [Bản đồ file → chức năng](#5-bản-đồ-file--chức-năng)
6. [Nhật ký thay đổi](#6-nhật-ký-thay-đổi)

---

## 1. Dự án này làm về cái gì?

**SCAP** (Secure Conversational Application Platform) là **ứng dụng chat AI nhiều người dùng**,
giống như một "ChatGPT thu nhỏ" nhưng tập trung vào **bảo mật toàn diện**.

Đây là đồ án môn học **Bảo mật Ứng dụng và Hệ thống**.

> **Mục tiêu cốt lõi KHÔNG phải** là xây một ứng dụng chat đẹp.
> Mục tiêu là **minh họa một chuỗi kiểm soát an ninh đầy đủ** từ đầu đến cuối —
> từ lúc người dùng gõ mật khẩu đến lúc tin nhắn được lưu vào cơ sở dữ liệu.

**Công nghệ chính:**
- **Backend:** FastAPI (một tiến trình duy nhất) — `src/app/main.py`
- **Frontend:** Gradio 6 (mount vào FastAPI tại `/`) — `src/app/gradio_ui.py`
- **Database:** SQLite (demo) / PostgreSQL (production)
- **AI:** Google Gemini SDK hoặc demo AI ngoại tuyến
- **Mã hóa:** AES-256-GCM + Envelope Encryption (Vault/KMS)

---

## 2. Vòng đời của một tin nhắn

Khi người dùng gõ tin nhắn "Xin chào" và gửi đi, hành trình của tin nhắn qua **6 lớp bảo vệ**:

```
👤 Người dùng gõ "Xin chào"
    │
    ▼
🔐 [Lớp 1] XÁC THỰC — Bạn có phải là bạn? (JWT token hợp lệ?)
    │
    ▼
🚧 [Lớp 2] IDS/IPS — Tin nhắn có chứa mã độc không? (SQLi? XSS?)
    │
    ▼
🔍 [Lớp 3] DLP — Có lộ dữ liệu nhạy cảm không? (Số thẻ? Email?)
    │
    ▼
🤖 [Lớp 4] AI xử lý và trả lời (Gemini / Demo AI)
    │
    ▼
🔒 [Lớp 5] MÃ HÓA — Lưu dưới dạng bản mã AES-256-GCM
    │
    ▼
📋 [Lớp 6] AUDIT — Ghi nhật ký chống giả mạo (HMAC chain)
```

**Quan trọng:** Giao diện Gradio **không gọi thẳng database**. Mọi thao tác UI đều gọi
REST API qua HTTP → đi qua đầy đủ JWT, RBAC, rate limit, IDS, audit. Không có "đường tắt".

---

## 3. Chi tiết từng tính năng

### 3.1 🔐 Xác thực & Quản lý phiên

**File liên quan:**
- `src/app/security.py` — Argon2id, JWT, TOTP, Rate limiter
- `src/app/main.py` — Routes `/api/auth/*`, middleware
- `src/app/models.py` — `User`, `AuthSession`, `RevokedToken`, `MfaRecoveryCode`

**Dùng để làm gì?** Xác minh "bạn là ai" trước khi cho làm bất cứ điều gì.

| Thành phần | Ý nghĩa thực tế | Vị trí trong code |
|:---|:---|:---|
| **Argon2id** (hash mật khẩu) | Mật khẩu không lưu dạng text, mà qua hàm băm cực mạnh. Kẻ tấn công lấy được DB cũng không đọc được | `security.py → PasswordService` |
| **TOTP 2FA** (xác thực hai bước) | Sau password, phải nhập mã 6 số từ Google Authenticator. Lộ password vẫn không vào được | `security.py → TotpService` |
| **JWT token** | Sau đăng nhập, server phát "thẻ ra vào" có hạn (30 phút). Mọi request phải trình thẻ | `security.py → TokenService` |
| **Khóa tài khoản** | Nhập sai password quá nhiều → khóa tạm thời (chống brute force) | `main.py → login route` |
| **Rate limit** | Giới hạn số lần gọi API — chặn tấn công từ 1 IP lẫn dàn trải nhiều IP | `security.py → RateLimiter` |
| **Trần phiên tuyệt đối** | Dù refresh liên tục, sau 8h phải đăng nhập lại | `main.py → refresh route` |
| **Idle timeout** | Không thao tác 30 phút → phiên hết hạn | `main.py → verify_token` |
| **Hash giả** | Username không tồn tại vẫn verify hash giả → chống enumerate user qua timing | `main.py → login route` |
| **Recovery code** | Mã dùng 1 lần khi mất điện thoại 2FA, lưu dạng hash Argon2id | `security.py → TotpService` |

**Ví dụ thực tế:** Như vào ngân hàng — cần CMND (password) + OTP từ điện thoại (2FA),
thẻ ra vào có hạn (JWT), và bảo vệ đếm số lần thử sai (rate limit).

---

### 3.2 🔒 Mã hóa dữ liệu

**File liên quan:**
- `src/app/envelope.py` — DEK riêng từng session, AAD canonical, cache DEK ngắn hạn
- `src/app/key_management.py` — Adapter Local/Vault Transit/AWS KMS/GCP KMS
- `src/app/e2ee.py` — Ed25519, canonical JSON, opaque envelope cho E2EE
- `src/app/security.py` — `CryptoService` (AES-256-GCM + key ring)

**Dùng để làm gì?** Đảm bảo nội dung tin nhắn trong database là **bản mã** —
không ai đọc được nếu không có khóa.

| Thành phần | Ý nghĩa thực tế | Vị trí trong code |
|:---|:---|:---|
| **AES-256-GCM** | Mã hóa chuẩn quân sự. Mỗi tin nhắn mã hóa riêng với nonce ngẫu nhiên | `security.py → CryptoService` |
| **DEK riêng từng hội thoại** | Mỗi cuộc trò chuyện có khóa riêng. Lộ khóa A không ảnh hưởng B | `envelope.py → ConversationEnvelopeService` |
| **Envelope encryption** | DEK được bọc (wrap) bởi KEK từ Vault/KMS. DB chỉ giữ DEK đã bọc | `key_management.py → KMSAdapter` |
| **AAD** (Additional Authenticated Data) | Ràng buộc ciphertext với metadata (ai sở hữu, hội thoại nào, tin nhắn thứ mấy). Không thể tráo ciphertext | `envelope.py → _build_aad()` |
| **E2EE** (mode private) | Server chỉ trung chuyển bản mã, không giải mã được | `e2ee.py` |
| **3 trust boundary** | `secure` / `confidential` / `private_e2ee` — mỗi mức có chính sách mã hóa riêng | `models.py → ChatSession.security_mode` |

**Ví dụ thực tế:** Két sắt lồng trong két sắt — mỗi hội thoại là 1 két riêng (DEK),
tất cả nằm trong phòng bảo mật có khóa chủ (KEK).

---

### 3.3 🔍 DLP — Chống rò rỉ dữ liệu

**File liên quan:**
- `src/app/dlp.py` — Detector engine + Policy engine (37KB, module lớn nhất sau main/gradio)
- `src/app/services.py` — Tích hợp DLP vào luồng gửi tin nhắn, consent, context minimization

**Dùng để làm gì?** Ngăn người dùng vô tình (hoặc cố ý) gửi dữ liệu nhạy cảm ra AI bên ngoài.

| Loại dữ liệu | Hành động | Vị trí trong code |
|:---|:---|:---|
| Số thẻ tín dụng | **Chặn** — không gửi | `dlp.py → CreditCardDetector` |
| Private key, API secret | **Chặn** — không gửi | `dlp.py → SecretDetector` |
| Email, số điện thoại | **Che** — thay bằng `[EMAIL]`, `[PHONE]` | `dlp.py → EmailDetector, PhoneDetector` |
| Dữ liệu mã hóa nhiều lớp | Giải mã tạm để kiểm tra, che cả dạng gốc | `dlp.py → _decode_layers()` |

**Đặc điểm quan trọng:**
- Kiểm tra **cả prompt gửi đi LẪN phản hồi nhận về** từ AI
- Policy hỗ trợ: `allow` / `redact` / `confirm` / `block` / `local-only`
- Dữ liệu user được bọc trong `UNTRUSTED_USER_DATA_JSON` → giảm prompt injection
- Chỉ gọi AI ngoài khi user bật **consent** (`PATCH /api/auth/ai-consent`)
- Context chỉ lấy tối đa 8 message sau thời điểm consent

**Ví dụ thực tế:** Bộ phận kiểm duyệt thư — trước khi thư ra khỏi công ty,
mọi thông tin mật đều bị bôi đen.

---

### 3.4 🚧 IDS/IPS — Phát hiện & ngăn chặn xâm nhập

**File liên quan:**
- `src/app/ids.py` — Signature engine + Anomaly engine (30KB)
- `src/app/browser_security.py` — Kiểm tra Origin/Sec-Fetch-Site
- `src/app/request_limits.py` — Giới hạn body size 1 MiB

**Dùng để làm gì?** Phát hiện và chặn các cuộc tấn công vào ứng dụng.

| Engine | Phát hiện gì | Vị trí trong code |
|:---|:---|:---|
| **Signature** (10 nhóm luật) | SQLi, XSS, Path Traversal, Command Injection, SSTI, Log4Shell, NoSQL Injection, Scanner UA, Honeypot paths | `ids.py → SignatureEngine` |
| **Anomaly** (phân tích audit log) | Credential stuffing, brute force, password spraying, đăng nhập sau chuỗi thất bại, dò IDOR | `ids.py → AnomalyEngine` |

**Cơ chế chặn:**
- Điểm rủi ro tích lũy: `high=3` / `medium=2` / `low=1`
- Vượt `IDS_BLOCK_THRESHOLD` → **chặn IP** trong `IDS_BLOCK_SECONDS`, trả 403 + `Retry-After`
- Mỗi phát hiện gắn nhãn `mitre_technique` (ví dụ `T1190`) cho đối soát ATT&CK
- Admin có thể chạy kiểm chứng Hit/Miss bằng `POST /api/admin/ids/verify-detection`

**Ví dụ thực tế:** Camera an ninh + bảo vệ — camera nhận diện khuôn mặt đáng ngờ (signature),
bảo vệ theo dõi hành vi bất thường (anomaly), chặn người lạ khi cần (IPS).

---

### 3.5 📋 Audit — Nhật ký kiểm toán chống giả mạo

**File liên quan:**
- `src/app/audit.py` — Ghi sự kiện, xác định IP nguồn
- `src/app/audit_chain.py` — Chuỗi HMAC-SHA256 chống giả mạo
- `src/app/audit_checkpoint.py` — Ký mốc + giao qua HTTPS tới WORM/SIEM
- `src/app/siem.py` — Xuất JSON một dòng cho SIEM (ECS-like)

**Dùng để làm gì?** Ghi lại MỌI hành động trong hệ thống, đảm bảo nhật ký
không thể bị sửa/xóa mà không bị phát hiện.

| Thành phần | Ý nghĩa | Vị trí trong code |
|:---|:---|:---|
| **HMAC chain** | Mỗi bản ghi nối chuỗi bằng HMAC-SHA256. Sửa 1 dòng → gãy chuỗi → phát hiện ngay | `audit_chain.py → compute_entry_hash()` |
| **Checkpoint** | Ký mốc cuối chuỗi gửi ra WORM. Admin server cũng không xóa được nhật ký | `audit_checkpoint.py → sign_checkpoint()` |
| **SIEM export** | Xuất JSON cho ELK/Splunk/Wazuh | `siem.py → emit_siem_event()` |
| **Xác minh chuỗi** | API + nút UI để kiểm tra toàn vẹn chuỗi bất kỳ lúc nào | `main.py → GET /api/admin/audit/verify` |

**Ví dụ thực tế:** Sổ cái ngân hàng — mỗi giao dịch được ghi, đánh số, ký tên liên tục.
Xé 1 trang → tất cả số thứ tự phía sau sai → phát hiện ngay.

---

### 3.6 🖥️ Giao diện Gradio (7 tab)

**File liên quan:**
- `src/app/gradio_ui.py` — Toàn bộ giao diện (116KB, ~2474 dòng)
- `src/app/ui_session.py` — Quản lý state phiên UI
- `src/app/static/` — CSS / assets tĩnh
- `src/app/ui_assets/` — Assets giao diện bổ sung

| Tab | Chức năng | Ai dùng | Vị trí trong code |
|:---|:---|:---|:---|
| **Trò chuyện** | Chat với AI, tạo/xóa/đổi tên hội thoại, xuất JSON | Mọi người | `gradio_ui.py → _build_chat_tab()` |
| **Dữ liệu mã hóa** | Xem bản mã AES-256-GCM thật (ciphertext, nonce, key version) | Mọi người | `gradio_ui.py → _build_cipher_tab()` |
| **Tìm kiếm** | Tìm tin nhắn trong các hội thoại của mình | Mọi người | `gradio_ui.py → _build_search_tab()` |
| **Tài khoản** | Đổi password, bật/tắt 2FA, quản lý thiết bị, consent AI | Mọi người | `gradio_ui.py → _build_account_tab()` |
| **Quản trị** | Quản lý người dùng, thống kê hệ thống | Admin | `gradio_ui.py → _build_admin_tab()` |
| **Nhật ký kiểm toán** | Xem audit log | Mod, Admin | `gradio_ui.py → _build_audit_tab()` |
| **Bảo mật** | IDS detections, bất thường, xác minh audit, blocklist | Mod, Admin | `gradio_ui.py → _build_security_tab()` |

**Đặc điểm thiết kế:**
- Theme `gr.themes.Soft` — emerald/slate, font `Be Vietnam Pro`
- Cột nội dung giới hạn 1400px, hỗ trợ dark mode
- Tránh dùng `gr.HTML` (vì CSP không cho `unsafe-eval`)
- Thanh trên cùng: username, vai trò, `jti`, đồng hồ đếm ngược token
- Trang đăng nhập: luồng 2 bước (password → TOTP/recovery code)

---

## 4. Mối quan hệ giữa các tính năng

Tất cả các tính năng hình thành **một chuỗi phòng thủ nhiều lớp (Defense in Depth)**:

```
[Xác thực] → [Phân quyền RBAC] → [IDS/IPS] → [DLP] → [Mã hóa] → [Audit]
```

### Bảng quan hệ chi tiết:

| Tính năng A | ↔ | Tính năng B | Quan hệ cụ thể |
|:---|:---:|:---|:---|
| **Xác thực** | → | **Audit** | Mọi lần login/logout/thất bại đều ghi audit. Audit cung cấp dữ liệu cho IDS |
| **Xác thực** | → | **IDS Anomaly** | IDS phân tích audit log đăng nhập để phát hiện credential stuffing, brute force |
| **IDS** | → | **Audit** | Mỗi phát hiện IDS ghi vào audit chain + xuất SIEM |
| **DLP** | → | **Mã hóa** | DLP kiểm tra trước, nội dung sạch mới được mã hóa lưu trữ |
| **DLP** | → | **Audit** | Mỗi lần che/chặn dữ liệu ghi audit (ai gửi gì, đã che gì) |
| **DLP** | → | **Consent** | Chỉ gọi AI ngoài khi user bật consent; consent có timestamp/policy version |
| **Mã hóa** | → | **Key Mgmt** | DEK được Vault/KMS bọc; xoay KEK chỉ rewrap, không giải mã lại |
| **RBAC** | → | **Mọi thứ** | Mỗi API endpoint kiểm tra quyền trước khi thực hiện |
| **Audit Chain** | → | **Checkpoint** | Checkpoint ký mốc cuối chuỗi gửi ra WORM — bảo vệ cả khi mất server |
| **Gradio UI** | → | **REST API** | UI gọi API qua httpx → đi qua đầy đủ mọi lớp bảo vệ |

### Tại sao phải có TẤT CẢ?

- Chỉ có **mã hóa** mà không có **xác thực** → ai cũng đọc được dữ liệu đã giải mã
- Chỉ có **xác thực** mà không có **IDS** → kẻ tấn công brute force thoải mái
- Chỉ có **IDS** mà không có **DLP** → user hợp lệ vẫn vô tình lộ số thẻ cho AI bên ngoài
- Chỉ có tất cả mà không có **audit** → không biết chuyện gì đã xảy ra khi sự cố xảy ra

**Bảo mật không phải MỘT tính năng, mà là MỘT CHUỖI các lớp phòng thủ phối hợp nhau.**

---

## 5. Bản đồ file → chức năng

### Thư mục `src/app/` (backend chính)

| File | Kích thước | Chức năng |
|:---|:---|:---|
| `main.py` | 190KB | **Trung tâm:** Tạo app, middleware, TẤT CẢ REST routes, mount Gradio |
| `gradio_ui.py` | 117KB | **Giao diện:** 7 tab, gọi API qua httpx |
| `dlp.py` | 38KB | **DLP:** Detector + Policy engine |
| `config.py` | 31KB | **Cấu hình:** Settings từ env + guard production |
| `security_validation.py` | 33KB | **Kiểm chứng:** Validation scripts cho bảo mật |
| `ids.py` | 30KB | **IDS/IPS:** Signature + Anomaly engine |
| `services.py` | 25KB | **Dịch vụ:** DLP integration, consent, AIService, ChatService |
| `e2ee.py` | 25KB | **E2EE:** Ed25519, canonical JSON, opaque envelope |
| `security.py` | 23KB | **Crypto primitives:** Argon2id, JWT, AES-256-GCM, TOTP, rate limiter |
| `demo_seed.py` | 23KB | **Demo:** Sinh tài khoản/hội thoại mẫu |
| `models.py` | 21KB | **ORM:** User, AuthSession, ChatSession, SecureMessage, AuditEvent... |
| `key_management.py` | 21KB | **Key Mgmt:** Adapter Local/Vault/AWS KMS/GCP KMS |
| `db.py` | 19KB | **Database:** SQLAlchemy engine/session |
| `envelope.py` | 19KB | **Envelope:** DEK riêng session, AAD canonical, cache DEK |
| `audit_checkpoint.py` | 18KB | **Checkpoint:** Ký mốc + giao HTTPS tới WORM |
| `schemas.py` | 17KB | **Schemas:** Pydantic request/response |
| `maintenance.py` | 13KB | **Bảo trì:** Tác vụ định kỳ |
| `audit_chain.py` | 12KB | **HMAC chain:** Chuỗi băm chống giả mạo |
| `retention.py` | 9KB | **Retention:** Chính sách lưu giữ dữ liệu |
| `ui_session.py` | 9KB | **UI state:** Quản lý phiên giao diện |
| `siem.py` | 6KB | **SIEM:** Xuất JSON cho hệ thống giám sát |
| `audit.py` | 4KB | **Audit writer:** Ghi sự kiện, xác định IP |
| `request_limits.py` | 4KB | **Request limits:** Giới hạn body 1 MiB |
| `browser_security.py` | 3KB | **Browser:** Origin/Sec-Fetch-Site check |

### Thư mục `src/core/`

| File | Chức năng |
|:---|:---|
| `ai_core/gemini_ai.py` | Wrapper quanh SDK `google-genai` |

### Thư mục `scripts/`

| Script | Chức năng |
|:---|:---|
| `demo_local.py` | Launcher demo: SQLite + AI offline + auto seed |
| `validate_security.py` | Kiểm chứng bảo mật tự động |
| `seed_demo_data.py` | Nạp dữ liệu mẫu |
| `seed_learning_data.py` | Nạp dữ liệu học tập |

### REST API — Các nhóm route chính (tất cả trong `main.py`)

| Nhóm | Prefix | Mô tả |
|:---|:---|:---|
| Xác thực | `/api/auth/*` | Login, register, MFA, refresh, logout, consent, password, sessions |
| Hội thoại | `/api/sessions/*` | CRUD session, messages, ciphertexts, export, search |
| E2EE | `/api/e2ee/*` | Device registration, prekey bundle, member management, envelope relay |
| Quản trị | `/api/admin/*` | Users CRUD, audit, IDS, stats, blocklist, verify, checkpoint |
| Health | `/api/health`, `/api/ready` | Kiểm tra sức khỏe ứng dụng |

---

## 6. Nhật ký thay đổi

> Ghi lại các thay đổi lớn khi phát triển dự án. Cập nhật section này mỗi khi
> thêm tính năng hoặc sửa đổi kiến trúc đáng kể.

| Ngày | Thay đổi | File ảnh hưởng |
|:---|:---|:---|
| 2026-09-28 | Tạo tài liệu phân tích ban đầu | `docs/PHAN_TICH_DU_AN.md` |
| | | |

---

> **Một câu tổng kết:**
> SCAP = Ứng dụng chat AI + 6 lớp bảo mật liên kết chặt chẽ,
> chứng minh rằng bảo mật ứng dụng là một **hệ thống tổng thể**, không phải một tính năng đơn lẻ.
