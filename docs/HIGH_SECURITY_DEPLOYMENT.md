# Triển khai hồ sơ bảo mật cao

Tài liệu này là runbook cho các yêu cầu nâng cấp hội thoại rất nhạy cảm. Chỉ
đặt `SECURITY_PROFILE=high` khi toàn bộ cổng kiểm soát bên dưới đã có dịch vụ
thật. Cờ cấu hình không phải chứng nhận an toàn; ứng dụng chủ động từ chối khởi
động nếu thấy cấu hình hạ cấp.

## Ba chế độ dữ liệu

- `secure`: máy chủ xử lý nội dung; mỗi hội thoại có một DEK AES-256-GCM ngẫu
  nhiên, DEK được KMS/Vault bọc. Lưu tối đa 90 ngày theo mặc định.
- `confidential`: cùng envelope encryption, giữ 7 ngày mặc định; mọi egress AI
  phải qua consent phiên bản hóa, DLP và xác nhận riêng.
- `private_e2ee`: máy chủ không có DEK, khóa riêng, ratchet state hay plaintext.
  Máy chủ chỉ lưu thành viên, khóa công khai/prekey và envelope bản mã. Client
  phải dùng Double Ratchet đã kiểm toán cho 1:1 hoặc RFC 9420 MLS cho nhóm.

Không thể đổi trust boundary sau khi phiên đã có dữ liệu. Không được quảng bá
`private_e2ee` cho giao diện/client chưa triển khai hợp đồng trong
`docs/E2EE_CLIENT_CONTRACT.md`.

## Cổng bắt buộc trước khi go-live

1. PostgreSQL chạy bằng role `scap_app`, không phải owner/superuser; TLS DB và
   backup mã hóa đã được kiểm thử phục hồi.
2. `KEY_PROVIDER=vault`, `aws-kms` hoặc `gcp-kms`; web runtime không chứa
   `MASTER_ENCRYPTION_KEY(S)`. Dùng workload identity hoặc token file ngắn hạn.
3. Identity-aware proxy đã xác thực OIDC, xóa header do client gửi và chèn
   `OIDC_USER_HEADER` cùng `OIDC_PROXY_SECRET_HEADER`. Bí mật proxy dài ít nhất
   32 ký tự, mount read-only tại `OIDC_PROXY_SECRET_FILE`.
4. Redis riêng cho rate limit đa instance; IDS, SIEM JSON, audit chain và kiểm
   tra mật khẩu rò rỉ đều bật.
5. `AUDIT_WORM_ENDPOINT` là HTTPS tới kho append-only/retention-lock; credential
   nằm ở `AUDIT_WORM_TOKEN_FILE`. SOC phải cảnh báo nếu checkpoint ngừng đến,
   `last_event_id` giảm hoặc cùng ID có root hash khác.
6. Base image và các image hạ tầng đã xác minh/pin digest; CI test, SAST, secret
   scan, dependency scan, image scan, SBOM và provenance đều xanh.
7. Đã chạy migration envelope, retention dry-run, restore drill, DAST có xác
   thực, kiểm thử tải và pentest độc lập. Không còn dữ liệu legacy phụ thuộc
   master key trong web runtime.

## Cấu hình Vault tham chiếu

Sao chép `.env.example`, sinh các secret riêng và đặt tối thiểu:

```dotenv
APP_ENV=production
SECURITY_PROFILE=high
KEY_PROVIDER=vault
VAULT_ADDR=https://vault.internal.example
VAULT_TRANSIT_MOUNT=transit
VAULT_TRANSIT_KEY=scap-conversations
VAULT_TOKEN_FILE_HOST=/secure-host-path/scap-vault-token

GRADIO_AUTH_MODE=oidc
OIDC_PROXY_SECRET_FILE_HOST=/secure-host-path/oidc-proxy-secret

AUDIT_WORM_ENDPOINT=https://worm.internal.example/v1/scap/checkpoints
AUDIT_WORM_TOKEN_FILE_HOST=/secure-host-path/worm-token
AUDIT_CHECKPOINT_INTERVAL=100

PUBLIC_DOMAIN=chat.example.com
PUBLIC_BASE_URL=https://chat.example.com
BASE_IMAGE=python:3.12-slim@sha256:<digest-da-xac-minh>
POSTGRES_IMAGE=postgres:17-alpine@sha256:<digest-da-xac-minh>
REDIS_IMAGE=redis:7.4-alpine@sha256:<digest-da-xac-minh>
CADDY_IMAGE=caddy:2.10-alpine@sha256:<digest-da-xac-minh>
```

Để trống hoàn toàn `MASTER_ENCRYPTION_KEY` và `MASTER_ENCRYPTION_KEYS`. Khởi
động bằng overlay tham chiếu:

```sh
docker compose -f docker-compose.yml -f docker-compose.high-security.yml config
docker compose -f docker-compose.yml -f docker-compose.high-security.yml up -d --build
```

Lệnh `config` phải được review để chắc rằng không có secret xuất hiện trong
environment đã render. Overlay không tự cài một nhà cung cấp danh tính; đội vận
hành phải đặt OIDC proxy/gateway đã được phê duyệt trước Caddy và mount cùng bí
mật proxy vào workload đó.

Không dùng Caddy cũ hơn 2.8 cho overlay này vì cấu hình chủ động bỏ access log
ở đường dẫn vé export bằng `log_skip`. Caddyfile còn xóa Authorization, Cookie,
Set-Cookie và secret header của OIDC proxy trước khi ghi log.

## IAM tối thiểu cho khóa

Web runtime chỉ cần tạo data key, decrypt/unwrap và rewrap trên đúng một key
resource; không có quyền tạo/xóa key, sửa policy hoặc export key. Migration job
dùng identity riêng, có thời hạn, và bị thu hồi sau cửa sổ thay đổi. Bật audit
log của Vault/cloud KMS và cảnh báo theo lỗi unwrap, tăng đột biến, truy cập từ
workload lạ và thao tác quản trị khóa.

`LocalAesKeyProvider` chỉ dành cho test/demo. High profile từ chối nó và cũng từ
chối nạp keyring legacy vào tiến trình web.

## Migration không tạo plaintext file

Trong maintenance workload cô lập (không nhận traffic), tạm nạp key legacy và
KMS/Vault mới, nhưng đặt `SECURITY_PROFILE=standard` cho riêng job migration:

```sh
python scripts/migrate_envelope_encryption.py --dry-run
python scripts/migrate_envelope_encryption.py --batch-size 100
python scripts/rewrap_deks.py --dry-run
```

Script giải mã từng dòng trong RAM, mã hóa lại ngay với AAD chứa owner, session,
message UUID, index, role và crypto epoch; không tạo tệp plaintext. Sau khi kiểm
tra mẫu/backup/rollback window, xóa key legacy khỏi web runtime và bật high
profile. Không xóa khóa cũ trước khi mọi dòng đã migrate và restore drill đạt.

Xoay KEK định kỳ hoặc khi nghi lộ bằng provider, sau đó chạy
`scripts/rewrap_deks.py`. Rewrap chỉ thay ciphertext của DEK; không giải mã lại
toàn bộ nội dung hội thoại. Sự cố lộ DEK của riêng một phiên cần xoay DEK phiên
và cân nhắc tái mã hóa dữ liệu, không chỉ rewrap.

## Retention và xóa mật mã

Ứng dụng sweep dữ liệu hết hạn lúc khởi động. Scheduler/CronJob phải chạy thêm:

```sh
python scripts/enforce_retention.py --dry-run
python scripts/enforce_retention.py --batch-size 500
```

Xóa phiên sẽ xóa ciphertext và mọi wrapped DEK, rồi xóa DEK cache trong tiến
trình web. Đây là cryptographic erasure đối với bản dữ liệu hiện hành. Backup,
snapshot, replica và bản xuất của người dùng phải có lifecycle không dài hơn
retention công bố; code ứng dụng không thể xóa một bản sao độc lập mà nó không
kiểm soát.

## Audit WORM

Mỗi checkpoint gửi JSON canonical gồm `format`, `checkpoint_id`,
`last_event_id`, `root_hash`, `created_at`, `signature`, `signer`. Receiver phải:

- xác thực Bearer token/mTLS và `Idempotency-Key`;
- chỉ append, bật object lock/retention lock, không cho web runtime sửa/xóa;
- trả 2xx sau khi dữ liệu đã bền vững;
- cảnh báo gap, rollback ID, root xung đột và im lặng quá SLA;
- sao lưu/giám sát bằng tài khoản khác với đội vận hành SCAP.

`GET /api/admin/audit/verify` trả cả trạng thái chuỗi cục bộ và checkpoint.
`high_assurance_intact=true` chỉ khi chuỗi và checkpoint đều nguyên vẹn, đồng
thời checkpoint ngoài đã được giao nếu cấu hình WORM. Admin có thể ép tạo mốc
bằng `POST /api/admin/audit/checkpoint` sau step-up authentication.

## DLP và AI

Consent có timestamp và policy version; đổi `AI_CONSENT_VERSION` buộc người dùng
đồng ý lại. Chỉ tối đa tám message sau thời điểm consent được giải mã làm context.
Detector chuẩn hóa Unicode và phát hiện secret/JWT/Bearer/private key/API key,
email, điện thoại, thẻ Luhn, CCCD, mã số thuế, dữ liệu sức khỏe và từ điển nội
bộ. Audit chỉ ghi category/count, không ghi mẫu dữ liệu.

- public/internal: allow hoặc redact theo policy;
- confidential: cần xác nhận riêng và redact;
- highly confidential: block egress;
- e2ee private: local-only phía client, máy chủ không gọi provider.

Output của provider cũng qua DLP để ngăn phản chiếu bí mật. Cấu hình high từ
chối demo AI. Vendor AI, DPA, data residency, zero-retention và opt-out training
vẫn phải được phê duyệt ở cấp tổ chức.

## Bằng chứng phát hành

Lưu cùng release: commit SHA, SBOM, attestation, digest image, báo cáo test/SAST/
DAST/dependency/image scan, kết quả restore, bằng chứng checkpoint WORM, cấu hình
guard đã làm sạch secret và biên bản pentest. Nếu thiếu bất kỳ bằng chứng P0
nào, hạ nhãn triển khai về `standard` và không dùng dữ liệu rất nhạy cảm.
