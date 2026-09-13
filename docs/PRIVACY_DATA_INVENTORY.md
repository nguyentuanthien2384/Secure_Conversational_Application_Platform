# Privacy data inventory and DPIA baseline

Tài liệu này là baseline kỹ thuật cho privacy-by-design của SCAP. Nó không phải
ý kiến pháp lý hay chứng nhận GDPR, HIPAA hoặc Luật Bảo vệ dữ liệu cá nhân Việt
Nam. Chủ hệ thống phải điền căn cứ xử lý, chủ thể chịu trách nhiệm, nhà cung cấp
và thời hạn theo môi trường thật trước production.

## 1. Phạm vi và vai trò

- Data controller/quyết định mục đích: phải được tổ chức triển khai chỉ định.
- Processor/subprocessor: nhà vận hành hạ tầng, IdP/OIDC, Vault/KMS, WORM/SIEM,
  backup và nhà cung cấp AI nếu được bật.
- Data owner: chủ tài khoản và chủ hội thoại; thành viên E2EE chỉ nhận dữ liệu
  theo membership/epoch.
- Security/Privacy owner: phải được ghi tên trong hồ sơ release và chịu trách
  nhiệm phê duyệt DPIA, retention, transfer và incident notification.

## 2. Kiểm kê dữ liệu và mục đích tối thiểu

### Tài khoản và xác thực

- Username/định danh IdP: đăng nhập, phân quyền và liên hệ tài khoản.
- Password hash Argon2id: chỉ ở chế độ application auth; không giữ mật khẩu gốc.
- TOTP secret được envelope-encrypt, recovery code chỉ giữ hash; dùng cho MFA.
- Login-session ID, token version, thời điểm, IP và user-agent đã làm sạch: phát
  hiện chiếm tài khoản, thu hồi phiên và điều tra sự cố.
- Public identity key, signed prekey, one-time prekey, device ID/fingerprint:
  thiết lập trust cho client Private E2EE; server không nhận private key.

### Nội dung và metadata hội thoại

- `secure`/`confidential`: ciphertext AES-256-GCM, nonce, wrapped DEK, AAD-bound
  identifiers; server chỉ giải mã cho luồng đã xác thực/ủy quyền.
- `private_e2ee`: opaque ciphertext, public routing header, membership và epoch;
  server không nhận plaintext, message key, ratchet state hay MLS secret.
- Tiêu đề, owner/member ID, mode/classification, timestamp, message index và
  retention deadline: định tuyến, authorization, replay protection và lifecycle.
- Không thu thập location, contact list, microphone/camera hoặc advertising ID.

### AI và DLP

- External AI mặc định cần consent có version/timestamp; Private E2EE và dữ liệu
  `highly_confidential` không được gửi cloud AI.
- Khi được phép, chỉ message hiện tại và tối đa tám message sau thời điểm consent
  đi qua DLP; secret/identifier bị block hoặc redact theo classification.
- Audit chỉ giữ category/action/provider và opaque ID, không giữ matched value,
  prompt hay response plaintext.
- Differential privacy chỉ phù hợp cho thống kê tổng hợp đã được phê duyệt; nó
  không thay thế DLP cho prompt chứa dữ liệu cụ thể.

### Audit, CSP và vận hành

- Audit giữ actor/target opaque ID, event/outcome, request ID, source IP,
  user-agent đã DLP-redact và metadata allowlisted/scrubbed.
- CSP reporting chỉ giữ directive, status code và URL origin; path, query,
  script sample, DOM snippet và nội dung người dùng bị loại bỏ.
- Không đưa access token, password, key, connection string hoặc chat body vào
  log. Export capability URL bị loại khỏi access log và telemetry path.

## 3. Retention và xóa

- `secure`: mặc định tối đa 90 ngày; `confidential`/`private_e2ee`: mặc định tối
  đa 7 ngày. Thay đổi policy chỉ được rút ngắn, không được gia hạn deadline cũ.
- Retention sweep chạy khi khởi động, khi truy cập và qua scheduled command; xóa
  message/envelope metadata, wrapped DEK và auth-session metadata hết hạn.
- Xóa session hoặc tài khoản theo luồng được ủy quyền sẽ cascade dữ liệu liên
  quan; sự kiện xóa tối thiểu vẫn ở audit/WORM để chứng minh thao tác.
- Backup, snapshot, SIEM và WORM phải có lifecycle riêng tương ứng legal hold và
  nghĩa vụ chứng cứ. Không thể tuyên bố erasure hoàn tất nếu bản sao ngoài hệ
  thống chưa hết hạn hoặc chưa được crypto-erase theo quy trình đã duyệt.

## 4. Quyền của chủ thể dữ liệu

Quy trình vận hành phải xác minh danh tính và ghi audit trước khi thực hiện:

- Access/portability: dùng export streaming sau step-up; E2EE export chỉ chứa
  ciphertext mà client tin cậy tự giải mã.
- Rectification: thay đổi thông tin tài khoản qua IdP/admin được ủy quyền; không
  sửa lịch sử audit.
- Erasure: xóa session/tài khoản bằng API có authorization, sau đó theo dõi
  backup/WORM lifecycle và các ngoại lệ legal hold.
- Withdraw consent: tắt AI consent có hiệu lực cho mọi lần gửi tiếp theo; consent
  version mới bắt buộc người dùng đồng ý lại.
- Restriction/objection: khóa tài khoản, tắt external AI hoặc chuyển sang
  confidential/Private E2EE trước khi có dữ liệu.
- Complaint/contact: địa chỉ và SLA phải được controller điền trong privacy
  notice; không dùng địa chỉ mẫu trong tài liệu này.

## 5. Transfer và nhà cung cấp

Trước khi bật một dịch vụ ngoài, hồ sơ release phải ghi: pháp nhân, vùng dữ liệu,
loại dữ liệu, mục đích, retention/logging, subprocessor, cơ chế transfer, DPA/BAA
nếu áp dụng, quyền xóa/export và cách thông báo sự cố. Riêng Gemini/cloud AI phải
xác minh paid/ZDR feature thực tế; không suy luận ZDR chỉ từ việc có billing.

Vault/KMS, IdP, WORM/SIEM và backup cũng là processor/security dependency và cần
supplier review, IAM tối thiểu, rotation, availability và exit plan.

## 6. DPIA release gate

Không phát hành high-sensitivity nếu chưa có câu trả lời và owner phê duyệt cho:

1. Mục đích có cần thiết/tương xứng hay có cách ít dữ liệu hơn?
2. Có dữ liệu sức khỏe, sinh trắc học, vị trí, trẻ em, profiling hoặc quy mô lớn?
3. Threat model bao phủ DB theft, app/KMS compromise, insider, XSS, AI leakage,
   endpoint loss, backup, metadata/traffic analysis và cross-border transfer?
4. Retention, legal hold, backup deletion và key destruction có kiểm thử được?
5. Consent/lawful basis và privacy notice có đúng với từng mode/AI provider?
6. DLP benchmark có false-positive/false-negative corpus đại diện dữ liệu thật?
7. Quyền access/rectification/erasure/restriction có owner và SLA?
8. Incident notification, regulator/customer contact và evidence preservation đã
   tabletop; restore drill và pentest độc lập đã đạt?

Nếu rủi ro cao còn lại không thể giảm, dừng go-live và thực hiện bước tham vấn/
phê duyệt theo pháp luật và chính sách tổ chức áp dụng.

## 7. HIPAA và tuyên bố tuân thủ

Chỉ đánh giá HIPAA khi tổ chức là covered entity/business associate và dữ liệu là
ePHI thuộc phạm vi. Khi đó cần BAA phù hợp với cloud/AI processor, administrative,
physical và technical safeguards, risk analysis, contingency plan và bằng chứng
vận hành. Mã hóa, MFA hoặc KMS riêng lẻ không tạo thành tuyên bố "HIPAA compliant".

