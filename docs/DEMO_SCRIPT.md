# Kịch bản demo chi tiết

Tài liệu này viết cho người **đứng trước giảng viên và bấm từng nút**. Mỗi mục
có: thao tác cụ thể, kết quả mong đợi, và một câu giải thích ngắn để nói ra
miệng. Thời lượng đầy đủ ~12 phút; bản rút gọn ~6 phút (chỉ làm các mục ★).

> Quy ước: `[Tab X]` là tab trên giao diện web, `→` là thao tác kế tiếp.
> Bản tóm tắt của kịch bản này nằm ở mục 8 của `HUONG_DAN_CHAY.md`.

---

## 0. Chuẩn bị trước khi vào phòng (làm trước 15 phút)

### Ba chốt kiểm tra — làm lần lượt, chốt trước pass rồi mới sang chốt sau

| # | Lệnh | Đạt khi thấy |
|---|---|---|
| 1 | `uv run python src/core/ai_core/gemini_ai.py` | In ra câu trả lời thật, vd. *"Hello! How can I help you today?"* |
| 2 | `uv run pytest -q` | `106 passed` |
| 3 | `uv run python run_app.py` | `Uvicorn running on http://127.0.0.1:8000` |

Chạy tuần tự để khoanh vùng lỗi cho dễ: chốt 1 hỏng là vấn đề key/model/mạng,
chưa liên quan tới mã ứng dụng.

**Chốt 2 quan trọng nhất với đồ án:** ảnh chụp màn hình kết quả `pytest` là
**bằng chứng trực tiếp** cho phần kiểm thử trong báo cáo. Chụp cả dòng tổng kết
`106 passed`. Muốn kèm độ phủ thì dùng lệnh đầy đủ ở mục 10.

> **Nếu máy chưa cài `uv`** (`uv: command not found`): chạy `bash setup.sh --no-run`
> để cài, hoặc dùng thẳng môi trường ảo — thay `uv run` bằng
> `.venv\Scripts\python.exe` (Windows) / `.venv/bin/python` (macOS, Linux).

### Danh sách chuẩn bị

| Việc | Lệnh / thao tác | Xác nhận |
|---|---|---|
| Cài đặt & sinh secrets | `bash setup.sh --no-run` | Có file `.env` |
| Dán Gemini key | Sửa `.env`: `GOOGLE_GENAI_API_KEY=<key>`, `GEMINI_MODEL=gemini-flash-lite-latest` | — |
| Thử key (chốt 1) | `uv run python src/core/ai_core/gemini_ai.py` | In ra câu trả lời |
| Chạy test (chốt 2) | `uv run pytest -q` | `106 passed` |
| Khởi động (chốt 3) | `uv run python run_app.py` | `Uvicorn running on …:8000` |
| Bật đồng ý AI | Đăng nhập `demo.user` → `[Tab Tài khoản]` → tick ô đồng ý | Ô được tick |
| Gửi thử 1 tin | `[Tab Trò chuyện]` | Trả lời **không** có tiền tố `[DEMO AI]` |

> **Về tên model:** dùng alias `gemini-flash-lite-latest`, đừng ghim số phiên bản.
> Google khai tử model cũ theo thời gian — `gemini-2.5-flash-lite` nay trả **404**
> *"no longer available to new users"*. Alias tự trỏ sang thế hệ còn hiệu lực.

**Mở sẵn 3 tab trình duyệt:**

1. `http://127.0.0.1:8000` — giao diện chính
2. `http://127.0.0.1:8000/docs` — Swagger (dùng cho mục 5)
3. Một cửa sổ ẩn danh — để đăng nhập tài khoản thứ hai mà không mất phiên đầu

**Chuẩn bị thêm:** điện thoại có Google Authenticator; cửa sổ terminal đang
chạy server để trỏ vào log khi cần (mục 9).

**Tài khoản** (mật khẩu chung `Phenikaa-Vault#2026-Lab`):

| Tài khoản | Vai trò | Tab nhìn thấy |
|---|---|---|
| `demo.user` | user | Trò chuyện, Dữ liệu mã hóa, Tìm kiếm, Tài khoản |
| `demo.mod` | moderator | + Nhật ký kiểm toán, Bảo mật |
| `demo.boss` | admin | + Quản trị (đầy đủ) |

> **Nếu lỡ bị IDS chặn IP giữa buổi demo:** chờ 15 phút, hoặc dừng server,
> đặt `IDS_ENABLED=false` trong `.env`, chạy lại. Biết trước đường thoát này
> quan trọng hơn bạn tưởng — mục 6 và 7 rất dễ tự chặn chính mình.

---

## 1. ★ Xác thực — Argon2id và thông báo lỗi chung chung (1 phút)

**Thao tác**

1. Ở màn hình đăng nhập, nhập `demo.user` với mật khẩu **sai** → Đăng nhập
2. Nhập tài khoản **không tồn tại** `khong.ton.tai` với mật khẩu bất kỳ → Đăng nhập
3. Đăng nhập đúng bằng `demo.user` / `Phenikaa-Vault#2026-Lab`

**Kết quả mong đợi:** hai lần sai cho ra **cùng một thông báo lỗi**, không phân
biệt "sai mật khẩu" với "không có tài khoản này".

**Nói gì:** mật khẩu lưu bằng Argon2id — hàm băm thắng Password Hashing
Competition, có tham số điều chỉnh chi phí bộ nhớ nên chống được tấn công bằng
GPU/ASIC, khác hẳn MD5 hay SHA-1 vốn tính rất nhanh. Thông báo lỗi cố tình
giống nhau để không cho phép **liệt kê tài khoản** (user enumeration): nếu hệ
thống nói "tài khoản không tồn tại", kẻ tấn công có ngay danh sách username
hợp lệ để dồn sức brute-force.

---

## 2. ★ Mã hóa dữ liệu khi lưu trữ — AES-256-GCM (2 phút)

**Thao tác**

1. `[Tab Trò chuyện]` → chọn một hội thoại → gửi tin nhắn, ví dụ:
   `Mã số sinh viên của tôi là 21010999 và tôi đang học môn An toàn ứng dụng`
2. Đợi bot trả lời
3. Chuyển sang `[Tab Dữ liệu mã hóa]` → chọn đúng hội thoại đó → **Tải bản mã**

**Kết quả mong đợi:** bảng hiện `ciphertext` base64, `nonce` riêng cho từng
bản ghi, và cột `Key ver.`. Không đọc được chữ nào của tin nhắn gốc.

**Nói gì:** đây là dữ liệu **thật sự nằm trong database**. Chọn AES-256-GCM vì
nó là chế độ mã hóa có xác thực (AEAD) — vừa bảo mật vừa chống sửa đổi; nếu ai
đó lật một bit trong ciphertext, thẻ xác thực sẽ không khớp và giải mã thất bại
thay vì trả về rác. Mỗi bản ghi có nonce riêng, không bao giờ tái sử dụng.
Khóa **không nằm trong database** mà đọc từ biến môi trường, nên kẻ tấn công
chỉ dump được file DB thì vẫn không đọc được gì.

**Điểm nhấn thêm:** cột `Key ver.` phục vụ xoay vòng khóa —
`scripts/rotate_encryption_key.py` cho phép đổi khóa mà dữ liệu cũ vẫn giải mã
được, vì mỗi bản ghi nhớ nó được mã bằng khóa phiên bản nào.

> **Lưu ý nhỏ:** mã số 8 chữ số như `21010999` **không** bị DLP che (luật chỉ
> bắt dãy 9–12 chữ số), nên bot vẫn "thấy" nó — đúng ý đồ ở mục này. Nếu bạn
> đổi sang mã 9–12 chữ số, nó sẽ bị che và bot trả lời chung chung hơn.

---

## 3. ★ Chống rò rỉ dữ liệu ra bên thứ ba — DLP + đồng thuận (2 phút)

Đây là mục dễ ghi điểm nhất vì hầu hết đồ án chat AI không có.

**Thao tác**

1. `[Tab Tài khoản]` → **bỏ tick** ô đồng ý gửi dữ liệu ra AI bên ngoài
2. Quay lại `[Tab Trò chuyện]` → gửi một tin bất kỳ

   **Kết quả:** báo lỗi 403 *"Cần đồng ý trước khi gửi nội dung đến nhà cung
   cấp AI bên ngoài."*

3. Tick lại ô đồng ý
4. Gửi tin nhắn có dữ liệu nhạy cảm, ví dụ:

   `Email của tôi là nguyenvana@gmail.com, số thẻ 4111 1111 1111 1111, api_key=SECRET123. Hãy tóm tắt giúp tôi.`

**Kết quả mong đợi:** dải băng DLP hiện dưới khung chat, liệt kê đúng **ba loại**
đã che — `API key / token`, `số thẻ`, `email` — mà **không hiện lại giá trị**.
Cái mà Gemini thực sự nhận được là:

```
Email của tôi là [REDACTED-EMAIL], số thẻ [REDACTED-CARD], api_key=[REDACTED] Hãy tóm tắt giúp tôi.
```

**Nói gì:** trước khi bất kỳ nội dung nào rời khỏi biên tin cậy sang Google,
lớp DLP quét và thay thế các mẫu nhạy cảm. Quan trọng: báo cáo chỉ nêu *loại*
dữ liệu bị che, không echo lại giá trị — nếu in ra "đã che thẻ
4111-1111-1111-1111" thì chính báo cáo lại là chỗ rò rỉ mới, và nó còn bị ghi
vào nhật ký kiểm toán.

Cơ chế đồng thuận (`ai_data_consent`) mặc định **tắt**: hệ thống không gửi dữ
liệu người dùng cho bên thứ ba khi chưa được cho phép tường minh — đúng nguyên
tắc privacy by default của GDPR.

**Nếu giảng viên hỏi "DLP này có tuyệt đối không?":** trả lời thẳng là không.
Đây là phòng thủ theo chiều sâu, không thay thế được sản phẩm DLP thương mại;
biểu thức chính quy luôn có thể bị lách bằng cách viết biến thể. Giá trị của
nó là chặn được các trường hợp vô ý phổ biến. Trả lời trung thực như vậy ghi
điểm cao hơn là khẳng định quá đà.

---

## 4. ★ Xác thực hai lớp TOTP (2 phút)

**Thao tác**

1. `[Tab Tài khoản]` → mục *Xác thực hai lớp (TOTP)* → **Bắt đầu thiết lập 2FA**
2. Mở Google Authenticator trên điện thoại → quét mã QR
3. Nhập mã 6 số đang hiện trên điện thoại → **Kích hoạt**
4. **Chụp/lưu lại danh sách mã khôi phục hiện ra** — nó chỉ hiện đúng một lần
5. Đăng xuất → đăng nhập lại `demo.user` → hệ thống hỏi mã 6 số → nhập → vào được

**Nói gì:** TOTP theo RFC 6238, mã đổi mỗi 30 giây, sinh từ một bí mật chia sẻ
nên **không cần mạng** — khác OTP qua SMS vốn dễ bị SIM swap và chặn ở tầng
mạng viễn thông. Mã khôi phục chỉ hiện một lần và được lưu dưới dạng băm, dùng
được đúng một lần mỗi mã, để người dùng mất điện thoại không mất luôn tài khoản.

**Mẹo:** nếu điện thoại quét QR không ra, dùng ô *Khóa thủ công* để nhập tay
vào app xác thực.

---

## 5. ★ Kiểm soát truy cập — thử tấn công IDOR (2 phút)

Đây là mục nên demo bằng Swagger để giảng viên thấy rõ là bạn gọi API trực tiếp,
không bị giao diện che.

**Chuẩn bị:** đăng nhập `demo.boss` ở cửa sổ ẩn danh, tạo một hội thoại mới,
copy `session_id` của nó.

**Thao tác**

1. Ở cửa sổ chính (đang là `demo.user`), mở `/docs`
2. Lấy access token của `demo.user`: gọi `POST /api/auth/login` trong Swagger,
   copy `access_token` → bấm **Authorize** dán vào
3. Gọi `GET /api/sessions/{session_id}/messages` với `session_id` **của
   demo.boss**

**Kết quả mong đợi:** 404 (hoặc 403), không trả về nội dung.

4. Chuyển sang `demo.mod` hoặc `demo.boss` → `[Tab Nhật ký kiểm toán]` →
   **Tải nhật ký** → tìm dòng `authorization.denied`

**Nói gì:** IDOR là lỗ hổng đứng đầu OWASP Top 10 2021 ở hạng mục A01 Broken
Access Control. Ở đây mọi truy vấn hội thoại đều gắn điều kiện `owner_id =
người dùng hiện tại` ngay trong câu truy vấn, chứ không phải lấy ra rồi mới
kiểm tra — nên không có đường nào quên kiểm tra.

**Điểm nhấn đáng nói:** kể cả tài khoản **admin cũng không đọc được** nội dung
chat của người khác qua API. Đây là quyết định thiết kế có chủ đích: trang quản
trị dùng để giám sát an ninh, không phải để giám sát người dùng. Trả lời trước
câu hỏi này thường gây ấn tượng tốt.

---

## 6. Chống brute-force và khóa tài khoản (1 phút)

> Làm mục này **sau** mục 5, vì nó có thể kích hoạt IDS.

**Thao tác**

1. Đăng xuất → nhập sai mật khẩu `demo.user` **6 lần liên tiếp**
2. Lần thứ 6 trở đi, kể cả nhập **đúng** mật khẩu vẫn không vào được

**Nói gì:** hai lớp chặn cùng lúc — giới hạn tần suất theo cửa sổ trượt trên
địa chỉ nguồn (`LOGIN_MAX_ATTEMPTS`/`LOGIN_WINDOW_SECONDS`), và khóa tài khoản
tạm thời sau số lần sai (`LOGIN_LOCKOUT_SECONDS`, mặc định 15 phút). Lớp thứ
nhất chặn kẻ tấn công dò nhiều tài khoản từ một IP; lớp thứ hai chặn kẻ tấn
công dò một tài khoản từ nhiều IP (credential stuffing).

**Khôi phục để demo tiếp:** chờ 15 phút, hoặc dừng server → xóa
`secure_chat.db` → chạy lại (dữ liệu mẫu sẽ tự tạo lại). Chuẩn bị sẵn tài
khoản `demo.mod` để đăng nhập tiếp mà không phải chờ.

---

## 7. IDS/IPS tầng ứng dụng (1,5 phút)

**Thao tác**

1. Đăng nhập `demo.mod` hoặc `demo.boss`
2. Trên thanh địa chỉ, gọi thẳng một URL mang chữ ký tấn công:

   ```
   http://127.0.0.1:8000/api/search/messages?q=' OR 1=1--
   ```

   rồi thử một đường dẫn mồi nhử:

   ```
   http://127.0.0.1:8000/wp-admin
   ```

3. `[Tab Bảo mật]` → **Làm mới toàn bộ** → xem mục *2 · IDS — mẫu tấn công đã
   phát hiện*: có dòng `SQLI-002` và dòng đường dẫn mồi nhử
4. Mục *3 · IDS — hành vi bất thường* → **Phân tích**: thấy cụm sự kiện đăng
   nhập thất bại từ mục 6
5. Mục *4 · IPS — nguồn đang bị chặn*: nếu điểm rủi ro tích lũy vượt ngưỡng,
   IP của bạn xuất hiện ở đây

**Nói gì:** hai engine phản ánh đúng phân loại trong bài giảng. Engine **chữ
ký** khớp mẫu trên URL và header — nhanh, bắt tốt công cụ quét đã biết, nhưng
mù trước tấn công mới. Engine **bất thường** thống kê trên chính luồng audit
của ứng dụng — phát hiện được credential stuffing và chuỗi từ chối quyền liên
tiếp kiểu dò IDOR. Khi điểm rủi ro vượt ngưỡng, hệ thống chuyển từ *phát hiện*
sang *ngăn chặn*, tạm chặn địa chỉ nguồn.

**Câu nên nói thêm để tránh bị phản biện:** SQL injection ở dự án này vốn đã
bất khả thi về mặt cấu trúc, vì mọi truy vấn đi qua tham số hóa của SQLAlchemy.
Engine chữ ký tồn tại để **ghi nhận nỗ lực tấn công**, không phải là lý do ứng
dụng an toàn. Khớp mẫu trên URL rất dễ lách. Nói rõ giới hạn này thường được
đánh giá cao hơn là trình bày nó như lớp phòng thủ chính.

**Lưu ý:** IDS chỉ quét URL và header, **không đọc body** — cố ý, vì đệm body
trong middleware sẽ phá streaming và tạo ra một sơ hở khuếch đại bộ nhớ. Vì
vậy gõ `' OR 1=1` vào ô chat sẽ **không** kích hoạt IDS; phải đưa vào query
string như bước 2.

---

## 8. ★ Nhật ký kiểm toán chống giả mạo (1,5 phút)

Đây là mục kỹ thuật ấn tượng nhất, nên để cuối.

**Thao tác**

1. Đăng nhập `demo.boss` → `[Tab Bảo mật]` → mục 1 → **Xác minh chuỗi**

   **Kết quả:** báo chuỗi nguyên vẹn, kèm số bản ghi đã xác minh.

2. Giờ đóng vai kẻ tấn công có quyền ghi vào database. Mở terminal thứ hai:

   ```bash
   sqlite3 secure_chat.db "UPDATE audit_events SET outcome='success' WHERE outcome='denied' LIMIT 1;"
   ```

3. Quay lại giao diện → **Xác minh chuỗi** lần nữa

   **Kết quả:** chuỗi **gãy**, chỉ đúng vị trí bản ghi bị sửa.

**Nói gì:** mỗi bản ghi kiểm toán cam kết vào bản ghi trước bằng
`HMAC-SHA256(khóa, prev_hash ‖ nội_dung_bản_ghi)` — cùng ý tưởng với chuỗi khối,
nhưng chỉ cần một khóa bí mật thay vì cả mạng đồng thuận. Kẻ tấn công chiếm
được quyền ghi database vẫn không sửa được lịch sử một cách im lặng: sửa một
dòng làm gãy toàn bộ chuỗi từ điểm đó về sau, và muốn tính lại chuỗi thì phải
có khóa HMAC, mà khóa đó không nằm trong database.

Đây là thuộc tính **Accounting** trong bộ AAA — và là thứ thường bị bỏ qua:
nhật ký kiểm toán mà kẻ tấn công sửa được thì không phải bằng chứng.

**Khôi phục:** `uv run python scripts/repair_audit_chain.py` hoặc xóa
`secure_chat.db` rồi seed lại.

---

## 9. Xử lý lỗi an toàn — CWE-209 (1 phút, tùy chọn)

Mục này chứng minh bạn hiểu rằng *thông báo lỗi cũng là bề mặt tấn công*.

**Thao tác**

1. Dừng server → sửa `.env`, làm hỏng key: `GOOGLE_GENAI_API_KEY=AIzaSyHONG`
2. Chạy lại server → đăng nhập → gửi một tin nhắn

**Kết quả mong đợi:** thông báo *"Dịch vụ AI tạm thời không khả dụng. Vui lòng
thử lại sau. Thử lại sau 30 giây."* — **không** có traceback, không có tên
model, không có mã lỗi của Google, không có mảnh API key nào. Mã trạng thái là
**503** kèm header `Retry-After: 30`.

3. Chỉ vào terminal đang chạy server: nguyên nhân thật (401 UNAUTHENTICATED)
   nằm đầy đủ trong log phía máy chủ, logger `secure_chat.ai`.

**Nói gì:** đây là CWE-209 — *Information Exposure Through an Error Message*,
thuộc A09 trong OWASP Top 10. Nếu để exception của SDK lọt ra client, kẻ tấn
công biết được stack công nghệ, phiên bản thư viện, đôi khi cả đường dẫn hệ
thống. Nguyên tắc: **chi tiết cho người vận hành, thông báo chung cho người
dùng**. Và mã trạng thái phải đúng ngữ nghĩa — đây là 503 (lỗi tạm thời phía
nhà cung cấp, có thể thử lại), không phải 500.

Có test tự động khóa hành vi này: `tests/test_ai_provider_errors.py`, trong đó
một test khẳng định chuỗi `AIzaSy`, `googleapis.com` và `Traceback` không bao
giờ xuất hiện trong response HTTP.

**Nhớ khôi phục key đúng sau khi demo xong.**

---

## 10. Bằng chứng kiểm thử và quét bảo mật (1 phút)

Chạy trước buổi demo, chụp màn hình đưa vào báo cáo; trên lớp chỉ cần chiếu ảnh.

```bash
uv run pytest --cov=src.app --cov-report=term-missing   # kiểm thử + độ phủ
uv run ruff check src tests scripts                      # lint
uv run bandit -q -r src/app -ll -ii                      # SAST
uv export --frozen --no-dev --no-emit-project --output-file /tmp/req.txt
uv run pip-audit -r /tmp/req.txt                         # SCA — CVE của dependency
```

DAST bằng OWASP ZAP (cần Docker, server đang chạy):

```bash
bash scripts/run_zap_baseline.sh http://host.docker.internal:8000
```

**Nói gì:** bốn tầng kiểm thử khác nhau — unit/regression test cho logic, SAST
đọc mã nguồn tìm mẫu nguy hiểm, SCA đối chiếu thư viện với cơ sở dữ liệu CVE,
DAST tấn công ứng dụng đang chạy từ bên ngoài. Không tầng nào thay được tầng
nào: SAST không thấy lỗi cấu hình runtime, DAST không thấy nhánh code không
được kích hoạt.

---

## Bản rút gọn 6 phút

Nếu bị giục thời gian, làm đúng các mục ★ theo thứ tự: **1 → 2 → 3 → 4 → 5 →
8**. Bỏ mục 6, 7, 9, 10 và chỉ nhắc bằng lời rằng chúng có trong báo cáo.

---

## Những câu hỏi giảng viên hay hỏi

**"Nếu mất `MASTER_ENCRYPTION_KEY` thì sao?"**
Mất toàn bộ dữ liệu chat — đúng theo thiết kế, vì khóa không nằm trong database.
Đó là cái giá của mã hóa thật. Có `scripts/rotate_encryption_key.py` để xoay
khóa mà giữ dữ liệu, nhờ trường `key_version` trên từng bản ghi.

**"Sao không mã hóa đầu cuối luôn?"**
Vì tính năng cốt lõi là gửi nội dung cho AI xử lý — máy chủ buộc phải đọc được
plaintext tại thời điểm đó. E2EE thật sự sẽ loại bỏ luôn tính năng này. Phạm vi
bảo vệ ở đây là **at-rest**, và nói rõ giới hạn đó là trung thực hơn là gán
nhãn E2EE cho một hệ thống không phải E2EE.

**"IDS này chặn được tấn công thật không?"**
Chặn được công cụ quét tự động và kẻ tấn công nghiệp dư. Người biết việc lách
được dễ dàng vì nó khớp mẫu trên chuỗi. Giá trị chính là **phát hiện và ghi
nhận**, phục vụ điều tra sau sự cố, chứ không phải là lớp bảo vệ chính.

**"Rate limit lưu ở đâu, nhiều instance thì sao?"**
Mặc định lưu trong bộ nhớ tiến trình — chỉ đúng khi chạy một instance. Vì vậy
cấu hình production **bắt buộc** `REDIS_URL`; `src/app/config.py` từ chối khởi
động ở môi trường production nếu thiếu biến này.

**"Nếu Gemini bị prompt injection thì sao?"**
Nội dung người dùng được bọc trong JSON và đánh dấu là dữ liệu không tin cậy,
chỉ thị hệ thống truyền qua trường `system_instruction` của SDK chứ không nối
vào chuỗi prompt. Nhưng cần nói thẳng: đây là giảm thiểu, không phải giải pháp
triệt để — prompt injection hiện chưa có cách phòng chống hoàn toàn. Điều bảo
đảm được là mô hình **không có quyền gọi công cụ hay truy cập dữ liệu người
dùng khác**, nên injection thành công cũng chỉ ảnh hưởng nội dung câu trả lời
trong chính phiên đó.

**"Sao model lại là `gemini-flash-lite-latest` mà không ghim phiên bản?"**
Vì Google khai tử model theo thời gian: bản ghim `gemini-2.5-flash-lite` nay
trả 404 *"no longer available to new users"*. Alias `-latest` tự trỏ sang thế hệ
còn hiệu lực. Đánh đổi là hành vi model có thể thay đổi giữa các lần chạy — với
đồ án thì tính chạy được quan trọng hơn tính tái lập tuyệt đối.
