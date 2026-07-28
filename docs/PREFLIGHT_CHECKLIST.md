# Checklist trước khi chạy và nộp

## 1. Trạng thái kiểm chứng — đọc phần này trước

Môi trường tôi làm việc **không có mạng và không cài được thư viện**, nên tôi
**chưa từng khởi động ứng dụng hay chạy `pytest`**. Dưới đây là mức độ tin cậy
thật của từng phần:

| Thành phần | Mức kiểm chứng | Ghi chú |
|---|---|---|
| Regex DLP đã sửa | ✅ Chạy thật, đối chiếu đầu vào/đầu ra | Đã che đúng 7/7 loại dữ liệu nhạy cảm |
| Engine chữ ký IDS | ✅ Chạy thật | 9/9 payload bị bắt, 6/6 lưu lượng thường không báo giả |
| Toán học chuỗi băm audit | ✅ Mô phỏng đầy đủ | Bắt được sửa / xóa / đảo thứ tự / sai khóa |
| Cú pháp toàn bộ file `.py` | ✅ `py_compile` sạch | Không đảm bảo đúng lúc chạy |
| `docker-compose.yml` | ✅ YAML hợp lệ | Chưa `docker compose up` |
| **Tích hợp với FastAPI / SQLAlchemy** | ❌ **Chưa chạy** | Rủi ro còn lại tập trung ở đây |
| **38 test trong `test_security_v2.py`** | ❌ **Chưa chạy** | Viết theo API hiện có, có thể cần chỉnh fixture |
| Xoay khóa trên dữ liệu thật | ❌ Chưa chạy | Bắt buộc `--dry-run` trước |

### Một lỗi tôi tự tìm ra sau khi bàn giao

`seal_event` tra cứu "bản ghi cuối" **sau khi** bản ghi mới đã được flush, nên
nó tìm thấy chính bản ghi mới (chưa có hash) và mọi `prev_hash` đều bằng
genesis. Hệ quả: `/api/admin/audit/verify` sẽ **luôn báo chuỗi gãy** ngay từ
dòng thứ hai.

Đã sửa: truy vấn thêm điều kiện `id < event.id`. Đã mô phỏng lại để xác nhận
chuỗi đúng và vẫn bắt được cả ba kiểu giả mạo.

Nêu điều này ở đây vì nó minh họa đúng luận điểm bạn sẽ trình bày: lỗi bảo mật
thường **im lặng**, và cách duy nhất để bắt là chạy thật.

---

## 2. Ba bước bắt buộc trước khi coi là "chạy được"

```bash
# Bước 1 — cài đặt và khóa phụ thuộc
uv sync --group dev
uv lock                      # BẮT BUỘC: tạo uv.lock rồi commit

# Bước 2 — chạy toàn bộ test
uv run pytest -q
# Kỳ vọng: 4 file cũ PASS. File test_security_v2.py là phần cần soi kỹ nhất.

# Bước 3 — khởi động
cp .env.example .env
python scripts/generate_secrets.py     # điền APP_SECRET_KEY + MASTER_ENCRYPTION_KEY
uv run python run_app.py
```

Mở `http://127.0.0.1:8000` — nếu giao diện Gradio hiện lên và đăng ký/đăng nhập
được thì phần lõi đã chạy.

---

## 3. Kiểm tra khói (smoke test) cho các tính năng mới

Chạy lần lượt, mỗi lệnh phải cho kết quả như mô tả:

```bash
# (a) Chuỗi băm audit — QUAN TRỌNG NHẤT vì đây là chỗ vừa sửa lỗi
#     Đăng nhập bằng tài khoản admin, lấy token vào biến $ADMIN, rồi:
curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/audit/verify
# PHẢI thấy: "chain_intact": true
# Nếu thấy false ngay khi chưa ai sửa gì -> báo lại cho tôi, còn lỗi.

# (b) Cố ý giả mạo rồi xác minh lại
sqlite3 secure_chat.db "UPDATE audit_events SET outcome='success' WHERE id=2;"
curl -s -H "Authorization: Bearer $ADMIN" localhost:8000/api/admin/audit/verify
# PHẢI thấy: "chain_intact": false, "first_broken_id": 2

# (c) IDS
curl -i "localhost:8000/api/health?id=1'%20OR%20'1'='1"
# PHẢI thấy: 403 kèm Retry-After (hoặc 200 ở lần đầu rồi 403 ở lần sau)

# (d) DLP
uv run python -c "
from src.app.services import AIService
print(AIService._redact_for_external_ai('password: SuperSecret123 thẻ 4111 1111 1111 1111'))"
# PHẢI thấy: password=[REDACTED] ... [REDACTED-CARD]

# (e) Log SIEM
uv run python run_app.py | grep 'scap.audit'
# PHẢI thấy JSON một dòng cho mỗi sự kiện
```

---

## 4. Những chỗ dễ hỏng nhất (nếu có lỗi, tìm ở đây trước)

| Triệu chứng | Nguyên nhân khả dĩ | Xử lý |
|---|---|---|
| `chain_intact: false` khi chưa ai sửa gì | SQLite trả `created_at` dạng naive, Postgres trả dạng aware → chuỗi tính lúc ghi và lúc xác minh khác nhau | Đặt `AUDIT_CHAIN_ENABLED=false` để chạy demo, báo lại cho tôi |
| `database is locked` (SQLite) | Middleware IDS mở session riêng khi ghi cảnh báo | Đặt `IDS_ENABLED=false`, hoặc chuyển sang Postgres |
| Giao diện Gradio không tải được | Chữ ký IDS báo giả trên đường dẫn `/gradio_api/...` | Đặt `IDS_ENABLED=false` rồi xem `/api/admin/ids/detections` để biết luật nào bắt nhầm |
| Test `test_health_endpoint...production` treo | `create_app` dựng lại toàn bộ Gradio UI | Có thể bỏ test này, không ảnh hưởng chức năng |
| `column audit_events.prev_hash does not exist` | Database cũ chưa nâng cấp | Xóa `secure_chat.db` rồi chạy lại, hoặc kiểm tra `Database.create_all` |

**Nguyên tắc an toàn khi bảo vệ đồ án:** cả ba tính năng mới đều có công tắc
tắt riêng (`IDS_ENABLED`, `AUDIT_CHAIN_ENABLED`, `SIEM_JSON_LOGS`). Nếu có gì
trục trặc ngay trước giờ demo, tắt tính năng đó — phần lõi của dự án (xác thực,
mã hóa, RBAC, audit) hoàn toàn không phụ thuộc vào chúng.

---

## 5. Dọn dẹp trước khi nộp

```bash
rm -f secure_chat.db .coverage
rm -rf .pytest_cache .ruff_cache
find . -name __pycache__ -type d -exec rm -rf {} +
```

`secure_chat.db` trong bản nộp cũ có chứa dữ liệu thật — `.gitignore` đã loại
nó nhưng file zip vẫn kèm theo.

---

## 6. Trả lời ngắn gọn: đã sẵn sàng chưa?

- **Phần lõi ban đầu của bạn:** đã sẵn sàng, đã chạy được từ trước.
- **Phần tôi bổ sung:** hoàn chỉnh về mã nguồn và tài liệu, nhưng **chưa được
  chạy lần nào**. Cần bạn thực hiện mục 2 và mục 3.
- **Còn thiếu bắt buộc:** `uv lock` (chưa chạy được vì không có mạng).

Hãy dành 15 phút chạy mục 2 và 3 trước. Nếu có lỗi, gửi lại thông báo lỗi cho
tôi — đó là lúc tôi sửa được chính xác thay vì đoán.
