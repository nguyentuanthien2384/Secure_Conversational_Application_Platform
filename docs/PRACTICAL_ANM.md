# Thực hành ANM và xử lý sự cố trong SCAP

SCAP đã có luồng phòng thủ ứng dụng thực chạy: xác thực, phân quyền hội thoại,
quản lý phiên, DLP, IDS/IPS và audit có HMAC. Trước đợt bổ sung này, dự án chưa
có bài học nối mạng và hệ điều hành với bằng chứng ứng dụng, chưa nhóm bài theo
năm giai đoạn trong tài liệu môn học, và chưa có hồ sơ theo dõi điều tra sự cố.

Bản bổ sung đưa các bài học vào tab **Thực hành ANM**, xuất báo cáo kiểm chứng
có thể xem ngoại tuyến, cung cấp PCAP mẫu để đọc bằng Wireshark và lưu hồ sơ
sự cố gắn với các sự kiện audit thực của ứng dụng. Phần mạng/hệ điều hành có
bước quan sát và tiêu chí hoàn thành; SCAP chưa tự thu dữ liệu của host.

## Chạy một lượt thực hành

Từ thư mục dự án, sau khi đã cài thư viện:

```powershell
.\.venv\Scripts\python.exe -m scripts.practice_lab --output-dir reports/practice-lab
```

Linux dùng `.venv/bin/python` thay cho đường dẫn Python Windows. Bộ chạy sử
dụng các kịch bản cố định, API trong tiến trình và SQLite tạm riêng cho từng
kịch bản; không cần API key, Docker hoặc URL mục tiêu. Mỗi lượt chạy dùng dữ
liệu và khóa tạm, không đọc cấu hình `.env` hay CSDL ứng dụng đang sử dụng.

Có thể chọn một hoặc nhiều giai đoạn:

```powershell
.\.venv\Scripts\python.exe -m scripts.practice_lab --stage initial_access --stage persistence --output-dir reports/practice-lab
```

Kết quả gồm:

- `practice-report.html`: báo cáo đọc trong trình duyệt, gồm phạm vi từng
  giai đoạn, check đạt/không đạt và liên kết yêu cầu với bằng chứng audit.
- `practice-summary.json`: tổng hợp máy đọc được theo năm giai đoạn.
- `security-validation.json` và `security-validation.junit.xml`: kết quả
  chi tiết từ bộ kiểm chứng bảo mật đã có.
- `network-training.pcap`: gói DNS/TCP/HTTP tổng hợp hợp lệ để học phân tích.
- `network-training.json`: hướng dẫn, số gói và đáp án đọc PCAP.

Mã thoát khác 0 nghĩa là ít nhất một kiểm chứng thất bại. Chọn giai đoạn chỉ
chạy các kịch bản liên quan; không suy ra phần không chạy đã đạt. Các file
trong thư mục kết quả được cập nhật khi chạy lại.

## Dùng giao diện

```powershell
.\.venv\Scripts\python.exe -m scripts.demo_local
```

Mở `http://127.0.0.1:8000`, đăng nhập tài khoản demo có vai trò moderator hoặc
admin, rồi mở **Thực hành ANM**. Chọn **Làm mới bài thực hành**, chọn bài và đọc
mục tiêu, các bước làm, bằng chứng cần thu, câu hỏi và tiêu chí hoàn thành.
Tài khoản thường không có tab này; API vẫn kiểm tra quyền độc lập với UI.

Danh mục có 11 bài: địa chỉ mạng; phân tích gói; HTTP/TLS; PID và log Windows;
quyền và dịch vụ Linux; bề mặt công khai; IDS/IPS; đăng nhập; quyền sở hữu và
thời hạn phiên; dữ liệu và audit; điều tra và ứng phó. Các bài thủ công không
tự chạy lệnh trên máy người dùng khi chọn trong giao diện.

## Nối nội dung môn học với các kiểm chứng

### 1 Trinh sát

`benign` và `missing-auth` kiểm chứng mẫu truy cập hợp lệ, headers bảo vệ và
từ chối tài nguyên cần xác thực. Bài IP/subnet/gateway/DNS và HTTP/TLS giúp
người học xác định dịch vụ đặt ở đâu và biên truyền dữ liệu. Các bài này không
thực hiện OSINT, kiểm kê Internet hoặc fingerprint máy bên ngoài.

### 2 Quét và xác định dấu hiệu

`encoded-sqli` kiểm chứng phát hiện chữ ký rồi chặn nguồn; `browser-origin`
kiểm chứng từ chối thao tác trình duyệt từ nguồn không tin cậy. Đọc PCAP giúp
nối DNS, IP, cổng và kết nối TCP. Phát hiện chữ ký SQLi không chứng minh khai
thác SQL injection thành công; bộ bài chưa quét cổng hoặc kiểm tra CVE.

### 3 Truy cập ban đầu

`brute-force`, `invalid-token` và `auth-correlation` kiểm chứng khóa/giới hạn
thử đăng nhập, token sai và tương quan đăng nhập bất thường. Phần tương quan
dùng audit được tổng hợp, niêm phong và kiểm tra qua API; không phải cuộc tấn
công thật từ nhiều máy. Người học liên kết HTTP status, request ID và audit
ID trước khi đưa ra nhận định.

### 4 Duy trì và mở rộng quyền truy cập

`idor` và `session-timeout` kiểm chứng quyền sở hữu và thời hạn phiên của
ứng dụng. Bài thủ công PID, tiến trình, quyền file và log hệ điều hành mở rộng
cách quan sát. Kết quả API không chứng minh phát hiện persistence host,
malware, tác vụ khởi động hoặc lateral movement giữa các máy.

### 5 Dữ liệu và dấu vết

`encoded-dlp` kiểm chứng dữ liệu tại biên AI với provider ghi nhận cục bộ;
`audit-tamper` sửa một fixture trong CSDL tạm để kiểm chứng phát hiện log bị
thay đổi. Hồ sơ sự cố giúp ghi nhận bằng chứng, diễn tiến và kết luận. WORM,
EDR, SIEM ngoài hệ thống và sao lưu/khôi phục thực cần môi trường riêng để
đánh giá; báo cáo này không xác nhận chúng đã vận hành.

## Thực hành đọc mạng và hệ điều hành

Mở `network-training.pcap` trong Wireshark. Dùng display filter `dns`, `tcp`
và `http`, đối chiếu số gói trong `network-training.json`. Tìm DNS query và
response cùng transaction ID, ba bước SYN → SYN ACK → ACK, sau đó HTTP
request và response. Địa chỉ TEST-NET và tên `training.invalid` là dữ liệu
mẫu; file này không phải lưu lượng thực của máy người học và không chứa TLS.

Để thu bằng chứng thật của SCAP, bắt gói trên adapter loopback **trước** khi
gọi `GET /api/health` của demo, rồi lọc `tcp.port == 8000`. Chỉ dùng yêu cầu
health không mang thông tin đăng nhập cho bài capture. URL IP loopback không
đòi hỏi DNS và không đi qua gateway. HTTPS phải được quan sát riêng trên môi
trường TLS đã dựng; đánh dấu chưa thực hiện nếu chỉ có demo HTTP.

Trên Windows, đọc `ipconfig /all`, `netstat -ano`, đối chiếu PID với Task
Manager, rồi so sánh Event Viewer với audit SCAP. Đăng nhập SCAP không phải
đăng nhập Windows. Trên Linux/container, đọc `id`, `ls -l`, `ps`, `ss` khi có
sẵn và log của đúng dịch vụ. Bài quan sát không yêu cầu đổi quyền file, thêm
rule firewall hoặc cài công cụ vào image production.

## Lập và xử lý hồ sơ sự cố

1. Trong **Nhật ký kiểm toán**, chọn 1–20 ID audit thực liên quan đến cảnh báo.
2. Trong **Thực hành ANM**, nhập tiêu đề chung không chứa thông tin nhạy cảm,
   giai đoạn, mức độ và các ID để tạo hồ sơ. Backend kiểm tra bằng chứng đã
   niêm phong và giữ snapshot trường cần thiết.
3. Chuyển `new` → `investigating`. Đối chiếu event type, outcome, request ID,
   thời điểm và bằng chứng trước khi xác nhận sự cố.
4. Với sự cố xác nhận, thực hiện biện pháp theo
   [runbook ứng phó](INCIDENT_RESPONSE_HIGH_SECURITY.md) và luồng quản trị
   hiện có: thu hồi phiên, vô hiệu hóa tài khoản, kiểm tra cấu hình/khóa khi
   phù hợp. Kiểm tra lại kết quả rồi ghi `contained`.
5. Chuyển `contained` → `closed` với kết luận `confirmed`. Nếu cảnh báo sai
   hoặc trùng, có thể chuyển `investigating` → `closed` với `false_positive`
   hoặc `duplicate`. Không bỏ qua điều tra để đóng trực tiếp từ `new`.

`contained` là mốc do người điều tra ghi nhận sau khi xác minh, không tự thực
hiện firewall, thu hồi token hoặc khóa tài khoản. UI lưu phiên bản hồ sơ đã
tải; nếu người khác cập nhật trước, API trả `409` và cần tải lại để quyết định
trên bản mới. Mỗi tạo/chuyển trạng thái có audit; không có API xóa hồ sơ hoặc
chỉnh sửa bằng chứng.

ID audit trong báo cáo CLI thuộc các CSDL tạm của từng kịch bản. Không dùng
chúng để lập hồ sơ trên CSDL demo/production. Hồ sơ của demo ngoại tuyến chỉ
tồn tại trong lượt demo và được xóa cùng CSDL tạm khi kết thúc.

## Triển khai và giới hạn vận hành

Development tạo các bảng incident mới bằng cơ chế migration nhẹ hiện có.
Production phải chạy migration bằng role sở hữu trước khi mở app; role app
không được tự nâng schema. Script migration hiện có cũng áp quyền tối thiểu:
bằng chứng và lịch sử incident chỉ thêm/đọc, hồ sơ không được xóa/truncate.
High profile tiếp tục yêu cầu MFA cho vai trò đặc quyền.

Hồ sơ dùng tiêu đề có giới hạn và kết luận cố định, không lưu nội dung tin
nhắn, body yêu cầu, token, mật khẩu hoặc `details` của audit. Nhật ký HMAC và
snapshot giúp truy vết nhưng không thay thế điều tra độc lập khi cả host/khóa
bị chiếm. Retention của hồ sơ cần chính sách vận hành riêng trước khi dùng
với dữ liệu tổ chức thật; cơ chế retention hội thoại không xóa hồ sơ sự cố.

Các kiểm chứng tự động là bằng chứng bảo mật ứng dụng ở phạm vi được nêu,
không phải chứng nhận production hoặc kết luận đã bao phủ toàn bộ hai giáo
trình. Phần VLAN/NAT/ACL trong Packet Tracer/GNS3, Sysmon/EDR, SIEM ngoài hệ
thống, TLS triển khai thực và backup/restore vẫn là các bài mở rộng cần môi
trường tương ứng.

## Tài liệu tham chiếu

- `03. Thực hành cơ bản cho ANM.docx`: IP/DNS/TCP/gói tin, tiến trình, quyền
  truy cập và log Linux/Windows.
- `02. 5 giai đoạn tấn công mạng.docx`: năm giai đoạn và cơ hội phát hiện,
  phòng ngừa, điều tra ở từng giai đoạn.
- [Microsoft ipconfig](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig)
  và [netstat](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat):
  ý nghĩa các trường cấu hình, kết nối và PID.
- [Wireshark display filters](https://www.wireshark.org/docs/man-pages/wireshark-filter.html):
  cú pháp lọc giao thức và trường gói tin.
- [RFC 5737](https://www.rfc-editor.org/info/rfc5737/) và
  [RFC 2606](https://www.rfc-editor.org/info/rfc2606/): địa chỉ và tên miền dành
  cho ví dụ.
