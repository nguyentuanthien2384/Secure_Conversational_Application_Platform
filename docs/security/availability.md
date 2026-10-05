# Giới hạn tài nguyên và vận hành an toàn

Dự án hiện dùng trên laptop, truy cập qua `127.0.0.1` hoặc `localhost` và chưa có tên miền. Các biện pháp trong ứng dụng hoạt động ở chế độ local; việc mua tên miền, mở cổng router, cấu hình CDN hoặc triển khai production chưa được thực hiện.

## Các giới hạn đã có trong ứng dụng

Ứng dụng từ chối sớm khi hết ngân sách, thay vì giữ thêm một hàng đợi không giới hạn. API trả `429` khi vượt số yêu cầu theo cửa sổ thời gian, hoặc `503` khi hết năng lực xử lý/tầng rate limit không khả dụng. Phản hồi có `Retry-After`; client cần chờ, tránh tự thử lại liên tục.

Các giá trị mặc định có thể cấu hình bằng biến môi trường:

- `REQUEST_MAX_CONCURRENT=32`: yêu cầu HTTP thông thường đang xử lý trong một worker.
- `REQUEST_MAX_STREAMS=16`: luồng Gradio SSE đang mở, tách khỏi ngân sách HTTP thông thường.
- `REQUEST_IP_MAX_CONCURRENT=16`, `REQUEST_IP_MAX_STREAMS=2`: giới hạn cùng lúc cho từng IP. Trần 8 đã chặn cold load module Gradio trong trình duyệt local; 16 giữ giới hạn và cho phép tải giao diện. Nếu `.env` cũ đặt 8 rõ ràng, cần điều chỉnh biến đó; biến đã đặt luôn ưu tiên hơn default mới.
- `REQUEST_WINDOW_SECONDS=60`, `REQUEST_GLOBAL_MAX_ATTEMPTS=600`, `REQUEST_IP_MAX_ATTEMPTS=300`: số yêu cầu trong cửa sổ thời gian.
- `AUTH_GLOBAL_MAX_ATTEMPTS=120`: trần chung cho các POST vào `/api/auth/`, bổ sung cho giới hạn đăng nhập/MFA/khôi phục riêng.
- `PASSWORD_MAX_CONCURRENT=2`: phép băm/xác minh Argon2 đồng thời, kể cả đăng nhập, đổi mật khẩu và mã khôi phục. Với tham số hiện tại, hai phép Argon2 sử dụng khoảng 128 MiB riêng cho vùng nhớ băm; còn phải dự phòng RAM cho ứng dụng và hệ điều hành.
- `AI_MAX_CONCURRENT=2`: lời gọi AI bên ngoài đang chạy trong một tiến trình.
- `AI_GLOBAL_MAX_ATTEMPTS=60`, `AI_DAILY_MAX_ATTEMPTS=1000`: ngân sách lời gọi AI theo phút và theo cửa sổ 24 giờ.
- `AI_MAX_OUTPUT_TOKENS=1024`: trần token đầu ra mỗi lần gọi model; `GEMINI_TIMEOUT_SECONDS=20` là timeout cấu hình cho SDK.
- `GRADIO_QUEUE_MAX_SIZE=32`, `GRADIO_CONCURRENCY_LIMIT=4`: hàng đợi giao diện hữu hạn và trần mặc định cho mỗi nhóm callback.
- `GRADIO_RETAINED_EVENTS=128`, `GRADIO_RESULT_TTL_SECONDS=120`: số kết quả/sự kiện giữ lại và thời hạn lưu kết quả, tránh tích lũy phản hồi sau khi client rời đi.
- `GRADIO_STATE_CAPACITY=256`: số state giao diện được giữ; vé chuyển phiên và browser-session store cũng có giới hạn dung lượng/thời gian riêng.

Trần concurrency bảo vệ từng tiến trình/worker. Khi chạy nhiều worker, tổng RAM và số tác vụ đồng thời tăng theo số worker. Redis phối hợp quota theo thời gian giữa các worker; nó không biến semaphore trong bộ nhớ thành semaphore toàn cụm. Chế độ local không có Redis dùng bộ đếm trong tiến trình, mất lịch sử quota khi khởi động lại.

Limiter dự phòng giữ tối đa 10.000 khóa và không đẩy khóa đang còn ngân sách ra khỏi bộ nhớ để nhận khóa mới. Mỗi Redis limiter có pool tối đa 16 kết nối, timeout kết nối/đọc 3 giây và không retry. PostgreSQL trong web runtime có tối đa 5 kết nối pool + 5 overflow, chờ pool/kết nối tối đa 5 giây, statement 30 giây và lock 5 giây. Giới hạn từng thao tác không phải thời hạn tuyệt đối cho toàn bộ request; DNS, nhiều bước tuần tự và xử lý cục bộ còn cần đo riêng. Migration/maintenance giữ cấu hình cũ để không cắt tác vụ quản trị dài.

Gradio dọn kết quả khi nhận yêu cầu/đọc tiếp: TTL giới hạn khả năng dùng lại, không hứa xóa mọi dữ liệu đúng giây thứ 120 khi hệ thống đứng yên. Trần lưu giữ vẫn chặn tăng bộ nhớ giữa các lượt dọn. Adapter kiểm tra cấu trúc Gradio lúc khởi động và chỉ hỗ trợ callback không stream của SCAP; khi nâng Gradio phải chạy lại kiểm thử hàng đợi/lưu giữ, không bỏ adapter nếu kiểm tra không tương thích thất bại.

Ngân sách AI đếm lần ứng dụng gọi provider. SDK có thể thử lại một lần, nên số yêu cầu thực tế tới provider có thể cao hơn. Trần token đầu ra và ngân sách lời gọi giảm rủi ro chi phí; chưa thay thế hạn mức tiền/credit và cảnh báo billing trong tài khoản nhà cung cấp. Thời gian không hoạt động của HTTP cũng không phải timeout cứng cho toàn bộ một lời gọi AI.

Lớp request boundary áp dụng cả API và giao diện: body tối đa 1 MiB, thời gian đọc body tối đa 30 giây, URI tối đa 16 KiB, tổng header tối đa 32 KiB/100 header và JSON sâu tối đa 64 cấp. Header `Content-Length` thiếu hoặc sai không được dùng để bỏ qua giới hạn dung lượng thực đọc. Dữ liệu JSON trùng khóa, số không hữu hạn và Unicode không hợp lệ bị từ chối trước nghiệp vụ.

## Chạy local

Giữ bind trên loopback. Không đổi `HOST` thành `0.0.0.0`, publish cổng ra LAN hoặc mở cổng router chỉ để thử giới hạn. Launcher local không tin proxy header do trình duyệt tự gửi; `X-Forwarded-For` không được dùng làm IP nguồn khi chạy trực tiếp.

Launcher/server có giới hạn hữu hạn cho concurrency, backlog, HTTP keep-alive và header đang đọc. Mốc khởi đầu là concurrency 64, backlog 128, keep-alive 5 giây và h11 incomplete-event cap 16 KiB. Trần admission trong ứng dụng thấp hơn trần server để còn cơ hội trả phản hồi quá tải. Demo local có thời gian graceful shutdown riêng 5 giây; môi trường container cần thời gian dừng phù hợp với tác vụ thực tế.

Kiểm tra demo ngoại tuyến, không mở cổng lắng nghe:

```powershell
.\.venv\Scripts\python.exe scripts/demo_local.py --check
```

Chạy demo trong dữ liệu tạm riêng:

```powershell
.\.venv\Scripts\python.exe scripts/demo_local.py --port 8000
```

Giới hạn theo IP có thể ảnh hưởng nhiều tab/người cùng đi qua một NAT. Hãy đo một phiên sử dụng bình thường trước khi tăng giới hạn; tăng số worker hoặc tất cả quota cùng lúc có thể làm vượt RAM laptop.

## Health, readiness và giám sát

`GET /api/health` kiểm tra liveness tối giản, không truy vấn DB hay WORM. `GET /api/ready` kiểm tra phụ thuộc với một tác vụ duy nhất đang chạy. Profile standard cache kết quả thành công 5 giây; profile high kiểm chứng WORM và không dùng success cache đó. Mặc định chỉ cho 12 yêu cầu readiness/phút; healthcheck 30 giây/lần nằm trong ngân sách này.

Trong cấu hình Caddy production, chặn truy cập readiness từ Internet; Docker healthcheck gọi trực tiếp địa chỉ loopback của container. Khi chạy trên laptop, endpoint vẫn dùng được qua loopback. Không dùng `/api/ready` làm endpoint theo dõi công khai với tần suất cao.

`GET /api/admin/availability` yêu cầu tài khoản admin và trả snapshot của worker: số yêu cầu/stream đang chạy, số lần từ chối, năng lực băm mật khẩu, readiness và các trần giao diện/AI. Bộ đếm reset khi tiến trình khởi động lại. Không coi snapshot của một worker là số liệu tổng cụm.

Trong tab Quản trị, chọn làm mới để xem các slot yêu cầu/luồng/băm mật khẩu, số sự kiện giữ lại và lượt từ chối ghi nhận. Snapshot tài nguyên gồm chính yêu cầu lấy số liệu. Phần HTTP dùng cửa sổ 60 giây với vòng đệm cố định 60 ô: nhóm status, thường/SSE, histogram và trung bình thời gian ứng dụng phát header. SSE được đo ngay khi bắt đầu phản hồi, không chờ luồng đóng; yêu cầu hủy/lỗi trước header được đếm riêng. Trung bình gồm tất cả phản hồi có header, không phải latency riêng của phản hồi thành công hay thời gian truyền hết body.

Cảnh báo tự hết khi cửa sổ trôi: ít nhất 5 phản hồi `429`/`503`; ít nhất 5 lỗi `5xx` với tỷ lệ từ 10%; ít nhất 5 yêu cầu chưa phát header; hoặc ít nhất 20 phản hồi và từ 20% mất hơn 1 giây đến header. Snapshot cũng cảnh báo khi ngân sách request/SSE/password/email đang đầy. Đây là dấu hiệu vận hành để điều tra, không tự kết luận DDoS. Chỉ admin có quyền xem; không giữ URL/IP/body/header/token cho thống kê này.

Sự kiện `availability.overload` được gom mẫu với nhãn cố định; không chứa prompt, mật khẩu, token, IP hay đường dẫn yêu cầu. Nhật ký từ chối xác thực vô danh cũng được lấy mẫu để giảm lượng ghi audit khi có burst. Điều này giữ bằng chứng đại diện; số lần bị từ chối cần đối chiếu bộ đếm, không chỉ đếm dòng audit.

Chưa cấu hình sẵn dịch vụ giám sát bên ngoài, dashboard Prometheus/Grafana, cảnh báo email hay paging. Trước production, người vận hành cần đặt ngưỡng và kênh cảnh báo cho:

- tỷ lệ `429`/`503`, thời gian phản hồi và số slot còn trống;
- RAM/CPU, số file descriptor, restart/OOM và mức đầy hàng đợi giao diện;
- Redis memory, lỗi OOM/write, connected clients, timeout; DB pool/lock và dung lượng ổ đĩa;
- lỗi AI/chi phí billing, lỗi readiness, WORM và kiểm chứng audit.

Không thu thập body, Authorization, Cookie hoặc URL chứa capability export. Lưu dữ liệu giám sát ở nơi có kiểm soát truy cập và retention phù hợp.

## Hạ tầng production để chuẩn bị sau

Compose production không publish cổng ứng dụng; Caddy là điểm vào. IP nguồn được Uvicorn tin chỉ là IP của Caddy trên mạng edge. Caddy nằm ngoài dải IP cấp động, tránh app khởi động trước nhận mất địa chỉ cố định của proxy. Nếu đổi subnet, phải đổi dải IP động và địa chỉ Caddy đồng bộ: dải động nằm trong subnet, IP Caddy nằm trong subnet nhưng ngoài dải động. Chọn subnet không trùng LAN, VPN hoặc các Docker network đang có. Không dùng wildcard trust hoặc tin toàn bộ mạng backend.

Các biến hạ tầng: `SCAP_EDGE_SUBNET=172.30.45.0/28`, `SCAP_EDGE_DYNAMIC_RANGE=172.30.45.8/29`, `SCAP_CADDY_IPV4=172.30.45.2`, `UVICORN_LIMIT_CONCURRENCY=64`, `UVICORN_BACKLOG=128`, `UVICORN_KEEPALIVE_SECONDS=5`, `UVICORN_SHUTDOWN_SECONDS=20`, `REDIS_MAXMEMORY=128mb`, `REDIS_MAXCLIENTS=256`. Compose đọc biến cho cả standard/high; CMD mặc định của image giữ giá trị khởi điểm. Tổng pool Redis tăng theo số worker, nên trần client Redis cần tính cho tất cả worker và các công cụ vận hành.

Redis được giới hạn bộ nhớ và số client. Chính sách `noeviction` giữ các khóa rate limit/bảo vệ tài khoản thay vì âm thầm xóa chúng khi đầy. Khi chạm trần, thao tác ghi có thể lỗi và ứng dụng trả `503` theo nguyên tắc đóng khi phụ thuộc bảo mật lỗi. Cần dự phòng thêm RAM ngoài `maxmemory` cho overhead, client buffers và TLS; không đặt `maxmemory` bằng `mem_limit` container. Redis hiện tắt AOF/snapshot, vì vậy restart có thể làm mất lịch sử quota đang sống.

Overlay high dùng TLS nội bộ và secret-file mount. Compose standard vẫn nhận `.env` cho app; không coi nó có mức cô lập bí mật tương đương overlay high. Production cần chọn profile, quyền file và tài khoản DB/Redis tương ứng, kiểm tra không đưa credential quản trị vào tiến trình web.

Nếu sau này công khai dịch vụ, triển khai chống DDoS ở upstream có khả năng hấp thụ lưu lượng: CDN/WAF hoặc dịch vụ của nhà cung cấp mạng. Firewall/security group của origin chỉ cho nguồn proxy/gateway được phép; chỉ ẩn tên origin trong DNS không ngăn truy cập trực tiếp. Cấu hình proxy phải xóa header nguồn/identity do client gửi và tạo lại header đã xác thực. Xác minh TLS giữa edge và origin; rà soát IPv4 lẫn IPv6 và các cổng quản trị.

Turnstile hoặc một challenge tương đương là lựa chọn tương lai cho endpoint xác thực công khai. Dự án chưa tích hợp/chưa cấu hình Turnstile và không kiểm chứng token challenge tại server. Khi tích hợp cần secret phía server, kiểm tra token một lần, hostname/action dự kiến, timeout và đường hỗ trợ người dùng khi provider lỗi. Challenge bổ sung cho quota; không bỏ quota, MFA hoặc bước xác thực hiện có.

Các giới hạn trong ứng dụng không ngăn bão lưu lượng làm đầy đường truyền hoặc cạn tài nguyên trước khi tới ASGI. Laptop local hiện chưa cần provisioning các dịch vụ upstream này.

## Kiểm thử và triển khai theo giai đoạn

### Công cụ kiểm chứng local đã có

Kiểm tra HTTP thật trên hai tiến trình ứng dụng tạm riêng, socket chỉ bind `127.0.0.1` ở cổng do hệ điều hành cấp:

```powershell
.\.venv\Scripts\python.exe -m scripts.security_load_check
```

Công cụ không nhận URL mục tiêu, không đọc cấu hình/DB/secret thật và dùng provider AI giả lập. Kiểm tra baseline health; giữ bốn body chưa hoàn tất để xác nhận `503`, `Retry-After` và thu hồi slot sau ngắt kết nối; giữ provider slot thật để xác nhận API chat bận rồi phục hồi; chờ deadline body 30 giây trả `408`; xác minh DB/crypto/audit sau tải; vượt quota IP rồi thử header chuyển tiếp giả và phục hồi sau cửa sổ trôi. `--quick` bỏ bài chờ body timeout và báo rõ phần chưa kiểm chứng.

Các trần thử nghiệm được hạ xuống (request 4, password/AI 1, quota IP 6/2 giây) để kiểm tra hành vi chặn mà không cần tải lớn. SQLite giữ writer transaction qua lời gọi chat nên kiểm tra AI dùng một reservation trong core, không giữ DB transaction, rồi gọi API thật. Đây không phải phép đo parallel chat throughput hay công suất cấu hình mặc định.

Tối đa 160 request mỗi worker, năm kết nối tải cùng lúc (bốn body giữ slot + một probe), ngân sách công việc 100 giây và tối đa 14 giây dọn tiến trình khi lỗi. Guard bắt đầu trước khi dựng app/seed, lấy mẫu RSS worker mỗi 0,1 giây, ngừng worker tạm nếu vượt 1 GiB, 30 giây CPU hoặc thời gian còn lại; RSS không đọc được cũng không tiếp tục. Lấy mẫu có thể bỏ lỡ đỉnh RAM rất ngắn; đây không phải giới hạn bộ nhớ cứng của hệ điều hành. Parent cũng giới hạn thời gian chờ khởi động/I/O và thu hồi tiến trình khi lỗi.

Báo cáo `reports/security-load-local/security-load.json` chỉ có nhãn cố định, số lượng/status, thời gian, CPU và RSS. p50/p95 tính riêng phản hồi thành công và phản hồi bị chặn, gồm kết nối + đọc phản hồi HTTP từ client; không trộn lỗi nhanh vào latency thành công. CPU % tính theo một lõi, RSS/CPU chỉ đo worker, không gồm client hay tổng RAM máy. Báo cáo không chứa token, khóa hoặc nội dung chat. Chưa thử slow header, SYN flood, DDoS Internet, tải nhiều worker hay phụ thuộc production thật.

Diễn tập backup/restore SQLite ngoại tuyến, không mở cổng:

```powershell
.\.venv\Scripts\python.exe -m scripts.security_recovery_drill
```

Công cụ xuất JSON với 33 bước kiểm tra và thời gian local, dùng SQLite online backup để giữ cả commit mới còn trong WAL. Xác nhận wrapped DEK/epoch/KEK metadata được giữ, giải mã với khóa đúng và từ chối khóa sai hoặc bản mã/metadata bị sửa; token logout và tài khoản inactive trước backup vẫn bị chặn sau restore; audit chain còn nguyên. DB mẫu và bản khôi phục được dọn trong thư mục tạm; KEK/JWT key giữ riêng trong RAM, không nhúng vào snapshot. Đây là diễn tập, không phải lệnh backup cho DB hiện có hoặc bằng chứng RTO/RPO production.

Một snapshot cũ không chứa các thu hồi phiên/tài khoản xảy ra sau thời điểm backup. Trước phục hồi dữ liệu thật phải đối chiếu các thu hồi đó từ nguồn tin cậy hoặc thu hồi toàn bộ phiên phục hồi theo quy trình vận hành; không đưa bản khôi phục ra phục vụ chỉ vì giải mã và audit chain đạt. Vault/KMS/WORM, backup dài hạn và khôi phục sau mất máy vẫn cần diễn tập với hạ tầng thực tế.

### Quy trình khi triển khai thực tế

1. Chạy kiểm thử tự động và demo ngoại tuyến; xác nhận các giới hạn cấu hình hợp lệ, dữ liệu kiểm thử tách khỏi dữ liệu thật. Kiểm tra Compose bằng `config --quiet` với môi trường placeholder hoặc môi trường vận hành được giữ kín; không in bản Compose đã nội suy bí mật.
2. Đo baseline ở local/staging: một tài khoản, nhiều tab vừa đủ, thao tác đăng nhập, chat và export bình thường. Ghi RAM đỉnh, độ trễ và số slot; không đưa prompt thật vào kết quả đo.
3. Với provider AI giả lập, tăng từng loại tải một: burst auth, request song song, stream SSE, body chậm, hàng đợi đầy và client ngắt kết nối. Xác nhận `429`/`503`, `Retry-After`, slot được thu hồi và ứng dụng tiếp tục đáp ứng sau khi ngừng tải. Không dùng API AI trả phí để chạy burst.
4. Chỉ trên staging riêng, thử phụ thuộc timeout/Redis đầy, restart worker và provider lỗi. Kiểm tra đóng an toàn, liveness còn phản hồi, readiness báo đúng, không sinh nửa cuộc trao đổi chat và không phát tán nội dung nhạy cảm trong lỗi/log.
5. Theo dõi số liệu rồi thay một giới hạn mỗi lần. Đặt ngưỡng dừng test trước khi RAM/CPU/ổ đĩa chạm trần; có người theo dõi và cơ chế ngừng tải. Không chạy flood vào Internet hay dữ liệu production.
6. Khi thực sự triển khai, canary nhỏ trước, xem lỗi/latency/chi phí, rồi mở rộng. Giữ cấu hình và image trước đó để rollback; không rollback schema hoặc audit bằng thao tác tùy tiện.

Trước khi dùng dữ liệu quan trọng, thực hành restore trong môi trường cô lập: backup DB cùng wrapped-DEK/key metadata, giữ quyền truy cập KEK/Vault đúng phiên bản, đối chiếu checkpoint WORM và tính toàn vẹn audit. Xác nhận có thể đọc bản mã bằng khóa đúng, bản mã/metadata bị sửa bị từ chối và tài khoản/phiên bị thu hồi vẫn không truy cập được. Đo thời gian restore và lượng dữ liệu mất theo lịch backup; ghi RTO/RPO đã đo, không chỉ ghi mục tiêu.

Không dùng `docker compose down -v`, reset dữ liệu demo hoặc sửa chuỗi audit để phục hồi hệ thống thật. Backup thiếu khóa/phụ thuộc WORM có thể không đủ để khôi phục ứng dụng; kiểm thử restore phải bao gồm các phụ thuộc đó.

## Email và biên giao diện

`MAIL_MAX_PENDING=32` giới hạn cả thư đang gửi và đang chờ trong mỗi worker; tối đa hai luồng gửi. Shutdown chờ tối đa 10 giây rồi hủy thư chưa chạy; tác vụ SMTP đang chạy vẫn kết thúc theo timeout từng thao tác 15 giây. Bộ đếm `mail` trong API quản trị không chứa địa chỉ/nội dung; cần theo dõi `failed`/`rejected` vì thư nền không thể báo lỗi lại cho request đã hoàn tất. Gửi reset khi hàng đợi đầy vẫn trả cùng `202` cho tài khoản có/không tồn tại, mã chưa gửi bị thu hồi đúng yêu cầu.

Outbox chỉ dùng local/demo: tối đa 512 tệp, 16 MiB và 64 KiB mỗi thư. Không tự xóa thư cũ; khi đầy, chuyển thư cần giữ ra kho riêng rồi dọn theo quyết định của người vận hành. Không trỏ tới thư mục chứa tệp khác, symlink, junction hoặc hardlink. Quota được đồng bộ trong một tiến trình; không chia sẻ cùng outbox giữa nhiều worker. Thư mục/tệp mới có ACL riêng trên Windows hoặc quyền POSIX trước khi ghi mã. Cả quyền từng thư cũ cũng được kiểm tra; thư mục hoặc thư cũ không đạt sẽ bị từ chối, không tự sửa quyền. Production tiếp tục từ chối outbox.

Host mặc định local chỉ là `127.0.0.1`, `localhost`, `::1`; muốn truy cập LAN phải khai báo host cụ thể. CSP chỉ cho script bootstrap đã xác minh dùng nonce mới và script asset cùng origin; CSS inline vẫn cần cho Gradio. Không tự cấp nonce cho HTML/dữ liệu người dùng. Adapter từ chối bootstrap/custom script không tương thích khi nâng thư viện. Báo cáo CSP giữ allowance CSS này để tránh burst báo cáo hợp lệ làm nghẽn giao diện. Deep-link lưu trạng thái plaintext bị chặn; header origin thô của thư viện bị bỏ, scope do server/proxy xác minh được giữ.

## Sao lưu SQLite mã hóa và phục hồi offline

Đây là công cụ cho **SQLite local tối đa 64 MiB**; không thay quy trình PostgreSQL/Vault/WORM production. Tạo một thư mục đầu ra **mới** trên ổ mã hóa bằng lệnh dưới đây; thư mục có ACL/mode riêng được công cụ kiểm tra trước khi tạo plaintext. Thay các đường dẫn ví dụ bằng DB đã xác nhận và tên đầu ra mới; công cụ không suy ra cấu hình từ `.env`:

```powershell
.\.venv\Scripts\python.exe -m scripts.local_storage mkdir --directory "D:\SCAP-private"
.\.venv\Scripts\python.exe -m scripts.secure_backup backup --database "D:\SCAP-private\current.db" --output "D:\SCAP-private\copy.scapbak"
.\.venv\Scripts\python.exe -m scripts.secure_backup restore --archive "D:\SCAP-private\copy.scapbak" --output "D:\SCAP-private\recovered.db"
```

Mật khẩu backup được nhập ẩn, tối thiểu 16 byte UTF-8, xác nhận khi tạo; không đưa vào argument/env/log. AES-256-GCM xác thực cả snapshot và header phiên bản/kích thước/KDF. Argon2id cố định 64 MiB, ba lượt; từ chối header/kích thước sai trước KDF. SQLite online backup giữ commit WAL; không sao chép riêng file `.db` đang chạy. Bước snapshot và validation có deadline riêng 30 giây. Tệp chỉ được xuất nguyên tử nếu chưa tồn tại, cần filesystem hỗ trợ hardlink; không có tùy chọn ghi đè. Điều này chưa bảo đảm directory entry tồn tại sau mất điện.

DB chứa wrapped DEK/epoch/phiên bản khóa; công cụ **không xuất KEK, JWT key, `.env` hoặc trạng thái dịch vụ ngoài**. Cất khóa và mật khẩu backup riêng, bảo toàn các phiên bản khóa còn cần đọc. Plaintext snapshot tạm nằm trong thư mục được tạo riêng quyền trước khi SQLite mở nó; Windows giữ handle của thư mục đầu ra và các thư mục cha xuyên suốt snapshot/restore/dọn tệp để chặn đổi tên thay đường dẫn. Archive và DB phục hồi giữ ACL riêng sau xuất nguyên tử. Không cam kết xóa an toàn trên SSD. Archive `.scapbak` được loại khỏi Git nhưng vẫn phải bảo vệ.

Restore thu hồi toàn bộ phiên/JWT challenge, tiêu thụ recovery code/MFA code/prekey E2EE và xóa challenge passkey/E2EE. Token version nhảy ngẫu nhiên để tránh trùng phiên bản của challenge phát sau snapshot. TOTP tiêu thụ cửa sổ hiện tại, có thể cần chờ tối đa khoảng 60 giây để dùng mã mới. Audit chain, wrapped DEK và ciphertext được giữ nguyên. **Mọi tài khoản bị khóa mặc định** vì backup cũ không biết các thay đổi/thu hồi mới hơn.

Giữ DB phục hồi offline, tắt `SEED_DEMO_DATA` và bootstrap tạo admin trước khi phục vụ. Đối chiếu từ nguồn mới hơn các khóa/xóa tài khoản, mật khẩu, MFA/seed, email khôi phục, passkey, thiết bị E2EE, membership/epoch và dữ liệu đã xóa. Chỉ tài khoản đã đối chiếu mới được kích hoạt bằng cách phục hồi vào một tệp mới khác với tùy chọn `--activate-reviewed-user USERNAME` (lặp lại cho từng tài khoản); tùy chọn này là quyết định của operator, không tự chứng minh review đã hoàn tất. Phát hành prekey/recovery code mới qua luồng hiện có sau review.

Trước chuyển cấu hình sang DB mới, xác minh khóa đúng/sai, chain/checkpoint ngoài và các account/phiên đã thu hồi không truy cập được. Không đổi khóa/DB đang chạy chỉ để thử công cụ. Lịch sao lưu, bản sao ngoài máy, retention và diễn tập mất máy vẫn do người vận hành thiết lập; lần phát triển này chỉ dùng dữ liệu giả trong thư mục tạm.

## Kho dữ liệu local và tệp bí mật

`setup.ps1`/`setup.sh` cài dependency trước, sau đó gọi `python -m scripts.local_storage init`. Với cài đặt mới, lệnh tạo `.env` độc quyền có quyền riêng trước khi ghi khóa ngẫu nhiên; khóa không đi qua argument/env của shell hoặc log. DB mới và sidecar SQLite nằm trong `local_data/`, outbox mới trong `local_data/mail_outbox/`. Thư mục này bị loại khỏi Git. Nếu `.env` đã tồn tại, chỉ kiểm tra metadata và giữ nguyên bytes/quyền/đường dẫn; lệnh không chứng nhận cài đặt cũ đã có ACL tốt. Nếu thiếu `.env` nhưng có DB/sidecar ở hai vị trí mặc định, hoặc template chọn DB tùy chỉnh, lệnh từ chối tạo khóa mới. Phải phục hồi cấu hình và các khóa khớp dữ liệu trước khi tiếp tục.

Windows dùng SID từ token tiến trình, DACL được bảo vệ khỏi kế thừa và chỉ cấp quyền cho người chạy cùng SYSTEM; không dựa vào tên người dùng/env hoặc `chmod`. Chỉ nhận filesystem local khả dụng, từ chối UNC, ổ mạng gắn ký tự, đường dẫn thiết bị/ADS, reparse point, junction, symlink và hardlink. POSIX tạo thư mục/tệp với `0700`/`0600`, kiểm tra chủ sở hữu và quyền khác. Hệ thống tệp không lưu được chính sách quyền sẽ dừng an toàn. [Microsoft mô tả ACL tại thời điểm tạo và quyền riêng của từng tệp](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights).

Nếu outbox cũ bị từ chối, dừng ứng dụng, tạo thư mục **mới** rồi tự đổi đúng `MAIL_OUTBOX_DIR` trong `.env` hiện có và khởi động lại:

```powershell
.\.venv\Scripts\python.exe -m scripts.local_storage mkdir --directory "D:\SCAP-mail-private"
```

Không sao chép thư cũ vào thư mục mới rồi mặc định chúng đã riêng quyền: thao tác di chuyển có thể giữ ACL cũ. Công cụ không tự sửa ACL lịch sử, di chuyển DB đang chạy hoặc xoay khóa. DB cũ cần quy trình offline riêng: giữ khóa cũ, backup mã hóa, restore mới vào thư mục private, đối chiếu tài khoản/phiên và audit theo mục phục hồi trên trước khi đổi `DATABASE_URL`. Không chọn một DB trống để vượt qua lỗi quyền. `.env` cũ và quyền truy cập khóa cũng cần được người vận hành rà lại; `init` giữ nguyên chúng.

Các secret `_FILE`/Vault/WORM/OIDC dùng cùng reader: kiểm tra loại tệp qua handle, đọc tối đa ngân sách byte + 1, giải mã UTF-8 nghiêm ngặt; lỗi không in đường dẫn/nội dung. Config tối đa 16 KiB, token Vault/WORM/OIDC tối đa 4 KiB. Reader không bắt buộc chủ sở hữu riêng để hỗ trợ regular-file mount đọc được của service; các thư mục cha cũng phải đọc được. Mount thông qua symlink/projected-secret không được chấp nhận: stage thành regular file trong runtime private theo entrypoint high hiện có. Vault/WORM đọc lại mỗi lần để nhận rotation. Trên Windows cần hoàn tất thay tệp giữa các lần đọc hoặc retry khi OS báo tệp bận.

ACL hạn chế tài khoản khác trên cùng máy; không chặn malware chạy bằng chính tài khoản ứng dụng, SYSTEM/root hay administrator có quyền lấy ownership. Dùng tài khoản vận hành riêng và ổ mã hóa; quyền của đường dẫn cha phải tin cậy, đặc biệt với SQLite mở lại đường dẫn trên POSIX. Không suy ra bảo vệ trước DDoS Internet từ ACL local.
