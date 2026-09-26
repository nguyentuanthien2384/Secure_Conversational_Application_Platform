# Security evidence output

Thư mục này dành cho kết quả test/scan khi nộp bài. Không commit token, API key, database hoặc nội dung chat thật.

Tên file gợi ý: `pytest.txt`, `coverage.xml`, `bandit.json`, `pip-audit.json`, `trivy.json`, `zap-report.html`.

Chạy `uv run python -m scripts.validate_security` để tạo bằng chứng kiểm chứng
ứng dụng trong `security-validation/security-validation.json` và
`security-validation/security-validation.junit.xml`. Các tệp này được bỏ qua
bởi Git; CI tải chúng lên artifact khi chạy workflow bảo mật. Xem
[`docs/SECURITY_AUTOMATION.md`](../docs/SECURITY_AUTOMATION.md) về phạm vi và cách đọc.
