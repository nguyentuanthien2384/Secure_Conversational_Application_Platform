-- ============================================================================
-- Phân quyền tối thiểu cho cơ sở dữ liệu (Bài 4 §4.3, Bài 1 §Least Privilege)
-- ============================================================================
--
-- VẤN ĐỀ: mặc định ứng dụng kết nối bằng chính vai trò SỞ HỮU schema. Nghĩa là
-- một lỗ hổng SQL injection duy nhất (hoặc một lệnh sai của lập trình viên) đủ
-- để DROP TABLE, đọc pg_shadow, hoặc tạo function chạy lệnh hệ điều hành.
--
-- NGUYÊN TẮC: ứng dụng chỉ cần đọc/ghi DỮ LIỆU, không cần sửa CẤU TRÚC. Tách
-- thành ba vai trò:
--
--   secure_chat  (owner)     - chỉ dùng khi migrate, không dùng lúc chạy
--   scap_app     (runtime)   - SELECT/INSERT/UPDATE/DELETE, không DDL
--   scap_auditor (read-only) - chỉ đọc audit_events, cho SOC/giảng viên chấm bài
--
-- CÁCH DÙNG:
--   SCAP_APP_DB_PASSWORD="..." SCAP_AUDITOR_DB_PASSWORD="..." \
--     psql -U secure_chat -d secure_chat -f scripts/db_least_privilege.sql
--
-- Docker gọi file này qua init_db_roles.sh. Không có mật khẩu dự phòng:
-- thiếu biến là lỗi dừng triển khai, không tạo credential có thể đoán.
-- ============================================================================

\set ON_ERROR_STOP on
-- Role passwords must never appear in PostgreSQL statement/duration logs.
-- Session-local settings are restored after the two ALTER ROLE statements.
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET log_min_error_statement = 'panic';
\if :{?app_password}
\else
  \getenv app_password SCAP_APP_DB_PASSWORD
\endif
\if :{?auditor_password}
\else
  \getenv auditor_password SCAP_AUDITOR_DB_PASSWORD
\endif
\if :{?app_password}
\else
  \echo 'ERROR: app_password is required'
  \quit 3
\endif
\if :{?auditor_password}
\else
  \echo 'ERROR: auditor_password is required'
  \quit 3
\endif

-- ── 1. Vai trò runtime của ứng dụng ────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scap_app') THEN
        CREATE ROLE scap_app LOGIN;
    END IF;
END
$$;
ALTER ROLE scap_app WITH PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
    CONNECTION LIMIT 40;

-- ── 2. Vai trò chỉ đọc dùng cho giám sát / chấm bài ────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scap_auditor') THEN
        CREATE ROLE scap_auditor LOGIN;
    END IF;
END
$$;
ALTER ROLE scap_auditor WITH PASSWORD :'auditor_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION
    CONNECTION LIMIT 5;

RESET log_min_error_statement;
RESET log_min_duration_statement;
RESET log_statement;
\unset app_password
\unset auditor_password

-- ── 3. Thu hồi quyền mặc định của PUBLIC ───────────────────────────────────
-- Mặc định Postgres cho MỌI vai trò quyền CREATE trên schema public. Đây là
-- đường leo thang đặc quyền kinh điển (Bài 1 §Privilege Escalation).
REVOKE ALL ON DATABASE secure_chat FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- ── 4. Cấp quyền tối thiểu cho ứng dụng ────────────────────────────────────
GRANT CONNECT ON DATABASE secure_chat TO scap_app;
GRANT USAGE  ON SCHEMA public         TO scap_app;   -- USAGE, KHÔNG phải CREATE
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO scap_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO scap_app;

-- Bảng tạo về sau cũng tự thừa hưởng đúng quyền này.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO scap_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO scap_app;

-- ── 5. Audit log: chỉ được THÊM, không được SỬA/XÓA ────────────────────────
-- Kết hợp với chuỗi băm trong src/app/audit_chain.py: chuỗi băm PHÁT HIỆN việc
-- sửa đổi, còn quyền hạn ở đây NGĂN CHẶN nó ngay từ đầu. Hai lớp bổ sung nhau
-- đúng theo nguyên tắc Defense in Depth (Bài 1 §e3).
-- Khi chạy trong /docker-entrypoint-initdb.d, bảng chưa tồn tại. Lệnh migration
-- one-shot sẽ áp quyền này sau khi tạo schema; nhánh dưới vẫn hỗ trợ chạy tay
-- trên database đã có bảng.
SELECT to_regclass('public.audit_events') IS NOT NULL AS audit_table_exists \gset
SELECT to_regclass('public.audit_checkpoints') IS NOT NULL AS checkpoint_table_exists \gset
\if :audit_table_exists
  REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_events FROM scap_app;
  GRANT  SELECT, INSERT            ON TABLE audit_events TO   scap_app;
\endif
\if :checkpoint_table_exists
  REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_checkpoints FROM scap_app;
  GRANT  SELECT, INSERT            ON TABLE audit_checkpoints TO   scap_app;
\endif

-- ── 6. Vai trò kiểm toán chỉ đọc ───────────────────────────────────────────
GRANT CONNECT ON DATABASE secure_chat TO scap_auditor;
GRANT USAGE   ON SCHEMA public        TO scap_auditor;
\if :audit_table_exists
  GRANT SELECT ON TABLE audit_events TO scap_auditor;
\endif
\if :checkpoint_table_exists
  GRANT SELECT ON TABLE audit_checkpoints TO scap_auditor;
\endif
-- KHÔNG cấp quyền đọc secure_messages: kiểm toán viên xem được "ai làm gì",
-- không xem được nội dung hội thoại (dù có đọc cũng chỉ thấy bản mã AES-GCM).

-- ── 7. Ép mã hóa đường truyền ──────────────────────────────────────────────
-- High-security overlay đặt các dòng `hostnossl ... reject` ở ĐẦU pg_hba.conf
-- bằng scripts/enforce_postgres_tls.sh. Kết nối ứng dụng đồng thời bắt buộc
-- sslmode=verify-full và CA nội bộ, nên cả mã hóa, CA và hostname đều được xác
-- minh. Mạng backend internal vẫn là lớp phân đoạn bổ sung, không thay thế TLS.

-- ── 8. Xác minh ────────────────────────────────────────────────────────────
-- SELECT grantee, table_name, privilege_type
--   FROM information_schema.role_table_grants
--  WHERE grantee IN ('scap_app','scap_auditor')
--  ORDER BY grantee, table_name, privilege_type;
