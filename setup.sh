#!/usr/bin/env bash
# =====================================================================
# setup.sh — Cài đặt & chạy dự án bằng 1 lệnh (macOS / Linux / WSL)
#   bash setup.sh          -> cài đặt rồi chạy server
#   bash setup.sh --test   -> cài đặt, chạy test + scan, rồi chạy server
#   bash setup.sh --no-run -> chỉ cài đặt, không chạy
# =====================================================================
set -euo pipefail

cd "$(dirname "$0")"
BLUE='\033[1;34m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; NC='\033[0m'
step() { echo -e "\n${BLUE}==> $*${NC}"; }
ok()   { echo -e "${GREEN}  ✓ $*${NC}"; }
warn() { echo -e "${YELLOW}  ! $*${NC}"; }
die()  { echo -e "${RED}  ✗ $*${NC}"; exit 1; }

RUN_TESTS=0; DO_RUN=1
for arg in "$@"; do
  case "$arg" in
    --test)   RUN_TESTS=1 ;;
    --no-run) DO_RUN=0 ;;
    *) die "Tham số không hợp lệ: $arg" ;;
  esac
done

# ---------- 1. Kiểm tra Python ----------
step "1/5 Kiểm tra Python"
if command -v python3 >/dev/null 2>&1; then
  PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  ok "Đã có python3 $PY_VER"
else
  warn "Chưa có python3 trên máy — uv sẽ tự tải Python 3.12 riêng cho dự án."
fi

# ---------- 2. Cài uv nếu chưa có ----------
step "2/5 Kiểm tra uv (trình quản lý package)"
if ! command -v uv >/dev/null 2>&1; then
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
if ! command -v uv >/dev/null 2>&1; then
  warn "Chưa có uv — đang cài (cần Internet)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
command -v uv >/dev/null 2>&1 || die "Không cài được uv. Xem https://docs.astral.sh/uv/getting-started/installation/"
ok "uv $(uv --version | awk '{print $2}')"

# ---------- 3. File .env ----------
step "3/5 Kiểm tra cấu hình .env"
if [ -f .env ]; then
  ok ".env đã tồn tại — giữ nguyên"
else
  cp .env.example .env
  warn "Đã tạo .env từ .env.example — đang sinh secrets ngẫu nhiên..."
  SECRETS="$(python3 scripts/generate_secrets.py 2>/dev/null || uv run --no-project python scripts/generate_secrets.py)"
  APP_SECRET="$(echo "$SECRETS" | grep '^APP_SECRET_KEY=' | cut -d= -f2-)"
  MASTER_KEY="$(echo "$SECRETS" | grep '^MASTER_ENCRYPTION_KEY=' | cut -d= -f2-)"
  python3 - "$APP_SECRET" "$MASTER_KEY" <<'PYEOF'
import sys, pathlib
app_secret, master_key = sys.argv[1], sys.argv[2]
p = pathlib.Path(".env"); out = []
for line in p.read_text(encoding="utf-8").splitlines():
    if line.startswith("APP_SECRET_KEY="):
        line = "APP_SECRET_KEY=" + app_secret
    elif line.startswith("MASTER_ENCRYPTION_KEY="):
        line = "MASTER_ENCRYPTION_KEY=" + master_key
    elif line.startswith("SEED_DEMO_DATA="):
        line = "SEED_DEMO_DATA=true"
    out.append(line)
if not any(l.startswith("SEED_DEMO_DATA=") for l in out):
    out.append("SEED_DEMO_DATA=true")
p.write_text("\n".join(out) + "\n", encoding="utf-8")
PYEOF
  ok "Đã sinh APP_SECRET_KEY và MASTER_ENCRYPTION_KEY"
fi

# ---------- 4. Cài dependency ----------
step "4/5 Cài dependency (uv sync --group dev)"
uv sync --group dev
ok "Môi trường ảo .venv đã sẵn sàng"

# ---------- 5. Test + scan (tùy chọn) ----------
if [ "$RUN_TESTS" -eq 1 ]; then
  step "5/5 Kiểm thử và quét bảo mật"
  uv run pytest --cov=src.app --cov-report=term-missing || warn "Có test thất bại — xem log ở trên"
  uv run ruff check src/app tests scripts/migrate_database.py || warn "Ruff báo lỗi lint"
  uv run bandit -q -r src/app -ll -ii || warn "Bandit báo cảnh báo"
else
  step "5/5 Bỏ qua test (thêm --test nếu muốn chạy)"
fi

echo
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN} CÀI ĐẶT XONG${NC}"
echo -e "${GREEN}========================================================${NC}"
echo "  Giao diện web  : http://127.0.0.1:8000"
echo "  Swagger API    : http://127.0.0.1:8000/docs"
echo "  SPA tĩnh       : http://127.0.0.1:8000/spa"
echo
echo "  Tài khoản demo (mật khẩu chung: Phenikaa-Vault#2026-Lab)"
echo "    demo.user  — vai trò user"
echo "    demo.mod   — vai trò moderator"
echo "    demo.boss  — vai trò admin"
echo "  Admin bootstrap: xem BOOTSTRAP_ADMIN_* trong file .env"
echo

if [ "$DO_RUN" -eq 1 ]; then
  step "Đang khởi động server... (Ctrl+C để dừng)"
  exec uv run python run_app.py
else
  echo "  Chạy server bằng: uv run python run_app.py"
fi
