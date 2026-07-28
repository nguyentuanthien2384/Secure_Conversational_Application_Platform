#!/usr/bin/env python3
"""Sinh dữ liệu mẫu cho Secure Conversational Application Platform.

Chạy từ thư mục gốc dự án (cần .env giống lúc chạy app, vì tin nhắn được
mã hóa bằng đúng MASTER_ENCRYPTION_KEY mà server sẽ dùng để giải mã):

    uv run python scripts/seed_demo_data.py           # tạo dữ liệu mẫu
    uv run python scripts/seed_demo_data.py --reset   # xóa demo cũ rồi tạo lại

Ngoài ra có thể auto-seed khi khởi động server bằng SEED_DEMO_DATA=true trong .env.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.app.config import Settings  # noqa: E402
from src.app.db import Database  # noqa: E402
from src.app.demo_seed import DEMO_PASSWORD, DEMO_USERS, seed_demo_data  # noqa: E402
from src.app.security import CryptoService, PasswordService  # noqa: E402

if __name__ == "__main__":
    settings = Settings.from_env()
    seed_demo_data(
        Database(settings.database_url),
        PasswordService(),
        CryptoService(settings.master_encryption_key),
        reset="--reset" in sys.argv,
    )
    print("\n=== TÀI KHOẢN DEMO ===")
    print(f"Mật khẩu chung : {DEMO_PASSWORD}")
    for username, role in DEMO_USERS:
        print(f"  {username:<12} → vai trò {role}")
    print(
        "\nGợi ý khám phá:\n"
        "  1. Đăng nhập demo.user  → tab Trò chuyện có sẵn 4 hội thoại giải thích dự án.\n"
        "  2. Tab 'Dữ liệu mã hóa' → xem ciphertext/nonce thật trong DB.\n"
        "  3. Tab 'Tìm kiếm'       → thử từ khóa 'AAD' hoặc 'Argon2id'.\n"
        "  4. Đăng nhập demo.boss  → tab Quản trị: thống kê, cảnh báo brute-force, audit.\n"
        "  5. Đăng nhập demo.mod   → chỉ thấy nhật ký kiểm toán (đúng RBAC 3 cấp)."
    )
