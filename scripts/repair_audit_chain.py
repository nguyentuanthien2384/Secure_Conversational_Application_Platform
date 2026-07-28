#!/usr/bin/env python3
"""Vá các bản ghi audit chưa được niêm phong vào chuỗi băm.

Dùng khi ``GET /api/admin/audit/verify`` báo ``unsealed_events > 0`` — thường là
database tạo từ phiên bản trước khi có hash chain, hoặc dữ liệu mẫu sinh bởi bản
``demo_seed.py`` cũ (bản đó INSERT thẳng, không gọi ``seal_event``).

    uv run python scripts/repair_audit_chain.py --check    # chỉ xem, không sửa
    uv run python scripts/repair_audit_chain.py            # vá

Giới hạn có chủ đích: script chỉ vá được khi các bản ghi chưa niêm phong nằm ở
*cuối* bảng. Nếu khoảng trống nằm giữa chuỗi, vá sẽ buộc phải băm lại những bản
ghi đã niêm phong phía sau — tức là tự tay xoá bỏ đúng bằng chứng mà chuỗi băm
sinh ra để giữ. Khi đó script dừng lại và yêu cầu điều tra như một sự cố toàn vẹn.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.app.audit_chain import derive_audit_key, reseal_unsealed, verify_chain  # noqa: E402
from src.app.config import Settings  # noqa: E402
from src.app.db import Database  # noqa: E402


def main() -> int:
    check_only = "--check" in sys.argv
    settings = Settings.from_env()
    if not settings.audit_chain_enabled:
        print("AUDIT_CHAIN_ENABLED=false — chuỗi audit đang tắt, không có gì để vá.")
        return 1

    key = derive_audit_key(settings.secret_key)
    database = Database(settings.database_url)

    with database.session_factory() as db:
        before = verify_chain(db, key)
        print(
            f"Trước khi vá: {before.verified}/{before.total} bản ghi được bảo vệ "
            f"({before.coverage:.1%}), {before.unsealed} bản ghi chưa niêm phong, "
            f"{before.segments} đoạn chuỗi."
        )
        if before.first_broken_id is not None:
            print(
                f"  ✗ Chuỗi ĐÃ GÃY tại bản ghi #{before.first_broken_id} "
                f"({before.reason}). Đây là dấu hiệu bị sửa/xoá, KHÔNG phải lỗi "
                f"thiếu niêm phong — không vá, hãy điều tra."
            )
            return 2
        if before.unsealed == 0:
            print("  ✓ Không có bản ghi nào cần vá.")
            return 0
        if check_only:
            print("  (--check: không thay đổi gì.)")
            return 0

        try:
            repaired = reseal_unsealed(db, key)
        except ValueError as exc:
            print(f"  ✗ Không vá được: {exc}")
            return 2

        after = verify_chain(db, key)
        print(f"Đã niêm phong {repaired} bản ghi.")
        print(
            f"Sau khi vá: {after.verified}/{after.total} bản ghi được bảo vệ "
            f"({after.coverage:.1%}), chuỗi nguyên vẹn: {after.intact}."
        )
        return 0 if after.intact else 2


if __name__ == "__main__":
    raise SystemExit(main())
