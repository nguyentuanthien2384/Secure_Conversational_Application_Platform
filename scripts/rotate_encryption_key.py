#!/usr/bin/env python3
"""Xoay vòng khóa mã hóa AES-256-GCM (Bài 4 — quản lý vòng đời khóa).

Vì sao phải xoay khóa: một khóa dùng vĩnh viễn nghĩa là mọi bản mã từ trước tới
nay đều mất an toàn cùng lúc nếu khóa lộ. Xoay khóa định kỳ giới hạn "blast
radius" và là yêu cầu bắt buộc trong PCI-DSS / ISO 27001.

Cách dùng:

1. Sinh khóa mới:
       python scripts/generate_secrets.py

2. Đưa CẢ HAI khóa vào ``.env`` (khóa cũ vẫn cần để giải mã dữ liệu cũ):
       MASTER_ENCRYPTION_KEYS=1:<khóa_cũ>,2:<khóa_mới>
       ACTIVE_KEY_VERSION=2

3. Chạy khô để xem sẽ đổi bao nhiêu bản ghi:
       uv run python scripts/rotate_encryption_key.py --dry-run

4. Sao lưu database, rồi chạy thật:
       uv run python scripts/rotate_encryption_key.py --to-version 2

5. Sau khi mọi bản ghi đã ở version mới, gỡ khóa cũ khỏi ``MASTER_ENCRYPTION_KEYS``
   và huỷ khóa cũ theo quy trình.

Script chạy theo lô và commit từng lô nên có thể dừng/chạy lại an toàn
(idempotent): bản ghi đã ở version đích sẽ bị bỏ qua.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select  # noqa: E402

from src.app.config import Settings  # noqa: E402
from src.app.db import Database  # noqa: E402
from src.app.models import SecureMessage, User  # noqa: E402
from src.app.security import CryptoService  # noqa: E402


def build_crypto(settings: Settings, target_version: int) -> CryptoService:
    keyring = dict(settings.master_encryption_keys)
    if settings.master_encryption_key:
        keyring.setdefault(1, settings.master_encryption_key)
    if target_version not in keyring:
        raise SystemExit(
            f"Không tìm thấy khóa version {target_version} trong MASTER_ENCRYPTION_KEYS. "
            f"Các version đang có: {sorted(keyring) or 'trống'}."
        )
    return CryptoService(keyring=keyring, active_key_version=target_version)


def rotate_messages(
    db, crypto: CryptoService, target: int, batch: int, dry_run: bool
) -> tuple[int, int]:
    """Re-encrypt every message not yet on the target key version."""
    rotated = 0
    failed = 0
    rows = list(db.scalars(select(SecureMessage).where(SecureMessage.key_version != target)))
    for index, row in enumerate(rows, start=1):
        try:
            plaintext = crypto.decrypt(
                row.ciphertext, row.nonce, row.session_id, row.role, row.key_version
            )
        except ValueError as exc:
            failed += 1
            print(f"  [BỎ QUA] message id={row.id}: {exc}", file=sys.stderr)
            continue
        if dry_run:
            rotated += 1
            continue
        ciphertext, nonce, version = crypto.encrypt(plaintext, row.session_id, row.role)
        row.ciphertext, row.nonce, row.key_version = ciphertext, nonce, version
        rotated += 1
        if index % batch == 0:
            db.commit()
            print(f"  ... đã xử lý {index}/{len(rows)} tin nhắn")
    if not dry_run:
        db.commit()
    return rotated, failed


def rotate_mfa_secrets(db, crypto: CryptoService, dry_run: bool) -> tuple[int, int]:
    """Re-wrap stored TOTP seeds under the new key."""
    rotated = 0
    failed = 0
    users = list(db.scalars(select(User).where(User.mfa_secret_ciphertext.is_not(None))))
    for user in users:
        context = f"mfa:{user.id}"
        try:
            secret = crypto.decrypt_secret(
                user.mfa_secret_ciphertext, user.mfa_secret_nonce, context
            )
        except ValueError as exc:
            failed += 1
            print(f"  [BỎ QUA] mfa seed user={user.username}: {exc}", file=sys.stderr)
            continue
        if dry_run:
            rotated += 1
            continue
        user.mfa_secret_ciphertext, user.mfa_secret_nonce = crypto.encrypt_secret(secret, context)
        rotated += 1
    if not dry_run:
        db.commit()
    return rotated, failed


def main() -> int:
    parser = argparse.ArgumentParser(description="Xoay vòng khóa mã hóa AES-256-GCM.")
    parser.add_argument(
        "--to-version",
        type=int,
        default=None,
        help="Key version đích (mặc định: ACTIVE_KEY_VERSION).",
    )
    parser.add_argument("--batch", type=int, default=200, help="Số bản ghi mỗi lần commit.")
    parser.add_argument("--dry-run", action="store_true", help="Chỉ đếm, không ghi thay đổi.")
    args = parser.parse_args()

    settings = Settings.from_env()
    keyring = dict(settings.master_encryption_keys)
    target = args.to_version or settings.active_key_version or (max(keyring) if keyring else 1)
    crypto = build_crypto(settings, target)

    print(f"Keyring nạp được: {crypto.known_key_versions}")
    print(f"Key version đích: {target}")
    if args.dry_run:
        print("Chế độ DRY-RUN — không có thay đổi nào được ghi.\n")
    else:
        print("!! Hãy chắc chắn bạn đã SAO LƯU database trước khi tiếp tục.\n")

    database = Database(settings.database_url)
    database.create_all()
    with database.session_factory() as db:
        print("Đang xoay khóa cho tin nhắn...")
        msg_ok, msg_fail = rotate_messages(db, crypto, target, args.batch, args.dry_run)
        print("Đang xoay khóa cho TOTP seed...")
        mfa_ok, mfa_fail = rotate_mfa_secrets(db, crypto, args.dry_run)
    database.engine.dispose()

    print(f"\nTin nhắn: {msg_ok} thành công, {msg_fail} lỗi")
    print(f"TOTP seed: {mfa_ok} thành công, {mfa_fail} lỗi")
    if msg_fail or mfa_fail:
        print(
            "\nCó bản ghi không giải mã được — kiểm tra lại keyring trước khi gỡ khóa cũ.",
            file=sys.stderr,
        )
        return 1
    if not args.dry_run:
        print("\nHoàn tất. Sau khi xác minh, có thể gỡ các khóa cũ khỏi MASTER_ENCRYPTION_KEYS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
