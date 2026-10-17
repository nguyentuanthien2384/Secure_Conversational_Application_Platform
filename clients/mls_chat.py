"""Interactive native MLS terminal: python -m clients.mls_chat --username alice."""
from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

import httpx

from clients.e2ee_client import (
    ClientError,
    ClientPersistenceError,
    EncryptedVault,
    PrivateClient,
    checked_server,
)
from clients.mls_client import MlsClient
from clients.private_chat import _authenticate, hidden, terminal_json

HELP = """Lệnh MLS:
  fingerprint / register                Fingerprint và đăng ký thiết bị
  device-offer / approve / register-approved   Phê duyệt thiết bị bổ sung
  pin <username>                        Đối chiếu fingerprint thiết bị qua kênh khác
  offer / refresh-offer                 JSON KeyPackage công khai, có chữ ký thiết bị
  accept-offer                          Nhập JSON offer từ thiết bị đã pin
  new                                   Tạo nhóm MLS (owner)
  add <session-id> <device-id>           Thêm account + MLS Commit/Welcome
  remove <session-id> <device-id>        Xóa account + MLS Commit thay khóa epoch
  send <session-id>                     Nhập tin nhắn và mã hóa cục bộ
  receive <session-id> [owner-device]   Lần đầu chỉ rõ device owner đã pin
  retry / stepup / login / help / quit
Mỗi account đóng góp một thiết bị cho nhóm; owner quản lý membership.
Mọi thành viên phải pin fingerprint và accept-offer của toàn bộ roster.
Sau khi dùng Welcome, tạo refresh-offer nếu cần gia nhập một nhóm khác.
Kho native MLS được mã hóa cùng profile; không chạy hai client cùng profile.
"""


def interact(group):
    client = group.client
    print(HELP)
    while True:
        try:
            command, *args = shlex.split(input("scap-mls> ")) or ["help"]
            if command == "quit":
                return
            if command == "help":
                print(HELP)
            elif command == "fingerprint":
                print(terminal_json({"device_id": client.device_id, "fingerprint": client.fingerprint}))
            elif command == "register":
                print(terminal_json(client.register_device()))
            elif command == "device-offer":
                print(terminal_json(client.registration_offer()))
            elif command == "approve":
                offer = json.loads(input("Device offer công khai (JSON): "))
                if input("Nhập APPROVE và device UUID sau khi đối chiếu fingerprint: ") != f"APPROVE {offer['device_id']}":
                    raise ClientError("Device approval cancelled.")
                print(terminal_json(client.approve(offer)))
            elif command == "register-approved":
                print(terminal_json(client.register_device(approval=json.loads(input("Approval JSON: ")))))
            elif command == "pin" and len(args) == 1:
                fingerprint = input("Fingerprint đầy đủ đã đối chiếu qua kênh riêng: ")
                device = input("Device UUID của người nhận: ").strip()
                print(terminal_json(client.pin_peer(args[0], fingerprint, device)))
            elif command in {"offer", "refresh-offer"}:
                print(terminal_json(group.refresh_offer() if command == "refresh-offer" else group.offer()))
            elif command == "accept-offer":
                group.pin_offer(json.loads(input("KeyPackage offer công khai (JSON): ")))
                print("Đã xác minh chữ ký và pin MLS credential.")
            elif command == "new":
                print(terminal_json({"session_id": group.create()}))
            elif command in {"add", "remove"} and len(args) == 2:
                print(terminal_json(group.change_member(args[0], args[1], remove=command == "remove")))
            elif command == "send" and len(args) == 1:
                print(terminal_json(group.send(args[0], input("Tin nhắn: "))))
            elif command == "receive" and len(args) in {1, 2}:
                for message in group.receive(args[0], owner_device=args[1] if len(args) == 2 else None):
                    print(terminal_json(message))
                if group.last_receive_error:
                    print("Đã dừng nhận; các tin ở trên đã được nhận. Kiểm tra bản mã tiếp theo và thử lại.")
                if client.requires_restart:
                    raise ClientPersistenceError("Client profile must be reopened.")
            elif command == "retry":
                print(terminal_json(group.flush()))
            elif command == "stepup":
                client.request("POST", "/api/auth/step-up", json={"password": hidden("Mật khẩu SCAP: "),
                    "code": hidden("TOTP (Enter nếu không dùng): ") or None})
                print("Đã xác thực lại.")
            elif command == "login":
                client.token = _authenticate(client.api, client.me["username"])
                print("Đã đăng nhập lại.")
            else:
                print("Lệnh không hợp lệ. Gõ help.")
        except ClientPersistenceError:
            print("Không lưu được trạng thái; đóng client và mở lại profile trước khi tiếp tục.")
            raise
        except (ClientError, ValueError, KeyError, TypeError, OSError, httpx.HTTPError):
            print("Không hoàn tất. Kiểm tra fingerprint, MLS offer, epoch, phiên/step-up và outbox. Không tự xóa profile.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args(argv)
    try:
        origin = checked_server(args.server)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,31}", args.username):
            raise ClientError("Use a canonical SCAP username.")
        profile = args.profile or Path("client_data") / args.username
        password = hidden("Mật khẩu kho client (ít nhất 16 byte, khác mật khẩu SCAP): ")
        if not (profile / "client.scapclient").exists() and password != hidden("Nhập lại mật khẩu kho client: "):
            raise ClientError("Passphrases did not match.")
        with EncryptedVault(profile, password) as vault:
            with httpx.Client(base_url=origin, timeout=15, trust_env=False, follow_redirects=False) as api:
                interact(MlsClient(PrivateClient(api, _authenticate(api, args.username), vault, server=origin)))
    except (ClientError, OSError, ValueError, httpx.HTTPError):
        print("Không mở được MLS client. Kiểm tra native image, HTTPS/loopback, kho private và đăng nhập.")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nĐã đóng client; giữ profile để nhận tiếp hoặc gửi lại outbox.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

