"""Interactive E2EE terminal: uv run --extra e2ee-client python -m clients.private_chat."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import shlex
import unicodedata
import warnings
from pathlib import Path

import httpx

from clients.e2ee_client import (
    ClientError,
    ClientPersistenceError,
    EncryptedVault,
    PrivateClient,
    checked_server,
)
from src.app.e2ee import safety_fingerprint


def hidden(prompt):
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except (getpass.GetPassWarning, EOFError) as exc:
            raise ClientError("Use an interactive terminal with hidden password input.") from exc


def terminal_json(value):
    """Render one JSON value without giving peer text terminal controls.

    Preserve normal Unicode text, including Vietnamese. JSON itself escapes
    C0 controls, but its Unicode mode leaves C1 controls, bidi directives and
    lone surrogates literal. Escape those after serialization as valid JSON;
    the displayed sender/field boundaries must remain visible and printable.
    """
    rendered = json.dumps(value, ensure_ascii=False)
    return "".join(
        json.dumps(character, ensure_ascii=True)[1:-1]
        if unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        else character
        for character in rendered
    )


def _authenticate(api, username):
    response = api.post("/api/auth/login", json={"username": username, "password": hidden("Mật khẩu SCAP: ")})
    if response.status_code != 200:
        raise ClientError(f"Login rejected (HTTP {response.status_code}).")
    data = response.json()
    if "mfa_token" in data:
        response = api.post("/api/auth/mfa/verify", json={"mfa_token": data["mfa_token"],
                                                        "code": hidden("TOTP / recovery code: ")})
        if response.status_code != 200:
            raise ClientError("Second factor rejected.")
        data = response.json()
    return data["access_token"]


HELP = """Lệnh:
  fingerprint                         Khóa công khai/fingerprint của chính bạn
  register                            Đăng ký hoặc kiểm tra lại thiết bị hiện tại
  offer / approve / register-approved  Phê duyệt thiết bị thứ hai qua kênh riêng
  pin <username>                      Xác minh đầy đủ fingerprint người nhận
  peers                               Danh sách thiết bị đã xác minh
  new <username>                      Tạo hội thoại Private E2EE 1:1
  send <session-id> <peer-device-id>    Nhập tin nhắn ở bước tiếp theo
  receive <session-id>                 Giải mã cục bộ các tin chưa nhận
  retry                               Gửi lại đúng ciphertext đang chờ
  refill [count]                      Bổ sung one-time prekey (mặc định 20)
  stepup                              Xác thực lại mật khẩu/MFA khi cần
  login                               Đăng nhập lại khi bearer hết hạn
  help / quit
Khóa riêng và ratchet chỉ ở client. Hãy so sánh fingerprint qua kênh khác.
Không mở cùng một profile bằng hai tiến trình hoặc phục hồi bản ratchet cũ.
"""


def interact(client):
    print(HELP)
    while True:
        try:
            parts = shlex.split(input("scap-private> "))
            if not parts:
                continue
            command, *args = parts
            if command == "quit":
                return
            if command == "help":
                print(HELP)
            elif command == "fingerprint":
                print(terminal_json({"device_id": client.device_id, "fingerprint": client.fingerprint}))
            elif command == "register":
                print(terminal_json(client.register_device()))
            elif command == "offer":
                print(terminal_json(client.registration_offer()))
            elif command == "approve":
                offer = json.loads(input("Offer công khai từ thiết bị mới (JSON): "))
                print("Fingerprint thiết bị mới:", safety_fingerprint(offer["identity_key"]))
                if input("Nhập APPROVE và device UUID để xác nhận: ") != f"APPROVE {offer['device_id']}":
                    raise ClientError("Device approval cancelled.")
                print(terminal_json(client.approve(offer)))
            elif command == "register-approved":
                approval = json.loads(input("Approval công khai từ thiết bị đang trusted (JSON): "))
                print(terminal_json(client.register_device(approval=approval)))
            elif command == "pin" and len(args) == 1:
                fingerprint = input("Fingerprint đầy đủ đã đối chiếu qua kênh khác: ")
                device = input("Device UUID người nhận (Enter để lấy thiết bị đầu tiên): ").strip()
                peer = client.pin_peer(args[0], fingerprint, device or None)
                print(terminal_json({"verified_device": peer["device_id"], "fingerprint": peer["fingerprint"]}))
            elif command == "peers":
                print(terminal_json([{key: peer[key] for key in ("username", "device_id", "fingerprint")}
                                     for peer in client.vault.state["peers"].values()]))
            elif command == "new" and len(args) == 1:
                print("Session UUID:", terminal_json(client.new_conversation(args[0])))
            elif command == "send" and len(args) == 2:
                text = input("Tin nhắn (không lưu trong argv): ")
                print(terminal_json(client.send(args[0], args[1], text)))
            elif command == "receive" and len(args) == 1:
                for message in client.receive(args[0]):
                    print(terminal_json(message))
                if client.last_receive_error:
                    print("Đã dừng nhận. Các tin ở trên đã được nhận; kiểm tra bản mã tiếp theo hoặc kết nối trước khi thử lại.")
                if client.requires_restart:
                    raise ClientPersistenceError("Client profile must be reopened.")
            elif command == "retry":
                print(terminal_json(client.flush()))
            elif command == "refill" and len(args) <= 1:
                print(terminal_json(client.refill(int(args[0]) if args else 20)))
            elif command == "stepup":
                client.request("POST", "/api/auth/step-up", json={"password": hidden("Mật khẩu: "),
                                                                  "code": hidden("TOTP (Enter nếu không dùng): ") or None})
                print("Đã xác thực lại.")
            elif command == "login":
                client.token = _authenticate(client.api, client.me["username"])
                print("Đã đăng nhập lại; khóa client không đổi.")
            else:
                print("Lệnh không hợp lệ. Gõ help.")
        except ClientPersistenceError:
            print("Không lưu được trạng thái mã hóa. Đã đóng client; hãy mở lại profile trước khi tiếp tục.")
            raise
        except (ClientError, ValueError, KeyError, httpx.HTTPError):
            print("Không hoàn tất thao tác. Kiểm tra lệnh, phiên/step-up, fingerprint, prekey hoặc outbox; không tự xóa profile.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args(argv)
    try:
        server = checked_server(args.server)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,31}", args.username):
            raise ClientError("Use the canonical SCAP username.")
        profile = args.profile or Path("client_data") / args.username
        password = hidden("Mật khẩu kho client (ít nhất 16 byte; khác mật khẩu SCAP): ")
        if not (profile / "client.scapclient").exists() and password != hidden("Nhập lại mật khẩu kho client: "):
            raise ClientError("Passphrases did not match.")
        with EncryptedVault(profile, password) as vault:
            with httpx.Client(base_url=server, timeout=15, trust_env=False, follow_redirects=False) as api:
                token = _authenticate(api, args.username)
                interact(PrivateClient(api, token, vault, server=server))
    except ClientPersistenceError:
        return 1
    except (ClientError, OSError, ValueError, httpx.HTTPError):
        print("Không mở được client. Kiểm tra server HTTPS/loopback, kho private, dependency và đăng nhập.")
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nĐã đóng client; trạng thái mã hóa vẫn được giữ.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
