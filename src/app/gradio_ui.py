"""Giao diện Gradio (thuần Python) cho Secure Conversational Application Platform.

UI gọi chính REST API của dự án qua httpx nên mọi thao tác đều đi qua JWT,
RBAC, rate limiting và audit trail. Bao phủ toàn bộ API: xác thực (kèm 2FA),
trò chuyện, bản mã, tìm kiếm toàn cục, tài khoản, thiết bị, quản trị, nhật ký.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path

import gradio as gr

BASE_URL = os.getenv("SELF_BASE_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}")
PASSWORD_MIN = 15
# Ảnh tĩnh của giao diện (avatar trợ lý). Đặt cạnh module để không phụ thuộc
# thư mục làm việc khi chạy bằng uvicorn hay Docker.
ASSET_DIR = Path(__file__).resolve().parent / "ui_assets"
_ASSISTANT_AVATAR = ASSET_DIR / "assistant.png"
# Nếu vì lý do nào đó tệp ảnh không được đóng gói cùng mã nguồn, bỏ avatar đi
# thay vì để Gradio dừng khi khởi tạo — giao diện vẫn phải chạy được.
AVATARS = (None, str(_ASSISTANT_AVATAR)) if _ASSISTANT_AVATAR.is_file() else None

THEME = gr.themes.Soft(
    primary_hue=gr.themes.colors.emerald,
    secondary_hue=gr.themes.colors.slate,
    neutral_hue=gr.themes.colors.slate,
    # radius_lg (22px) trông như app tiêu dùng; md gọn và "công cụ" hơn.
    radius_size=gr.themes.sizes.radius_md,
    # Thang chữ và khoảng cách nhỏ hơn -> mật độ thông tin cao hơn, giống
    # bảng điều khiển vận hành thật thay vì một trang demo.
    text_size=gr.themes.sizes.text_sm,
    spacing_size=gr.themes.sizes.spacing_sm,
    font=[gr.themes.GoogleFont("Be Vietnam Pro"), "system-ui", "sans-serif"],
    font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "ui-monospace", "monospace"],
)

CUSTOM_CSS = """
/* ==========================================================================
   SCAP — bảng điều khiển bảo mật
   Nguyên tắc: cột nội dung có giới hạn chiều rộng, mật độ cao, dữ liệu mật mã
   luôn dùng monospace. Màu nhấn CHỈ dùng để báo trạng thái, không trang trí.
   ========================================================================== */

:root {
  --scap-shell: 1200px;      /* cột nội dung — thay cho max-width: 100% */
  --scap-rail-h: 44px;
  --scap-ok-bg: #ecfdf5;   --scap-ok-bd: #6ee7b7;   --scap-ok-fg: #065f46;
  --scap-warn-bg: #fffbeb; --scap-warn-bd: #fcd34d; --scap-warn-fg: #78350f;
  --scap-bad-bg: #fef2f2;  --scap-bad-bd: #fca5a5;  --scap-bad-fg: #7f1d1d;
  --scap-rail-bg: #f8fafc;
}
/* CSS cũ hardcode màu sáng nên ở chế độ tối thành chữ xanh trên nền xanh.
   Khai báo lại token cho dark mode để mọi khối trạng thái vẫn đọc được. */
.dark {
  --scap-ok-bg: rgba(16,185,129,.12);   --scap-ok-bd: #059669;   --scap-ok-fg: #6ee7b7;
  --scap-warn-bg: rgba(245,158,11,.12); --scap-warn-bd: #b45309; --scap-warn-fg: #fcd34d;
  --scap-bad-bg: rgba(239,68,68,.12);   --scap-bad-bd: #b91c1c;  --scap-bad-fg: #fca5a5;
  --scap-rail-bg: rgba(148,163,184,.08);
}

footer { display: none !important; }

/* ── Khung ngoài: đây chính là phần sửa "full màn hình" ─────────────────── */
.gradio-container {
  max-width: var(--scap-shell) !important;
  margin: 0 auto !important;
  padding: 18px 24px 48px !important;
}

/* ── Trang đăng nhập ───────────────────────────────────────────────────── */
/* 580px quá rộng cho một form 2 ô; 420px là chuẩn thực tế. */
#auth-wrap { max-width: 420px; margin: 8vh auto 0; }
#auth-card {
  border: 1px solid var(--border-color-primary);
  border-radius: 14px;
  padding: 8px 24px 26px;
  background: var(--background-fill-primary);
  box-shadow: 0 1px 2px rgba(15,23,42,.04), 0 12px 32px rgba(15,23,42,.06);
}
/* Giữ 16px để iOS không tự zoom khi focus vào input. */
#auth-card input, #auth-card textarea { font-size: 16px !important; }
#auth-card button.primary, #auth-card .primary { padding: 10px 16px; font-weight: 600; }
#brand-auth { text-align: center; margin-bottom: 14px; }
#brand-auth h1 {
  font-size: 22px; font-weight: 650; letter-spacing: .18em;
  text-transform: uppercase; margin: 0;
}
#brand-auth p {
  color: var(--body-text-color-subdued); margin-top: 6px;
  font-size: 12px; letter-spacing: .04em;
}

/* ── Thanh trạng thái: chi tiết đặc trưng của giao diện này ─────────────
   Đọc như màn hình chỉ báo của thiết bị: phiên khóa, thời hạn token, trạng
   thái chuỗi audit. tabular-nums để chữ số không nhảy khi đếm ngược. */
#topbar {
  min-height: var(--scap-rail-h);
  border: 1px solid var(--border-color-primary);
  border-radius: 10px;
  padding: 0 14px;
  background: var(--scap-rail-bg);
  align-items: center;
  gap: 14px;
  overflow: hidden;
}
#topbar .md p {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  letter-spacing: .01em;
  color: var(--body-text-color-subdued);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
#topbar .md strong, #topbar .md code {
  color: var(--body-text-color); font-weight: 600; background: none; padding: 0;
}
#topbar button { font-size: 12px !important; }

/* ── Thẻ nội dung ──────────────────────────────────────────────────────── */
.section-card {
  border: 1px solid var(--border-color-primary);
  border-radius: 10px;
  padding: 14px;
  background: var(--background-fill-primary);
}

/* ── Tab: gọn, chữ nhỏ ─────────────────────────────────────────────────── */
.tab-nav { gap: 2px; }
.tab-nav button {
  font-size: 13px !important;
  padding: 8px 12px !important;
  letter-spacing: .01em;
}

/* ── Bảng dữ liệu: mọi thứ liên quan mật mã đều monospace ──────────────── */
.mono-df table {
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-variant-numeric: tabular-nums;
}
.mono-df th { font-size: 11px !important; text-transform: uppercase; letter-spacing: .05em; }
.mono-df td { white-space: nowrap; }

/* ── Danh sách hội thoại ───────────────────────────────────────────────── */
#side-title h4 {
  margin: 0 0 10px; font-size: 11px; font-weight: 650;
  text-transform: uppercase; letter-spacing: .07em;
  color: var(--body-text-color-subdued);
}
#session-list { max-height: 400px; overflow-y: auto; margin-bottom: 10px; }
#session-list .wrap { flex-direction: column !important; gap: 3px !important; }
#session-list label {
  display: flex !important;
  align-items: center;
  width: 100%;
  padding: 8px 10px !important;
  border: 1px solid transparent !important;
  border-radius: 7px !important;
  background: transparent !important;
  font-size: 13px !important;
  cursor: pointer;
  transition: background .12s ease, border-color .12s ease;
}
#session-list label:hover { background: var(--background-fill-secondary) !important; }
#session-list label.selected {
  border-color: var(--scap-ok-bd) !important;
  background: var(--scap-ok-bg) !important;
  font-weight: 600;
}
#session-list input[type="radio"] { display: none !important; }
#session-list span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* ── Khối trạng thái ───────────────────────────────────────────────────── */
#enc-note { margin-bottom: 8px; }
#enc-note p {
  margin: 0; font-size: 12px; font-family: var(--font-mono);
  color: var(--body-text-color-subdued);
}
#dlp-banner, #sec-verdict-ok, #sec-verdict-bad {
  border-radius: 8px; padding: 10px 13px; margin-top: 6px;
  border-left-width: 3px; border-left-style: solid;
}
#dlp-banner {
  border: 1px solid var(--scap-warn-bd);
  border-left-color: var(--scap-warn-bd);
  background: var(--scap-warn-bg);
}
#dlp-banner p { margin: 0; font-size: 13px; color: var(--scap-warn-fg); }
#sec-verdict-ok {
  border: 1px solid var(--scap-ok-bd);
  border-left-color: var(--scap-ok-bd);
  background: var(--scap-ok-bg);
  color: var(--scap-ok-fg);
}
#sec-verdict-bad {
  border: 1px solid var(--scap-bad-bd);
  border-left-color: var(--scap-bad-bd);
  background: var(--scap-bad-bg);
  color: var(--scap-bad-fg);
}
#sec-verdict-ok p, #sec-verdict-bad p { margin: 0; font-size: 13px; }

/* ── Bố cục ngang ──────────────────────────────────────────────────────── */
@media (min-width: 1000px) {
  #chat-row { flex-wrap: nowrap !important; }
  #topbar { flex-wrap: nowrap !important; }
}
@media (max-width: 999px) {
  .gradio-container { padding: 12px 14px 32px !important; }
  #topbar { padding: 10px 12px; }
  #auth-wrap { margin-top: 4vh; }
}

/* Sàn chất lượng: focus thấy được bằng bàn phím, tôn trọng reduced-motion. */
:where(button, input, textarea, select, [tabindex]):focus-visible {
  outline: 2px solid var(--scap-ok-bd);
  outline-offset: 2px;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: .01ms !important;
    animation-duration: .01ms !important;
  }
}
"""


# ────────────────────────── API helper ──────────────────────────
def _api(token, method, path, body=None, *, params=None):
    import httpx

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(base_url=BASE_URL, timeout=60) as client:
            func = getattr(client, method.lower())
            if body is not None and method != "GET":
                resp = func(path, headers=headers, json=body)
            else:
                resp = func(path, headers=headers, params=params)
    except httpx.ConnectError as exc:
        raise gr.Error(
            f"Không kết nối được API nội bộ tại {BASE_URL}. "
            "Nếu server chạy ở cổng khác, hãy đặt SELF_BASE_URL trong .env."
        ) from exc
    if resp.status_code == 204:
        return {}
    try:
        data = resp.json()
    except ValueError as exc:
        raise gr.Error(f"Máy chủ trả về dữ liệu không hợp lệ (HTTP {resp.status_code}).") from exc
    if resp.status_code >= 400:
        detail = data.get("detail") if isinstance(data, dict) else None
        if isinstance(detail, list):
            detail = " · ".join(item.get("msg", str(item)) for item in detail)
        message = detail or f"HTTP {resp.status_code}"
        if resp.status_code == 429:
            retry = resp.headers.get("Retry-After")
            if retry:
                message += f" Thử lại sau {retry} giây."
        raise gr.Error(message)
    return data


def _fmt(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return iso


def _guard(fn, n_outputs):
    """Chạy handler; nếu API trả lỗi (gr.Error) thì hiển thị toast cảnh báo
    thay vì để Gradio gắn nhãn "Error" kẹt trên các component output."""

    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except gr.Error as err:
            gr.Warning(str(err))
            if n_outputs <= 1:
                return gr.skip()
            return tuple(gr.skip() for _ in range(n_outputs))

    return wrapper


def _session_choices(token):
    """Nhãn có ổ khoá để nhắc rằng nội dung phiên được mã hoá khi lưu."""
    return [(f"🔒  {row['title']}", row["id"]) for row in _api(token, "GET", "/api/sessions")]


def _chat_history(token, session_id):
    if not session_id:
        return []
    rows = _api(token, "GET", f"/api/sessions/{session_id}/messages")
    return [{"role": row["role"], "content": row["content"]} for row in rows]


def _devices_snapshot(token):
    rows = _api(token, "GET", "/api/auth/sessions")
    table = [
        [
            ("✔ thiết bị này" if row["is_current"] else ""),
            (row.get("user_agent") or "Không rõ")[:60],
            row.get("ip_address") or "—",
            _fmt(row["issued_at"]),
            _fmt(row["expires_at"]),
        ]
        for row in rows
    ]
    revoke = [
        (f"{(row.get('ip_address') or '—')} · {_fmt(row['issued_at'])}", row["id"])
        for row in rows
        if not row["is_current"]
    ]
    return table, revoke


# ────────────────────────── giao diện ──────────────────────────
def build_ui() -> gr.Blocks:
    with gr.Blocks(title="SCAP", theme=THEME, css=CUSTOM_CSS) as demo:
        st_token = gr.State("")
        st_exp = gr.State(0.0)
        st_mfa = gr.State("")

        # ============ XÁC THỰC ============
        with gr.Column(visible=True, elem_id="auth-wrap") as auth_sec:
            gr.Markdown(
                "# 🔐 SCAP\nSecure Conversational Application Platform",
                elem_id="brand-auth",
            )
            with gr.Column(elem_id="auth-card"):
                with gr.Tabs() as auth_tabs:
                    with gr.Tab("Đăng nhập", id="tab_login"):
                        li_user = gr.Textbox(label="Tên đăng nhập", max_length=64)
                        li_pass = gr.Textbox(label="Mật khẩu", type="password", max_length=128)
                        btn_login = gr.Button("Đăng nhập", variant="primary")
                    with gr.Tab("Tạo tài khoản", id="tab_register"):
                        re_user = gr.Textbox(
                            label="Tên đăng nhập", max_length=32, info="3–32 ký tự: chữ, số, . _ -"
                        )
                        re_pass = gr.Textbox(
                            label="Mật khẩu",
                            type="password",
                            max_length=128,
                            info=f"Tối thiểu {PASSWORD_MIN} ký tự",
                        )
                        btn_register = gr.Button("Tạo tài khoản", variant="primary")
                with gr.Group(visible=False) as grp_mfa_login:
                    tb_mfa_code = gr.Textbox(
                        label="Mã xác thực hai lớp",
                        info="Mã 6 số từ ứng dụng, hoặc mã khôi phục",
                        max_length=32,
                    )
                    with gr.Row():
                        btn_mfa_verify = gr.Button("Xác nhận", variant="primary")
                        btn_mfa_cancel = gr.Button("Quay lại")

        # ============ ỨNG DỤNG ============
        with gr.Column(visible=False) as app_sec:
            with gr.Row(elem_id="topbar"):
                md_banner = gr.Markdown("", elem_classes="md")
                md_countdown = gr.Markdown("", elem_classes="md")
                btn_logout = gr.Button("Đăng xuất", scale=0, size="sm")
            timer = gr.Timer(1, active=False)

            with gr.Tabs():
                # ---------- TRÒ CHUYỆN ----------
                with gr.Tab("Trò chuyện"):
                    with gr.Row(elem_id="chat-row"):
                        with gr.Column(scale=1, min_width=290, elem_classes="section-card"):
                            gr.Markdown("#### Phiên hội thoại", elem_id="side-title")
                            # Danh sách chọn được bằng một cú bấm (thay cho Dropdown).
                            # gr.Radio giữ nguyên API choices/value nên mọi handler cũ
                            # vẫn dùng được; CSS bên dưới biến mỗi lựa chọn thành một
                            # hàng có ổ khoá, cuộn được khi nhiều hội thoại.
                            dd_session = gr.Radio(
                                choices=[],
                                value=None,
                                show_label=False,
                                interactive=True,
                                elem_id="session-list",
                                container=False,
                            )
                            with gr.Row():
                                btn_create = gr.Button(
                                    "+ Hội thoại mới", variant="primary", size="sm", scale=3
                                )
                                btn_refresh = gr.Button("↻", size="sm", scale=1, min_width=44)
                            tb_new_title = gr.Textbox(
                                show_label=False,
                                max_lines=1,
                                placeholder="Tiêu đề cho hội thoại mới…",
                            )
                            with gr.Accordion("Quản lý hội thoại đang chọn", open=False):
                                tb_rename = gr.Textbox(label="Đổi tên", max_lines=1)
                                btn_rename = gr.Button("Lưu tên mới", size="sm")
                                with gr.Row():
                                    btn_export = gr.Button("Xuất JSON", size="sm")
                                    btn_delete = gr.Button("Xóa", variant="stop", size="sm")
                            file_export = gr.File(label="Tệp đã xuất", visible=False)
                        with gr.Column(scale=3, min_width=520):
                            # Nhắc trạng thái mã hoá ngay trên khung chat.
                            gr.Markdown(
                                "🔒 **Đã mã hoá** — nội dung lưu dưới dạng AES-256-GCM, "
                                "khoá không nằm trong cơ sở dữ liệu.",
                                elem_id="enc-note",
                            )
                            chatbot = gr.Chatbot(
                                label="Nội dung",
                                height=540,
                                avatar_images=AVATARS,
                                buttons=["copy", "copy_all"],
                                allow_file_downloads=False,
                            )
                            with gr.Row():
                                tb_msg = gr.Textbox(
                                    show_label=False,
                                    placeholder="Nhập tin nhắn — Enter để gửi…",
                                    max_lines=3,
                                    max_length=4000,
                                    scale=6,
                                )
                                btn_send = gr.Button(
                                    "Gửi", variant="primary", scale=1, min_width=110
                                )
                            # Băng thông báo DLP: hiện lên khi lớp chống rò rỉ dữ
                            # liệu đã che thứ gì đó trước khi gửi sang AI bên ngoài.
                            md_dlp = gr.Markdown("", visible=False, elem_id="dlp-banner")
                            with gr.Row():
                                tb_search = gr.Textbox(
                                    show_label=False,
                                    placeholder="Tìm trong hội thoại này…",
                                    max_lines=1,
                                    scale=4,
                                )
                                btn_search = gr.Button("Tìm", size="sm", scale=1)
                                btn_search_clear = gr.Button("Xem tất cả", size="sm", scale=1)

                # ---------- DỮ LIỆU MÃ HÓA ----------
                with gr.Tab("Dữ liệu mã hóa"):
                    with gr.Row():
                        dd_cipher = gr.Dropdown(
                            label="Hội thoại", choices=[], interactive=True, scale=3
                        )
                        btn_cipher = gr.Button("Tải bản mã", scale=1)
                    df_cipher = gr.Dataframe(
                        headers=[
                            "#",
                            "Vai trò",
                            "Ciphertext (base64, rút gọn)",
                            "Nonce",
                            "Key ver.",
                            "Thời điểm",
                        ],
                        interactive=False,
                        wrap=True,
                        elem_classes="mono-df",
                    )

                # ---------- TÌM KIẾM ----------
                with gr.Tab("Tìm kiếm"):
                    with gr.Row():
                        tb_gq = gr.Textbox(
                            label="Từ khóa (trên mọi hội thoại của bạn)", max_lines=1, scale=4
                        )
                        btn_gsearch = gr.Button("Tìm kiếm", variant="primary", scale=1)
                    df_gsearch = gr.Dataframe(
                        headers=["Hội thoại", "Vai trò", "Nội dung", "Thời điểm"],
                        interactive=False,
                        wrap=True,
                    )

                # ---------- TÀI KHOẢN ----------
                with gr.Tab("Tài khoản"):
                    md_profile = gr.Markdown("")
                    chk_consent = gr.Checkbox(
                        label="Cho phép gửi nội dung (đã lọc thông tin nhạy cảm) tới AI bên ngoài"
                    )
                    with gr.Accordion("Đổi mật khẩu", open=False):
                        tb_pw_cur = gr.Textbox(
                            label="Mật khẩu hiện tại", type="password", max_length=128
                        )
                        tb_pw_new = gr.Textbox(
                            label="Mật khẩu mới",
                            type="password",
                            max_length=128,
                            info=f"Tối thiểu {PASSWORD_MIN} ký tự — đổi xong sẽ cần đăng nhập lại",
                        )
                        btn_pw = gr.Button("Cập nhật mật khẩu", variant="primary", size="sm")
                    with gr.Accordion("Xác thực hai lớp (TOTP)", open=True):
                        md_mfa_state = gr.Markdown("")
                        with gr.Group(visible=False) as grp_mfa_enroll:
                            btn_enroll = gr.Button("Bắt đầu thiết lập 2FA", size="sm")
                            with gr.Group(visible=False) as grp_mfa_setup:
                                with gr.Row():
                                    img_qr = gr.Image(
                                        label="Quét bằng ứng dụng xác thực", height=220, scale=1
                                    )
                                    with gr.Column(scale=2):
                                        tb_secret = gr.Textbox(
                                            label="Khóa thủ công", interactive=False
                                        )
                                        tb_activate = gr.Textbox(label="Mã 6 số", max_length=8)
                                        btn_activate = gr.Button(
                                            "Kích hoạt", variant="primary", size="sm"
                                        )
                        md_recovery = gr.Markdown("", visible=False)
                        with gr.Group(visible=False) as grp_mfa_manage:
                            with gr.Row():
                                tb_dis_pw = gr.Textbox(
                                    label="Mật khẩu", type="password", max_length=128
                                )
                                tb_dis_code = gr.Textbox(label="Mã TOTP / khôi phục", max_length=32)
                            btn_disable = gr.Button("Tắt 2FA", variant="stop", size="sm")
                    with gr.Accordion("Thiết bị đang đăng nhập", open=True):
                        df_devices = gr.Dataframe(
                            headers=[
                                "",
                                "Thiết bị / trình duyệt",
                                "IP",
                                "Đăng nhập lúc",
                                "Hết hạn",
                            ],
                            interactive=False,
                            wrap=True,
                        )
                        with gr.Row():
                            dd_revoke = gr.Dropdown(label="Phiên cần thu hồi", choices=[], scale=3)
                            btn_revoke = gr.Button("Thu hồi", size="sm", scale=1)
                            btn_dev_refresh = gr.Button("Làm mới", size="sm", scale=1)
                        btn_logout_all = gr.Button(
                            "Đăng xuất mọi thiết bị", variant="stop", size="sm"
                        )

                # ---------- QUẢN TRỊ ----------
                with gr.Tab("Quản trị", visible=False) as adm_tab:
                    btn_adm_refresh = gr.Button("Làm mới toàn bộ", size="sm")
                    md_stats = gr.Markdown("")
                    md_alerts = gr.Markdown("")
                    df_users = gr.Dataframe(
                        headers=["Tên", "Vai trò", "Trạng thái", "2FA", "Ngày tạo"],
                        interactive=False,
                        wrap=True,
                    )
                    with gr.Row():
                        dd_user_pick = gr.Dropdown(label="Người dùng", choices=[], scale=2)
                        dd_role_new = gr.Dropdown(
                            label="Vai trò mới",
                            choices=["user", "moderator", "admin"],
                            value="user",
                            scale=1,
                        )
                        btn_set_role = gr.Button("Đổi vai trò", size="sm", scale=1)
                    with gr.Row():
                        btn_lock = gr.Button("Khóa", size="sm")
                        btn_unlock = gr.Button("Mở khóa", size="sm")
                        btn_del_user = gr.Button("Xóa tài khoản", variant="stop", size="sm")
                    with gr.Accordion("Tạo tài khoản mới", open=False):
                        with gr.Row():
                            tb_cu_name = gr.Textbox(label="Tên đăng nhập", max_length=32)
                            tb_cu_pw = gr.Textbox(label="Mật khẩu", type="password", max_length=128)
                            dd_cu_role = gr.Dropdown(
                                label="Vai trò",
                                choices=["user", "moderator", "admin"],
                                value="user",
                            )
                        btn_cu = gr.Button("Tạo", variant="primary", size="sm")

                # ---------- NHẬT KÝ ----------
                with gr.Tab("Nhật ký kiểm toán", visible=False) as mod_tab:
                    with gr.Row():
                        sl_audit = gr.Slider(10, 500, value=100, step=10, label="Số dòng", scale=3)
                        btn_audit = gr.Button("Tải nhật ký", size="sm", scale=1)
                    df_audit = gr.Dataframe(
                        headers=[
                            "#",
                            "Sự kiện",
                            "Kết quả",
                            "Actor",
                            "Đối tượng",
                            "IP",
                            "Thời điểm",
                        ],
                        interactive=False,
                        wrap=True,
                        elem_classes="mono-df",
                    )

                # ---------- TRUNG TÂM BẢO MẬT ----------
                # Màn hình giám sát cho moderator/admin: xác minh chuỗi băm audit
                # (Bài 1 §Accounting) và theo dõi IDS/IPS (Bài 7 §7.3).
                with gr.Tab("Bảo mật", visible=False) as sec_tab:
                    gr.Markdown(
                        "### Trung tâm giám sát\n"
                        "Xác minh tính toàn vẹn của nhật ký kiểm toán và theo dõi "
                        "hệ thống phát hiện xâm nhập."
                    )
                    btn_sec_all = gr.Button("Làm mới toàn bộ", variant="primary", size="sm")

                    with gr.Accordion("1 · Toàn vẹn nhật ký kiểm toán (hash chain)", open=True):
                        gr.Markdown(
                            "Mỗi bản ghi cam kết vào bản ghi trước bằng "
                            "`HMAC-SHA256(khóa, prev_hash ‖ bản_ghi)`. Sửa hoặc xoá một dòng "
                            "sẽ làm gãy chuỗi và bị phát hiện tại đây. *Chức năng này cần vai trò admin.*"
                        )
                        btn_sec_verify = gr.Button("Xác minh chuỗi", size="sm")
                        md_sec_verdict = gr.Markdown("")

                    with gr.Accordion("2 · IDS — mẫu tấn công đã phát hiện", open=True):
                        df_sec_det = gr.Dataframe(
                            headers=["Luật", "Mức", "Mô tả", "Nguồn", "Đường dẫn", "Dấu hiệu"],
                            interactive=False,
                            wrap=True,
                            elem_classes="mono-df",
                        )

                    with gr.Accordion("3 · IDS — hành vi bất thường", open=True):
                        with gr.Row():
                            sl_sec_win = gr.Slider(
                                5, 720, value=60, step=5, label="Cửa sổ thời gian (phút)", scale=3
                            )
                            btn_sec_anom = gr.Button("Phân tích", size="sm", scale=1)
                        df_sec_anom = gr.Dataframe(
                            headers=["Mã", "Mức", "Đối tượng", "Số lần", "Diễn giải"],
                            interactive=False,
                            wrap=True,
                            elem_classes="mono-df",
                        )

                    with gr.Accordion("4 · IPS — nguồn đang bị chặn", open=True):
                        gr.Markdown("*Xem và gỡ chặn cần vai trò admin.*")
                        df_sec_block = gr.Dataframe(
                            headers=["Địa chỉ IP", "Còn bị chặn (giây)"],
                            interactive=False,
                            wrap=True,
                            elem_classes="mono-df",
                        )
                        with gr.Row():
                            tb_sec_ip = gr.Textbox(label="IP cần gỡ chặn", max_lines=1, scale=3)
                            btn_sec_unblock = gr.Button("Gỡ chặn", size="sm", scale=1)

        # ══════════════════════ HANDLERS ══════════════════════
        # Giai đoạn 1 (nhẹ, ít output): xác thực + chuyển màn hình.
        STAGE1 = [st_token, st_exp, st_mfa, auth_sec, app_sec, grp_mfa_login, li_pass, tb_mfa_code]
        # Giai đoạn 2 (chạy nối bằng .then): nạp dữ liệu không gian làm việc.
        STAGE2 = [
            adm_tab,
            mod_tab,
            sec_tab,
            md_banner,
            dd_session,
            dd_cipher,
            chatbot,
            md_profile,
            chk_consent,
            md_mfa_state,
            grp_mfa_enroll,
            grp_mfa_manage,
            df_devices,
            dd_revoke,
            timer,
        ]
        RESET_OUTS = STAGE1 + STAGE2 + [md_countdown]

        def _reset_tuple():
            return (
                "",
                0.0,
                "",
                gr.update(visible=True),
                gr.update(visible=False),
                gr.update(visible=False),
                "",
                "",
                gr.update(visible=False),
                gr.update(visible=False),
                gr.update(visible=False),
                "",
                gr.update(choices=[], value=None),
                gr.update(choices=[], value=None),
                [],
                "",
                gr.update(value=False),
                "",
                gr.update(visible=False),
                gr.update(visible=False),
                [],
                gr.update(choices=[], value=None),
                gr.Timer(active=False),
                "",
            )

        # ---- đăng ký ----
        def do_register(username, password):
            username = (username or "").strip()
            if not (3 <= len(username) <= 32):
                gr.Warning("Tên đăng nhập phải từ 3 đến 32 ký tự.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            if len(password or "") < PASSWORD_MIN:
                gr.Warning(f"Mật khẩu phải có ít nhất {PASSWORD_MIN} ký tự.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            data = _api(
                None, "POST", "/api/auth/register", {"username": username, "password": password}
            )
            gr.Info(f"Tạo tài khoản “{data['username']}” thành công — mời đăng nhập.")
            return "", "", data["username"], gr.Tabs(selected="tab_login")

        btn_register.click(
            _guard(do_register, 4), [re_user, re_pass], [re_user, re_pass, li_user, auth_tabs]
        )

        # ---- đăng nhập ----
        def do_login(username, password):
            username = (username or "").strip()
            if not username or not password:
                gr.Warning("Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.")
                return tuple(gr.skip() for _ in STAGE1)
            data = _api(
                None, "POST", "/api/auth/login", {"username": username, "password": password}
            )
            if data.get("mfa_required"):
                gr.Info("Tài khoản đã bật 2FA — nhập mã xác thực để tiếp tục.")
                return (
                    "",
                    0.0,
                    data["mfa_token"],
                    gr.skip(),
                    gr.skip(),
                    gr.update(visible=True),
                    gr.skip(),
                    "",
                )
            gr.Info("Đăng nhập thành công.")
            return (
                data["access_token"],
                time.time() + data["expires_in"],
                "",
                gr.update(visible=False),
                gr.update(visible=True),
                gr.update(visible=False),
                "",
                "",
            )

        def load_workspace(token):
            if not token:
                return tuple(gr.skip() for _ in STAGE2)
            me = _api(token, "GET", "/api/auth/me")
            role = me["role"]
            choices = _session_choices(token)
            selected = choices[0][1] if choices else None
            devices, revoke = _devices_snapshot(token)
            mfa_on = me["mfa_enabled"]
            banner = f"**{me['username']}** · vai trò `{role}` · 2FA {'🟢' if mfa_on else '⚪'}"
            profile = (
                f"**Tên đăng nhập:** `{me['username']}` · **Vai trò:** `{role}` · "
                f"**Ngày tạo:** {_fmt(me['created_at'])}"
            )
            return (
                gr.update(visible=(role == "admin")),
                gr.update(visible=(role in ("moderator", "admin"))),
                gr.update(visible=(role in ("moderator", "admin"))),  # sec_tab
                banner,
                gr.update(choices=choices, value=selected),
                gr.update(choices=choices, value=selected),
                _chat_history(token, selected),
                profile,
                gr.update(value=me["ai_data_consent"]),
                (
                    "**2FA đang bật.**"
                    if mfa_on
                    else "**2FA đang tắt** — nên bật để bảo vệ tài khoản."
                ),
                gr.update(visible=not mfa_on),
                gr.update(visible=mfa_on),
                devices,
                gr.update(choices=revoke, value=None),
                gr.Timer(active=True),
            )

        btn_login.click(_guard(do_login, len(STAGE1)), [li_user, li_pass], STAGE1).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2
        )
        li_pass.submit(_guard(do_login, len(STAGE1)), [li_user, li_pass], STAGE1).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2
        )

        def do_mfa_verify(mfa_token, code):
            if not mfa_token:
                gr.Warning("Phiên xác thực đã hết — hãy đăng nhập lại.")
                return tuple(gr.skip() for _ in STAGE1)
            data = _api(
                None,
                "POST",
                "/api/auth/mfa/verify",
                {"mfa_token": mfa_token, "code": (code or "").strip()},
            )
            gr.Info("Đăng nhập thành công.")
            return (
                data["access_token"],
                time.time() + data["expires_in"],
                "",
                gr.update(visible=False),
                gr.update(visible=True),
                gr.update(visible=False),
                "",
                "",
            )

        btn_mfa_verify.click(
            _guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1
        ).then(_guard(load_workspace, len(STAGE2)), [st_token], STAGE2)
        tb_mfa_code.submit(_guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2
        )
        btn_mfa_cancel.click(
            lambda: ("", gr.update(visible=False), ""), None, [st_mfa, grp_mfa_login, tb_mfa_code]
        )

        # ---- đăng xuất + đồng hồ token ----
        def do_logout(token):
            if token:
                try:
                    _api(token, "POST", "/api/auth/logout")
                    gr.Info("Đã đăng xuất và thu hồi token trên máy chủ.")
                except Exception:
                    gr.Warning("Không xác nhận được với máy chủ; trạng thái cục bộ đã xóa.")
            return _reset_tuple()

        btn_logout.click(_guard(do_logout, len(RESET_OUTS)), [st_token], RESET_OUTS)

        def tick(exp):
            if not exp:
                return ""
            left = int(exp - time.time())
            if left <= 0:
                return "⛔ **Token đã hết hạn** — hãy đăng nhập lại."
            hours, rem = divmod(left, 3600)
            minutes, seconds = divmod(rem, 60)
            shown = f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"
            return f"⏳ **{shown}**"

        timer.tick(tick, [st_exp], [md_countdown])

        # ---- trò chuyện ----
        def refresh_sessions(token, selected=None):
            choices = _session_choices(token)
            ids = {value for _, value in choices}
            selected = selected if selected in ids else (choices[0][1] if choices else None)
            return (
                gr.update(choices=choices, value=selected),
                gr.update(choices=choices, value=selected),
                _chat_history(token, selected),
            )

        btn_refresh.click(
            _guard(refresh_sessions, 3), [st_token, dd_session], [dd_session, dd_cipher, chatbot]
        )

        def pick_session(token, session_id):
            """Bấm một hàng trong danh sách: nạp hội thoại và điền sẵn tên hiện tại."""
            history = _chat_history(token, session_id)
            title = ""
            if session_id:
                for label, value in _session_choices(token):
                    if value == session_id:
                        title = label.replace("🔒", "").strip()
                        break
            # Ẩn băng DLP của lượt trước khi chuyển sang hội thoại khác.
            return history, title, gr.update(value="", visible=False)

        dd_session.input(
            _guard(pick_session, 3), [st_token, dd_session], [chatbot, tb_rename, md_dlp]
        )

        def create_session(token, title):
            created = _api(
                token,
                "POST",
                "/api/sessions",
                {"title": (title or "").strip() or "Cuộc hội thoại mới"},
            )
            gr.Info("Đã tạo hội thoại.")
            dd1, dd2, history = refresh_sessions(token, created["id"])
            return dd1, dd2, history, ""

        btn_create.click(
            _guard(create_session, 4),
            [st_token, tb_new_title],
            [dd_session, dd_cipher, chatbot, tb_new_title],
        )

        def rename_session(token, session_id, title):
            if not session_id or not (title or "").strip():
                gr.Warning("Chọn hội thoại và nhập tiêu đề mới.")
                return gr.skip(), gr.skip(), gr.skip()
            _api(token, "PATCH", f"/api/sessions/{session_id}", {"title": title.strip()})
            gr.Info("Đã đổi tên hội thoại.")
            dd1, dd2, _ = refresh_sessions(token, session_id)
            return dd1, dd2, ""

        btn_rename.click(
            _guard(rename_session, 3),
            [st_token, dd_session, tb_rename],
            [dd_session, dd_cipher, tb_rename],
        )

        def delete_session(token, session_id):
            if not session_id:
                gr.Warning("Chọn một hội thoại trước.")
                return gr.skip(), gr.skip(), gr.skip()
            _api(token, "DELETE", f"/api/sessions/{session_id}")
            gr.Info("Đã xóa hội thoại và toàn bộ bản mã của nó.")
            return refresh_sessions(token)

        btn_delete.click(
            _guard(delete_session, 3), [st_token, dd_session], [dd_session, dd_cipher, chatbot]
        )

        def export_session(token, session_id):
            if not session_id:
                gr.Warning("Chọn một hội thoại trước.")
                return gr.skip()
            data = _api(token, "GET", f"/api/sessions/{session_id}/export")
            path = (
                Path(tempfile.gettempdir()) / f"scap-{session_id[:8]}-{uuid.uuid4().hex[:6]}.json"
            )
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            gr.Info("Đã xuất — bấm vào tệp bên dưới để tải về.")
            return gr.update(value=str(path), visible=True)

        btn_export.click(_guard(export_session, 1), [st_token, dd_session], [file_export])

        def send_message(token, session_id, message):
            message = (message or "").strip()
            if not message:
                return gr.skip(), gr.skip(), gr.skip(), "", gr.skip()
            if not session_id:
                title = message[:48] + ("…" if len(message) > 48 else "")
                created = _api(token, "POST", "/api/sessions", {"title": title})
                session_id = created["id"]
                gr.Info("Đã tự tạo hội thoại mới.")
            sent = _api(token, "POST", f"/api/sessions/{session_id}/messages", {"content": message})
            dd1, dd2, history = refresh_sessions(token, session_id)
            # Nếu DLP đã che dữ liệu nhạy cảm, nói rõ cho người dùng biết đã che
            # NHÓM nào — không bao giờ hiện lại giá trị gốc.
            labels = (sent or {}).get("dlp_redacted") or []
            if labels:
                gr.Warning("Đã che dữ liệu nhạy cảm trước khi gửi sang AI: " + ", ".join(labels))
                banner = gr.update(
                    value=(
                        "🛡️ **Lớp DLP đã can thiệp.** Trước khi gửi sang nhà cung cấp AI "
                        "bên ngoài, hệ thống đã che: **" + ", ".join(labels) + "**. "
                        "Bản gốc vẫn được mã hoá AES-256-GCM và lưu nguyên trong hội thoại của bạn."
                    ),
                    visible=True,
                )
            else:
                banner = gr.update(value="", visible=False)
            return dd1, dd2, history, "", banner

        SEND_OUTS = [dd_session, dd_cipher, chatbot, tb_msg, md_dlp]
        btn_send.click(_guard(send_message, 5), [st_token, dd_session, tb_msg], SEND_OUTS)
        tb_msg.submit(_guard(send_message, 5), [st_token, dd_session, tb_msg], SEND_OUTS)

        def search_in_session(token, session_id, query):
            if not session_id:
                gr.Warning("Chọn một hội thoại trước.")
                return gr.skip()
            query = (query or "").strip()
            if not query:
                return _chat_history(token, session_id)
            rows = _api(
                token, "GET", f"/api/sessions/{session_id}/messages", params={"query": query}
            )
            gr.Info(f"Tìm thấy {len(rows)} tin nhắn.")
            return [{"role": row["role"], "content": row["content"]} for row in rows]

        btn_search.click(_guard(search_in_session, 1), [st_token, dd_session, tb_search], [chatbot])
        btn_search_clear.click(
            _guard(lambda tk, sid: (_chat_history(tk, sid), ""), 2),
            [st_token, dd_session],
            [chatbot, tb_search],
        )

        # ---- dữ liệu mã hóa ----
        def load_cipher(token, session_id):
            if not session_id:
                gr.Warning("Chọn một hội thoại trước.")
                return gr.skip()
            rows = _api(token, "GET", f"/api/sessions/{session_id}/ciphertexts")
            if not rows:
                gr.Info("Hội thoại này chưa có tin nhắn nào.")
            return [
                [
                    row["id"],
                    row["role"],
                    row["ciphertext_preview"],
                    row["nonce"],
                    f"v{row['key_version']}",
                    _fmt(row["created_at"]),
                ]
                for row in rows
            ]

        btn_cipher.click(_guard(load_cipher, 1), [st_token, dd_cipher], [df_cipher])

        # ---- tìm kiếm toàn cục ----
        def global_search(token, query):
            query = (query or "").strip()
            if not query:
                gr.Warning("Nhập từ khóa trước.")
                return gr.skip()
            rows = _api(token, "GET", "/api/search/messages", params={"q": query})
            gr.Info(
                f"Tìm thấy {len(rows)} tin nhắn "
                f"trong {len({r['session_id'] for r in rows})} hội thoại."
            )
            return [
                [
                    row["session_title"],
                    ("Bạn" if row["role"] == "user" else "Trợ lý"),
                    row["content"][:200] + ("…" if len(row["content"]) > 200 else ""),
                    _fmt(row["created_at"]),
                ]
                for row in rows
            ]

        btn_gsearch.click(_guard(global_search, 1), [st_token, tb_gq], [df_gsearch])
        tb_gq.submit(_guard(global_search, 1), [st_token, tb_gq], [df_gsearch])

        # ---- tài khoản ----
        def set_consent(token, consent):
            data = _api(token, "PATCH", "/api/auth/ai-consent", {"ai_data_consent": bool(consent)})
            gr.Info("Đã cập nhật lựa chọn chia sẻ dữ liệu AI.")
            return gr.update(value=bool(data["ai_data_consent"]))

        chk_consent.input(_guard(set_consent, 1), [st_token, chk_consent], [chk_consent])

        def change_password(token, current, new):
            if not (current or "").strip() or not (new or "").strip():
                gr.Warning("Nhập cả mật khẩu hiện tại và mật khẩu mới.")
                return tuple(gr.skip() for _ in RESET_OUTS) + (gr.skip(), gr.skip())
            if len(new) < PASSWORD_MIN:
                gr.Warning(f"Mật khẩu mới phải có ít nhất {PASSWORD_MIN} ký tự.")
                return tuple(gr.skip() for _ in RESET_OUTS) + (gr.skip(), gr.skip())
            _api(
                token,
                "PATCH",
                "/api/auth/password",
                {"current_password": current, "new_password": new},
            )
            gr.Info("Đã đổi mật khẩu — mọi phiên bị thu hồi, mời đăng nhập lại.")
            return _reset_tuple() + ("", "")

        btn_pw.click(
            _guard(change_password, len(RESET_OUTS) + 2),
            [st_token, tb_pw_cur, tb_pw_new],
            RESET_OUTS + [tb_pw_cur, tb_pw_new],
        )

        # ---- 2FA ----
        def mfa_enroll(token):
            data = _api(token, "POST", "/api/auth/mfa/enroll")
            image = None
            try:
                import qrcode

                qr = qrcode.QRCode(box_size=6, border=2)
                qr.add_data(data["provisioning_uri"])
                qr.make(fit=True)
                image = qr.make_image(fill_color="black", back_color="white").get_image()
            except Exception:
                gr.Warning("Thiếu thư viện qrcode (chạy `uv sync`) — dùng khóa thủ công bên dưới.")
            if image is not None:
                gr.Info("Quét mã QR rồi nhập mã 6 số để kích hoạt.")
            else:
                gr.Info("Nhập khóa thủ công vào ứng dụng xác thực, rồi nhập mã 6 số.")
            return (
                gr.update(visible=True),
                gr.update(value=image, visible=image is not None),
                data["secret"],
            )

        btn_enroll.click(_guard(mfa_enroll, 3), [st_token], [grp_mfa_setup, img_qr, tb_secret])

        def mfa_activate(token, code):
            data = _api(token, "POST", "/api/auth/mfa/activate", {"code": (code or "").strip()})
            codes = data.get("recovery_codes", [])
            recovery = "#### Mã khôi phục — lưu ở nơi an toàn, mỗi mã dùng một lần\n" + " · ".join(
                f"`{c}`" for c in codes
            )
            gr.Info("2FA đã được kích hoạt.")
            return (
                gr.update(visible=False),
                gr.update(visible=True),
                gr.update(visible=False),
                gr.update(value=recovery, visible=True),
                "**2FA đang bật.**",
                "",
            )

        btn_activate.click(
            _guard(mfa_activate, 6),
            [st_token, tb_activate],
            [grp_mfa_enroll, grp_mfa_manage, grp_mfa_setup, md_recovery, md_mfa_state, tb_activate],
        )

        def mfa_disable(token, password, code):
            _api(
                token,
                "POST",
                "/api/auth/mfa/disable",
                {"password": password, "code": (code or "").strip()},
            )
            gr.Info("Đã tắt xác thực hai lớp.")
            return (
                gr.update(visible=True),
                gr.update(visible=False),
                gr.update(value="", visible=False),
                "**2FA đang tắt** — nên bật để bảo vệ tài khoản.",
                "",
                "",
            )

        btn_disable.click(
            _guard(mfa_disable, 6),
            [st_token, tb_dis_pw, tb_dis_code],
            [grp_mfa_enroll, grp_mfa_manage, md_recovery, md_mfa_state, tb_dis_pw, tb_dis_code],
        )

        # ---- thiết bị ----
        def refresh_devices(token):
            table, revoke = _devices_snapshot(token)
            return table, gr.update(choices=revoke, value=None)

        btn_dev_refresh.click(_guard(refresh_devices, 2), [st_token], [df_devices, dd_revoke])

        def revoke_device(token, jti):
            if not jti:
                gr.Warning("Chọn một phiên cần thu hồi.")
                return gr.skip(), gr.skip()
            _api(token, "DELETE", f"/api/auth/sessions/{jti}")
            gr.Info("Đã thu hồi phiên đăng nhập.")
            return refresh_devices(token)

        btn_revoke.click(_guard(revoke_device, 2), [st_token, dd_revoke], [df_devices, dd_revoke])

        def logout_all(token):
            try:
                _api(token, "POST", "/api/auth/logout-all")
            except Exception:
                pass
            gr.Info("Đã thu hồi mọi phiên đăng nhập.")
            return _reset_tuple()

        btn_logout_all.click(_guard(logout_all, len(RESET_OUTS)), [st_token], RESET_OUTS)

        # ---- quản trị ----
        def refresh_admin(token):
            stats = _api(token, "GET", "/api/admin/stats")
            stats_md = (
                "| Người dùng | Đang hoạt động | Hội thoại | Tin nhắn "
                "| Đăng nhập lỗi /1h | Truy cập chặn /1h |\n|---|---|---|---|---|---|\n"
                f"| {stats['total_users']} | {stats['active_users']} "
                f"| {stats['total_sessions']} | {stats['total_messages']} "
                f"| {stats['recent_login_failures']} | {stats['recent_auth_denials']} |"
            )
            alerts = _api(
                token, "GET", "/api/admin/security-alerts", params={"window_minutes": "60"}
            )
            if alerts:
                lines = "\n".join(
                    f"- {'🔴 CAO' if a['severity'] == 'high' else '🟡 TRUNG BÌNH'} — "
                    f"{a['count']} sự kiện `{a['code']}` trong {a['window_minutes']} phút"
                    for a in alerts
                )
                alerts_md = "**Cảnh báo an ninh (60 phút):**\n" + lines
            else:
                alerts_md = "**Cảnh báo an ninh (60 phút):** 🟢 không có."
            users = _api(token, "GET", "/api/admin/users")
            table = [
                [
                    u["username"],
                    u["role"],
                    ("Hoạt động" if u["is_active"] else "Đã khóa"),
                    ("Bật" if u["mfa_enabled"] else "—"),
                    _fmt(u["created_at"]),
                ]
                for u in users
            ]
            choices = [(f"{u['username']} ({u['role']})", u["id"]) for u in users]
            return stats_md, alerts_md, table, gr.update(choices=choices, value=None)

        ADMIN_OUTS = [md_stats, md_alerts, df_users, dd_user_pick]
        btn_adm_refresh.click(_guard(refresh_admin, 4), [st_token], ADMIN_OUTS)
        adm_tab.select(_guard(refresh_admin, 4), [st_token], ADMIN_OUTS)

        def set_role(token, user_id, role):
            if not user_id:
                gr.Warning("Chọn một người dùng trước.")
                return tuple(gr.skip() for _ in ADMIN_OUTS)
            _api(token, "PATCH", f"/api/admin/users/{user_id}/role", {"role": role})
            gr.Info(f"Đã đổi vai trò thành {role}.")
            return refresh_admin(token)

        btn_set_role.click(_guard(set_role, 4), [st_token, dd_user_pick, dd_role_new], ADMIN_OUTS)

        def set_status(token, user_id, active):
            if not user_id:
                gr.Warning("Chọn một người dùng trước.")
                return tuple(gr.skip() for _ in ADMIN_OUTS)
            _api(token, "PATCH", f"/api/admin/users/{user_id}/status", {"is_active": active})
            gr.Info("Đã mở khóa tài khoản." if active else "Đã khóa tài khoản.")
            return refresh_admin(token)

        btn_lock.click(
            _guard(lambda tk, uid: set_status(tk, uid, False), 4),
            [st_token, dd_user_pick],
            ADMIN_OUTS,
        )
        btn_unlock.click(
            _guard(lambda tk, uid: set_status(tk, uid, True), 4),
            [st_token, dd_user_pick],
            ADMIN_OUTS,
        )

        def delete_user(token, user_id):
            if not user_id:
                gr.Warning("Chọn một người dùng trước.")
                return tuple(gr.skip() for _ in ADMIN_OUTS)
            _api(token, "DELETE", f"/api/admin/users/{user_id}")
            gr.Info("Đã xóa tài khoản cùng toàn bộ dữ liệu của người đó.")
            return refresh_admin(token)

        btn_del_user.click(_guard(delete_user, 4), [st_token, dd_user_pick], ADMIN_OUTS)

        def create_user(token, username, password, role):
            _api(
                token,
                "POST",
                "/api/admin/users",
                {"username": (username or "").strip(), "password": password, "role": role},
            )
            gr.Info("Đã tạo tài khoản mới.")
            return refresh_admin(token) + ("", "")

        btn_cu.click(
            _guard(create_user, 6),
            [st_token, tb_cu_name, tb_cu_pw, dd_cu_role],
            ADMIN_OUTS + [tb_cu_name, tb_cu_pw],
        )

        # ---- nhật ký ----
        def load_audit(token, limit):
            rows = _api(token, "GET", "/api/admin/audit", params={"limit": str(int(limit))})
            return [
                [
                    row["id"],
                    row["event_type"],
                    row["outcome"],
                    (row.get("actor_id") or "—")[:8],
                    (
                        f"{row['target_type']}:{str(row.get('target_id') or '')[:8]}"
                        if row.get("target_type")
                        else "—"
                    ),
                    row.get("ip_address") or "—",
                    _fmt(row["created_at"]),
                ]
                for row in rows
            ]

        btn_audit.click(_guard(load_audit, 1), [st_token, sl_audit], [df_audit])
        mod_tab.select(_guard(load_audit, 1), [st_token, sl_audit], [df_audit])

        # ---- TRUNG TÂM BẢO MẬT ----
        _SEV_ICON = {"high": "🔴 cao", "medium": "🟠 vừa", "low": "🟡 thấp"}

        def verify_chain_ui(token):
            """Xác minh chuỗi băm audit và diễn giải kết quả cho người đọc."""
            data = _api(token, "GET", "/api/admin/audit/verify")
            total = data.get("total_events", 0)
            verified = data.get("verified_events", 0)
            if data.get("chain_intact"):
                return (
                    '<div id="sec-verdict-ok">'
                    f"<b>✅ Chuỗi nguyên vẹn.</b> Đã xác minh {verified}/{total} bản ghi. "
                    "Không có dấu hiệu bản ghi bị sửa, xoá hay đảo thứ tự."
                    "</div>"
                )
            reason = {
                "entry_hash_mismatch": "nội dung bản ghi đã bị sửa",
                "prev_hash_mismatch": "có bản ghi bị xoá hoặc bị đảo thứ tự",
            }.get(data.get("reason"), data.get("reason") or "không xác định")
            return (
                '<div id="sec-verdict-bad">'
                f"<b>🚨 Chuỗi đã bị phá vỡ.</b> Bản ghi đầu tiên có vấn đề: "
                f"<code>#{data.get('first_broken_id')}</code> — {reason}. "
                f"Đã xác minh được {verified}/{total} bản ghi trước điểm gãy. "
                "Sự kiện phát hiện này cũng đã được ghi vào nhật ký."
                "</div>"
            )

        def load_detections(token):
            rows = _api(token, "GET", "/api/admin/ids/detections", params={"limit": "100"})
            return [
                [
                    r.get("rule_id", ""),
                    _SEV_ICON.get(r.get("severity"), r.get("severity", "")),
                    r.get("description", ""),
                    r.get("source_ip", ""),
                    f"{r.get('method', '')} {r.get('path', '')}".strip(),
                    (r.get("evidence") or "")[:60],
                ]
                for r in (rows or [])
            ]

        def load_anomalies(token, window):
            rows = _api(
                token,
                "GET",
                "/api/admin/ids/anomalies",
                params={"window_minutes": str(int(window))},
            )
            return [
                [
                    r.get("code", ""),
                    _SEV_ICON.get(r.get("severity"), r.get("severity", "")),
                    r.get("subject") or "—",
                    r.get("count", ""),
                    r.get("message", ""),
                ]
                for r in (rows or [])
            ]

        def load_blocklist(token):
            rows = _api(token, "GET", "/api/admin/ids/blocklist")
            return [[r.get("source_ip", ""), r.get("seconds_remaining", "")] for r in (rows or [])]

        def unblock_ip(token, ip):
            ip = (ip or "").strip()
            if not ip:
                gr.Warning("Nhập địa chỉ IP cần gỡ chặn.")
                return gr.skip(), gr.skip()
            _api(token, "DELETE", f"/api/admin/ids/blocklist/{ip}")
            gr.Info(f"Đã gỡ chặn {ip}.")
            return load_blocklist(token), ""

        def refresh_security(token, window):
            """Nạp cả bốn khối. Mỗi khối bọc riêng để thiếu quyền ở một khối
            không làm trắng toàn bộ màn hình (moderator không có quyền admin)."""

            def safe(fn, fallback):
                try:
                    return fn()
                except gr.Error as err:
                    gr.Warning(str(err))
                    return fallback

            verdict = safe(
                lambda: verify_chain_ui(token), "*Cần vai trò admin để xác minh chuỗi băm.*"
            )
            det = safe(lambda: load_detections(token), [])
            anom = safe(lambda: load_anomalies(token, window), [])
            block = safe(lambda: load_blocklist(token), [])
            return verdict, det, anom, block

        SEC_OUTS = [md_sec_verdict, df_sec_det, df_sec_anom, df_sec_block]
        btn_sec_all.click(_guard(refresh_security, 4), [st_token, sl_sec_win], SEC_OUTS)
        sec_tab.select(_guard(refresh_security, 4), [st_token, sl_sec_win], SEC_OUTS)
        btn_sec_verify.click(_guard(verify_chain_ui, 1), [st_token], [md_sec_verdict])
        btn_sec_anom.click(_guard(load_anomalies, 1), [st_token, sl_sec_win], [df_sec_anom])
        btn_sec_unblock.click(
            _guard(unblock_ip, 2), [st_token, tb_sec_ip], [df_sec_block, tb_sec_ip]
        )

    return demo
