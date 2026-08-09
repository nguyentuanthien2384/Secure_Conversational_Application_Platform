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
    # text_sm (chữ nền 13px) từng được chọn để tăng mật độ thông tin, nhưng ở
    # zoom 100% trên màn hình thường thì phải nheo mắt hoặc phóng to mới đọc
    # được. text_lg đưa chữ nền lên 16px — đúng cỡ mà giao diện vẫn dễ đọc
    # ngay khi mở, không cần zoom. Mật độ giảm một chút là cái giá xứng đáng.
    text_size=gr.themes.sizes.text_lg,
    spacing_size=gr.themes.sizes.spacing_md,
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
  /* Cột nội dung: 1400px lấp vừa một cửa sổ trình duyệt cỡ thường mà vẫn không
     trải dài vô tận trên màn hình rộng — dòng chữ quá dài thì mắt khó bắt dòng. */
  --scap-shell: 1400px;
  --scap-rail-h: 52px;
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
  padding: 22px 28px 56px !important;
}

/* ── Trang đăng nhập ─────────────────────────────────────────────────────
   Một thẻ duy nhất, canh giữa, chỉ làm đúng hai việc: đăng nhập và tạo tài
   khoản. Trang xác thực không phải chỗ giới thiệu sản phẩm, nên không có cột
   quảng bá, không gợi ý tài khoản mẫu, không chú thích dài dòng.
   ───────────────────────────────────────────────────────────────────────── */
#auth-wrap {
  max-width: 440px;
  /* 34px trong số này là chỗ cho nửa huy hiệu nhô lên khỏi mép thẻ. */
  margin: calc(6vh + 34px) auto 0;
  display: block !important;
  animation: auth-rise .35s cubic-bezier(.2,.7,.3,1) both;
}
@keyframes auth-rise { from { opacity: 0; transform: translateY(8px); } }
/* BẮT BUỘC: display:block ở trên dùng !important nên nó sẽ thắng cả cơ chế ẩn
   của Gradio (class .hide, thuộc tính hidden, hoặc style inline) và màn đăng
   nhập sẽ không biến mất sau khi đăng nhập. Bốn quy tắc dưới có specificity
   1-1-0 nên luôn thắng lại 1-0-0 ở trên. Đừng xoá. */
#auth-wrap.hide,
#auth-wrap[hidden],
#auth-wrap[style*="display: none"],
#auth-wrap[style*="display:none"] { display: none !important; }
#auth-wrap > * { min-width: 0; }

/* Gỡ padding/viền mặc định của các khối Gradio nằm trong khung xác thực. */
#auth-wrap .html-container,
#auth-wrap .html-container > div { padding: 0 !important; border: 0 !important; background: none !important; }
#auth-wrap > .html-container { min-width: 0 !important; }

/* Khối markup tĩnh (xem _static_html): dựng bằng gr.Markdown để không cần
   'unsafe-eval', nên phải trung hoà khung và kiểu chữ mặc định của Markdown thì
   mới giống hệt gr.HTML trước đây. */
.static-md,
.static-md > div,
.static-md .md,
.static-md .prose {
  padding: 0 !important; border: 0 !important; background: none !important;
  max-width: none !important; min-width: 0 !important;
  overflow: visible !important; max-height: none !important;
}
.static-md ul, .static-md ol { list-style: none; margin: 0; padding: 0; }

/* ── Thẻ xác thực ─────────────────────────────────────────────────────── */
#auth-card {
  padding: 30px 28px 26px !important;
  gap: 0 !important;
  border: 1px solid var(--border-color-primary) !important;
  border-radius: 16px;
  background: var(--background-fill-primary);
  box-shadow: 0 1px 2px rgba(2,6,23,.05), 0 18px 44px -30px rgba(2,6,23,.3);
  /* overflow phải là visible thì huy hiệu tròn mới nhô được ra ngoài mép trên. */
  overflow: visible !important;
}
/* Giữ >=16px để iOS không tự phóng to khi focus vào input. */
#auth-card input, #auth-card textarea { font-size: 16px !important; }

/* Huy hiệu tròn nhô lên nửa trên mép thẻ. Vòng nền cùng màu thẻ tạo cảm giác
   viền thẻ bị khoét một khoảng cho huy hiệu lọt vào, đúng như mẫu tham chiếu. */
.auth-brand {
  display: flex; flex-direction: column; align-items: center;
  gap: 12px; margin: 0 0 24px;
}
.auth-medallion {
  width: 68px; height: 68px; flex: none;
  margin-top: -64px;
  border-radius: 50%;
  background:
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23ffffff' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Crect x='9' y='11' width='6' height='5' rx='1'/%3E%3Cpath d='M10.5 11V9.6a1.5 1.5 0 0 1 3 0V11'/%3E%3C/svg%3E")
      center / 31px no-repeat,
    linear-gradient(150deg, #34d399, #059669 72%);
  box-shadow:
    0 0 0 9px var(--background-fill-primary),
    0 10px 22px -10px rgba(5,150,105,.75);
}
.mark-word {
  font-family: var(--font-mono); font-size: 15px; font-weight: 600;
  letter-spacing: .34em; color: var(--body-text-color);
}

/* Thanh tab bị ẩn: hai nút xếp dọc (đặc / viền) mới là thứ chuyển giữa đăng
   nhập và tạo tài khoản — giống mẫu, và bớt một tầng điều hướng. */
#auth-card .tab-nav, #auth-card [role="tablist"] { display: none !important; }
#auth-card .tabitem, #auth-card [role="tabpanel"] {
  padding: 0 !important; border: 0 !important; background: none !important;
}

/* Ô nhập bo tròn hoàn toàn, icon nằm sẵn bên trong lề trái. */
#auth-card label > span { font-size: 14px !important; font-weight: 600 !important; }
#auth-card input[type="text"], #auth-card input[type="password"] {
  padding: 14px 18px 14px 48px !important;
  border-radius: 999px !important;
  background-repeat: no-repeat;
  background-position: 19px center;
  background-size: 19px 19px;
}
#li-user input, #re-user input {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'/%3E%3Ccircle cx='12' cy='7' r='4'/%3E%3C/svg%3E");
}
#li-pass input, #re-pass input {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='11' width='18' height='11' rx='2'/%3E%3Cpath d='M7 11V7a5 5 0 0 1 10 0v4'/%3E%3C/svg%3E");
}

/* Nút chính (đặc) và nút phụ (viền) — cùng dáng viên thuốc, xếp dọc. */
#auth-card button.primary {
  width: 100%; margin-top: 6px;
  padding: 15px 18px !important;
  font-size: 16px !important; font-weight: 650 !important;
  letter-spacing: .01em;
  border-radius: 999px !important;
}
#auth-card button.auth-alt {
  width: 100%; margin-top: 10px;
  padding: 14px 18px !important;
  font-size: 15px !important; font-weight: 600 !important;
  border-radius: 999px !important;
  border: 1px solid var(--border-color-primary) !important;
  background: transparent !important;
  color: var(--body-text-color-subdued) !important;
  box-shadow: none !important;
  transition: border-color .15s ease, color .15s ease, background .15s ease;
}
#auth-card button.auth-alt:hover {
  border-color: var(--scap-ok-bd) !important;
  color: var(--body-text-color) !important;
  background: var(--scap-ok-bg) !important;
}

/* Hàng tiện ích dưới ô mật khẩu (hiện mật khẩu…). */
#auth-util { margin: -6px 0 12px !important; gap: 8px !important; }
#auth-util .block, #auth-util .form {
  padding: 0 !important; border: 0 !important; background: none !important;
  min-width: 0 !important; box-shadow: none !important;
}
#chk-showpw label { font-size: 14px !important; color: var(--body-text-color-subdued); }

/* Thang đo độ mạnh mật khẩu — 4 vạch, đọc được không cần màu. */
#pw-meter { margin: -4px 0 12px; }
.pw-bars { display: grid; grid-template-columns: repeat(4, 1fr); gap: 4px; }
.pw-bars i {
  height: 4px; border-radius: 99px;
  background: var(--border-color-primary);
  transition: background .2s ease;
}
.pw-bars i.lv1 { background: #f87171; }
.pw-bars i.lv2 { background: #fbbf24; }
.pw-bars i.lv3 { background: #34d399; }
.pw-bars i.lv4 { background: #10b981; }
.pw-text {
  margin: 8px 0 0; font-size: 13px; line-height: 1.55;
  color: var(--body-text-color-subdued);
}
.pw-text b { color: var(--body-text-color); font-weight: 600; }

/* Bước 2 — xác thực hai lớp. */
#mfa-panel { border: 0 !important; background: none !important; padding: 0 !important; gap: 0 !important; }
.mfa-badge {
  display: inline-flex; align-items: center; gap: 7px;
  font-family: var(--font-mono); font-size: 11.5px;
  letter-spacing: .16em; text-transform: uppercase;
  color: var(--scap-ok-fg); background: var(--scap-ok-bg);
  border: 1px solid var(--scap-ok-bd);
  padding: 6px 12px; border-radius: 99px;
}
.mfa-head { margin-bottom: 16px; text-align: center; }
.mfa-head h3 { margin: 12px 0 0; font-size: 19px; font-weight: 620; color: var(--body-text-color); }
#tb-mfa input {
  font-family: var(--font-mono) !important;
  font-size: 23px !important; letter-spacing: .34em !important;
  text-align: center; padding: 15px !important;
}
#mfa-row { gap: 8px !important; }
#mfa-row button.primary { margin-top: 0; }

/* ── Thanh trạng thái: chi tiết đặc trưng của giao diện này ─────────────
   Đọc như màn hình chỉ báo của thiết bị: phiên khóa, thời hạn token, trạng
   thái chuỗi audit. tabular-nums để chữ số không nhảy khi đếm ngược. */
#topbar {
  min-height: var(--scap-rail-h);
  border: 1px solid var(--border-color-primary);
  border-radius: 10px;
  padding: 0 18px;
  background: var(--scap-rail-bg);
  align-items: center;
  gap: 16px;
  overflow: hidden;
}
#topbar .md p {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 14px;
  font-variant-numeric: tabular-nums;
  letter-spacing: .01em;
  color: var(--body-text-color-subdued);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
#topbar .md strong, #topbar .md code {
  color: var(--body-text-color); font-weight: 600; background: none; padding: 0;
}
#topbar button { font-size: 14px !important; }

/* ── Thẻ nội dung ──────────────────────────────────────────────────────── */
.section-card {
  border: 1px solid var(--border-color-primary);
  border-radius: 10px;
  padding: 16px;
  background: var(--background-fill-primary);
}

/* ── Tab ───────────────────────────────────────────────────────────────── */
.tab-nav { gap: 2px; }
.tab-nav button {
  font-size: 15px !important;
  padding: 10px 16px !important;
  letter-spacing: .01em;
}

/* ── Bảng dữ liệu: mọi thứ liên quan mật mã đều monospace ──────────────── */
.mono-df table {
  font-family: var(--font-mono);
  font-size: 13.5px;
  font-variant-numeric: tabular-nums;
}
.mono-df th { font-size: 12.5px !important; text-transform: uppercase; letter-spacing: .05em; }
.mono-df td { white-space: nowrap; }

/* ── Danh sách hội thoại ───────────────────────────────────────────────── */
#side-title h4 {
  margin: 0 0 10px; font-size: 12.5px; font-weight: 650;
  text-transform: uppercase; letter-spacing: .07em;
  color: var(--body-text-color-subdued);
}
#session-list { max-height: 460px; overflow-y: auto; margin-bottom: 10px; }
#session-list .wrap { flex-direction: column !important; gap: 3px !important; }
#session-list label {
  display: flex !important;
  align-items: center;
  width: 100%;
  padding: 10px 12px !important;
  border: 1px solid transparent !important;
  border-radius: 7px !important;
  background: transparent !important;
  font-size: 15px !important;
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
  margin: 0; font-size: 14px; font-family: var(--font-mono);
  color: var(--body-text-color-subdued);
}
#dlp-banner, #sec-verdict {
  border-radius: 8px; padding: 12px 15px; margin-top: 6px;
  border-left: 3px solid var(--scap-warn-bd);
}
#dlp-banner {
  border: 1px solid var(--scap-warn-bd);
  border-left-color: var(--scap-warn-bd);
  background: var(--scap-warn-bg);
}
#dlp-banner p { margin: 0; font-size: 15px; color: var(--scap-warn-fg); }
#sec-verdict {
  border: 1px solid var(--scap-warn-bd);
  background: var(--scap-warn-bg);
  color: var(--scap-warn-fg);
}
#sec-verdict p { margin: 0; font-size: 15px; }

/* ── Bố cục ngang ──────────────────────────────────────────────────────── */
@media (min-width: 1000px) {
  #chat-row { flex-wrap: nowrap !important; }
  #topbar { flex-wrap: nowrap !important; }
}
@media (max-width: 999px) {
  .gradio-container { padding: 14px 16px 36px !important; }
  #topbar { padding: 12px 14px; }
}
/* Dưới 900px: thẻ bám sát mép trên để ô nhập đầu tiên luôn nằm trên nếp gấp
   màn hình điện thoại. */
@media (max-width: 900px) {
  #auth-wrap { margin-top: 3vh; }
  #auth-card { padding: 24px 20px 20px !important; }
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
# Cạnh ô hiển thị mã QR. Ảnh được dựng đúng bằng số pixel này rồi mới đưa vào
# gr.Image, để trình duyệt không phải co giãn — co giãn không nguyên lần làm nhoè
# biên các module và là lý do chính khiến camera điện thoại không đọc được mã.
QR_DISPLAY_PX = 352


def _totp_qr_image(uri: str, target_px: int = QR_DISPLAY_PX):
    """Dựng ảnh QR sắc nét, đúng ``target_px`` pixel mỗi cạnh.

    Ba điểm quyết định việc quét được hay không:

    1. ``border=4`` — vùng yên tĩnh (quiet zone) tối thiểu theo ISO/IEC 18004.
       Bản cũ dùng ``border=2``, thiếu viền nên bộ dò khó khoá được ba ô định vị.
    2. ``box_size`` là số nguyên chia hết, và phần thiếu được **đệm thêm viền
       trắng** thay vì phóng to ảnh. Nhờ vậy mỗi module luôn là một khối pixel
       vuông sắc nét, không có pixel xám ở biên do nội suy.
    3. Mức sửa lỗi M (mặc định) là cân bằng đúng: L quá mỏng khi màn hình loá,
       Q/H làm mã dày thêm mà không cần thiết cho khoảng cách quét gần.
    """
    import qrcode
    from PIL import Image

    qr = qrcode.QRCode(border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    total_modules = qr.modules_count + 2 * qr.border
    box_size = max(1, target_px // total_modules)
    qr.box_size = box_size
    image = qr.make_image(fill_color="black", back_color="white").get_image().convert("RGB")

    # Đệm cho đủ kích thước đích. Đệm bằng nền trắng nên chỉ làm quiet zone rộng
    # thêm — luôn có lợi cho việc quét, khác hẳn với phóng to ảnh.
    if image.width < target_px:
        canvas = Image.new("RGB", (target_px, target_px), "white")
        offset = (target_px - image.width) // 2
        canvas.paste(image, (offset, offset))
        image = canvas
    return image


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
        if resp.status_code in (429, 503):
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


# ─────────────────── mảnh HTML tĩnh của trang đăng nhập ───────────────────
# Trang đăng nhập chỉ giữ đúng hai việc: đăng nhập và tạo tài khoản. Dấu nhận
# diện dưới đây là thứ duy nhất còn lại — đủ để người dùng biết mình đang gõ
# mật khẩu vào đâu, không kèm bất kỳ nội dung giới thiệu nào.
AUTH_BRAND_HTML = (
    '<div class="auth-brand">'
    '<span class="auth-medallion" role="img" aria-label="Khiên bảo mật SCAP"></span>'
    '<span class="mark-word">SCAP</span>'
    "</div>"
)

MFA_HEAD_HTML = (
    '<div class="mfa-head">'
    '<span class="mfa-badge">Bước 2 · Xác thực hai lớp</span>'
    "<h3>Nhập mã xác thực</h3>"
    "</div>"
)


def _static_html(markup: str, **kwargs) -> gr.Markdown:
    """Đổ một khối markup tĩnh mà không cần 'unsafe-eval'.

    Từ Gradio 6, gr.HTML luôn biên dịch giá trị qua ``new Function(...)`` (nội
    suy ``html_template`` và chạy ``js_on_load``). CSP của ứng dụng không cấp
    ``'unsafe-eval'`` cho script-src nên component đó chỉ hiện dòng "Error
    rendering HTML". gr.Markdown dựng DOM trực tiếp, không eval, nên hiển thị
    đúng markup mà chính sách vẫn giữ nguyên.

    ``sanitize_html=False`` là an toàn ở đây vì mọi chuỗi truyền vào đều là hằng
    số trong mã nguồn; không có đường nào cho dữ liệu người dùng lọt vào (kể cả
    thang đo mật khẩu bên dưới cũng chỉ dùng độ dài, không in lại mật khẩu).
    """
    classes = kwargs.pop("elem_classes", [])
    if isinstance(classes, str):
        classes = [classes]
    return gr.Markdown(
        markup,
        sanitize_html=False,
        container=False,
        padding=False,
        elem_classes=["static-md", *classes],
        **kwargs,
    )


def _pw_meter_html(password: str) -> str:
    """Thang đo độ mạnh mật khẩu cho ô đăng ký.

    Chấm điểm theo đúng chính sách của hệ thống (độ dài tối thiểu là điều kiện
    cần) chứ không theo một công thức chung chung: dưới ngưỡng thì luôn là mức
    1, kèm số ký tự còn thiếu — người dùng biết chính xác phải gõ thêm bao nhiêu
    thay vì đoán. Bốn vạch cũng đọc được khi không phân biệt được màu.
    """
    pw = password or ""
    if not pw:
        return (
            '<div class="pw-bars"><i></i><i></i><i></i><i></i></div>'
            f'<p class="pw-text">Tối thiểu {PASSWORD_MIN} ký tự.</p>'
        )
    variety = sum(
        (
            any(c.islower() for c in pw),
            any(c.isupper() for c in pw),
            any(c.isdigit() for c in pw),
            any(not c.isalnum() for c in pw),
        )
    )
    if len(pw) < PASSWORD_MIN:
        level, note = 1, f"Còn thiếu {PASSWORD_MIN - len(pw)} ký tự."
    elif len(pw) >= 20 and variety >= 3:
        level, note = 4, "Đủ dài và đa dạng ký tự."
    elif variety >= 3:
        level, note = 3, "Đã đạt yêu cầu của hệ thống."
    else:
        level, note = 2, "Đạt độ dài — thêm chữ hoa, chữ số hoặc ký tự đặc biệt."
    labels = {1: "Chưa dùng được", 2: "Trung bình", 3: "Mạnh", 4: "Rất mạnh"}
    bars = "".join(f'<i class="lv{level}"></i>' if i < level else "<i></i>" for i in range(4))
    return f'<div class="pw-bars">{bars}</div><p class="pw-text"><b>{labels[level]}</b> · {note}</p>'


# ────────────────────────── giao diện ──────────────────────────
def build_ui() -> gr.Blocks:
    with gr.Blocks(title="SCAP", theme=THEME, css=CUSTOM_CSS) as demo:
        st_token = gr.State("")
        st_exp = gr.State(0.0)
        st_mfa = gr.State("")
        # Đã hiện cảnh báo "sắp hết phiên" chưa — để chỉ nhắc một lần cho mỗi
        # phiên thay vì mỗi giây một lần trong suốt hai phút cuối.
        st_warned = gr.State(False)

        # ============ XÁC THỰC ============
        # Một thẻ duy nhất: dấu nhận diện, hai tab (đăng nhập / tạo tài khoản),
        # và bước xác thực hai lớp khi tài khoản có bật 2FA. Không có gì khác.
        with gr.Column(visible=True, elem_id="auth-wrap") as auth_sec:
            with gr.Column(elem_id="auth-card"):
                _static_html(AUTH_BRAND_HTML)

                # Cả cụm form được ẩn khi chuyển sang bước xác thực hai lớp, để
                # màn hình chỉ còn đúng một việc phải làm.
                with gr.Column(elem_id="auth-forms") as grp_auth_forms:
                    with gr.Tabs() as auth_tabs:
                        with gr.Tab("Đăng nhập", id="tab_login"):
                            li_user = gr.Textbox(
                                label="Tên đăng nhập",
                                placeholder="Nhập tên đăng nhập",
                                max_length=64,
                                autofocus=True,
                                elem_id="li-user",
                            )
                            li_pass = gr.Textbox(
                                label="Mật khẩu",
                                type="password",
                                max_length=128,
                                placeholder="Nhập mật khẩu",
                                elem_id="li-pass",
                            )
                            with gr.Row(elem_id="auth-util"):
                                chk_showpw = gr.Checkbox(
                                    label="Hiện mật khẩu",
                                    value=False,
                                    container=False,
                                    elem_id="chk-showpw",
                                )
                            btn_login = gr.Button("Đăng nhập", variant="primary")
                            # Nút viền: vừa là lối sang tab tạo tài khoản, vừa là
                            # thứ thay cho thanh tab đã ẩn.
                            btn_goto_register = gr.Button(
                                "Tạo tài khoản", elem_classes="auth-alt"
                            )

                            # Ô mật khẩu che ký tự là nguyên nhân gõ sai phổ biến
                            # nhất trên điện thoại; cho phép nhìn là cách sửa rẻ
                            # nhất, và người dùng tự quyết định khi nào an toàn.
                            chk_showpw.change(
                                lambda show: gr.update(type="text" if show else "password"),
                                chk_showpw,
                                li_pass,
                            )

                        with gr.Tab("Tạo tài khoản", id="tab_register"):
                            re_user = gr.Textbox(
                                label="Tên đăng nhập",
                                placeholder="3–32 ký tự",
                                max_length=32,
                                info="Cho phép chữ, số và các ký tự . _ -",
                                elem_id="re-user",
                            )
                            re_pass = gr.Textbox(
                                label="Mật khẩu",
                                type="password",
                                max_length=128,
                                placeholder=f"Tối thiểu {PASSWORD_MIN} ký tự",
                                elem_id="re-pass",
                            )
                            html_pw_meter = _static_html(_pw_meter_html(""), elem_id="pw-meter")
                            btn_register = gr.Button("Tạo tài khoản", variant="primary")
                            btn_goto_login = gr.Button(
                                "Quay lại đăng nhập", elem_classes="auth-alt"
                            )

                            re_pass.change(_pw_meter_html, re_pass, html_pw_meter)

                    # Thanh tab đã ẩn bằng CSS nên hai nút này là đường duy nhất
                    # đi lại giữa hai biểu mẫu.
                    btn_goto_register.click(
                        lambda: gr.Tabs(selected="tab_register"), None, auth_tabs
                    )
                    btn_goto_login.click(lambda: gr.Tabs(selected="tab_login"), None, auth_tabs)

                # ---- bước 2: xác thực hai lớp ----
                with gr.Column(visible=False, elem_id="mfa-panel") as grp_mfa_login:
                    _static_html(MFA_HEAD_HTML)
                    tb_mfa_code = gr.Textbox(
                        label="Mã xác thực",
                        placeholder="000000",
                        max_length=32,
                        elem_id="tb-mfa",
                    )
                    with gr.Row(elem_id="mfa-row"):
                        btn_mfa_verify = gr.Button("Xác minh", variant="primary")
                        btn_mfa_cancel = gr.Button("Quay lại")

        # ============ ỨNG DỤNG ============
        with gr.Column(visible=False) as app_sec:
            with gr.Row(elem_id="topbar"):
                md_banner = gr.Markdown("", elem_classes="md")
                md_countdown = gr.Markdown("", elem_classes="md")
                btn_extend = gr.Button("Gia hạn phiên", scale=0, size="sm")
                btn_logout = gr.Button("Đăng xuất", scale=0, size="sm")
            timer = gr.Timer(1, active=False)

            with gr.Tabs():
                # ---------- TRÒ CHUYỆN ----------
                with gr.Tab("Trò chuyện"):
                    with gr.Row(elem_id="chat-row"):
                        with gr.Column(scale=1, min_width=330, elem_classes="section-card"):
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
                        with gr.Column(scale=3, min_width=600):
                            # Nhắc trạng thái mã hoá ngay trên khung chat.
                            gr.Markdown(
                                "🔒 **Đã mã hoá** — nội dung lưu dưới dạng AES-256-GCM, "
                                "khoá không nằm trong cơ sở dữ liệu.",
                                elem_id="enc-note",
                            )
                            chatbot = gr.Chatbot(
                                label="Nội dung",
                                height=600,
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
                                    # height/width khớp đúng ảnh sinh ra (xem
                                    # _totp_qr_image) nên tỉ lệ hiển thị là 1:1.
                                    img_qr = gr.Image(
                                        label="Quét bằng ứng dụng xác thực",
                                        height=QR_DISPLAY_PX,
                                        width=QR_DISPLAY_PX,
                                        scale=1,
                                        interactive=False,
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
                        btn_sec_verify = gr.Button("Xác minh chuỗi", variant="primary", size="sm")
                        md_sec_verdict = gr.Markdown(
                            "*Chưa xác minh trong phiên làm việc này.*",
                            elem_id="sec-verdict",
                        )

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
        STAGE1 = [
            st_token,
            st_exp,
            st_mfa,
            auth_sec,
            app_sec,
            grp_mfa_login,
            li_pass,
            tb_mfa_code,
            grp_auth_forms,
        ]
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
        # st_warned nằm ở CUỐI danh sách một cách có chủ đích: các handler chỉ
        # trả về STAGE1 (đăng nhập, xác minh MFA) không phải sửa gì thêm.
        RESET_OUTS = STAGE1 + STAGE2 + [md_countdown, st_warned]

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
                gr.update(visible=True),  # grp_auth_forms
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
                False,
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
                    gr.update(visible=False),  # ẩn form đăng nhập ở bước 2
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
                gr.update(visible=True),
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
                gr.update(visible=True),
            )

        btn_mfa_verify.click(
            _guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1
        ).then(_guard(load_workspace, len(STAGE2)), [st_token], STAGE2)
        tb_mfa_code.submit(_guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2
        )
        btn_mfa_cancel.click(
            lambda: ("", gr.update(visible=False), "", gr.update(visible=True)),
            None,
            [st_mfa, grp_mfa_login, tb_mfa_code, grp_auth_forms],
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

        # Ngưỡng nhắc trước khi phiên hết hạn (giây).
        WARN_BEFORE_EXPIRY = 120

        def _alive(countdown_markdown, warned):
            """Giữ nguyên mọi output trừ đồng hồ và cờ cảnh báo.

            gr.skip() để đồng hồ chạy mỗi giây không ghi đè state của người dùng
            (ô đang gõ, hội thoại đang chọn…).
            """
            return tuple(gr.skip() for _ in range(len(RESET_OUTS) - 2)) + (
                countdown_markdown,
                warned,
            )

        def tick(exp, warned):
            """Chạy mỗi giây: đếm ngược, nhắc trước, và tự đăng xuất khi hết hạn.

            Trước đây hàm này chỉ đổi dòng chữ thành "token đã hết hạn" rồi thôi:
            giao diện vẫn hiện đầy đủ, mọi nút vẫn bấm được, và người dùng chỉ
            biết mình đã mất phiên khi một thao tác trả về 401. Tệ hơn, dữ liệu
            hội thoại đã giải mã vẫn nằm trong state của trình duyệt sau khi
            phiên đã chết. Bây giờ hết hạn là dọn sạch state và quay về màn đăng
            nhập, đúng như khi bấm Đăng xuất.
            """
            if not exp:
                return _alive("", False)
            left = int(exp - time.time())
            if left <= 0:
                gr.Warning("Phiên đã hết hạn — vui lòng đăng nhập lại.")
                return _reset_tuple()
            if left <= WARN_BEFORE_EXPIRY and not warned:
                gr.Warning(
                    f"Phiên sẽ hết hạn sau {left} giây. "
                    "Bấm “Gia hạn phiên” để tiếp tục làm việc."
                )
                warned = True
            hours, rem = divmod(left, 3600)
            minutes, seconds = divmod(rem, 60)
            shown = f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"
            icon = "⚠️" if left <= WARN_BEFORE_EXPIRY else "⏳"
            return _alive(f"{icon} **{shown}**", warned)

        timer.tick(tick, [st_exp, st_warned], RESET_OUTS)

        def extend_session(token):
            """Xin token mới trước khi token hiện tại hết hạn (sliding session).

            Máy chủ xoay jti và thu hồi cái cũ, đồng thời áp trần tuyệt đối tính
            từ lần đăng nhập gốc — nên phiên không thể được gia hạn vô hạn.
            """
            data = _api(token, "POST", "/api/auth/refresh")
            gr.Info("Đã gia hạn phiên.")
            return data["access_token"], time.time() + data["expires_in"], False

        btn_extend.click(
            _guard(extend_session, 3), [st_token], [st_token, st_exp, st_warned]
        )

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
                image = _totp_qr_image(data["provisioning_uri"], QR_DISPLAY_PX)
            except ImportError:
                gr.Warning("Thiếu thư viện qrcode (chạy `uv sync`) — dùng khóa thủ công bên dưới.")
            except Exception:
                gr.Warning("Không dựng được mã QR — hãy dùng khóa thủ công bên dưới.")
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
            """Return a persistent, readable audit-chain verification result.

            This handler handles API failures itself. The generic Gradio guard
            returns gr.skip() on errors, which previously left this panel blank
            and hid the only useful diagnostic in a transient toast.
            """
            if not token:
                return "**Không thể xác minh:** phiên đăng nhập đã hết hạn. Hãy đăng nhập lại."
            try:
                data = _api(token, "GET", "/api/admin/audit/verify")
            except gr.Error as err:
                return f"**Không thể xác minh chuỗi:** {err}"
            total = data.get("total_events", 0)
            verified = data.get("verified_events", 0)
            unsealed = data.get("unsealed_events", 0)
            checked_at = _fmt(data.get("checked_at"))
            checked_by = data.get("checked_by") or "admin"
            if total == 0:
                return (
                    "**Chưa có nhật ký để xác minh.** Hệ thống sẽ tạo nhật ký khi có đăng ký, "
                    "đăng nhập, tạo hội thoại hoặc gửi tin nhắn."
                )
            if data.get("chain_intact"):
                return (
                    f"**Chuỗi nguyên vẹn.** Đã xác minh **{verified}/{total}** bản ghi; "
                    "toàn bộ nhật ký đều được chuỗi băm bảo vệ. Không có dấu hiệu bản ghi bị "
                    f"sửa, xóa hoặc đảo thứ tự.\n\nKiểm tra lúc {checked_at} bởi {checked_by}."
                )
            # Trường hợp riêng: không có mắt xích nào sai, nhưng một số bản ghi
            # nằm ngoài chuỗi. Đó là lỗ hổng phạm vi bảo vệ, không phải bằng
            # chứng bị tấn công — và phải nói đúng như vậy.
            if data.get("reason") == "unsealed_events":
                return (
                    f"**Chuỗi chưa phủ hết nhật ký.** {verified}/{total} bản ghi được bảo vệ; "
                    f"**{unsealed} bản ghi chưa được niêm phong** (bản ghi đầu tiên: "
                    f"#{data.get('first_unsealed_id')}). Các bản ghi này có thể bị sửa mà "
                    "không bị phát hiện. Chạy python scripts/repair_audit_chain.py để vá."
                )
            reason = {
                "entry_hash_mismatch": "nội dung bản ghi đã bị sửa",
                "prev_hash_mismatch": "có bản ghi bị xoá hoặc bị đảo thứ tự",
            }.get(data.get("reason"), data.get("reason") or "không xác định")
            return (
                "**Chuỗi đã bị phá vỡ.** Bản ghi đầu tiên có vấn đề: "
                f"#{data.get('first_broken_id')} - {reason}. Đã xác minh được "
                f"{verified}/{total} bản ghi trước điểm gãy. Sự kiện phát hiện này cũng đã "
                "được ghi vào nhật ký."
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
                lambda: verify_chain_ui(token), "**Không thể xác minh chuỗi.**"
            )
            det = safe(lambda: load_detections(token), [])
            anom = safe(lambda: load_anomalies(token, window), [])
            block = safe(lambda: load_blocklist(token), [])
            return verdict, det, anom, block

        SEC_OUTS = [md_sec_verdict, df_sec_det, df_sec_anom, df_sec_block]
        btn_sec_all.click(_guard(refresh_security, 4), [st_token, sl_sec_win], SEC_OUTS)
        sec_tab.select(_guard(refresh_security, 4), [st_token, sl_sec_win], SEC_OUTS)
        btn_sec_verify.click(verify_chain_ui, [st_token], [md_sec_verdict])
        btn_sec_anom.click(_guard(load_anomalies, 1), [st_token, sl_sec_win], [df_sec_anom])
        btn_sec_unblock.click(
            _guard(unblock_ip, 2), [st_token, tb_sec_ip], [df_sec_block, tb_sec_ip]
        )

    return demo
