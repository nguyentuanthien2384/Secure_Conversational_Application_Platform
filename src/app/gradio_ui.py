"""Giao diện Gradio (thuần Python) cho Secure Conversational Application Platform.

UI gọi chính REST API của dự án qua httpx nên mọi thao tác đều đi qua JWT,
RBAC, rate limiting và audit trail. Bao phủ toàn bộ API: xác thực (kèm 2FA),
trò chuyện, bản mã, tìm kiếm toàn cục, tài khoản, thiết bị, quản trị, nhật ký.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import html
import http.cookiejar
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

import gradio as gr
from markdown_it import MarkdownIt
from markdown_it.renderer import RendererHTML

from src.app.account_security import DEVICE_COOKIE_NAME, DEVICE_TOKEN_HEADER
from src.app.audit import sign_ui_client_context
from src.app.crypto_workbench_ui import WORKBENCH_CSS, WORKBENCH_HTML
from src.app.gradio_capacity import install_gradio_capacity
from src.app.services import EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE
from src.app.ui_session import COOKIE_NAME, BrowserSessionStore, UISessionCapacityError
from src.core.ai_core.gemini_ai import validate_search_suggestions_html

BASE_URL = os.getenv("SELF_BASE_URL", f"http://127.0.0.1:{os.getenv('PORT', '8000')}")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", BASE_URL).rstrip("/")
PASSWORD_MIN = 15
# Set by build_ui(); lets _api() vouch for the browser behind each call.
_CLIENT_CONTEXT_KEY: bytes | None = None
# Set by build_ui(); lets _api() follow token rotations made by another tab.
_SESSION_STORE: BrowserSessionStore | None = None
_UI_RESULT_SESSION = contextvars.ContextVar("scap_ui_result_session", default=None)

# Fixed markup consumed by our static CSP-compatible session bridge. Bearer
# tokens never enter this DOM component, cookies readable by JS, or storage.
SESSION_CLEAR_MARKUP = '<span data-scap-session-clear="1"></span>'

# Đồng hồ phiên. Trước đây gr.Timer gọi máy chủ MỖI GIÂY và trả về ~110 output:
# mỗi giây 2 request (queue/join + SSE) ăn vào hạn mức REQUEST_IP_MAX_ATTEMPTS và
# frontend phải cập nhật trạng thái của cả trăm component, khiến chuyển tab bị
# đứng/treo. Giờ trình duyệt tự đếm từng giây (session_bridge.js); máy chủ chỉ
# đồng bộ lại sau mỗi SESSION_TICK_SECONDS, nhắc trước khi hết hạn và tự đăng
# xuất đúng lúc hết hạn (khoảng tick được rút ngắn khi gần hết hạn).
SESSION_TICK_SECONDS = 10
# Ngưỡng nhắc trước khi phiên hết hạn (giây).
WARN_BEFORE_EXPIRY = 120
MAX_UI_SEARCH_ROWS = 500

# Vùng lịch sử co theo chiều cao màn hình để ô soạn và nút Gửi luôn ở gần nội
# dung. Giới hạn dưới vẫn đủ đọc hội thoại; giới hạn trên tránh khoảng trắng lớn
# đẩy trình soạn thảo xuống dưới nếp gấp trên laptop.
CHAT_HISTORY_HEIGHT = "clamp(320px, calc(100dvh - 360px), 480px)"

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
    # Keep typography local. Remote font CSS is an unnecessary browser-side
    # connection and would also be rejected by the application's strict CSP.
    font=["system-ui", "sans-serif"],
    font_mono=["ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
)

CUSTOM_CSS = """
/* ==========================================================================
   SCAP — bảng điều khiển bảo mật
   Nguyên tắc: workspace dùng toàn bộ chiều rộng khả dụng, mật độ cao, dữ liệu
   mật mã luôn dùng monospace. Màu emerald dẫn hướng thao tác và trạng thái.
   ========================================================================== */

:root {
  --scap-page-gutter: clamp(14px, 2vw, 28px);
  --scap-rail-h: 52px;
  --scap-ok-bg: #ecfdf5;   --scap-ok-bd: #6ee7b7;   --scap-ok-fg: #065f46;
  --scap-warn-bg: #fffbeb; --scap-warn-bd: #fcd34d; --scap-warn-fg: #78350f;
  --scap-bad-bg: #fef2f2;  --scap-bad-bd: #fca5a5;  --scap-bad-fg: #7f1d1d;
  --scap-rail-bg: #f8fafc;
  --scap-ink: #0f172a;
  --scap-muted: #64748b;
  --scap-panel: #ffffff;
  --scap-line: #e2e8f0;
  --scap-navy: #0b1324;
  --scap-blue: #2563eb;
}
/* CSS cũ hardcode màu sáng nên ở chế độ tối thành chữ xanh trên nền xanh.
   Khai báo lại token cho dark mode để mọi khối trạng thái vẫn đọc được. */
.dark {
  --scap-ok-bg: rgba(16,185,129,.12);   --scap-ok-bd: #059669;   --scap-ok-fg: #6ee7b7;
  --scap-warn-bg: rgba(245,158,11,.12); --scap-warn-bd: #b45309; --scap-warn-fg: #fcd34d;
  --scap-bad-bg: rgba(239,68,68,.12);   --scap-bad-bd: #b91c1c;  --scap-bad-fg: #fca5a5;
  --scap-rail-bg: rgba(148,163,184,.08);
  --scap-ink: #e5edf8;
  --scap-muted: #94a3b8;
  --scap-panel: #101a2e;
  --scap-line: #26344d;
  --scap-navy: #091120;
  --scap-blue: #60a5fa;
}

footer { display: none !important; }
#session-bridge, #login-ready, #passkey-bridge, #passkey-result,
#btn-passkey-login-done, #btn-passkey-register-done,
#btn-passkey-step-up-done { display: none !important; }
#security-push-bridge, #security-push-result, #btn-security-push-done { display: none !important; }
#scap-session-warning { padding: 12px; color: var(--scap-warn-fg); background: var(--scap-warn-bg); }

/* ── Khung ngoài: một workspace full-width duy nhất cho mọi tab ─────────
   Gradio tự thêm padding cho cả .gradio-container và div.main. Nếu giữ cả hai,
   lề bị cộng đôi và trang trông như lúc full, lúc bị co theo breakpoint. Chỉ
   div.main giữ gutter; 100% (không phải 100vw) tránh dư đúng bề rộng scrollbar. */
.gradio-container {
  width: 100% !important;
  max-width: none !important;
  min-width: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  box-sizing: border-box !important;
  background:
    radial-gradient(circle at 6% 0%, rgba(16,185,129,.07), transparent 28rem),
    radial-gradient(circle at 95% 8%, rgba(37,99,235,.06), transparent 24rem);
}

.gradio-container > .main {
  width: 100% !important;
  max-width: none !important;
  min-width: 0 !important;
  margin: 0 !important;
  padding: 16px var(--scap-page-gutter) 48px !important;
  box-sizing: border-box !important;
}

#app-sec,
#workspace-tabs {
  width: 100% !important;
  max-width: 100% !important;
  min-width: 0 !important;
  box-sizing: border-box !important;
}

/* Đảm bảo toàn bộ tab panel và nội dung bên trong luôn chiếm 100% chiều rộng */
.tabitem,
[role="tabpanel"] {
  width: 100% !important;
  max-width: 100% !important;
  min-width: 0 !important;
  box-sizing: border-box !important;
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
/* Gradio moves tabs that do not fit into an overflow "⋯" menu beside the list;
   the auth card navigates with its own buttons, so hide the whole header. */
#auth-card .tab-wrapper, #auth-card .overflow-menu { display: none !important; }
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
  display: grid !important;
  grid-template-columns: max-content minmax(0, 1fr) max-content max-content max-content;
  grid-template-areas: "brand user timer extend logout";
  width: 100% !important;
  max-width: 100% !important;
  min-width: 0 !important;
  min-height: var(--scap-rail-h);
  border: 1px solid #1e3a5f;
  border-radius: 10px;
  padding: 8px 18px;
  background: linear-gradient(105deg, var(--scap-navy), #10284a 70%, #0f766e);
  align-items: center;
  gap: 16px;
  overflow: hidden;
  box-shadow: 0 14px 30px -22px rgba(15,23,42,.8);
  box-sizing: border-box !important;
}
#topbar > * {
  width: auto !important;
  max-width: 100% !important;
  min-width: 0 !important;
  margin: 0 !important;
}
#topbar .md p {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 14px;
  font-variant-numeric: tabular-nums;
  letter-spacing: .01em;
  color: #cbd5e1;
  white-space: nowrap;
}
#topbar .md strong, #topbar .md code {
  color: #f8fafc; font-weight: 600; background: none; padding: 0;
}
#topbar button {
  font-size: 13.5px !important;
  width: clamp(120px, 12vw, 200px) !important;
  white-space: nowrap !important;
}
#topbar > .topbar-brand {
  grid-area: brand;
  width: max-content !important;
  overflow: visible !important;
}
.app-wordmark {
  white-space: nowrap !important;
}
.app-wordmark .app-kicker {
  display: block; color: #5eead4; font-family: var(--font-mono); font-size: 10px;
  font-weight: 700; letter-spacing: .14em; text-transform: uppercase;
}
.app-wordmark .app-name {
  display: block; margin-top: 2px; color: #fff; font-size: 15px; font-weight: 680;
  letter-spacing: .01em;
}

#topbar > .topbar-user {
  grid-area: user;
  min-width: 0 !important;
  overflow: hidden !important;
  padding: 0 !important;
}
#topbar .topbar-user p {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

#topbar > .topbar-timer {
  grid-area: timer;
  width: max-content !important;
  overflow: visible !important;
  padding: 0 !important;
  white-space: nowrap !important;
}
#topbar .topbar-timer p {
  color: #fcd34d;
}
#topbar > .topbar-extend { grid-area: extend; }
#topbar > .topbar-logout { grid-area: logout; }

/* ── Thẻ nội dung ──────────────────────────────────────────────────────── */
.section-card {
  border: 1px solid var(--border-color-primary);
  border-radius: 10px;
  padding: 16px;
  background: var(--background-fill-primary);
  box-shadow: 0 10px 26px -25px rgba(15,23,42,.7);
}

/* ── Tab ───────────────────────────────────────────────────────────────── */
.tab-nav { gap: 2px; }
.tab-nav button {
  font-size: 15px !important;
  padding: 10px 16px !important;
  letter-spacing: .01em;
}
.tab-nav button.selected {
  color: var(--scap-ok-fg) !important;
  font-weight: 650 !important;
}

/* ── Dashboard theo phong cách SOC/Purple Team ───────────────────────────
   Khối số liệu lớn, ngắn và có nhãn rõ tạo nhịp đọc giống dashboard trong
   tài liệu tham khảo; toàn bộ dữ liệu vẫn lấy từ API của SCAP. */
.dashboard-hero {
  margin: 4px 0 16px; padding: 20px 22px;
  border: 1px solid var(--scap-line); border-radius: 12px;
  background: linear-gradient(120deg, rgba(15,23,42,.98), rgba(15,50,76,.96));
  box-shadow: 0 18px 34px -28px rgba(15,23,42,.9);
}
.dashboard-hero h3 { margin: 0 0 6px; color: #fff; font-size: 22px; font-weight: 680; }
.dashboard-hero p { margin: 0; max-width: 780px; color: #cbd5e1; line-height: 1.6; }
.dashboard-hero strong { color: #5eead4; }
.dashboard-eyebrow {
  margin: 0 0 6px !important; color: #5eead4 !important; font-family: var(--font-mono);
  font-size: 11px !important; font-weight: 700; letter-spacing: .13em; text-transform: uppercase;
}
.metric-grid { gap: 12px !important; margin: 0 0 14px !important; }
.metric-card {
  min-height: 122px; padding: 15px 16px !important;
  border: 1px solid var(--scap-line) !important; border-radius: 10px !important;
  background: var(--scap-panel) !important;
  box-shadow: 0 10px 24px -24px rgba(15,23,42,.9);
}
.metric-card p { margin: 0 !important; color: var(--scap-muted); font-size: 12px; font-weight: 650; letter-spacing: .06em; text-transform: uppercase; }
.metric-card h1, .metric-card h2 { margin: 7px 0 3px !important; color: var(--scap-ink); font-size: 29px !important; font-weight: 720; line-height: 1.1; }
.metric-card strong { color: var(--scap-ink); }
.metric-card-green { border-top: 3px solid #10b981 !important; }
.metric-card-blue { border-top: 3px solid #3b82f6 !important; }
.metric-card-amber { border-top: 3px solid #f59e0b !important; }
.metric-card-red { border-top: 3px solid #ef4444 !important; }
.dashboard-panel {
  margin: 10px 0 14px; padding: 14px 16px !important; border: 1px solid var(--scap-line);
  border-radius: 10px; background: var(--scap-panel);
}
.dashboard-panel p:first-child { margin-top: 0; }
.dashboard-panel p:last-child { margin-bottom: 0; }
.dashboard-section-title { margin: 20px 0 8px !important; color: var(--scap-ink); font-size: 16px !important; font-weight: 700; }
.dashboard-table .scap-table th { background: rgba(148,163,184,.16) !important; }

/* ── Bảng dữ liệu chỉ đọc (HTML dựng sẵn ở máy chủ, xem _table_html) ───── */
.scap-table-block { width: 100%; min-width: 0 !important; max-width: 100%; }
.scap-table-scroll {
  max-height: 560px; overflow: auto;
  border: 1px solid var(--scap-line); border-radius: 10px;
  background: var(--background-fill-primary);
}
.scap-table-block table.scap-table {
  width: 100%; margin: 0 !important; border: 0 !important;
  border-collapse: separate; border-spacing: 0;
  font-size: 14px; line-height: 1.45;
}
.scap-table th, .scap-table td {
  padding: 8px 12px !important; border: 0 !important;
  border-bottom: 1px solid var(--scap-line) !important;
  text-align: left; vertical-align: top; overflow-wrap: anywhere;
}
.scap-table th {
  position: sticky; top: 0; z-index: 1;
  background: var(--background-fill-secondary) !important;
  color: var(--scap-ink); font-weight: 650; white-space: nowrap;
}
.scap-table tbody tr:nth-child(even) td { background: rgba(148,163,184,.06); }
.scap-table tbody tr:last-child td { border-bottom: 0 !important; }
.scap-table td.scap-table-empty { color: var(--scap-muted); text-align: center; font-style: italic; }
.scap-table-nowrap .scap-table td { white-space: nowrap; overflow-wrap: normal; }

/* Mọi thứ liên quan mật mã đều monospace. */
.mono-df .scap-table {
  font-family: var(--font-mono);
  font-size: 13.5px;
  font-variant-numeric: tabular-nums;
}
.mono-df .scap-table th { font-size: 12.5px; text-transform: uppercase; letter-spacing: .05em; }

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
  border-color: var(--scap-blue) !important;
  background: #dbeafe !important;
  color: #1e3a8a !important;
  font-weight: 600;
  box-shadow: inset 3px 0 0 var(--scap-blue);
}
#session-list label.selected span {
  color: inherit !important;
  font-weight: inherit;
}
.dark #session-list label.selected {
  background: #1e3a5f !important;
  color: #dbeafe !important;
}
#session-list input[type="radio"] {
  /* Keep native keyboard focus and Space-key activation available. */
  position: absolute; opacity: 0; width: 1px; height: 1px;
}
#session-list label:focus-within {
  outline: 2px solid var(--scap-ok-fg); outline-offset: 2px;
}
#session-list span { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* Fixed-choice dropdowns are pick-only (filterable=False makes the input
   readOnly); hide the text caret so the field does not look editable. */
.pick-only input { caret-color: transparent; cursor: pointer; }

/* Shared surfaces and clear hierarchy across all eight workspace tabs. */
#workspace-tabs > .tab-wrapper {
  padding: 6px; margin-bottom: 12px;
  border: 1px solid var(--scap-line); border-radius: 12px;
  background: var(--background-fill-primary);
}
#workspace-tabs > .tab-wrapper .tab-nav button {
  border-radius: 8px; min-height: 44px;
}
#workspace-tabs > .tab-wrapper .tab-nav button.selected {
  background: var(--scap-ok-bg) !important;
}
#workspace-tabs .gr-accordion > button { align-items: center; }
#workspace-tabs > .tabitem { padding: 16px 0 !important; }
#chat-sidebar { border-top: 3px solid #10b981; }
#session-delete-confirm { border: 1px solid var(--scap-bad-bd); border-radius: 12px; padding: 12px; }
#chat-main { min-width: 0 !important; }
#chat-history {
  border: 1px solid var(--scap-line); border-radius: 14px;
  background: var(--background-fill-primary);
}
.chat-welcome { max-width: 430px; margin: auto; padding: 24px; text-align: center; }
.chat-welcome .welcome-symbol {
  display: inline-flex; align-items: center; justify-content: center;
  width: 48px; height: 48px; border-radius: 14px;
  color: var(--scap-ok-fg); background: var(--scap-ok-bg);
  font-size: 25px; margin-bottom: 12px;
}
.chat-welcome h3 { margin: 0 0 10px; font-size: 22px; color: var(--scap-ink); }
.chat-welcome p { margin: 0; line-height: 1.7; color: var(--scap-muted); }
.tab-intro { margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--scap-line); }
.tab-intro h3 { margin: 0 0 6px; color: var(--scap-ink); font-size: 22px; }
.tab-intro p { margin: 0; color: var(--scap-muted); line-height: 1.6; }
.auth-caption { margin: 0; color: var(--scap-muted); font-size: 14px; }
#chat-composer { align-items: end; }
#chat-composer textarea { font-size: 16px !important; line-height: 1.6; }
#chat-composer button { min-height: 46px; }
.mono-df { max-width: 100%; min-width: 0 !important; }

/* ── Khối trạng thái ───────────────────────────────────────────────────── */
#chat-notice, #sec-verdict, #sec-ids-verdict {
  border-radius: 8px; padding: 12px 15px; margin-top: 6px;
  border-left: 3px solid var(--scap-warn-bd);
}
#chat-notice {
  border: 1px solid var(--scap-warn-bd);
  border-left-color: var(--scap-warn-bd);
  background: var(--scap-warn-bg);
}
#chat-notice p { margin: 0; font-size: 15px; color: var(--scap-warn-fg); }
#export-link a.scap-export-link {
  display: block; text-align: center; padding: 7px 12px; border-radius: 8px;
  border: 1px solid var(--button-secondary-border-color, #d0d7de);
  background: var(--button-secondary-background-fill, #f6f8fa);
  color: var(--button-secondary-text-color, inherit); font-weight: 600; text-decoration: none;
}
#export-link a.scap-export-link:hover { filter: brightness(0.97); }
#sec-verdict, #sec-ids-verdict {
  border: 1px solid var(--scap-warn-bd);
  background: var(--scap-warn-bg);
  color: var(--scap-warn-fg);
}
#sec-verdict p, #sec-ids-verdict p { margin: 0; font-size: 15px; }

/* ── QR 2FA: ảnh nội tuyến, không có toolbar lưu/chia sẻ ──────────────── */
.scap-totp-qr-panel { min-width: 0 !important; }
.scap-totp-qr {
  display: flex; align-items: center; justify-content: center;
  min-height: 352px; width: 100%; overflow: hidden;
  border: 1px solid var(--scap-line); border-radius: 8px;
  background: #fff;
}
.scap-totp-qr img {
  display: block; width: min(352px, 100%); height: auto;
  aspect-ratio: 1; image-rendering: pixelated; user-select: none;
}
@media (max-width: 820px) {
  .scap-totp-qr { min-height: min(352px, 80vw); }
}

/* ── Bố cục ngang ──────────────────────────────────────────────────────── */
@media (min-width: 1024px) {
  #chat-row { flex-wrap: nowrap !important; }
}
@media (max-width: 1023px) {
  #chat-row { flex-direction: column !important; }
  #chat-sidebar, #chat-main {
    width: 100% !important; min-width: 0 !important;
  }
  #session-list { max-height: 180px; }
}
@media (max-width: 999px) {
  .gradio-container > .main {
    padding: 12px var(--scap-page-gutter) 32px !important;
  }
}
@media (max-width: 820px) {
  #topbar {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    grid-template-areas:
      "brand timer"
      "user user"
      "extend logout";
    gap: 10px 12px;
    padding: 10px 14px;
  }
  #topbar > .topbar-timer { justify-self: end; }
  #topbar > .topbar-extend,
  #topbar > .topbar-logout { width: 100% !important; }
  #topbar button { width: 100% !important; }
}
/* Dưới 900px: thẻ bám sát mép trên để ô nhập đầu tiên luôn nằm trên nếp gấp
   màn hình điện thoại. */
@media (max-width: 900px) {
  #auth-wrap { margin-top: max(40px, 3vh); }
  #auth-card { padding: 24px 20px 20px !important; }
}
@media (max-width: 640px) {
  #workspace-tabs > .tabitem { padding: 10px 0 !important; }
  #workspace-tabs button, #app-sec .section-card button { min-height: 44px; }
  #chat-composer { flex-wrap: nowrap !important; }
  #chat-composer button { min-width: 72px !important; }
  .chat-welcome { padding: 18px; }
  .chat-welcome h3 { font-size: 20px; }
}

/* Sàn chất lượng: focus thấy được bằng bàn phím, tôn trọng reduced-motion. */
:where(button, input, textarea, select, [tabindex]):focus-visible {
  outline: 2px solid var(--scap-ok-fg);
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
# Cạnh ô hiển thị mã QR. Ảnh được dựng đúng bằng số pixel này rồi mới nhúng vào
# trang — co giãn không nguyên lần làm nhoè biên module và khiến camera khó đọc.
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


def _totp_qr_markup(uri: str, target_px: int = QR_DISPLAY_PX) -> str:
    """Return the QR as inline HTML instead of a Gradio-managed image file.

    ``gr.Image`` post-processes PIL values into the Gradio cache directory.  That
    is unnecessary for an enrollment QR and leaves a copy on the host running
    the UI (as well as exposing download/share controls).  Encoding the already
    generated PNG in a ``data:`` URL keeps it in the current page memory only;
    the browser never receives a file path or a download action.
    """
    import base64
    import io

    image = _totp_qr_image(uri, target_px)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False)
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return (
        '<div class="scap-totp-qr" role="img" '
        'aria-label="Mã QR thiết lập xác thực hai lớp">'
        f'<img src="data:image/png;base64,{encoded}" '
        f'width="{target_px}" height="{target_px}" '
        'alt="Mã QR thiết lập xác thực hai lớp" draggable="false">'
        "</div>"
    )


def _browser_context_headers() -> dict[str, str]:
    """Sign the address/User-Agent of the browser whose event is being handled.

    Every UI call reaches the API from this process over loopback. Without this,
    all users would share one source address: one person's failed logins or
    IDS hits would rate-limit or block everyone, and the audit trail, device
    list and anomaly engine would only ever see 127.0.0.1.
    """
    from gradio.context import LocalContext

    request = LocalContext.request.get(None)
    if request is None:
        return {}
    try:
        client = getattr(request, "client", None)
        host = getattr(client, "host", None) if client is not None else None
        headers = getattr(request, "headers", None)
        user_agent = headers.get("user-agent", "") if headers is not None else ""
        cookies = getattr(request, "cookies", None)
        device_cookie = cookies.get(DEVICE_COOKIE_NAME) if cookies is not None else None
    except (AttributeError, KeyError, TypeError):
        return {}
    forwarded: dict[str, str] = {}
    if _CLIENT_CONTEXT_KEY is not None and isinstance(host, str):
        forwarded.update(
            sign_ui_client_context(_CLIENT_CONTEXT_KEY, host, str(user_agent or ""))
        )
    # The HttpOnly device cookie never reaches page scripts; the server-side UI
    # relays it so the API recognises this browser at sign-in.
    if isinstance(device_cookie, str) and 0 < len(device_cookie) <= 200 and device_cookie.isascii():
        forwarded[DEVICE_TOKEN_HEADER] = device_cookie
    return forwarded


# Tab tokens the API has refused as unusable (revoked on another device, account
# locked or deleted, session expired on the server). Only digests are kept; the
# session clock sends such a tab back to sign-in at its next tick.
_ENDED_TOKENS: dict[str, None] = {}
_ENDED_TOKENS_LOCK = threading.Lock()
_ENDED_TOKENS_MAX = 10_000


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _mark_session_ended(token: str) -> None:
    with _ENDED_TOKENS_LOCK:
        _ENDED_TOKENS[_token_digest(token)] = None
        while len(_ENDED_TOKENS) > _ENDED_TOKENS_MAX:
            del _ENDED_TOKENS[next(iter(_ENDED_TOKENS))]


def _take_session_ended(token: str) -> bool:
    digest = _token_digest(token)
    with _ENDED_TOKENS_LOCK:
        if digest not in _ENDED_TOKENS:
            return False
        del _ENDED_TOKENS[digest]
        return True


# Tên trường trong lỗi 422 của API -> nhãn trên giao diện.
_VALIDATION_FIELDS = {
    "username": "Tên đăng nhập", "password": "Mật khẩu", "current_password": "Mật khẩu hiện tại",
    "new_password": "Mật khẩu mới", "title": "Tiêu đề", "content": "Nội dung", "email": "Email",
    "identifier": "Tên đăng nhập hoặc email", "code": "Mã xác thực", "name": "Tên",
    "role": "Vai trò", "query": "Từ khóa", "q": "Từ khóa", "security_mode": "Chế độ bảo mật",
    "data_classification": "Phân loại dữ liệu",
}


def _validation_text(items) -> str:
    """Vietnamese text for FastAPI 422 items ``{type, loc, msg}``.

    Pydantic's own wording is English; our validators already speak Vietnamese
    but arrive prefixed with "Value error, ". Input values are never echoed.
    """
    messages = []
    for item in items:
        if not isinstance(item, dict):
            continue
        loc = [part for part in item.get("loc") or []
               if isinstance(part, str) and part not in {"body", "query", "path", "header"}]
        label = _VALIDATION_FIELDS.get(loc[-1], loc[-1]) if loc else "Dữ liệu"
        kind, msg = str(item.get("type") or ""), str(item.get("msg") or "")
        number = re.search(r"\d+", msg)
        if kind == "value_error":
            text = msg.removeprefix("Value error, ")
        elif kind == "string_too_short" and number:
            text = f"{label} phải có ít nhất {number.group()} ký tự."
        elif kind == "string_too_long" and number:
            text = f"{label} chỉ được tối đa {number.group()} ký tự."
        elif kind == "missing":
            text = f"Thiếu {label[:1].lower() + label[1:]}."
        else:
            text = f"{label} không hợp lệ."
        messages.append(text)
    return " ".join(dict.fromkeys(messages)) or "Dữ liệu không hợp lệ."


class _RejectCookies(http.cookiejar.DefaultCookiePolicy):
    """The shared API client serves every user: never store or replay a cookie."""

    def set_ok(self, cookie, request):
        return False

    def return_ok(self, cookie, request):
        return False


# Mỗi lần mở hội thoại hay chuyển tab, handler gọi API 3–5 lần. Tạo
# httpx.Client mới cho từng lần tốn ~35 ms (dựng SSL context + mở TCP), so với
# ~2 ms trên kết nối keep-alive dùng lại — phần lớn thời gian "processing" mà
# người dùng thấy. Một client có pool dùng chung cho mọi luồng (httpx.Client an
# toàn đa luồng).
_API_CLIENT = None  # (factory, client)
_API_CLIENT_LOCK = threading.Lock()
# Ngắn hơn --timeout-keep-alive mặc định của uvicorn (5 giây): client bỏ kết nối
# rảnh trước khi máy chủ đóng, để không ghi yêu cầu lên socket vừa bị đóng.
_API_KEEPALIVE_SECONDS = 2.0


def _api_client():
    import httpx

    global _API_CLIENT
    with _API_CLIENT_LOCK:
        # Dựng lại khi httpx.Client bị thay (test thay bằng lớp/hàm giả).
        if _API_CLIENT is None or _API_CLIENT[0] is not httpx.Client:
            _API_CLIENT = (httpx.Client, httpx.Client(
                timeout=60,
                limits=httpx.Limits(
                    max_connections=100,
                    max_keepalive_connections=20,
                    keepalive_expiry=_API_KEEPALIVE_SECONDS,
                ),
                cookies=http.cookiejar.CookieJar(policy=_RejectCookies()),
            ))
        return _API_CLIENT[1]


def _api(token, method, path, body=None, *, params=None):
    import httpx

    tab_token = token
    headers = {"Content-Type": "application/json", **_browser_context_headers()}
    if token and _SESSION_STORE is not None:
        token = _SESSION_STORE.current_token(token)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        func = getattr(_api_client(), method.lower())
        url = BASE_URL.rstrip("/") + path
        if body is not None and method != "GET":
            resp = func(url, headers=headers, json=body)
        else:
            resp = func(url, headers=headers, params=params)
    except httpx.ConnectError as exc:
        raise gr.Error(
            f"Không kết nối được API nội bộ tại {BASE_URL}. "
            "Nếu server chạy ở cổng khác, hãy đặt SELF_BASE_URL trong .env."
        ) from exc
    except httpx.TimeoutException as exc:
        # Do not pass transport exceptions (URLs/headers) through Gradio. A
        # timed-out write may have completed; never retry it automatically.
        raise gr.Error(
            "Máy chủ phản hồi quá chậm; chưa xác nhận được kết quả yêu cầu. "
            "Hãy tải lại lịch sử hội thoại trước khi gửi lại."
        ) from exc
    except httpx.RequestError as exc:
        raise gr.Error(
            "Kết nối tới máy chủ bị gián đoạn; chưa xác nhận được kết quả yêu cầu. "
            "Hãy tải lại lịch sử hội thoại trước khi gửi lại."
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
            detail = _validation_text(detail)
        elif isinstance(detail, dict):
            detail = detail.get("message") or detail.get("code") or "Yêu cầu bị từ chối."
        message = detail or f"HTTP {resp.status_code}"
        # Only the RFC 6750 invalid_token challenge ends the tab's session; a
        # 401 for a wrong step-up password or 2FA code must not sign out.
        if (
            resp.status_code == 401
            and tab_token
            and 'error="invalid_token"' in resp.headers.get("WWW-Authenticate", "")
        ):
            _mark_session_ended(tab_token)
        if resp.status_code in (429, 503):
            retry = resp.headers.get("Retry-After")
            if retry:
                message += f" Thử lại sau {retry} giây."
        error = gr.Error(message)
        # Callers that expect a permission boundary (403) can render it quietly.
        error.status_code = resp.status_code
        # A rejected precondition is safe to retry once after step-up. Error
        # text alone must never replay an HTTP write whose outcome is unknown.
        error.step_up_required = (
            resp.status_code == 403
            and resp.headers.get("X-Step-Up-Required", "").lower() == "true"
        )
        raise error
    return data


def _countdown_markup(left: int) -> str:
    """Đồng hồ phiên trên thanh trạng thái.

    ``data-scap-countdown`` là số giây còn lại tại thời điểm máy chủ dựng; từ đó
    session_bridge.js tự đếm lùi từng giây mà không cần gọi lại máy chủ. Chỉ chứa
    số nguyên và biểu tượng cố định, nên an toàn khi tắt sanitize.
    """
    left = max(0, int(left))
    hours, rem = divmod(left, 3600)
    minutes, seconds = divmod(rem, 60)
    shown = f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"
    icon = "⚠️" if left <= WARN_BEFORE_EXPIRY else "⏳"
    return (
        f'<span data-scap-countdown="{left}" data-scap-warn-at="{WARN_BEFORE_EXPIRY}">'
        f"<span data-scap-countdown-icon>{icon}</span> <strong>{shown}</strong></span>"
    )


def _fmt(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return iso


def _error_text(err: gr.Error) -> str:
    """Nội dung lỗi để hiển thị: ``str(gr.Error)`` là ``repr`` nên bị bọc dấu nháy."""
    return err.message if isinstance(getattr(err, "message", None), str) else str(err)


def _guard(fn, n_outputs):
    """Chạy handler; nếu API trả lỗi (gr.Error) thì hiển thị toast cảnh báo
    thay vì để Gradio gắn nhãn "Error" kẹt trên các component output."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except gr.Error as err:
            _ui_notice(gr.Warning, _error_text(err))
            if n_outputs <= 1:
                return gr.skip()
            return tuple(gr.skip() for _ in range(n_outputs))

    return wrapper


def _ui_notice(notice, *args, **kwargs):
    """Keep obsolete callbacks from sending account details through toasts."""
    observation = _UI_RESULT_SESSION.get()
    if observation is not None:
        state = observation["state"]
        if (state._scap_auth_generation != observation["generation"]
            or tuple(state[item] for item in observation["identity_ids"]) != observation["identity"]):
            return
    return notice(*args, **kwargs)


def _install_session_result_guard(demo, token_component, mfa_component):
    """Discard results belonging to a login that has since ended or changed.

    Gradio runs callbacks concurrently, including logout and workspace loading.
    Check at publication, before postprocessing writes any component/state, and
    serialize only that short publication step per browser SessionState. A
    generation also covers logout while a login is still pending (both start
    with an empty token), and challenge cancellation. No cookie or JWT parsing
    is needed: restored sessions and raw token callers use the same boundary.
    Queued inputs retain their admission identity until invocation; checking
    publication alone would let an old request execute with the next token.
    GradioCapacity rejects streaming/batched callbacks in this application.
    """
    process_api, postprocess_data, call_function = demo.process_api, demo.postprocess_data, demo.call_function
    identity_ids = (token_component._id, mfa_component._id)
    reset_names = {"do_logout", "expire_session", "logout_all", "change_password",
                   "mfa_activate", "mfa_disable"}

    def prepare_state(state):
        if not hasattr(state, "_scap_output_lock"):
            state._scap_output_lock = asyncio.Lock()
            state._scap_auth_generation = 0

    def binding(state):
        return (id(state), state._scap_auth_generation,
                tuple(_token_digest(str(state[item])) for item in identity_ids))

    async def capture_binding(state):
        prepare_state(state)
        async with state._scap_output_lock:
            return binding(state)

    def stale(observation):
        state = observation["state"]
        return (observation["stale"] or state._scap_auth_generation != observation["generation"]
                or tuple(state[item] for item in identity_ids) != observation["identity"]
                or tuple(state[item] for item in observation.get("scope_ids", ()))
                != observation.get("scope", ()))

    def skipped_result(block_fn):
        return {
            "data": [gr.skip() for _ in block_fn.outputs], "is_generating": False,
            "iterator": None, "duration": 0, "average_duration": 0,
            "render_config": None, "changed_state_ids": [], "used_cache": None,
        }

    demo.scap_capacity.capture_auth_binding = capture_binding

    @wraps(process_api)
    async def process(*args, **kwargs):
        state = kwargs.get("state", args[2] if len(args) > 2 else None)
        event_id = kwargs.get("event_id", args[6] if len(args) > 6 else None)
        block_fn = kwargs.get("block_fn", args[0] if args else None)
        if isinstance(block_fn, int):
            block_fn = demo.fns[block_fn]
        if state is None:
            if event_id is not None:
                return skipped_result(block_fn)
            return await process_api(*args, **kwargs)
        prepare_state(state)
        async with state._scap_output_lock:
            if event_id is not None:
                session_hash = kwargs.get("session_hash", args[5] if len(args) > 5 else None)
                admitted = demo.scap_capacity.admitted_auth_binding(event_id, session_hash, block_fn._id)
                if admitted is None or admitted != binding(state):
                    return skipped_result(block_fn)
            observation = {
                "state": state, "generation": state._scap_auth_generation,
                "identity": tuple(state[item] for item in identity_ids),
                "identity_ids": identity_ids, "stale": False,
                "scope_ids": getattr(block_fn, "_scap_scope_ids", ()),
                "scope": tuple(state[item] for item in getattr(block_fn, "_scap_scope_ids", ())),
            }
        handle = _UI_RESULT_SESSION.set(observation)
        try:
            result = await process_api(*args, **kwargs)
            if observation["stale"]:
                # A different callback may have changed State while this one
                # was running. Do not trigger change events on its behalf.
                result["changed_state_ids"] = []
                result["render_config"] = None
            return result
        finally:
            _UI_RESULT_SESSION.reset(handle)

    @wraps(call_function)
    async def invoke(*args, **kwargs):
        observation = _UI_RESULT_SESSION.get()
        # Preprocessing awaits component work. Recheck before calling any
        # handler so a token read after an intervening logout cannot execute an
        # older request using the next account's credentials.
        if observation is not None and stale(observation):
            observation["stale"] = True
            return {"prediction": gr.skip(), "duration": 0,
                    "is_generating": False, "iterator": None}
        return await call_function(*args, **kwargs)

    @wraps(postprocess_data)
    async def publish(block_fn, predictions, state):
        observation = _UI_RESULT_SESSION.get()
        if observation is None or observation["state"] is not state:
            return await postprocess_data(block_fn, predictions, state)
        async with state._scap_output_lock:
            before = tuple(state[item] for item in identity_ids)
            if stale(observation):
                observation["stale"] = True
                # Do not pass skips through postprocess_data: even gr.skip()
                # reconstructs component config. Leave the current state intact.
                return [gr.skip() for _ in block_fn.outputs]
            clears_session = (
                block_fn.fn is not None and block_fn.fn.__name__ in reset_names
                and token_component in block_fn.outputs
                and isinstance(predictions, (tuple, list))
                and predictions[block_fn.outputs.index(token_component)] == ""
            )
            try:
                return await postprocess_data(block_fn, predictions, state)
            finally:
                after = tuple(state[item] for item in identity_ids)
                if clears_session or after != before:
                    state._scap_auth_generation += 1

    demo.process_api = process
    demo.postprocess_data = publish
    demo.call_function = invoke


def _session_choices(token):
    """Nhãn có ổ khoá để nhắc rằng nội dung phiên được mã hoá khi lưu."""
    icons = {"secure": "🔒", "confidential": "🛡️", "private_e2ee": "🔐"}
    return [
        (f"{icons.get(row.get('security_mode'), '🔒')}  {row['title']}", row["id"])
        for row in _read_page(token, "/api/sessions/page")["items"]
    ]


def _read_page(token, path, *, offset=0, limit=100, params=None):
    """Read the explicit paging contract, never infer a total from a page size."""
    page = _api(token, "GET", path, params={
        **(params or {}), "offset": offset, "limit": limit,
    })
    if (not isinstance(page, dict) or not isinstance(page.get("items"), list)
        or type(page.get("total")) is not int or page["total"] < 0
        or type(page.get("has_more")) is not bool):
        raise gr.Error("Máy chủ chưa trả được thông tin phân trang hợp lệ. Hãy làm mới.")
    next_offset = page.get("next_offset")
    if page["has_more"] and (type(next_offset) is not int or next_offset <= offset):
        raise gr.Error("Máy chủ chưa trả được vị trí tải tiếp hợp lệ. Hãy làm mới.")
    return page


def _page_state(token, page, *, previous=None, **scope):
    previous = previous or {}
    matches = previous.get("account") == _token_digest(token) and all(
        previous.get(key) == value for key, value in scope.items()
    )
    items = list(previous.get("items", [])) if matches else []
    by_id = {item.get("id", item.get("message_id")): item for item in items}
    for item in page["items"]:
        by_id[item.get("id", item.get("message_id"))] = item
    return {
        "account": _token_digest(token), "items": list(by_id.values()),
        "total": page["total"], "next_offset": page.get("next_offset"),
        "has_more": page["has_more"], **scope,
    }


def _page_summary(state, noun):
    count = len(state.get("items", []))
    if state.get("has_more"):
        more = " · Còn kết quả, bấm **Tải thêm**."
    elif count != state.get("total", count):
        more = " · Danh sách đã thay đổi; hãy làm mới để đối chiếu lại."
    else:
        more = " · Đã tải hết."
    return f"Đang hiển thị **{count}/{state.get('total', count)}** {noun}{more}"


# Dùng chung cho dropdown "Thiết lập hội thoại mới" và dòng chế độ đã khóa.
SECURITY_MODE_CHOICES = [
    ("Secure — mã hóa phía máy chủ", "secure"),
    ("Confidential — DLP/xác nhận nghiêm ngặt", "confidential"),
]
DATA_CLASS_CHOICES = [
    ("Public", "public"),
    ("Internal", "internal"),
    ("Confidential", "confidential"),
    ("Highly confidential", "highly_confidential"),
]
_SECURITY_MODE_LABELS = {
    **{value: label for label, value in SECURITY_MODE_CHOICES},
    "private_e2ee": "Private E2EE — mã hóa đầu cuối",
}
_DATA_CLASS_LABELS = {
    **{value: label for label, value in DATA_CLASS_CHOICES},
    "e2ee_private": "E2EE private",
}


def _pick_dropdown(**kwargs) -> gr.Dropdown:
    """Dropdown chỉ để chọn, dùng cho mọi dropdown của UI.

    Gradio mặc định ``filterable=True`` biến ô thành ô gõ chữ có con trỏ, trông
    như sửa được giá trị. ``filterable=False`` làm ô nhập readOnly; lớp
    ``pick-only`` ẩn nốt con trỏ.
    """
    return gr.Dropdown(filterable=False, elem_classes=["pick-only"], **kwargs)


def _session_policy_markdown(token, session_id):
    """Chế độ của hội thoại đang chọn, chỉ để xem.

    Chế độ được chốt khi tạo: UI không có đường nào để đổi, còn API từ chối
    đổi trust boundary khi hội thoại đã có dữ liệu.
    """
    if not session_id:
        return ""
    session = _api(token, "GET", f"/api/sessions/{session_id}")
    mode = session.get("security_mode")
    data_class = session.get("data_classification")
    mode_label = _SECURITY_MODE_LABELS.get(mode) or _safe_markdown_text(mode)
    class_label = _DATA_CLASS_LABELS.get(data_class) or _safe_markdown_text(data_class)
    return (
        f"🔒 **Hội thoại đang chọn:** {mode_label} · {class_label} (không thể đổi)  \n"
        "Bấm **Gửi** là xác nhận gửi tin nhắn tới AI; DLP vẫn che hoặc chặn dữ liệu nhạy cảm."
    )


class _SafeChatRenderer(RendererHTML):
    """Render a small Markdown surface without browser-side image requests."""

    def image(self, tokens, idx, options, env):
        # Parse images before dropping them: inline/reference images and escaped
        # backslashes have the same treatment, without a regex parser bypass.
        token = tokens[idx]
        label = self.renderInlineAsText(token.children or [], options, env)
        return html.escape(label or "[Ảnh đã ẩn]", quote=True)

    def fence(self, tokens, idx, options, env):
        # Code is always inert. Do not opt untrusted fences into Mermaid, math,
        # custom components, or any executable browser renderer.
        return "<pre><code>" + html.escape(tokens[idx].content, quote=False) + "</code></pre>\n"


_CHAT_MARKDOWN = MarkdownIt(
    "commonmark", {"html": False, "breaks": True}, renderer_cls=_SafeChatRenderer,
).enable(["table", "strikethrough"])


def _safe_chat_link(value: str) -> bool:
    # Reject browser-normalized control characters/backslashes before parsing.
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


# Công thức LaTeX trong tin nhắn. markdown-it làm hỏng chúng nếu phân tích như
# văn bản thường: ``$x_1$ … $x_2$`` thành chữ nghiêng, ``\\`` mất một gạch,
# ``\{`` mất gạch. Mã (khối ``` và `inline`) được khớp trước để ký hiệu $ trong
# mã giữ nguyên; ``\$`` là ký tự $ thường. $...$ theo quy tắc của Pandoc: không
# có khoảng trắng sát bên trong và không có chữ số ngay sau dấu đóng, nên
# "giá 5$ và 10$" không bị coi là công thức.
_MATH_SOURCE = re.compile(
    r"(?P<fence>^[ \t]*(?P<mark>`{3,}|~{3,})[^\n]*\n[\s\S]*?(?:^[ \t]*(?P=mark)[ \t]*$|\Z))"
    r"|(?P<code>(?<!`)(?P<ticks>`+)(?!`)[\s\S]+?(?<!`)(?P=ticks)(?!`))"
    r"|(?P<literal>\\[\\$])"
    r"|\$\$(?P<display>[\s\S]+?)\$\$"
    r"|\\\[(?P<display_b>[\s\S]+?)\\\]"
    r"|\\\((?P<inline_b>[\s\S]+?)\\\)"
    r"|\$(?P<inline>[^\s$](?:[^\n$]*?[^\s$\\])?)\$(?!\d)",
    re.M,
)
# Trình duyệt chỉ dựng công thức trong \( \) và \[ \] — dạng máy chủ viết ra sau
# khi đã tách. Không dùng $: ký hiệu $ còn lại trong văn bản là ký tự thường.
# KaTeX của Gradio chạy với trust=false (không \href, \url, \html...) và bỏ qua
# <pre>/<code>.
CHAT_LATEX_DELIMITERS = [
    {"left": "\\[", "right": "\\]", "display": True},
    {"left": "\\(", "right": "\\)", "display": False},
]


def _protect_math(content: str) -> tuple[str, re.Pattern[str], list[str]]:
    """Swap formulas for placeholders markdown-it leaves alone."""
    nonce = secrets.token_hex(8)
    segments: list[str] = []

    def replace(match: re.Match[str]) -> str:
        display = match.group("display") or match.group("display_b")
        tex = display or match.group("inline_b") or match.group("inline")
        if tex is None or not tex.strip():
            return match.group(0)
        # Dòng trống kết thúc khối HTML ở bộ Markdown phía trình duyệt; LaTeX
        # vốn bỏ qua nó, nên gộp lại.
        tex = html.escape(re.sub(r"\n\s*\n", "\n", tex.strip()), quote=True)
        segments.append(rf"\[{tex}\]" if display else rf"\({tex}\)")
        return f"{nonce}:{len(segments) - 1}"

    placeholder = re.compile(f"{nonce}:(\\d+)")
    return _MATH_SOURCE.sub(replace, content), placeholder, segments


def _safe_chat_text(content: str) -> str:
    """Render safe formatting while keeping source messages unchanged.

    Raw input HTML is escaped by the server parser. Images become text and only
    HTTP(S) links can navigate, with no referrer or opener. Gradio sanitizes the
    generated standard markup once more. Rendering server-generated block HTML
    also avoids interpreting leftover Markdown under a second parser dialect.
    Formulas bypass the Markdown parser as escaped text in \\( \\) / \\[ \\],
    which the browser typesets with KaTeX.
    """

    # Provider output and legacy rows did not necessarily pass through the API
    # schema. Make directional controls visible at the display boundary too.
    for codepoint in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)):
        content = content.replace(chr(codepoint), f"\\u{codepoint:04X}")
    content, placeholder, formulas = _protect_math(content)
    tokens = _CHAT_MARKDOWN.parse(content)
    for token in tokens:
        if token.type != "inline":
            continue
        safe_links = []
        for child in token.children or []:
            if child.type == "link_open":
                allowed = _safe_chat_link(child.attrGet("href") or "")
                safe_links.append(allowed)
                if allowed:
                    child.attrSet("target", "_blank")
                    child.attrSet("rel", "noopener noreferrer")
                    child.attrSet("referrerpolicy", "no-referrer")
            elif child.type == "link_close":
                allowed = safe_links.pop() if safe_links else False
            else:
                continue
            if not allowed:
                # Keep the label, but discard both ends of a rejected link.
                child.type, child.tag, child.content, child.nesting = "text", "", "", 0
                child.attrs = {}
    rendered = _CHAT_MARKDOWN.renderer.render(tokens, _CHAT_MARKDOWN.options, {})
    return placeholder.sub(lambda match: formulas[int(match.group(1))], rendered)


def _search_widget_marker(original: str | None) -> str:
    """Only validated, unchanged Google markup enters the scoped widget bridge."""
    if original is None:
        return ""
    if not validate_search_suggestions_html(original):
        raise gr.Error("Không hiển thị được gợi ý Google Search an toàn. Vui lòng thử lại.")
    encoded = base64.b64encode(original.encode("utf-8")).decode("ascii")
    return f'<div data-scap-google-search-widget="{encoded}"></div>'


def _safe_markdown_text(value) -> str:
    """Keep API values inert inside the UI's own Markdown structure.

    HTML escaping alone still permits Markdown links and remote images. Each
    value occupies one text span, so newlines and Markdown syntax are escaped
    as well. The surrounding guide headings/lists are trusted UI markup.
    """
    text = " ".join(str(value if value is not None else "—").split())
    for codepoint in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)):
        text = text.replace(chr(codepoint), f"\\u{codepoint:04X}")
    text = text.replace("\\", "\\\\")
    for char in "`*_{}[]()#+-.!|~":
        text = text.replace(char, "\\" + char)
    return html.escape(text, quote=True)


# ─────────────────────────── bảng chỉ đọc ───────────────────────────
# gr.Dataframe của Gradio 6 tính lại mô hình hàng (TanStack table) qua chuỗi
# reactive cho từng ô. Đo trên Chrome: bảng audit 100 dòng × 7 cột chặn luồng
# chính ~10 giây mỗi lần cập nhật — đó là hiện tượng "bấm sang tab là treo".
# Mọi bảng ở đây chỉ để đọc, nên máy chủ dựng sẵn HTML (escape từng ô) và
# gr.Markdown chỉ việc hiển thị: không eval, không reactive theo ô.
CUSTOM_CSS += WORKBENCH_CSS
CIPHER_HEADERS = ("#", "Vai trò", "Ciphertext (base64, rút gọn)", "Nonce", "Phiên bản khóa", "Thời điểm")
SEARCH_HEADERS = ("Hội thoại", "Vai trò", "Nội dung", "Thời điểm")
DEVICE_HEADERS = (
    "", "Thiết bị / trình duyệt", "IP", "Đăng nhập lúc", "Hoạt động gần nhất",
    "Hết hạn nếu không hoạt động", "Giới hạn phiên tối đa",
)
PASSKEY_HEADERS = ("Tên", "Tạo lúc", "Dùng gần nhất", "Đồng bộ đám mây")
ACTIVITY_HEADERS = ("Thời gian", "Sự kiện", "Kết quả", "IP", "Thiết bị")
USER_HEADERS = ("Tên", "Vai trò", "Trạng thái", "2FA", "Ngày tạo")
AUDIT_HEADERS = ("#", "Sự kiện", "Kết quả", "Actor", "Đối tượng", "IP", "Thời điểm")
DETECTION_HEADERS = ("Luật", "MITRE", "Mức", "Mô tả", "Nguồn", "Đường dẫn", "Dấu hiệu")
ANOMALY_HEADERS = ("Mã", "Mức", "Đối tượng", "Số lần", "Diễn giải")
BLOCKLIST_HEADERS = ("Địa chỉ IP", "Còn bị chặn (giây)")


def _table_cell(value) -> str:
    """Một ô bảng: dữ liệu từ API/người dùng luôn là văn bản trơ."""
    text = "" if value is None else str(value)
    # Gộp xuống một dòng: dòng trống sẽ kết thúc khối HTML và phần còn lại bị
    # Markdown diễn giải.
    text = " ".join(text.split())
    for codepoint in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)):
        text = text.replace(chr(codepoint), f"\\u{codepoint:04X}")
    return html.escape(text, quote=True)


def _table_html(headers, rows) -> str:
    head = "".join(f"<th>{_table_cell(header)}</th>" for header in headers)
    if rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{_table_cell(cell)}</td>" for cell in row) + "</tr>"
            for row in rows
        )
    else:
        body = (
            f'<tr><td class="scap-table-empty" colspan="{len(headers)}">'
            "Chưa có dữ liệu.</td></tr>"
        )
    return (
        '<div class="scap-table-scroll"><table class="scap-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _data_table(headers, *, elem_id=None, elem_classes=()) -> gr.Markdown:
    """Bảng chỉ đọc; handler trả về _table_html(headers, rows) cho output này."""
    return gr.Markdown(
        _table_html(headers, []),
        elem_id=elem_id,
        elem_classes=["scap-table-block", *elem_classes],
        # Ô bảng là dữ liệu: không để KaTeX diễn giải chuỗi kiểu $$...$$.
        latex_delimiters=[],
    )


def _chat_history(token, session_id, session=None):
    if not session_id:
        return []
    if session is None:
        session = _api(token, "GET", f"/api/sessions/{session_id}")
    if session.get("security_mode") == "private_e2ee":
        return [
            {
                "role": "assistant",
                "content": (
                    "🔐 Private E2EE · Dùng client Olm độc lập. "
                    "`uv run --frozen --extra e2ee-client python -m scripts.demo_e2ee --check`."
                ),
            }
        ]
    rows = _api(token, "GET", f"/api/sessions/{session_id}/messages")
    return [{"role": row["role"], "content": _safe_chat_text(row["content"])} for row in rows]


def _devices_snapshot(token):
    rows = _api(token, "GET", "/api/auth/sessions")
    table = [
        [
            ("✔ thiết bị này" if row["is_current"] else ""),
            (row.get("user_agent") or "Không rõ")[:60],
            row.get("ip_address") or "—",
            _fmt(row["issued_at"]),
            _fmt(row["last_activity_at"]),
            _fmt(row["idle_expires_at"]),
            _fmt(row["absolute_expires_at"]),
        ]
        for row in rows
    ]
    table = _table_html(DEVICE_HEADERS, table)
    revoke = [
        (f"{(row.get('ip_address') or '—')} · {_fmt(row['issued_at'])}", row["id"])
        for row in rows
        if not row["is_current"]
    ]
    return table, revoke


AI_CONSENT_SCOPE = (
    "Sau khi bạn đồng ý, tin nhắn hiện tại và một phần lịch sử hội thoại "
    "(mặc định 16, tối đa 40 tin lịch sử theo cấu hình) được gửi tới AI bên ngoài. "
    "Nội dung đi qua lớp DLP để che hoặc chặn dữ liệu nhạy cảm trước khi gửi."
)
CONSENT_NOTICE = (
    "⚠️ **Tin nhắn chưa được gửi.** Bấm **Đồng ý và gửi** bên dưới "
    "để lưu lựa chọn cho tài khoản này. " + AI_CONSENT_SCOPE
)
ACTIVITY_PLACEHOLDER = "_Hoạt động bảo mật sẽ hiển thị sau khi đăng nhập._"
EMAIL_PLACEHOLDER = "_Thông tin email khôi phục sẽ hiển thị sau khi đăng nhập._"
_PASSKEY_ERRORS = {
    "NotAllowedError": "Đã hủy hoặc hết thời gian xác nhận passkey trên thiết bị.",
    "InvalidStateError": "Thiết bị này đã có passkey cho tài khoản.",
    "unsupported": "Trình duyệt hoặc thiết bị này không hỗ trợ passkey.",
    "not_prepared": "Yêu cầu passkey chưa sẵn sàng; hãy chuẩn bị lại.",
    "http_429": "Thử passkey quá nhiều lần; vui lòng đợi rồi thử lại.",
}


def _with_step_up(token, password, code, call, action):
    """Run a sensitive call, re-proving password/2FA once if the server asks."""
    try:
        return call()
    except gr.Error as err:
        required = getattr(err, "step_up_required", None)
        # Compatibility for local callers which synthesize Gradio errors;
        # every real HTTP error carries the explicit flag set in _api().
        if required is None:
            required = (
                getattr(err, "status_code", None) is None
                and "xác thực lại" in str(err).lower()
            )
        if not required:
            raise
        if not password:
            raise gr.Error(
                "Cần xác thực lại. Nhập mật khẩu hiện tại (và mã 2FA nếu đã bật) "
                f"rồi bấm “{action}” lần nữa."
            ) from err
        _api(
            token, "POST", "/api/auth/step-up",
            {"password": password, "code": (code or "").strip() or None},
        )
        return call()


def _passkey_payload(raw, mode):
    """Parse the browser result; it is untrusted and bounded."""
    if not isinstance(raw, str) or not raw or len(raw) > 20_000:
        return {"error": "not_prepared"}
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return {"error": "malformed"}
    if not isinstance(payload, dict) or payload.get("mode") != mode:
        return {"error": "malformed"}
    return payload


def _passkey_error_message(payload):
    error = str(payload.get("error", ""))
    if error in ("wrong_host", "SecurityError"):
        rp_id = str(payload.get("rp_id") or "localhost")
        if not all(ch.isalnum() or ch in ".-" for ch in rp_id):
            rp_id = "localhost"
        return (
            f"Passkey chỉ hoạt động khi mở ứng dụng bằng tên miền {rp_id} "
            "(ví dụ http://localhost:8000), không dùng địa chỉ IP."
        )
    return _PASSKEY_ERRORS.get(error, "Không hoàn tất được passkey. Vui lòng thử lại.")


def _passkeys_snapshot(token):
    rows = _api(token, "GET", "/api/auth/passkeys")
    table = [
        [
            row["name"],
            _fmt(row["created_at"]),
            _fmt(row.get("last_used_at")),
            "Có" if row.get("backed_up") else "Không",
        ]
        for row in rows
    ]
    table = _table_html(PASSKEY_HEADERS, table)
    choices = [(f"{row['name']} · {_fmt(row['created_at'])}", row["id"]) for row in rows]
    return table, choices


def _email_markdown(data):
    lines = []
    if data.get("email"):
        lines.append(
            f"**Email khôi phục:** {_safe_markdown_text(data['email'])} — đã xác minh "
            f"{_fmt(data.get('verified_at'))}."
        )
    else:
        lines.append(
            "**Chưa có email khôi phục.**"
        )
    if data.get("pending_email"):
        lines.append(
            f"⏳ Đang chờ xác minh: {_safe_markdown_text(data['pending_email'])} — nhập mã trong email."
        )
    if not data.get("delivery_available", True):
        lines.append("⚠️ Máy chủ chưa được cấu hình gửi email nên chưa thể thêm email.")
    return "\n\n".join(lines)
_SEVERITY_MARKS = {"critical": "🔴", "warning": "🟠", "info": "🟢"}


def _security_activity_snapshot(token):
    """Return (summary markdown, table markup, alerts) like an account security page."""
    data = _api(token, "GET", "/api/auth/security-activity", params={"limit": 30})
    rows = [
        [
            _fmt(event["created_at"]),
            f"{_SEVERITY_MARKS.get(event['severity'], '')} {event['title']}".strip(),
            event["outcome_label"],
            event.get("ip_address") or ("Quản trị viên" if event["by_administrator"] else "—"),
            event.get("device") or "—",
        ]
        for event in data["events"]
    ]
    previous = data.get("previous_sign_in")
    if previous:
        where = " · ".join(
            part for part in (
                f"IP `{previous['ip_address']}`" if previous.get("ip_address") else "",
                previous.get("device") or "",
            ) if part
        )
        lines = [f"**Lần đăng nhập trước:** {_fmt(previous['at'])}" + (f" · {where}" if where else "")]
    else:
        lines = ["**Chưa có lần đăng nhập nào trước phiên này.**"]
    alerts = []
    failed = data["failed_sign_ins_since_previous"]
    mfa_failed = data["mfa_failures_since_previous"]
    new_devices = data["new_device_sign_ins_since_previous"]
    if mfa_failed:
        alerts.append(
            f"{mfa_failed} lần có người nhập ĐÚNG mật khẩu nhưng sai mã 2FA. "
            "Nếu không phải bạn, hãy đổi mật khẩu ngay."
        )
    if failed > mfa_failed:
        alerts.append(
            f"{failed - mfa_failed} lần đăng nhập thất bại vào tài khoản kể từ lần đăng nhập trước."
        )
    if new_devices:
        alerts.append(
            f"{new_devices} lần đăng nhập từ thiết bị mới. Nếu không phải bạn, "
            "hãy thu hồi thiết bị đó và đổi mật khẩu."
        )
    lines.extend(f"⚠️ {alert}" for alert in alerts)
    if not alerts:
        lines.append("✅ Không có dấu hiệu bất thường kể từ lần đăng nhập trước.")
    return "\n\n".join(lines), _table_html(ACTIVITY_HEADERS, rows), alerts


# ─────────────────── mảnh HTML tĩnh của trang đăng nhập ───────────────────
# Nhận diện ngắn cho các luồng đăng nhập, đăng ký và khôi phục tài khoản.
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

APP_WORDMARK_HTML = (
    '<div class="app-wordmark">'
    '<span class="app-kicker">Security console</span>'
    '<span class="app-name">SCAP · Secure Workspace</span>'
    "</div>"
)

CHAT_WELCOME_HTML = (
    '<div class="chat-welcome">'
    '<span class="welcome-symbol" aria-hidden="true">✦</span>'
    '<h3>Bắt đầu một cuộc trò chuyện</h3>'
    '</div>'
)


def _static_html(markup: str, **kwargs) -> gr.Markdown:
    """Đổ một khối markup tĩnh mà không cần 'unsafe-eval'.

    Từ Gradio 6, gr.HTML luôn biên dịch giá trị qua ``new Function(...)`` (nội
    suy ``html_template`` và chạy ``js_on_load``). CSP của ứng dụng không cấp
    ``'unsafe-eval'`` cho script-src nên component đó chỉ hiện dòng "Error
    rendering HTML". gr.Markdown dựng DOM trực tiếp, không eval, nên hiển thị
    đúng markup mà chính sách vẫn giữ nguyên.

    ``sanitize_html=False`` chỉ dành cho markup do server tạo: hằng số, giá trị
    đã escape, hoặc marker base64 sau khi widget Google đã được kiểm tra. Không
    truyền HTML thô của người dùng/provider vào component này.
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
def build_ui(
    session_store: BrowserSessionStore | None = None,
    *,
    client_context_key: bytes | None = None,
    queue_max_size: int = 32,
    concurrency_limit: int = 4,
    retained_events: int = 128,
    result_ttl_seconds: int = 120,
    state_capacity: int = 256,
    gemini_web_search_enabled: bool = False,
) -> gr.Blocks:
    global _CLIENT_CONTEXT_KEY, _SESSION_STORE
    if any(type(value) is not int or value < 1 for value in (queue_max_size, concurrency_limit)):
        raise ValueError("Gradio queue and callback limits must be positive integers.")
    session_store = session_store if session_store is not None else BrowserSessionStore()
    _SESSION_STORE = session_store
    if client_context_key is not None:
        _CLIENT_CONTEXT_KEY = client_context_key
    if AVATARS is not None:
        # Serve the public avatar file in place. Copied into the cache it was swept
        # by delete_cache below a minute later, after which every chat reply showed
        # a broken image (403 "File not allowed"). Only this one file is exposed.
        gr.set_static_paths([str(_ASSISTANT_AVATAR)])
    # Gradio 6 applies theme and CSS when the UI is mounted/launched.  Supplying
    # them to Blocks itself is deprecated and emits a warning on every startup.
    with gr.Blocks(
        title="SCAP",
        analytics_enabled=False,
        # Defensive cleanup for any future file component. Current exports are
        # direct one-use URLs and never enter Gradio's cache.
        delete_cache=(60, 60),
        fill_width=True,
    ) as demo:
        st_token = gr.State("")
        st_exp = gr.State(0.0)
        st_mfa = gr.State("")
        resume_ticket = _static_html("", elem_id="session-bridge")
        login_ready = _static_html("", elem_id="login-ready")
        # Passkey bridge: the server publishes ceremony options here, the static
        # passkey.js script returns the public result through this hidden box.
        passkey_bridge = _static_html("", elem_id="passkey-bridge")
        tb_passkey_result = gr.Textbox(
            label="Kết quả passkey", elem_id="passkey-result", max_lines=1, container=False,
        )
        btn_passkey_login_done = gr.Button("Hoàn tất passkey", elem_id="btn-passkey-login-done")
        btn_passkey_register_done = gr.Button(
            "Lưu passkey", elem_id="btn-passkey-register-done"
        )
        st_passkey = gr.State({})
        btn_passkey_step_up_done = gr.Button("Hoàn tất xác thực lại", elem_id="btn-passkey-step-up-done")
        st_passkey_step_up = gr.State({})
        push_bridge = _static_html("", elem_id="security-push-bridge")
        tb_push_result = gr.Textbox(label="Kết quả đăng ký Push", elem_id="security-push-result", container=False)
        btn_push_done = gr.Button("Lưu đăng ký Push", elem_id="btn-security-push-done")
        st_push = gr.State({})
        st_phone_proof = gr.State({})
        # Đã hiện cảnh báo "sắp hết phiên" chưa — để chỉ nhắc một lần cho mỗi
        # phiên thay vì ở mọi lần tick trong suốt hai phút cuối.
        st_warned = gr.State(False)
        # Mốc hết hạn của phiên vừa hết hạn. tick() chỉ đổi giá trị này; sự kiện
        # change của nó mới dọn toàn bộ giao diện, nên tick định kỳ luôn nhẹ.
        st_expired = gr.State(0.0)

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
                                max_lines=1,
                                autofocus=True,
                                elem_id="li-user",
                                html_attributes=gr.InputHTMLAttributes(
                                    autocomplete="username", autocapitalize="none",
                                    autocorrect="off", spellcheck=False, enterkeyhint="go",
                                ),
                            )
                            li_pass = gr.Textbox(
                                label="Mật khẩu",
                                type="password",
                                max_length=128,
                                placeholder="Nhập mật khẩu",
                                elem_id="li-pass",
                                html_attributes=gr.InputHTMLAttributes(
                                    autocomplete="current-password", enterkeyhint="go",
                                ),
                            )
                            with gr.Row(elem_id="auth-util"):
                                chk_showpw = gr.Checkbox(
                                    label="Hiện mật khẩu",
                                    value=False,
                                    container=False,
                                    elem_id="chk-showpw",
                                )
                            gr.Checkbox(
                                label="Lưu tài khoản và mật khẩu",
                                value=True,
                                interactive=True,
                                elem_id="chk-remember-login",
                            )
                            btn_login = gr.Button(
                                "Đăng nhập", variant="primary", elem_id="btn-login",
                            )
                            # Handled by passkey.js inside the click itself, as
                            # browsers require for the passkey prompt.
                            gr.Button(
                                "🔑 Đăng nhập bằng passkey",
                                elem_id="btn-passkey-login",
                                elem_classes="auth-alt",
                            )
                            # Nút viền: vừa là lối sang tab tạo tài khoản, vừa là
                            # thứ thay cho thanh tab đã ẩn.
                            btn_goto_register = gr.Button(
                                "Tạo tài khoản", elem_classes="auth-alt"
                            )
                            btn_goto_reset = gr.Button(
                                "Quên mật khẩu?", elem_classes="auth-alt"
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
                                max_lines=1,
                                info="Cho phép chữ, số và các ký tự . _ -",
                                elem_id="re-user",
                                html_attributes=gr.InputHTMLAttributes(
                                    autocomplete="username", autocapitalize="none",
                                    autocorrect="off", spellcheck=False,
                                ),
                            )
                            re_pass = gr.Textbox(
                                label="Mật khẩu",
                                type="password",
                                max_length=128,
                                placeholder=f"Tối thiểu {PASSWORD_MIN} ký tự",
                                elem_id="re-pass",
                                html_attributes=gr.InputHTMLAttributes(autocomplete="new-password"),
                            )
                            html_pw_meter = _static_html(_pw_meter_html(""), elem_id="pw-meter")
                            btn_register = gr.Button("Tạo tài khoản", variant="primary")
                            btn_goto_login = gr.Button(
                                "Quay lại đăng nhập", elem_classes="auth-alt"
                            )

                            re_pass.change(_pw_meter_html, re_pass, html_pw_meter)
                        with gr.Tab("Quên mật khẩu", id="tab_reset"):
                            tb_reset_identifier = gr.Textbox(
                                label="Tên đăng nhập hoặc email khôi phục",
                                max_length=254,
                                max_lines=1,
                                elem_id="reset-identifier",
                            )
                            btn_reset_send = gr.Button("Gửi mã qua email", variant="primary")
                            tb_reset_code = gr.Textbox(
                                label="Mã trong email", max_length=32, max_lines=1,
                                placeholder="xxxxx-xxxxx",
                            )
                            tb_reset_new = gr.Textbox(
                                label="Mật khẩu mới",
                                type="password",
                                max_length=128,
                                placeholder=f"Tối thiểu {PASSWORD_MIN} ký tự",
                                html_attributes=gr.InputHTMLAttributes(autocomplete="new-password"),
                            )
                            btn_reset_confirm = gr.Button("Đặt lại mật khẩu", variant="primary")
                            btn_reset_back = gr.Button(
                                "Quay lại đăng nhập", elem_classes="auth-alt"
                            )

                    # Thanh tab đã ẩn bằng CSS nên hai nút này là đường duy nhất
                    # đi lại giữa hai biểu mẫu.
                    btn_goto_register.click(
                        lambda: gr.Tabs(selected="tab_register"), None, auth_tabs
                    )
                    btn_goto_login.click(lambda: gr.Tabs(selected="tab_login"), None, auth_tabs)
                    btn_goto_reset.click(lambda: gr.Tabs(selected="tab_reset"), None, auth_tabs)
                    btn_reset_back.click(lambda: gr.Tabs(selected="tab_login"), None, auth_tabs)

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
                        btn_mfa_cancel = gr.Button("Quay lại", elem_id="btn-mfa-cancel")

        # ============ ỨNG DỤNG ============
        with gr.Column(visible=False, elem_id="app-sec") as app_sec:
            with gr.Row(elem_id="topbar"):
                _static_html(APP_WORDMARK_HTML, elem_classes="topbar-brand")
                md_banner = gr.Markdown("", elem_classes=["md", "topbar-user"])
                # Markup do _countdown_markup() dựng từ số nguyên; giữ nguyên
                # thuộc tính data-* cho bộ đếm phía trình duyệt.
                md_countdown = gr.Markdown(
                    "", sanitize_html=False, elem_classes=["md", "topbar-timer"]
                )
                btn_extend = gr.Button(
                    "Gia hạn phiên", size="sm", elem_classes=["topbar-action", "topbar-extend"]
                )
                btn_logout = gr.Button(
                    "Đăng xuất", size="sm", elem_id="btn-logout",
                    elem_classes=["topbar-action", "topbar-logout"]
                )
            timer = gr.Timer(SESSION_TICK_SECONDS, active=False)

            with gr.Tabs(elem_id="workspace-tabs"):
                # ---------- TRÒ CHUYỆN ----------
                with gr.Tab("Trò chuyện"):
                    with gr.Row(elem_id="chat-row"):
                        with gr.Column(
                            scale=1, min_width=300, elem_id="chat-sidebar", elem_classes="section-card"
                        ):
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
                            st_session_page = gr.State({})
                            md_session_page = gr.Markdown("", elem_id="sessions-page-status")
                            btn_sessions_more = gr.Button(
                                "Tải thêm hội thoại", visible=False, size="sm",
                            )
                            # Chế độ của hội thoại đang chọn chỉ hiển thị, không
                            # chỉnh được; dropdown bên dưới chỉ dành cho hội thoại mới.
                            md_session_policy = gr.Markdown("", elem_id="session-policy")
                            st_delete_target = gr.State("")
                            btn_delete = gr.Button(
                                "Xóa vĩnh viễn", variant="stop", size="sm",
                                elem_id="btn-session-delete",
                            )
                            with gr.Column(visible=False, elem_id="session-delete-confirm") as grp_delete_confirm:
                                md_delete_confirm = gr.Markdown("", elem_id="session-delete-notice")
                                with gr.Column(visible=False, elem_id="session-delete-auth") as grp_delete_auth:
                                    tb_delete_password = gr.Textbox(
                                        label="Mật khẩu để xác thực lại", type="password",
                                        max_length=128, elem_id="session-delete-password",
                                    )
                                    tb_delete_code = gr.Textbox(
                                        label="Mã 2FA (nếu đã bật)", max_length=32,
                                        elem_id="session-delete-code",
                                    )
                                with gr.Row():
                                    btn_delete_confirm = gr.Button(
                                        "Xác nhận xóa vĩnh viễn", variant="stop", size="sm",
                                        min_width=120, elem_id="btn-session-delete-confirm",
                                    )
                                    btn_delete_cancel = gr.Button(
                                        "Hủy xóa", size="sm", min_width=85,
                                        elem_id="btn-session-delete-cancel",
                                    )
                            with gr.Accordion("Thiết lập hội thoại mới", open=False):
                                tb_new_title = gr.Textbox(
                                    label="Tiêu đề (không bắt buộc)",
                                    max_lines=1,
                                    placeholder="Ví dụ: Ôn tập bảo mật ứng dụng",
                                )
                                dd_new_security = _pick_dropdown(
                                    choices=SECURITY_MODE_CHOICES,
                                    value="secure",
                                    label="Chế độ bảo mật (cho hội thoại mới)",
                                )
                                dd_new_class = _pick_dropdown(
                                    choices=DATA_CLASS_CHOICES,
                                    value="internal",
                                    label="Phân loại dữ liệu (cho hội thoại mới)",
                                )
                            with gr.Row():
                                btn_create = gr.Button(
                                    "+ Hội thoại mới", variant="primary", size="sm", scale=3
                                )
                                btn_refresh = gr.Button("Làm mới", size="sm", scale=1, min_width=85)
                            with gr.Accordion("Quản lý hội thoại đang chọn", open=False):
                                tb_rename = gr.Textbox(label="Đổi tên", max_lines=1)
                                btn_rename = gr.Button("Lưu tên mới", size="sm")
                                tb_export_password = gr.Textbox(
                                    label="Mật khẩu (chỉ nhập khi hệ thống yêu cầu xác thực lại)",
                                    type="password",
                                    max_length=128,
                                )
                                tb_export_code = gr.Textbox(
                                    label="Mã 2FA (nếu tài khoản đã bật)",
                                    max_length=32,
                                )
                                with gr.Row():
                                    btn_export = gr.Button("Xuất JSON", size="sm")
                            # A plain same-origin link: the browser redeems the one-time
                            # ticket itself. gr.DownloadButton fetched the URL server-side
                            # into Gradio's cache, spending the ticket and storing the
                            # plaintext export (or failing Gradio's SSRF check outright).
                            file_export = gr.Markdown(
                                "", visible=False, sanitize_html=False, elem_id="export-link"
                            )
                        with gr.Column(scale=3, min_width=360, elem_id="chat-main"):
                            chatbot = gr.Chatbot(
                                label="Nội dung",
                                # The floating label badge covered the first
                                # visible message whenever the history scrolled.
                                show_label=False,
                                height=CHAT_HISTORY_HEIGHT,
                                elem_id="chat-history",
                                placeholder=CHAT_WELCOME_HTML,
                                avatar_images=AVATARS,
                                buttons=["copy", "copy_all"],
                                # Formatting is generated by the server's safe
                                # Markdown parser; raw HTML/images stay inert.
                                # Formulas arrive escaped in \( \) / \[ \].
                                render_markdown=True,
                                sanitize_html=True,
                                allow_tags=False,
                                allow_file_downloads=False,
                                latex_delimiters=CHAT_LATEX_DELIMITERS,
                            )
                            with gr.Accordion("Tìm trong hội thoại này", open=False):
                                with gr.Row():
                                    tb_session_query = gr.Textbox(
                                        label="Từ khóa trong hội thoại đang mở", max_lines=1,
                                        max_length=120, scale=4, elem_id="session-search-query",
                                    )
                                    btn_session_search = gr.Button("Tìm trong hội thoại", scale=1)
                                    btn_session_search_clear = gr.Button("Xóa kết quả tìm", scale=1)
                                md_session_search = gr.Markdown("", visible=False)
                                st_session_search_page = gr.State({})
                                st_session_view = gr.State(None)
                                st_session_search_generation = gr.State(0)
                                df_session_search = _data_table(
                                    SEARCH_HEADERS, elem_id="session-search-table",
                                )
                                btn_session_search_more = gr.Button(
                                    "Tải thêm kết quả trong hội thoại", visible=False, size="sm",
                                )
                            with gr.Row(elem_id="chat-composer"):
                                tb_msg = gr.Textbox(
                                    label="Tin nhắn",
                                    placeholder="Nhập tin nhắn — Enter để gửi…",
                                    max_lines=3,
                                    max_length=4000,
                                    scale=6,
                                )
                                btn_send = gr.Button(
                                    "Gửi", variant="primary", scale=1, min_width=110
                                )
                            # Hidden while the server has web search off so the
                            # chat column is not padded by a control nobody can use.
                            cb_web_search = gr.Checkbox(
                                label="Tra cứu Internet và dẫn nguồn",
                                value=False,
                                interactive=gemini_web_search_enabled,
                                visible=gemini_web_search_enabled,
                                elem_id="chat-web-search",
                                info="Public · Gửi truy vấn tới Google · Có thể tính phí",
                            )
                            # Thông báo cố định dưới ô nhập, dùng cho consent và DLP.
                            # Không dùng toast vì toast che nội dung hội thoại trên màn hình nhỏ.
                            md_chat_notice = gr.Markdown(
                                "", visible=False, elem_id="chat-notice"
                            )
                            # Chỉ hiện sau khi máy chủ từ chối vì chưa có consent.
                            # Một cú bấm riêng, ghi rõ tác động, tránh coi thao tác Gửi
                            # ban đầu là sự đồng ý chia sẻ dữ liệu.
                            btn_consent_send = gr.Button(
                                "Đồng ý và gửi", variant="primary", size="sm", visible=False
                            )
                            md_search_answer = gr.Markdown(
                                "", visible=False, sanitize_html=True,
                                latex_delimiters=CHAT_LATEX_DELIMITERS,
                                elem_id="chat-search-answer",
                            )
                            md_search_suggestions = _static_html(
                                "", visible=False, elem_id="chat-search-suggestions",
                            )

                # ---------- DỮ LIỆU MÃ HÓA ----------
                with gr.Tab("Dữ liệu mã hóa"):
                    _static_html(
                        '<div class="tab-intro"><h3>Dữ liệu mã hóa</h3></div>'
                    )
                    with gr.Row():
                        dd_cipher = _pick_dropdown(
                            label="Hội thoại", choices=[], interactive=True, scale=3
                        )
                        btn_cipher = gr.Button("Tải bản mã", scale=1)
                    df_cipher = _data_table(
                        CIPHER_HEADERS, elem_id="cipher-table", elem_classes=["mono-df"]
                    )
                    crypto_info = gr.JSON(label="Thông số mã hóa hội thoại · không chứa khóa", value={})
                    st_cipher_view = gr.State(None)
                    st_cipher_generation = gr.State(0)
                    _static_html(WORKBENCH_HTML, elem_id="crypto-workbench")

                # ---------- TÌM KIẾM ----------
                with gr.Tab("Tìm kiếm"):
                    _static_html(
                        '<div class="tab-intro"><h3>Tìm lại nội dung</h3></div>'
                    )
                    with gr.Row():
                        tb_gq = gr.Textbox(
                            label="Từ khóa (trên mọi hội thoại của bạn)", max_lines=1, scale=4
                        )
                        btn_gsearch = gr.Button("Tìm kiếm", variant="primary", scale=1)
                    df_gsearch = _data_table(SEARCH_HEADERS, elem_id="global-search-table")
                    st_search_page = gr.State({})
                    md_search_page = gr.Markdown("", elem_id="global-search-page-status")
                    btn_search_more = gr.Button("Tải thêm kết quả", visible=False, size="sm")

                # ---------- TÀI KHOẢN ----------
                with gr.Tab("Tài khoản"):
                    _static_html(
                        '<div class="tab-intro"><h3>Bảo vệ tài khoản của bạn</h3></div>'
                    )
                    md_profile = gr.Markdown("")
                    chk_consent = gr.Checkbox(
                        label="Cho phép gửi tin nhắn và lịch sử tới AI bên ngoài",
                        info=AI_CONSENT_SCOPE,
                    )
                    with gr.Accordion("Đổi mật khẩu", open=False):
                        tb_pw_cur = gr.Textbox(
                            label="Mật khẩu hiện tại", type="password", max_length=128
                        )
                        tb_pw_new = gr.Textbox(
                            label="Mật khẩu mới",
                            type="password",
                            max_length=128,
                            info=f"Tối thiểu {PASSWORD_MIN} ký tự · Cần đăng nhập lại sau khi đổi",
                        )
                        btn_pw = gr.Button("Cập nhật mật khẩu", variant="primary", size="sm")
                    with gr.Accordion("Xác thực hai lớp (TOTP)", open=True):
                        md_mfa_state = gr.Markdown("")
                        with gr.Group(visible=False) as grp_mfa_enroll:
                            btn_enroll = gr.Button("Bắt đầu thiết lập 2FA", size="sm")
                            with gr.Group(visible=False) as grp_mfa_setup:
                                with gr.Row():
                                    # QR được nhúng trực tiếp vào HTML để Gradio
                                    # không ghi PNG tạm ra máy chạy giao diện.
                                    # Only internally generated PNG-base64
                                    # markup reaches this component; Markdown
                                    # renders it without Gradio HTML's eval.
                                    qr_html = gr.Markdown(
                                        label="Quét bằng ứng dụng xác thực",
                                        show_label=True,
                                        sanitize_html=False,
                                        buttons=[],
                                        container=True,
                                        padding=False,
                                        scale=1,
                                        elem_classes=["scap-totp-qr-panel"],
                                    )
                                    with gr.Column(scale=2):
                                        # Camera iPhone mở QR otpauth:// trong app
                                        # Mật khẩu, nơi mã phải gắn vào một mục đã lưu.
                                        gr.Markdown(
                                            "Quét QR trong ứng dụng xác thực hoặc nhập khóa thủ công."
                                        )
                                        tb_secret = gr.Textbox(
                                            label="Khóa thủ công",
                                            interactive=False,
                                        )
                                        tb_activate = gr.Textbox(label="Mã 6 số", max_length=8)
                                        btn_activate = gr.Button(
                                            "Kích hoạt", variant="primary", size="sm"
                                        )
                        with gr.Group(visible=False) as grp_mfa_manage:
                            with gr.Row():
                                tb_dis_pw = gr.Textbox(
                                    label="Mật khẩu", type="password", max_length=128
                                )
                                tb_dis_code = gr.Textbox(label="Mã TOTP / khôi phục", max_length=32)
                            btn_disable = gr.Button("Tắt 2FA", variant="stop", size="sm")
                    with gr.Accordion("Thiết bị đang đăng nhập", open=True):
                        df_devices = _data_table(DEVICE_HEADERS, elem_id="devices-table")
                        with gr.Row():
                            dd_revoke = _pick_dropdown(label="Phiên cần thu hồi", choices=[], scale=3)
                            btn_revoke = gr.Button("Thu hồi", size="sm", scale=1)
                            btn_dev_refresh = gr.Button("Làm mới", size="sm", scale=1)
                        btn_logout_all = gr.Button(
                            "Đăng xuất mọi thiết bị", variant="stop", size="sm",
                            elem_id="btn-logout-all",
                        )
                    with gr.Accordion("Email khôi phục & passkey", open=True):
                        with gr.Row():
                            tb_acct_pw = gr.Textbox(
                                label="Mật khẩu hiện tại (khi cần xác thực lại)",
                                type="password", max_length=128,
                            )
                            tb_acct_code = gr.Textbox(label="Mã 2FA (nếu đã bật)", max_length=32)
                        btn_passkey_step_up_prepare = gr.Button("Xác thực lại bằng passkey", size="sm")
                        md_passkey_step_up_hint = gr.Markdown("", visible=False)
                        btn_passkey_step_up = gr.Button(
                            "Xác nhận passkey trên thiết bị", elem_id="btn-passkey-step-up",
                            visible=False, size="sm", variant="primary",
                        )
                        md_email_state = gr.Markdown(EMAIL_PLACEHOLDER)
                        with gr.Row():
                            tb_email_new = gr.Textbox(
                                label="Email khôi phục mới", max_length=254, max_lines=1, scale=3
                            )
                            btn_email_send = gr.Button("Gửi mã xác minh", size="sm", scale=1)
                        with gr.Row():
                            tb_email_code = gr.Textbox(
                                label="Mã xác minh trong email", max_length=32, max_lines=1,
                                scale=3,
                            )
                            btn_email_verify = gr.Button("Xác minh email", size="sm", scale=1)
                        btn_email_remove = gr.Button(
                            "Gỡ email khôi phục", size="sm", variant="stop"
                        )
                        df_passkeys = _data_table(PASSKEY_HEADERS, elem_id="passkeys-table")
                        with gr.Row():
                            tb_passkey_name = gr.Textbox(
                                label="Tên passkey (tuỳ chọn)", max_length=64, max_lines=1,
                                scale=3,
                            )
                            btn_passkey_add = gr.Button("Thêm passkey", size="sm", scale=1)
                        md_passkey_hint = gr.Markdown("", visible=False)
                        btn_passkey_create = gr.Button(
                            "Xác nhận trên thiết bị này", variant="primary", visible=False,
                            elem_id="btn-passkey-create",
                        )
                        with gr.Row():
                            dd_passkey_remove = _pick_dropdown(
                                label="Passkey cần xóa", choices=[], scale=3
                            )
                            btn_passkey_remove = gr.Button(
                                "Xóa passkey", size="sm", variant="stop", scale=1
                            )
                    with gr.Accordion("Thông báo bảo mật qua Push / SMS", open=False):
                        gr.Markdown(
                            "SMS có thể phát sinh phí nhà cung cấp."
                        )
                        md_notifications = gr.Markdown("")
                        btn_notifications_refresh = gr.Button("Làm mới kênh thông báo", size="sm")
                        btn_push_prepare = gr.Button("Chuẩn bị bật Push trên trình duyệt này", size="sm")
                        btn_push_local_remove = gr.Button("Gỡ đăng ký Push trên trình duyệt này", size="sm")
                        btn_push_enable = gr.Button("Cho phép và bật thông báo Push", visible=False,
                                                    elem_id="btn-security-push-enable", size="sm")
                        btn_push_disable = gr.Button("Tắt Push của tài khoản trên mọi trình duyệt", size="sm")
                        with gr.Row():
                            tb_alert_phone = gr.Textbox(label="Số điện thoại quốc tế (ví dụ +84…)", max_length=16)
                            btn_phone_request = gr.Button("Gửi mã xác minh số điện thoại", size="sm")
                        with gr.Row():
                            tb_alert_code = gr.Textbox(label="Mã 8 số nhận qua SMS", max_length=8)
                            btn_phone_verify = gr.Button("Xác minh và bật SMS", size="sm")
                        btn_phone_remove = gr.Button("Tắt SMS và gỡ số điện thoại", size="sm")
                    with gr.Accordion("Hoạt động bảo mật gần đây", open=True):
                        md_activity = gr.Markdown(ACTIVITY_PLACEHOLDER)
                        df_activity = _data_table(ACTIVITY_HEADERS, elem_id="activity-table")
                        btn_activity_refresh = gr.Button("Làm mới hoạt động", size="sm")
                        md_geoip_status = gr.Markdown("")
                        btn_geoip_status = gr.Button("Kiểm tra đánh giá vị trí đăng nhập", size="sm")

                # ---------- QUẢN TRỊ ----------
                with gr.Tab("Quản trị", visible=False) as adm_tab:
                    gr.Markdown(
                        "<h3>Trung tâm vận hành &amp; bảo mật</h3>",
                        sanitize_html=False,
                        elem_classes="dashboard-hero",
                    )
                    with gr.Row(equal_height=True, elem_classes="metric-grid"):
                        md_metric_users = gr.Markdown("**Người dùng**\n\n## —\n\nĐang hoạt động —", elem_classes=["metric-card", "metric-card-green"])
                        md_metric_sessions = gr.Markdown("**Hội thoại**\n\n## —\n\nTin nhắn đã mã hóa —", elem_classes=["metric-card", "metric-card-blue"])
                        md_metric_login = gr.Markdown("**Đăng nhập lỗi**\n\n## —\n\nTrong 60 phút", elem_classes=["metric-card", "metric-card-amber"])
                        md_metric_denials = gr.Markdown("**Từ chối quyền**\n\n## —\n\nTrong 60 phút", elem_classes=["metric-card", "metric-card-red"])
                    btn_adm_refresh = gr.Button("Làm mới dashboard", variant="primary", size="sm")
                    md_stats = gr.Markdown("*Đang chờ nạp dữ liệu vận hành.*", elem_classes="dashboard-panel")
                    md_alerts = gr.Markdown("*Đang chờ nạp cảnh báo.*", elem_classes="dashboard-panel")
                    gr.Markdown("#### Danh mục tài khoản", elem_classes="dashboard-section-title")
                    df_users = _data_table(
                        USER_HEADERS, elem_id="users-table", elem_classes=["dashboard-table"]
                    )
                    st_users_page = gr.State({})
                    md_users_page = gr.Markdown("", elem_id="users-page-status")
                    btn_users_more = gr.Button("Tải thêm tài khoản", visible=False, size="sm")
                    with gr.Row():
                        tb_admin_pw = gr.Textbox(
                            label="Mật khẩu quản trị viên (khi cần xác thực lại)",
                            type="password", max_length=128, elem_id="admin-step-up-password",
                        )
                        tb_admin_code = gr.Textbox(
                            label="Mã 2FA quản trị viên", type="password", max_length=32,
                            elem_id="admin-step-up-code",
                        )
                    with gr.Row():
                        dd_user_pick = _pick_dropdown(label="Người dùng", choices=[], scale=2)
                        dd_role_new = _pick_dropdown(
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
                    st_delete_user_target = gr.State({})
                    with gr.Column(visible=False, elem_id="account-delete-confirm") as grp_user_delete:
                        md_user_delete = gr.Markdown("", elem_id="account-delete-notice")
                        tb_user_delete_name = gr.Textbox(
                            label="Nhập đúng tên đăng nhập để xác nhận xóa", max_length=32,
                            elem_id="account-delete-name",
                        )
                        with gr.Row():
                            btn_user_delete_confirm = gr.Button(
                                "Xác nhận xóa tài khoản vĩnh viễn", variant="stop", size="sm",
                            )
                            btn_user_delete_cancel = gr.Button("Hủy xóa tài khoản", size="sm")
                    with gr.Accordion("Tạo tài khoản mới", open=False):
                        with gr.Row():
                            tb_cu_name = gr.Textbox(label="Tên đăng nhập", max_length=32)
                            tb_cu_pw = gr.Textbox(label="Mật khẩu", type="password", max_length=128)
                            dd_cu_role = _pick_dropdown(
                                label="Vai trò",
                                choices=["user", "moderator", "admin"],
                                value="user",
                            )
                        btn_cu = gr.Button("Tạo", variant="primary", size="sm")

                # ---------- NHẬT KÝ ----------
                with gr.Tab("Nhật ký kiểm toán", visible=False) as mod_tab:
                    _static_html(
                        '<div class="tab-intro"><h3>Nhật ký kiểm toán</h3></div>'
                    )
                    with gr.Row():
                        sl_audit = gr.Slider(10, 500, value=100, step=10, label="Số dòng", scale=3)
                        btn_audit = gr.Button("Tải nhật ký", size="sm", scale=1)
                    # Giữ nguyên audit ID/IP trên một dòng; bảng tự cuộn ngang khi
                    # màn hình hẹp thay vì bẻ đôi định danh khiến dữ liệu khó đọc.
                    df_audit = _data_table(
                        AUDIT_HEADERS, elem_id="audit-table",
                        elem_classes=["mono-df", "scap-table-nowrap"],
                    )

                # ---------- TRUNG TÂM BẢO MẬT ----------
                # Màn hình giám sát cho moderator/admin: xác minh chuỗi băm audit
                # (Bài 1 §Accounting) và theo dõi IDS/IPS (Bài 7 §7.3).
                with gr.Tab("Bảo mật", visible=False) as sec_tab:
                    gr.Markdown(
                        "<h3>Trung tâm giám sát an ninh</h3>",
                        sanitize_html=False,
                        elem_classes="dashboard-hero",
                    )
                    with gr.Row(equal_height=True, elem_classes="metric-grid"):
                        md_sec_detections = gr.Markdown("**Dấu hiệu IDS**\n\n## —\n\nTối đa 100 dấu hiệu gần nhất", elem_classes=["metric-card", "metric-card-blue"])
                        md_sec_anomalies = gr.Markdown("**Bất thường**\n\n## —\n\nTheo audit log", elem_classes=["metric-card", "metric-card-amber"])
                        md_sec_blocks = gr.Markdown("**Nguồn bị chặn**\n\n## —\n\nĐang hiệu lực", elem_classes=["metric-card", "metric-card-red"])
                    btn_sec_all = gr.Button("Làm mới toàn bộ", variant="primary", size="sm")

                    with gr.Accordion("1 · Toàn vẹn nhật ký kiểm toán (hash chain)", open=True):
                        btn_sec_verify = gr.Button("Xác minh chuỗi", variant="primary", size="sm")
                        md_sec_verdict = gr.Markdown(
                            "*Chưa xác minh trong phiên làm việc này.*",
                            elem_id="sec-verdict",
                        )

                    with gr.Accordion("2 · IDS — mẫu tấn công đã phát hiện", open=True):
                        df_sec_det = _data_table(
                            DETECTION_HEADERS, elem_id="sec-detections-table",
                            elem_classes=["mono-df", "dashboard-table"],
                        )

                    with gr.Accordion("3 · IDS — hành vi bất thường", open=True):
                        with gr.Row():
                            sl_sec_win = gr.Slider(
                                5, 720, value=60, step=5, label="Cửa sổ thời gian (phút)", scale=3
                            )
                            btn_sec_anom = gr.Button("Phân tích", size="sm", scale=1)
                        df_sec_anom = _data_table(
                            ANOMALY_HEADERS, elem_id="sec-anomalies-table", elem_classes=["mono-df"]
                        )

                    with gr.Accordion("4 · Purple Team — kiểm chứng luật phát hiện", open=False):
                        btn_sec_verify_ids = gr.Button(
                            "Chạy kiểm chứng Hit/Miss", variant="primary", size="sm"
                        )
                        md_sec_ids_verdict = gr.Markdown(
                            "*Chưa kiểm chứng trong phiên làm việc này.*", elem_id="sec-ids-verdict"
                        )

                    with gr.Accordion("5 · IPS — nguồn đang bị chặn", open=True):
                        df_sec_block = _data_table(
                            BLOCKLIST_HEADERS, elem_id="sec-blocklist-table", elem_classes=["mono-df"]
                        )
                        with gr.Row():
                            tb_sec_ip = gr.Textbox(label="IP cần gỡ chặn", max_lines=1, scale=3)
                            btn_sec_unblock = gr.Button("Gỡ chặn", size="sm", scale=1)
                        with gr.Row():
                            tb_sec_pw = gr.Textbox(
                                label="Mật khẩu hiện tại (khi cần xác thực lại)",
                                type="password", max_length=128, elem_id="security-step-up-password",
                            )
                            tb_sec_code = gr.Textbox(
                                label="Mã 2FA (nếu đã bật)", type="password", max_length=32,
                                elem_id="security-step-up-code",
                            )

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
            st_session_page,
            md_session_page,
            btn_sessions_more,
        ]
        # Chỉ ẩn app_sec không xóa dữ liệu khỏi trình duyệt. Mọi dữ liệu theo
        # tài khoản, bản nháp, thông tin xác thực và URL tải xuống phải được
        # xóa khi đăng xuất/hết hạn/đổi mật khẩu để lần đăng nhập tiếp theo
        # không nhìn thấy kết quả còn sót lại của tài khoản trước.
        # Ghép component với giá trị reset ngay tại đây để không lệch vị trí.
        EXTRA_RESET = [
            (resume_ticket, SESSION_CLEAR_MARKUP),
            (li_user, ""),
            (re_user, ""),
            (re_pass, ""),
            (chk_showpw, False),
            (auth_tabs, gr.update(selected="tab_login")),
            (html_pw_meter, _pw_meter_html("")),
            (tb_new_title, ""),
            (dd_new_security, "secure"),
            (dd_new_class, "internal"),
            (md_session_policy, ""),
            (tb_rename, ""),
            (tb_export_password, ""),
            (tb_export_code, ""),
            (st_delete_target, ""),
            (grp_delete_confirm, gr.update(visible=False)),
            (md_delete_confirm, ""),
            (grp_delete_auth, gr.update(visible=False)),
            (tb_delete_password, ""),
            (tb_delete_code, ""),
            (st_delete_user_target, {}),
            (grp_user_delete, gr.update(visible=False)),
            (md_user_delete, ""),
            (tb_user_delete_name, ""),
            (st_users_page, {}),
            (md_users_page, ""),
            (btn_users_more, gr.update(visible=False)),
            (st_search_page, {}),
            (md_search_page, ""),
            (btn_search_more, gr.update(visible=False)),
            (tb_session_query, ""),
            (md_session_search, gr.update(value="", visible=False)),
            (st_session_search_page, {}),
            (st_session_view, None),
            (st_session_search_generation, 0),
            (df_session_search, _table_html(SEARCH_HEADERS, [])),
            (btn_session_search_more, gr.update(visible=False)),
            (file_export, gr.update(value="", visible=False)),
            (tb_msg, ""),
            (cb_web_search, gr.update(value=False)),
            (md_chat_notice, gr.update(value="", visible=False)),
            (btn_consent_send, gr.update(visible=False)),
            (md_search_answer, gr.update(value="", visible=False)),
            (md_search_suggestions, gr.update(value="", visible=False)),
            (df_cipher, _table_html(CIPHER_HEADERS, [])),
            (crypto_info, {}),
            (st_cipher_view, None),
            (st_cipher_generation, 0),
            (tb_gq, ""),
            (df_gsearch, _table_html(SEARCH_HEADERS, [])),
            (tb_pw_cur, ""),
            (tb_pw_new, ""),
            (grp_mfa_setup, gr.update(visible=False)),
            (qr_html, gr.update(value="", visible=False)),
            (tb_secret, ""),
            (tb_activate, ""),
            (tb_dis_pw, ""),
            (tb_dis_code, ""),
            (md_activity, ACTIVITY_PLACEHOLDER),
            (df_activity, _table_html(ACTIVITY_HEADERS, [])),
            (passkey_bridge, ""),
            (tb_passkey_result, ""),
            (st_passkey, {}),
            (st_passkey_step_up, {}),
            (md_passkey_step_up_hint, gr.update(value="", visible=False)),
            (btn_passkey_step_up, gr.update(visible=False)),
            (md_geoip_status, ""),
            (push_bridge, ""), (tb_push_result, ""), (st_push, {}), (st_phone_proof, {}),
            (btn_push_enable, gr.update(visible=False)),
            (md_notifications, ""),
            (tb_alert_phone, ""), (tb_alert_code, ""),
            (md_passkey_hint, gr.update(value="", visible=False)),
            (btn_passkey_create, gr.update(visible=False)),
            (df_passkeys, _table_html(PASSKEY_HEADERS, [])),
            (dd_passkey_remove, gr.update(choices=[], value=None)),
            (tb_passkey_name, ""),
            (tb_acct_pw, ""),
            (tb_acct_code, ""),
            (md_email_state, EMAIL_PLACEHOLDER),
            (tb_email_new, ""),
            (tb_email_code, ""),
            (tb_reset_identifier, ""),
            (tb_reset_code, ""),
            (tb_reset_new, ""),
            (md_metric_users, md_metric_users.value),
            (md_metric_sessions, md_metric_sessions.value),
            (md_metric_login, md_metric_login.value),
            (md_metric_denials, md_metric_denials.value),
            (md_stats, md_stats.value),
            (md_alerts, md_alerts.value),
            (df_users, _table_html(USER_HEADERS, [])),
            (dd_user_pick, gr.update(choices=[], value=None)),
            (dd_role_new, "user"),
            (tb_cu_name, ""),
            (tb_cu_pw, ""),
            (tb_admin_pw, ""),
            (tb_admin_code, ""),
            (dd_cu_role, "user"),
            (sl_audit, 100),
            (df_audit, _table_html(AUDIT_HEADERS, [])),
            (md_sec_detections, md_sec_detections.value),
            (md_sec_anomalies, md_sec_anomalies.value),
            (md_sec_blocks, md_sec_blocks.value),
            (md_sec_verdict, md_sec_verdict.value),
            (df_sec_det, _table_html(DETECTION_HEADERS, [])),
            (sl_sec_win, 60),
            (df_sec_anom, _table_html(ANOMALY_HEADERS, [])),
            (md_sec_ids_verdict, md_sec_ids_verdict.value),
            (df_sec_block, _table_html(BLOCKLIST_HEADERS, [])),
            (tb_sec_ip, ""),
            (tb_sec_pw, ""),
            (tb_sec_code, ""),
        ]
        # Hai output cuối là đồng hồ và cờ cảnh báo của phiên.
        RESET_OUTS =STAGE1 + STAGE2 + [item[0] for item in EXTRA_RESET] + [
            md_countdown, st_warned,
        ]

        def _cookie(request):
            return dict(request.cookies).get(COOKIE_NAME) if request is not None else None

        def _reset_tuple(request=None):
            session_store.revoke(_cookie(request))
            return (
                "",
                0.0,
                "",
                gr.update(visible=True),
                gr.update(visible=False),
                gr.update(visible=False),
                gr.update(value="", type="password"),  # li_pass
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
                _table_html(DEVICE_HEADERS, []),  # df_devices
                gr.update(choices=[], value=None),
                gr.Timer(active=False),
                {},
                "",
                gr.update(visible=False),
            ) + tuple(
                value.copy() if isinstance(value, (dict, list)) else value
                for _, value in EXTRA_RESET
            ) + (
                "",
                False,
            )

        # ---- đăng ký ----
        def do_register(username, password):
            username = (username or "").strip()
            if not (3 <= len(username) <= 32):
                _ui_notice(gr.Warning, "Tên đăng nhập phải từ 3 đến 32 ký tự.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            if len(password or "") < PASSWORD_MIN:
                _ui_notice(gr.Warning, f"Mật khẩu phải có ít nhất {PASSWORD_MIN} ký tự.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            data = _api(
                None, "POST", "/api/auth/register", {"username": username, "password": password}
            )
            _ui_notice(gr.Info, f"Tạo tài khoản “{data['username']}” thành công — mời đăng nhập.")
            return "", "", data["username"], gr.Tabs(selected="tab_login")

        btn_register.click(
            _guard(do_register, 4), [re_user, re_pass], [re_user, re_pass, li_user, auth_tabs]
        )

        # ---- đăng nhập ----
        def do_login(username, password):
            username = (username or "").strip()
            if not username or not password:
                _ui_notice(gr.Warning, "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.")
                return tuple(gr.skip() for _ in STAGE1)
            data = _api(
                None, "POST", "/api/auth/login", {"username": username, "password": password}
            )
            if data.get("mfa_required"):
                _ui_notice(gr.Info, "Tài khoản đã bật 2FA — nhập mã xác thực để tiếp tục.")
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
            if data.get("device_token"):
                session_store.remember_device(data["access_token"], data["device_token"])
            _ui_notice(gr.Info, "Đăng nhập thành công.")
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
            page_state, choices = session_page_snapshot(token)
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
                # Đặt lại cả chu kỳ: tick có thể đã rút ngắn nó ở phiên trước.
                gr.Timer(value=SESSION_TICK_SECONDS, active=True),
                page_state,
                _page_summary(page_state, "hội thoại"),
                gr.update(visible=page_state["has_more"]),
            )

        def remember_session(token, exp):
            # Acknowledge every submitted attempt, including failures and MFA
            # challenges, so the password manager can ignore overlapping submits.
            completed = f'<span data-scap-login-result="{secrets.token_hex(16)}"></span>'
            if not token or exp <= time.time():
                return completed
            try:
                ticket = session_store.issue(token, exp)
                return completed + (
                    f'<span data-scap-session-ticket="{html.escape(ticket, quote=True)}"></span>'
                )
            except UISessionCapacityError:
                _ui_notice(gr.Warning, "Không lưu được phiên trình duyệt lúc này. Vui lòng thử lại.")
                return completed

        def persist_after(event):
            return event.then(
                _guard(remember_session, 1), [st_token, st_exp], [resume_ticket], api_name=False,
                show_progress="hidden",
            )

        def _signed_out_on_load(request):
            """Signed-out layout for a page load with nothing to restore.

            Leave the login inputs alone: browsers and password managers fill them
            while this load event runs, and clearing li_pass made the next click
            answer "Vui lòng nhập đầy đủ…" although the form looked filled in.
            """
            result = list(_reset_tuple(request)[:len(STAGE1)])
            for component in (li_pass, tb_mfa_code):
                result[STAGE1.index(component)] = gr.skip()
            return tuple(result)

        def restore_session(request: gr.Request = None):
            saved = session_store.restore(_cookie(request))
            if saved is None:
                return _signed_out_on_load(request)
            token, expires_at = saved
            try:
                # Revalidate with the real auth service on every page load.
                # This rejects revoked/disabled/password-changed/idle-expired
                # sessions, without rotating tokens or extending their expiry.
                _api(token, "GET", "/api/auth/me")
            except gr.Error:
                return _signed_out_on_load(request)
            return (
                token, expires_at, "", gr.update(visible=False), gr.update(visible=True),
                gr.update(visible=False), "", "", gr.update(visible=True),
            )

        # ---- email khôi phục & passkey ----
        ACCOUNT_SECURITY_OUTS = [md_email_state, df_passkeys, dd_passkey_remove]

        def load_account_security(token):
            if not token:
                return gr.skip(), gr.skip(), gr.skip()
            table, choices = _passkeys_snapshot(token)
            email = _api(token, "GET", "/api/auth/email")
            return _email_markdown(email), table, gr.update(choices=choices, value=None)

        # ---- hoạt động bảo mật (kiểu trang bảo mật tài khoản Google/GitHub) ----
        ACTIVITY_OUTS = [md_activity, df_activity]

        def load_security_activity(token):
            if not token:
                return gr.skip(), gr.skip()
            summary, rows, _ = _security_activity_snapshot(token)
            return summary, rows

        def announce_security_activity(token):
            """After a fresh sign-in, surface what happened since the last visit."""
            if not token:
                return gr.skip(), gr.skip()
            summary, rows, alerts = _security_activity_snapshot(token)
            for alert in alerts:
                _ui_notice(gr.Warning, alert)
            return summary, rows

        demo.load(
            _guard(restore_session, len(STAGE1)), None, STAGE1,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2, show_progress="hidden",
        ).then(
            lambda: '<span data-scap-login-ready="1"></span>', None, [login_ready],
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_account_security, len(ACCOUNT_SECURITY_OUTS)), [st_token],
            ACCOUNT_SECURITY_OUTS, api_name=False, show_progress="hidden",
        )
        btn_activity_refresh.click(
            _guard(load_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False,
        )

        persist_after(gr.on(
            triggers=[btn_login.click, li_user.submit, li_pass.submit],
            fn=_guard(do_login, len(STAGE1)), inputs=[li_user, li_pass], outputs=STAGE1,
            trigger_mode="once",
        )).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2, show_progress="hidden",
        ).then(
            _guard(announce_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_account_security, len(ACCOUNT_SECURITY_OUTS)), [st_token],
            ACCOUNT_SECURITY_OUTS, api_name=False, show_progress="hidden",
        )

        def do_mfa_verify(mfa_token, code):
            if not mfa_token:
                _ui_notice(gr.Warning, "Phiên xác thực đã hết — hãy đăng nhập lại.")
                return tuple(gr.skip() for _ in STAGE1)
            data = _api(
                None,
                "POST",
                "/api/auth/mfa/verify",
                {"mfa_token": mfa_token, "code": (code or "").strip()},
            )
            if data.get("device_token"):
                session_store.remember_device(data["access_token"], data["device_token"])
            _ui_notice(gr.Info, "Đăng nhập thành công.")
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

        persist_after(btn_mfa_verify.click(
            _guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1
        )).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2, show_progress="hidden",
        ).then(
            _guard(announce_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_account_security, len(ACCOUNT_SECURITY_OUTS)), [st_token],
            ACCOUNT_SECURITY_OUTS, api_name=False, show_progress="hidden",
        )
        persist_after(tb_mfa_code.submit(
            _guard(do_mfa_verify, len(STAGE1)), [st_mfa, tb_mfa_code], STAGE1,
        )).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2, show_progress="hidden",
        ).then(
            _guard(announce_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_account_security, len(ACCOUNT_SECURITY_OUTS)), [st_token],
            ACCOUNT_SECURITY_OUTS, api_name=False, show_progress="hidden",
        )
        btn_mfa_cancel.click(
            lambda: ("", gr.update(visible=False), "", gr.update(visible=True)),
            None,
            [st_mfa, grp_mfa_login, tb_mfa_code, grp_auth_forms],
        )

        # ---- đăng nhập bằng passkey ----
        def finish_passkey_login(result):
            payload = _passkey_payload(result, "get")
            if "error" in payload:
                _ui_notice(gr.Warning, _passkey_error_message(payload))
                return tuple(gr.skip() for _ in STAGE1) + ("",)
            data = _api(
                None,
                "POST",
                "/api/auth/passkeys/authentication/verify",
                {
                    "challenge_id": str(payload.get("challenge_id", "")),
                    "credential": payload.get("credential"),
                },
            )
            if data.get("device_token"):
                session_store.remember_device(data["access_token"], data["device_token"])
            _ui_notice(gr.Info, "Đăng nhập bằng passkey thành công.")
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
                "",
            )

        persist_after(btn_passkey_login_done.click(
            _guard(finish_passkey_login, len(STAGE1) + 1), [tb_passkey_result],
            STAGE1 + [tb_passkey_result], api_name=False,
        )).then(
            _guard(load_workspace, len(STAGE2)), [st_token], STAGE2, show_progress="hidden",
        ).then(
            _guard(announce_security_activity, len(ACTIVITY_OUTS)), [st_token], ACTIVITY_OUTS,
            api_name=False, show_progress="hidden",
        ).then(
            _guard(load_account_security, len(ACCOUNT_SECURITY_OUTS)), [st_token],
            ACCOUNT_SECURITY_OUTS, api_name=False, show_progress="hidden",
        )

        # ---- quên mật khẩu ----
        def send_reset_code(identifier):
            identifier = (identifier or "").strip()
            if len(identifier) < 3:
                _ui_notice(gr.Warning, "Nhập tên đăng nhập hoặc email khôi phục.")
                return
            data = _api(
                None, "POST", "/api/auth/password-reset/request", {"identifier": identifier}
            )
            _ui_notice(gr.Info, data.get("message") or "Đã tiếp nhận yêu cầu.")

        btn_reset_send.click(_guard(send_reset_code, 0), [tb_reset_identifier], None)

        def confirm_reset(identifier, code, new_password):
            identifier = (identifier or "").strip()
            if len(identifier) < 3 or not (code or "").strip():
                _ui_notice(gr.Warning, "Nhập tên đăng nhập/email và mã trong email.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            if len(new_password or "") < PASSWORD_MIN:
                _ui_notice(gr.Warning, f"Mật khẩu mới phải có ít nhất {PASSWORD_MIN} ký tự.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            _api(
                None,
                "POST",
                "/api/auth/password-reset/confirm",
                {"identifier": identifier, "code": code.strip(), "new_password": new_password},
            )
            _ui_notice(gr.Info, "Đã đặt lại mật khẩu. Hãy đăng nhập bằng mật khẩu mới.")
            username = identifier if "@" not in identifier else gr.skip()
            return "", "", gr.Tabs(selected="tab_login"), username

        btn_reset_confirm.click(
            _guard(confirm_reset, 4),
            [tb_reset_identifier, tb_reset_code, tb_reset_new],
            [tb_reset_code, tb_reset_new, auth_tabs, li_user],
        )

        # ---- đăng xuất + đồng hồ token ----
        def do_logout(token, request: gr.Request = None):
            saved = session_store.restore(_cookie(request))
            # Another tab may have renewed the browser's token since this tab
            # was loaded. Revoke both, so the current cookie cannot resurrect it.
            tokens = dict.fromkeys([token, saved[0] if saved else ""])
            for active_token in tokens:
                if not active_token:
                    continue
                try:
                    _api(active_token, "POST", "/api/auth/logout")
                    _ui_notice(gr.Info, "Đã đăng xuất và thu hồi token trên máy chủ.")
                except Exception:
                    _ui_notice(gr.Warning, "Không xác nhận được với máy chủ; trạng thái cục bộ đã xóa.")
            return _reset_tuple(request)

        btn_logout.click(_guard(do_logout, len(RESET_OUTS)), [st_token], RESET_OUTS)

        def tick(exp, warned, token=None):
            """Đồng bộ đồng hồ, nhắc trước, và báo hết hạn để tự đăng xuất.

            Chạy theo gr.Timer (mỗi SESSION_TICK_SECONDS) và ngay khi st_exp đổi
            (đăng nhập, khôi phục, gia hạn) để đồng hồ hiện ngay. Chỉ có 4 output
            nhỏ; trình duyệt tự đếm từng giây giữa hai lần tick.

            Hết hạn không chỉ đổi dòng chữ: dữ liệu hội thoại đã giải mã không
            được nằm lại trong state của trình duyệt sau khi phiên đã chết. tick
            ghi mốc hết hạn vào st_expired; expire_session() (sự kiện change của
            nó) dọn sạch state và quay về màn đăng nhập như khi bấm Đăng xuất.
            Phiên bị máy chủ từ chối (thu hồi ở thiết bị khác, tài khoản bị khóa
            hoặc xóa) được ghi mốc âm để expire_session báo đúng lý do.
            """
            if not exp:
                return "", False, gr.skip(), gr.skip()
            if token and _take_session_ended(token):
                return "", False, gr.Timer(active=False), -time.time()
            left = int(exp - time.time())
            if left <= 0:
                return "", False, gr.Timer(active=False), exp
            if left <= WARN_BEFORE_EXPIRY and not warned:
                _ui_notice(gr.Warning,
                    f"Phiên sẽ hết hạn sau {left} giây. "
                    "Bấm “Gia hạn phiên” để tiếp tục làm việc."
                )
                warned = True
            # Gần hết hạn thì hẹn tick kế tiếp đúng lúc hết hạn thay vì trễ tới
            # một chu kỳ. Giá trị không đổi thì frontend không đặt lại Timer.
            interval = min(SESSION_TICK_SECONDS, left)
            return _countdown_markup(left), warned, gr.Timer(value=interval, active=True), gr.skip()

        gr.on(
            triggers=[timer.tick, st_exp.change],
            fn=tick,
            inputs=[st_exp, st_warned, st_token],
            outputs=[md_countdown, st_warned, timer, st_expired],
            show_progress="hidden",
            trigger_mode="always_last",
            api_name=False,
        )

        def expire_session(expired_at):
            if not expired_at:
                return tuple(gr.skip() for _ in RESET_OUTS)
            if expired_at < 0:
                _ui_notice(gr.Warning,
                    "Phiên đăng nhập này không còn hiệu lực (đã bị thu hồi, tài khoản bị khóa "
                    "hoặc bị xóa) — vui lòng đăng nhập lại."
                )
            else:
                _ui_notice(gr.Warning, "Phiên đã hết hạn — vui lòng đăng nhập lại.")
            # A newer token in another tab may still be valid. Clear only
            # this tab; expired cookie records are pruned by the store.
            result = list(_reset_tuple())
            result[RESET_OUTS.index(resume_ticket)] = ""
            return tuple(result)

        st_expired.change(
            expire_session, [st_expired], RESET_OUTS, show_progress="hidden", api_name=False,
        )

        def extend_session(token):
            """Xin token mới trước khi token hiện tại hết hạn (sliding session).

            Máy chủ xoay jti và thu hồi cái cũ, đồng thời áp trần tuyệt đối tính
            từ lần đăng nhập gốc — nên phiên không thể được gia hạn vô hạn.
            """
            data = _api(token, "POST", "/api/auth/refresh")
            expires_at = time.time() + data["expires_in"]
            session_store.rotate_token(token, data["access_token"], expires_at)
            _ui_notice(gr.Info, "Đã gia hạn phiên.")
            return data["access_token"], expires_at, False

        persist_after(btn_extend.click(
            _guard(extend_session, 3), [st_token], [st_token, st_exp, st_warned]
        ))

        # ---- trò chuyện ----
        SESSION_PAGE_OUTS = [st_session_page, md_session_page, btn_sessions_more]

        def session_page_snapshot(token, selected=None, previous=None):
            append = bool(previous and previous.get("account") == _token_digest(token)
                          and previous.get("has_more"))
            offset = previous["next_offset"] if append else 0
            page = _read_page(token, "/api/sessions/page", offset=offset)
            state = _page_state(token, page, previous=previous if append else None)
            # A selected older conversation remains reachable after a mutation
            # refresh, even when its updated_at is outside the first page.
            if selected and selected not in {item["id"] for item in state["items"]}:
                try:
                    item = _api(token, "GET", f"/api/sessions/{selected}")
                except gr.Error as err:
                    if getattr(err, "status_code", None) != 404:
                        raise
                else:
                    state["items"].append(item)
            icons = {"secure": "🔒", "confidential": "🛡️", "private_e2ee": "🔐"}
            choices = [
                (f"{icons.get(item.get('security_mode'), '🔒')}  {item['title']}", item["id"])
                for item in state["items"]
            ]
            return state, choices

        def refresh_sessions(token, selected=None):
            state, choices = session_page_snapshot(token, selected)
            ids = {value for _, value in choices}
            selected = selected if selected in ids else (choices[0][1] if choices else None)
            return (
                gr.update(choices=choices, value=selected),
                gr.update(choices=choices, value=selected),
                _chat_history(token, selected),
                state, _page_summary(state, "hội thoại"), gr.update(visible=state["has_more"]),
            )

        btn_refresh.click(
            _guard(refresh_sessions, 6), [st_token, dd_session],
            [dd_session, dd_cipher, chatbot, *SESSION_PAGE_OUTS],
        )

        def load_more_sessions(token, selected, previous):
            if (not previous or previous.get("account") != _token_digest(token)
                or not previous.get("has_more")):
                return refresh_sessions(token, selected)
            state, choices = session_page_snapshot(token, selected, previous)
            return (gr.update(choices=choices, value=selected), gr.update(choices=choices, value=selected),
                    gr.skip(), state, _page_summary(state, "hội thoại"),
                    gr.update(visible=state["has_more"]))

        btn_sessions_more.click(
            _guard(load_more_sessions, 6), [st_token, dd_session, st_session_page],
            [dd_session, dd_cipher, chatbot, *SESSION_PAGE_OUTS], trigger_mode="once",
        )

        def _session_title(token, session_id):
            if session_id:
                return _api(token, "GET", f"/api/sessions/{session_id}").get("title") or ""
            return ""

        # Thông báo consent/DLP thuộc về lượt gửi trước; giữ lại khi đã sang
        # hội thoại khác sẽ gắn nhầm cảnh báo vào hội thoại đang xem.
        NOTICE_HIDDEN = (gr.update(value="", visible=False), gr.update(visible=False))
        SEARCH_HIDDEN = (gr.update(value="", visible=False), gr.update(value="", visible=False))

        def pick_session(token, session_id):
            """Bấm một hàng trong danh sách: nạp hội thoại và điền sẵn tên hiện tại."""
            if not session_id:
                return [], "", *NOTICE_HIDDEN, *SEARCH_HIDDEN
            # Một lần đọc metadata đủ cho cả lịch sử lẫn tên; _session_title
            # tải lại cả danh sách hội thoại chỉ để lấy một tiêu đề.
            session = _api(token, "GET", f"/api/sessions/{session_id}")
            history = _chat_history(token, session_id, session)
            return history, session.get("title") or "", *NOTICE_HIDDEN, *SEARCH_HIDDEN

        # Chọn hội thoại là điều hướng, không phải thao tác chờ: nội dung cũ ở
        # lại tới khi nội dung mới về, không phủ lớp "processing" lên khung chat.
        dd_session.input(
            _guard(pick_session, 6),
            [st_token, dd_session],
            [chatbot, tb_rename, md_chat_notice, btn_consent_send,
             md_search_answer, md_search_suggestions],
            show_progress="hidden",
        )
        # Bấm chọn, tạo, xóa, gửi hay đăng nhập đều đổi value của danh sách,
        # nên một listener .change giữ dòng chế độ đã khóa luôn đúng hội thoại.
        dd_session.change(
            _guard(_session_policy_markdown, 1), [st_token, dd_session], [md_session_policy],
            api_name=False, show_progress="hidden",
        )

        def create_session(token, title, security_mode, data_classification):
            created = _api(
                token,
                "POST",
                "/api/sessions",
                {
                    "title": (title or "").strip() or "Cuộc hội thoại mới",
                    "security_mode": security_mode or "secure",
                    "data_classification": data_classification or "internal",
                },
            )
            _ui_notice(gr.Info, "Đã tạo hội thoại.")
            dd1, dd2, history, *paging = refresh_sessions(token, created["id"])
            # Ô "Đổi tên" phải theo hội thoại vừa chọn, nếu không bấm "Lưu tên
            # mới" sẽ chép tên hội thoại cũ sang hội thoại mới.
            return (dd1, dd2, history, "", _session_title(token, created["id"]),
                    *NOTICE_HIDDEN, *SEARCH_HIDDEN, *paging)

        btn_create.click(
            _guard(create_session, 12),
            [st_token, tb_new_title, dd_new_security, dd_new_class],
            [dd_session, dd_cipher, chatbot, tb_new_title, tb_rename, md_chat_notice, btn_consent_send,
             md_search_answer, md_search_suggestions, *SESSION_PAGE_OUTS],
        )

        def rename_session(token, session_id, title):
            if not session_id or not (title or "").strip():
                _ui_notice(gr.Warning, "Chọn hội thoại và nhập tiêu đề mới.")
                return tuple(gr.skip() for _ in range(6))
            _api(token, "PATCH", f"/api/sessions/{session_id}", {"title": title.strip()})
            _ui_notice(gr.Info, "Đã đổi tên hội thoại.")
            dd1, dd2, _, *paging = refresh_sessions(token, session_id)
            return dd1, dd2, "", *paging

        btn_rename.click(
            _guard(rename_session, 6),
            [st_token, dd_session, tb_rename],
            [dd_session, dd_cipher, tb_rename, *SESSION_PAGE_OUTS],
        )

        DELETE_HIDDEN = ("", gr.update(visible=False), "", gr.update(visible=False), "", "")
        DELETE_CONFIRM_OUTS = [st_delete_target, grp_delete_confirm, md_delete_confirm,
                               grp_delete_auth, tb_delete_password, tb_delete_code]
        DELETE_VIEW_RESET = (gr.update(value="", visible=False), "",
                             _table_html(CIPHER_HEADERS, []), _table_html(SEARCH_HEADERS, []))
        DELETE_OUTS = [dd_session, dd_cipher, chatbot, tb_rename, md_chat_notice, btn_consent_send,
                       md_search_answer, md_search_suggestions, *DELETE_CONFIRM_OUTS,
                       file_export, tb_msg, df_cipher, df_gsearch, *SESSION_PAGE_OUTS]

        def cancel_delete_session():
            return DELETE_HIDDEN

        def request_delete_session(token, session_id):
            if not session_id:
                _ui_notice(gr.Warning, "Chọn hội thoại cần xóa trước.")
                return DELETE_HIDDEN
            session = _api(token, "GET", f"/api/sessions/{session_id}")
            title = _safe_markdown_text(session.get("title") or "Hội thoại đang chọn")
            return (
                session_id, gr.update(visible=True),
                f"**Xóa vĩnh viễn hội thoại “{title}”?**\n\n"
                "Hội thoại và toàn bộ tin nhắn sẽ bị xóa. "
                "Thao tác này không thể hoàn tác trong ứng dụng.",
                gr.update(visible=False), "", "",
            )

        btn_delete.click(
            _guard(request_delete_session, 6), [st_token, dd_session], DELETE_CONFIRM_OUTS,
            trigger_mode="once",
        )
        btn_delete_cancel.click(cancel_delete_session, None, DELETE_CONFIRM_OUTS, api_name=False)
        # Clear confirmation immediately on a new selection, even if loading
        # that conversation fails. The frozen ID is also checked on confirm.
        dd_session.input(cancel_delete_session, None, DELETE_CONFIRM_OUTS, queue=False, api_name=False,
                         show_progress="hidden")
        btn_create.click(cancel_delete_session, None, DELETE_CONFIRM_OUTS, queue=False, api_name=False)
        btn_refresh.click(cancel_delete_session, None, DELETE_CONFIRM_OUTS, queue=False, api_name=False)

        def delete_session(token, session_id, pending_id, password="", code=""):
            if not pending_id or session_id != pending_id:
                _ui_notice(gr.Warning, "Hội thoại đã thay đổi. Chọn lại hội thoại và xác nhận xóa.")
                return (*(gr.skip() for _ in range(8)), *DELETE_HIDDEN,
                        *(gr.skip() for _ in range(len(DELETE_VIEW_RESET) + 3)))
            try:
                try:
                    _api(token, "DELETE", f"/api/sessions/{pending_id}")
                except gr.Error as err:
                    if "xác thực lại" not in _error_text(err).lower():
                        raise
                    if not password:
                        return (
                            *(gr.skip() for _ in range(8)), pending_id, gr.update(visible=True),
                            "**Cần xác thực lại để xóa vĩnh viễn.**\n\n"
                            "Nhập mật khẩu và mã 2FA (nếu đã bật), rồi bấm xác nhận xóa lần nữa.",
                            gr.update(visible=True), "", "", *(gr.skip() for _ in range(len(DELETE_VIEW_RESET) + 3)),
                        )
                    _api(token, "POST", "/api/auth/step-up", {
                        "password": password, "code": (code or "").strip() or None,
                    })
                    _api(token, "DELETE", f"/api/sessions/{pending_id}")
            except gr.Error as err:
                # A persistent error belongs beside this destructive action;
                # clear credential fields after every attempt, including failures.
                return (
                    *(gr.skip() for _ in range(8)), pending_id, gr.update(visible=True),
                    "⚠️ **Chưa xóa được hội thoại.** " + _safe_markdown_text(_error_text(err)),
                    gr.skip(), "", "", *(gr.skip() for _ in range(len(DELETE_VIEW_RESET) + 3)),
                )
            _ui_notice(gr.Info, "Đã xóa vĩnh viễn hội thoại và toàn bộ tin nhắn.")
            try:
                dd1, dd2, history, *paging = refresh_sessions(token)
                title = _session_title(token, dd1["value"])
            except gr.Error:
                # The DELETE succeeded. Never leave deleted plaintext selected
                # because a later list/history read failed, or invite a retry.
                empty = gr.update(choices=[], value=None)
                return (
                    empty, empty, [], "",
                    gr.update(value="Đã xóa hội thoại. Bấm **Làm mới** để tải lại danh sách.", visible=True),
                    gr.update(visible=False), *SEARCH_HIDDEN, *DELETE_HIDDEN,
                    *DELETE_VIEW_RESET, {}, "", gr.update(visible=False),
                )
            return (dd1, dd2, history, title, *NOTICE_HIDDEN, *SEARCH_HIDDEN,
                    *DELETE_HIDDEN, *DELETE_VIEW_RESET, *paging)

        btn_delete_confirm.click(
            _guard(delete_session, len(DELETE_OUTS)),
            [st_token, dd_session, st_delete_target, tb_delete_password, tb_delete_code],
            DELETE_OUTS,
            trigger_mode="once",
        )

        def export_session(token, session_id, password, code):
            if not session_id:
                _ui_notice(gr.Warning, "Chọn một hội thoại trước.")
                return gr.skip(), gr.skip(), gr.skip()
            try:
                grant = _api(token, "POST", f"/api/sessions/{session_id}/export-ticket")
            except gr.Error as err:
                if "xác thực lại" not in str(err).lower():
                    raise
                if not password:
                    raise gr.Error(
                        "Phiên xác thực lại đã hết hạn. Nhập mật khẩu và mã 2FA rồi bấm Xuất JSON lần nữa."
                    ) from err
                _api(
                    token,
                    "POST",
                    "/api/auth/step-up",
                    {"password": password, "code": (code or "").strip() or None},
                )
                grant = _api(
                    token,
                    "POST",
                    f"/api/sessions/{session_id}/export-ticket",
                )
            # Relative URL: works behind any proxy/host. The ticket is server-issued;
            # escape it anyway because this Markdown does not sanitize HTML.
            link = (
                f'<a class="scap-export-link" href="{html.escape(grant["download_url"], quote=True)}"'
                ' download rel="noopener">⬇ Tải tệp JSON (hết hạn sau 60 giây)</a>'
            )
            _ui_notice(gr.Info, "Vé tải có hiệu lực 60 giây và chỉ dùng được một lần.")
            return gr.update(value=link, visible=True), "", ""

        btn_export.click(
            _guard(export_session, 3),
            [st_token, dd_session, tb_export_password, tb_export_code],
            [file_export, tb_export_password, tb_export_code],
        )

        def _send_chat_message(token, session_id, message, confirm_external=False, use_web_search=False):
            message = (message or "").strip()
            if not message:
                return (gr.skip(), gr.skip(), gr.skip(), "", gr.skip(), gr.update(visible=False),
                        gr.skip(), gr.skip(), gr.skip())
            created_session = False
            try:
                if use_web_search and not gemini_web_search_enabled:
                    raise gr.Error("Máy chủ chưa bật tra cứu Internet. Bỏ chọn tra cứu để gửi tin nhắn.")
                if use_web_search and not session_id:
                    raise gr.Error(
                        "Để tra cứu Internet, chọn Public trong Thiết lập hội thoại mới, "
                        "rồi bấm + Hội thoại mới. Chỉ dùng nội dung công khai."
                    )
                if not session_id:
                    # Never copy plaintext message content into the unencrypted
                    # conversation-title metadata column.
                    created = _api(
                        token,
                        "POST",
                        "/api/sessions",
                        {"title": "Cuộc hội thoại mới"},
                    )
                    session_id = created["id"]
                    created_session = True
                    _ui_notice(gr.Info, "Đã tự tạo hội thoại mới.")
                session_metadata = _api(token, "GET", f"/api/sessions/{session_id}")
                if session_metadata.get("security_mode") == "private_e2ee":
                    raise gr.Error(
                        "Phiên Private E2EE chỉ nhận bản mã từ client Double Ratchet/MLS."
                    )
                if use_web_search and session_metadata.get("data_classification") != "public":
                    raise gr.Error(
                        "Tra cứu Internet chỉ dùng trong hội thoại Public. Chọn Public trong "
                        "Thiết lập hội thoại mới rồi bấm + Hội thoại mới, hoặc bỏ chọn tra cứu."
                    )
                sent = _api(
                    token,
                    "POST",
                    f"/api/sessions/{session_id}/messages",
                    {
                        "content": message, "confirm_external_ai": bool(confirm_external),
                        "use_web_search": bool(use_web_search),
                    },
                )
            except gr.Error as err:
                # Keep every refusal beside the composer. A toast disappears
                # quickly on mobile, making a failed send look like lost text.
                selection = (gr.skip(), gr.skip(), gr.skip())
                paging = (gr.skip(), gr.skip(), gr.skip())
                if created_session:
                    try:
                        refreshed = refresh_sessions(token, session_id)
                        selection, paging = refreshed[:3], refreshed[3:]
                    except gr.Error:
                        # The session was definitely created, even if the next
                        # read is unavailable. Keep it selected for the retry.
                        update = gr.update(
                            choices=[("🔒  Cuộc hội thoại mới", session_id)], value=session_id
                        )
                        selection = (update, update, gr.skip())
                # Consent là lựa chọn người dùng, không phải lỗi kỹ thuật. Hiển thị
                # ngay cạnh ô nhập và giữ nguyên nội dung để họ có thể gửi lại sau.
                if EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE in str(err):
                    notice = gr.update(value=CONSENT_NOTICE, visible=True)
                    return (*selection, gr.skip(), notice, gr.update(visible=True), *paging)
                notice = gr.update(
                    value=(
                        "⚠️ **Chưa nhận được phản hồi.** " + _safe_markdown_text(_error_text(err))
                        + "\n\nNội dung bạn nhập vẫn được giữ trong ô tin nhắn."
                    ),
                    visible=True,
                )
                return (*selection, gr.skip(), notice, gr.update(visible=False), *paging)
            try:
                dd1, dd2, history, *paging = refresh_sessions(token, session_id)
            except gr.Error as err:
                # The POST succeeded. Keep that success distinct from a failed
                # history read so retrying does not send the same text twice.
                selection = (
                    gr.update(choices=[("🔒  Cuộc hội thoại mới", session_id)], value=session_id)
                    if created_session else gr.skip()
                )
                return (
                    selection, selection, gr.skip(), "",
                    gr.update(
                        value=(
                            "✅ **Tin nhắn đã gửi.** Chưa tải lại được lịch sử hội thoại. "
                            + _safe_markdown_text(_error_text(err))
                            + "\n\nBấm **Làm mới** để tải lại nội dung."
                        ),
                        visible=True,
                    ),
                    gr.update(visible=False),
                    gr.skip(), gr.skip(), gr.skip(),
                )
            # Nếu DLP đã che dữ liệu nhạy cảm, nói rõ cho người dùng biết đã che
            # NHÓM nào — không bao giờ hiện lại giá trị gốc.
            labels = (sent or {}).get("dlp_redacted") or []
            if labels:
                banner = gr.update(
                    value=(
                        "🛡️ **Lớp DLP đã can thiệp.** Trong nội dung dành cho AI hoặc phản hồi AI, "
                        "hệ thống đã che: **" + ", ".join(labels) + "**. "
                        "Bản gốc vẫn được mã hoá AES-256-GCM và lưu nguyên trong hội thoại của bạn."
                    ),
                    visible=True,
                )
            else:
                banner = gr.update(value="", visible=False)
            return dd1, dd2, history, "", banner, gr.update(visible=False), *paging

        def send_message(token, session_id, message, confirm_external=False, use_web_search=False):
            if not use_web_search:
                sent = _send_chat_message(token, session_id, message, confirm_external)
                return (*sent[:6], *SEARCH_HIDDEN, *sent[6:])
            message = (message or "").strip()
            if not message:
                return (gr.skip(), gr.skip(), gr.skip(), "", *NOTICE_HIDDEN, *SEARCH_HIDDEN,
                        gr.skip(), gr.skip(), gr.skip())
            try:
                if not gemini_web_search_enabled:
                    raise gr.Error("Máy chủ chưa bật tra cứu Internet. Bỏ chọn tra cứu để gửi tin nhắn.")
                if not session_id:
                    raise gr.Error(
                        "Để tra cứu Internet, chọn Public trong Thiết lập hội thoại mới, "
                        "rồi bấm + Hội thoại mới. Chỉ dùng nội dung công khai."
                    )
                session_metadata = _api(token, "GET", f"/api/sessions/{session_id}")
                if session_metadata.get("data_classification") != "public":
                    raise gr.Error("Tra cứu Internet chỉ dùng trong hội thoại Public.")
                result = _api(token, "POST", f"/api/sessions/{session_id}/web-search", {
                    "content": message, "confirm_external_ai": bool(confirm_external),
                })
                # Revalidate at the rendering boundary. The provider widget is
                # transient and never becomes Chatbot content or chat history.
                marker = _search_widget_marker(result.get("search_suggestions_html"))
                answer = _safe_chat_text(result["content"])
            except gr.Error as err:
                needs_consent = EXTERNAL_AI_CONSENT_REQUIRED_MESSAGE in str(err)
                notice = gr.update(
                    value=CONSENT_NOTICE if needs_consent else (
                        "⚠️ **Chưa nhận được kết quả tra cứu.** "
                        + _safe_markdown_text(_error_text(err))
                        + "\n\nNội dung bạn nhập vẫn được giữ trong ô tin nhắn."
                    ), visible=True,
                )
                return (gr.skip(), gr.skip(), gr.skip(), gr.skip(), notice,
                        gr.update(visible=needs_consent), *SEARCH_HIDDEN,
                        gr.skip(), gr.skip(), gr.skip())
            return (
                gr.skip(), gr.skip(), gr.skip(), "", *NOTICE_HIDDEN,
                gr.update(value=answer, visible=True),
                gr.update(value=marker, visible=bool(marker)),
                gr.skip(), gr.skip(), gr.skip(),
            )

        SEND_OUTS = [dd_session, dd_cipher, chatbot, tb_msg, md_chat_notice, btn_consent_send,
                     md_search_answer, md_search_suggestions, *SESSION_PAGE_OUTS]
        def submit_chat_message(token, session_id, message, use_web_search=False):
            # Bấm Gửi chính là xác nhận gửi tin nhắn này tới AI bên ngoài (dòng
            # chế độ hội thoại nói rõ điều đó), nên hội thoại Internal/Confidential
            # không còn hỏi lại từng tin. API vẫn đòi confirm_external_ai cho
            # mọi client; DLP vẫn che dữ liệu nhạy cảm và chặn Highly confidential.
            return send_message(token, session_id, message, True, use_web_search)

        # One event covers Enter and tapping Send. Separate events could both
        # run while mobile Chrome was still waiting for the first response.
        gr.on(
            triggers=[btn_send.click, tb_msg.submit],
            fn=_guard(submit_chat_message, len(SEND_OUTS)),
            inputs=[st_token, dd_session, tb_msg, cb_web_search],
            outputs=SEND_OUTS,
            trigger_mode="once",
        )

        def consent_and_resend(token, session_id, message, use_web_search=False):
            """Grant the one-time account consent, then send the still-visible message.

            The consent is stored for the account, so this button appears only
            once. As with the Send button, sending is the per-message confirmation.
            """
            if not (message or "").strip():
                return (
                    gr.skip(),
                    gr.skip(),
                    gr.skip(),
                    "",
                    gr.update(value="", visible=False),
                    gr.update(visible=False),
                    *SEARCH_HIDDEN,
                    gr.skip(), gr.skip(), gr.skip(),
                )
            if not _api(token, "GET", "/api/auth/me").get("ai_data_consent"):
                _api(token, "PATCH", "/api/auth/ai-consent", {"ai_data_consent": True})
            return send_message(token, session_id, message, True, use_web_search)

        btn_consent_send.click(
            _guard(consent_and_resend, len(SEND_OUTS)), [st_token, dd_session, tb_msg, cb_web_search], SEND_OUTS
        )
        cb_web_search.input(lambda _selected: SEARCH_HIDDEN, [cb_web_search],
                            [md_search_answer, md_search_suggestions], api_name=False)

        # ---- dữ liệu mã hóa ----
        def load_cipher(token, session_id, view_id=None):
            if view_id != session_id:
                return gr.skip()
            if not session_id:
                _ui_notice(gr.Warning, "Chọn một hội thoại trước.")
                return gr.skip()
            rows = _api(token, "GET", f"/api/sessions/{session_id}/ciphertexts")
            if not rows:
                _ui_notice(gr.Info, "Hội thoại này chưa có tin nhắn nào.")
            return _table_html(CIPHER_HEADERS, [
                [
                    row["id"],
                    row["role"],
                    row["ciphertext_preview"],
                    row["nonce"],
                    (f"Epoch {row['crypto_epoch']} · {row['encryption_scheme']}"
                     if row.get("encryption_scheme") == "envelope-v1"
                     else (f"Legacy v{row['key_version']}"
                           if row.get("encryption_scheme", "legacy-v1") == "legacy-v1"
                           else "Định dạng không hỗ trợ")),
                    _fmt(row["created_at"]),
                ]
                for row in rows
            ])

        btn_cipher.click(_guard(load_cipher, 1), [st_token, dd_cipher, st_cipher_view], [df_cipher])

        def load_crypto_info(token, session_id, view_id=None):
            if view_id != session_id:
                return gr.skip()
            if not token or not session_id:
                return {}
            return _api(token, "GET", f"/api/sessions/{session_id}/crypto-info")

        btn_cipher.click(_guard(load_crypto_info, 1), [st_token, dd_cipher, st_cipher_view], [crypto_info],
                         api_visibility="private")

        def clear_crypto_view(session_id, generation):
            return _table_html(CIPHER_HEADERS, []), {}, session_id, int(generation or 0) + 1

        dd_cipher.change(
            clear_crypto_view, [dd_cipher, st_cipher_generation],
            [df_cipher, crypto_info, st_cipher_view, st_cipher_generation], queue=False,
            trigger_mode="always_last", api_visibility="private",
        )

        # ---- tìm kiếm toàn cục ----
        SEARCH_PAGE_OUTS = [df_gsearch, st_search_page, md_search_page, btn_search_more]
        SESSION_SEARCH_OUTS = [df_session_search, st_session_search_page,
                               md_session_search, btn_session_search_more]

        def search_page(token, query, previous=None, session_id=None):
            query = (query or "").strip()
            if not query:
                _ui_notice(gr.Warning, "Nhập từ khóa trước.")
                return _table_html(SEARCH_HEADERS, []), {}, "", gr.update(visible=False)
            valid_previous = (
                previous and previous.get("account") == _token_digest(token)
                and previous.get("query") == query and previous.get("session_id") == session_id
                and previous.get("has_more")
            )
            offset = previous["next_offset"] if valid_previous else 0
            path = (f"/api/sessions/{session_id}/messages/page" if session_id
                    else "/api/search/messages/page")
            try:
                page = _read_page(token, path, offset=offset, limit=50,
                                  params={"query" if session_id else "q": query})
            except gr.Error as err:
                message = "**Chưa tìm được nội dung.** " + _safe_markdown_text(_error_text(err))
                return message, {}, gr.update(value=message, visible=True), gr.update(visible=False)
            state = _page_state(token, page, previous=previous if valid_previous else None,
                                query=query, session_id=session_id)
            # The table contains previews; never retain every full plaintext
            # hit while paging through a large account's history.
            state["items"] = [
                {**item, "content": item["content"][:201]}
                for item in state["items"][-MAX_UI_SEARCH_ROWS:]
            ]
            table = _table_html(SEARCH_HEADERS, [
                [
                    row.get("session_title") or "Hội thoại đang mở",
                    ("Bạn" if row["role"] == "user" else "Trợ lý"),
                    row["content"][:200] + ("…" if len(row["content"]) > 200 else ""),
                    _fmt(row["created_at"]),
                ]
                for row in state["items"]
            ])
            end = offset + len(page["items"])
            start = max(0, end - len(state["items"]))
            shown = f"{start + 1}–{end}" if state["items"] else "0"
            status = (f"Từ khóa: **{_safe_markdown_text(query)}** · Đang hiển thị "
                      f"**{shown}/{state['total']}** tin nhắn.")
            status += " Còn kết quả; bấm **Tải thêm**." if state["has_more"] else " Đã đến cuối kết quả."
            if start:
                status += f" Chỉ giữ {MAX_UI_SEARCH_ROWS} kết quả gần nhất trên giao diện; tìm lại để xem từ đầu."
            return table, state, gr.update(value=status, visible=True), gr.update(visible=state["has_more"])

        def global_search(token, query):
            return search_page(token, query)

        btn_gsearch.click(_guard(global_search, 4), [st_token, tb_gq], SEARCH_PAGE_OUTS)
        tb_gq.submit(_guard(global_search, 4), [st_token, tb_gq], SEARCH_PAGE_OUTS)
        btn_search_more.click(_guard(search_page, 4), [st_token, tb_gq, st_search_page],
                              SEARCH_PAGE_OUTS, trigger_mode="once")

        def find_in_session(token, session_id, query, view_id=None, generation=0):
            if not session_id:
                message = "Chọn hội thoại trước khi tìm nội dung."
                return (_table_html(SEARCH_HEADERS, []), {},
                        gr.update(value=message, visible=True), gr.update(visible=False))
            if view_id is not None and view_id != session_id:
                return tuple(gr.skip() for _ in SESSION_SEARCH_OUTS)
            return search_page(token, query, session_id=session_id)

        def load_more_session_search(token, session_id, query, previous, view_id=None, generation=0):
            if view_id is not None and view_id != session_id:
                return tuple(gr.skip() for _ in SESSION_SEARCH_OUTS)
            return search_page(token, query, previous, session_id) if session_id else find_in_session(token, session_id, query)

        gr.on([btn_session_search.click, tb_session_query.submit],
              _guard(find_in_session, 4), [st_token, dd_session, tb_session_query,
                                          st_session_view, st_session_search_generation],
              SESSION_SEARCH_OUTS, trigger_mode="once")
        btn_session_search_more.click(
            _guard(load_more_session_search, 4), [st_token, dd_session, tb_session_query,
                                                  st_session_search_page, st_session_view,
                                                  st_session_search_generation],
            SESSION_SEARCH_OUTS, trigger_mode="once",
        )

        def clear_session_search(selected, generation):
            return ("", _table_html(SEARCH_HEADERS, []), {},
                    gr.update(value="", visible=False), gr.update(visible=False), selected, generation + 1)

        for trigger in (btn_session_search_clear.click, dd_session.change):
            trigger(clear_session_search, [dd_session, st_session_search_generation],
                    [tb_session_query, *SESSION_SEARCH_OUTS, st_session_view, st_session_search_generation],
                    api_name=False, queue=False, show_progress="hidden")

        # ---- tài khoản ----
        def set_consent(token, consent):
            data = _api(token, "PATCH", "/api/auth/ai-consent", {"ai_data_consent": bool(consent)})
            _ui_notice(gr.Info, "Đã cập nhật lựa chọn chia sẻ dữ liệu AI.")
            return gr.update(value=bool(data["ai_data_consent"]))

        chk_consent.input(_guard(set_consent, 1), [st_token, chk_consent], [chk_consent])

        def change_password(token, current, new, request: gr.Request = None):
            if not (current or "").strip() or not (new or "").strip():
                _ui_notice(gr.Warning, "Nhập cả mật khẩu hiện tại và mật khẩu mới.")
                return tuple(gr.skip() for _ in RESET_OUTS)
            if len(new) < PASSWORD_MIN:
                _ui_notice(gr.Warning, f"Mật khẩu mới phải có ít nhất {PASSWORD_MIN} ký tự.")
                return tuple(gr.skip() for _ in RESET_OUTS)
            _api(
                token,
                "PATCH",
                "/api/auth/password",
                {"current_password": current, "new_password": new},
            )
            _ui_notice(gr.Info, "Đã đổi mật khẩu — mọi phiên bị thu hồi, mời đăng nhập lại.")
            return _reset_tuple(request)

        btn_pw.click(
            _guard(change_password, len(RESET_OUTS)),
            [st_token, tb_pw_cur, tb_pw_new],
            RESET_OUTS,
        )

        # ---- 2FA ----
        def mfa_enroll(token):
            data = _api(token, "POST", "/api/auth/mfa/enroll")
            markup = ""
            try:
                markup = _totp_qr_markup(data["provisioning_uri"], QR_DISPLAY_PX)
            except ImportError:
                _ui_notice(gr.Warning, "Thiếu thư viện qrcode (chạy `uv sync`) — dùng khóa thủ công bên dưới.")
            except Exception:
                _ui_notice(gr.Warning, "Không dựng được mã QR — hãy dùng khóa thủ công bên dưới.")
            if markup:
                _ui_notice(gr.Info, "Quét mã QR rồi nhập mã 6 số để kích hoạt. QR chỉ hiển thị tạm thời, không tạo tệp tải xuống.")
            else:
                _ui_notice(gr.Info, "Nhập khóa thủ công vào ứng dụng xác thực, rồi nhập mã 6 số.")
            return (
                gr.update(visible=True),
                gr.update(value=markup, visible=bool(markup)),
                data["secret"],
            )

        btn_enroll.click(_guard(mfa_enroll, 3), [st_token], [grp_mfa_setup, qr_html, tb_secret])

        # The API revokes every session when 2FA is turned on or off, this one
        # included (tests/test_mfa.py). Staying in the workspace with that dead
        # token made every later action fail and F5 sign the user out, so both
        # handlers sign out like a password change and ask for a fresh login.
        def mfa_activate(token, code, request: gr.Request = None):
            data = _api(token, "POST", "/api/auth/mfa/activate", {"code": (code or "").strip()})
            codes = data.get("recovery_codes", [])
            _ui_notice(gr.Info,
                "Lưu các mã khôi phục sau ở nơi an toàn, mỗi mã chỉ dùng một lần: "
                + " · ".join(codes),
                duration=None,
                title="Mã khôi phục 2FA",
            )
            _ui_notice(gr.Info,
                "2FA đã được kích hoạt — mọi phiên bị thu hồi, mời đăng nhập lại "
                "bằng mật khẩu và mã 6 số."
            )
            return _reset_tuple(request)

        btn_activate.click(
            _guard(mfa_activate, len(RESET_OUTS)), [st_token, tb_activate], RESET_OUTS,
        )

        def mfa_disable(token, password, code, request: gr.Request = None):
            _api(
                token,
                "POST",
                "/api/auth/mfa/disable",
                {"password": password, "code": (code or "").strip()},
            )
            _ui_notice(gr.Info, "Đã tắt xác thực hai lớp — mọi phiên bị thu hồi, mời đăng nhập lại.")
            return _reset_tuple(request)

        btn_disable.click(
            _guard(mfa_disable, len(RESET_OUTS)), [st_token, tb_dis_pw, tb_dis_code], RESET_OUTS,
        )

        # ---- email khôi phục ----
        def send_email_code(token, email, password, code):
            email = (email or "").strip()
            if not email:
                _ui_notice(gr.Warning, "Nhập địa chỉ email khôi phục.")
                return gr.skip(), gr.skip(), gr.skip()
            data = _with_step_up(
                token, password, code,
                lambda: _api(token, "POST", "/api/auth/email", {"email": email}),
                "Gửi mã xác minh",
            )
            _ui_notice(gr.Info, "Đã gửi mã xác minh tới email mới. Mã có hiệu lực trong vài phút.")
            return _email_markdown(data), "", ""

        btn_email_send.click(
            _guard(send_email_code, 3), [st_token, tb_email_new, tb_acct_pw, tb_acct_code],
            [md_email_state, tb_acct_pw, tb_acct_code],
        )

        def verify_email_code(token, code):
            if not (code or "").strip():
                _ui_notice(gr.Warning, "Nhập mã xác minh trong email.")
                return gr.skip(), gr.skip(), gr.skip()
            data = _api(token, "POST", "/api/auth/email/verify", {"code": code.strip()})
            _ui_notice(gr.Info, "Đã xác minh email khôi phục.")
            return _email_markdown(data), "", ""

        btn_email_verify.click(
            _guard(verify_email_code, 3), [st_token, tb_email_code],
            [md_email_state, tb_email_code, tb_email_new],
        )

        def remove_email(token, password, code):
            _with_step_up(
                token, password, code,
                lambda: _api(token, "DELETE", "/api/auth/email"),
                "Gỡ email khôi phục",
            )
            _ui_notice(gr.Info, "Đã gỡ email khôi phục.")
            return _email_markdown(_api(token, "GET", "/api/auth/email")), "", ""

        btn_email_remove.click(
            _guard(remove_email, 3), [st_token, tb_acct_pw, tb_acct_code],
            [md_email_state, tb_acct_pw, tb_acct_code],
        )

        def prepare_passkey_step_up(token):
            options = _api(token, "POST", "/api/auth/passkeys/step-up/options")
            nonce = secrets.token_hex(16)
            encoded = base64.urlsafe_b64encode(json.dumps(
                options["public_key"], separators=(",", ":"),
            ).encode()).decode("ascii").rstrip("=")
            markup = (
                f'<span data-scap-passkey-request="{nonce}" data-scap-passkey-mode="step-up" '
                f'data-scap-passkey-options="{encoded}"></span>'
            )
            state = {"challenge_id": options["challenge_id"], "nonce": nonce, "account": _token_digest(token)}
            return (markup, state, gr.update(value=(
                "Bấm **Xác nhận passkey trên thiết bị** và xác minh bằng PIN/vân tay. "
                "Yêu cầu gắn với phiên hiện tại, có hạn 3 phút và chỉ được thử một lần."
            ), visible=True), gr.update(visible=True), "", "", "")

        btn_passkey_step_up_prepare.click(
            _guard(prepare_passkey_step_up, 7), [st_token],
            [passkey_bridge, st_passkey_step_up, md_passkey_step_up_hint, btn_passkey_step_up,
             tb_passkey_result, tb_acct_pw, tb_acct_code], api_name=False,
        )

        def finish_passkey_step_up(token, result, state):
            payload = _passkey_payload(result, "step-up")
            closed = ("", {}, gr.update(value="", visible=False), gr.update(visible=False), "")
            if (not state or state.get("account") != _token_digest(token)
                    or payload.get("nonce") != state.get("nonce")):
                _ui_notice(gr.Warning, "Yêu cầu xác thực lại đã hết hạn; hãy chuẩn bị passkey lại.")
                return closed
            if "error" in payload:
                _ui_notice(gr.Warning, _passkey_error_message(payload))
                return closed
            try:
                _api(token, "POST", "/api/auth/passkeys/step-up/verify", {
                    "challenge_id": state["challenge_id"], "credential": payload.get("credential"),
                })
            except gr.Error:
                _ui_notice(gr.Warning, "Passkey chưa được chấp nhận. Hãy chuẩn bị yêu cầu mới để thử lại.")
                return closed
            _ui_notice(gr.Info, "Đã xác thực lại bằng passkey. Bạn có thể thực hiện lại thao tác nhạy cảm.")
            return closed

        btn_passkey_step_up_done.click(
            _guard(finish_passkey_step_up, 5), [st_token, tb_passkey_result, st_passkey_step_up],
            [passkey_bridge, st_passkey_step_up, md_passkey_step_up_hint, btn_passkey_step_up,
             tb_passkey_result], api_name=False,
        )

        def load_geoip_status(token):
            status = _api(token, "GET", "/api/auth/sign-in-risk/status")
            if status.get("backend") == "disabled":
                return "GeoIP đang tắt. Cần cấu hình cơ sở dữ liệu City cục bộ để đánh giá vị trí."
            if not status.get("available"):
                return "GeoIP hiện không khả dụng; chưa thể kết luận về vị trí đăng nhập."
            return ("GeoIP dùng cơ sở dữ liệu cục bộ. Cảnh báo chỉ dựa trên vị trí IP ước lượng, "
                    "có thể sai khi dùng VPN và không tự khóa tài khoản.")

        btn_geoip_status.click(_guard(load_geoip_status, 1), [st_token], [md_geoip_status], api_name=False)

        def notification_markdown(status):
            labels = {"disabled": "Đang tắt", "outbox": "Demo outbox — chưa gửi ra dịch vụ thật",
                      "webpush": "Web Push đã cấu hình", "twilio": "SMS đã cấu hình"}
            push, sms = status.get("push", {}), status.get("sms", {})
            phone = sms.get("phone") or "Chưa có số đã xác minh"
            if not re.fullmatch(r"[•*]{4}[0-9]{4}", phone):
                phone = "Chưa có số đã xác minh"
            count = len(push.get("subscriptions", []))
            return (f"**Push:** {labels.get(push.get('mode'), 'Chưa xác định')} · {count} đăng ký.\n\n"
                    f"**SMS:** {labels.get(sms.get('mode'), 'Chưa xác định')} · {phone}.")

        def notifications_snapshot(token):
            return notification_markdown(_api(token, "GET", "/api/auth/notifications/status"))

        btn_notifications_refresh.click(_guard(notifications_snapshot, 1), [st_token], [md_notifications], api_name=False)

        def prepare_push(token):
            status = _api(token, "GET", "/api/auth/notifications/status")
            key = status.get("push", {}).get("application_server_key") or ""
            if not status.get("push", {}).get("available") or not re.fullmatch(r"[A-Za-z0-9_-]{87}", key):
                raise gr.Error("Web Push chưa được cấu hình. Hãy kiểm tra trạng thái kênh thông báo.")
            nonce = secrets.token_hex(16)
            marker = (f'<span data-scap-push-request="{nonce}" data-scap-push-key="{key}" '
                      'data-scap-push-action="subscribe"></span>')
            return (marker, {"nonce": nonce, "account": _token_digest(token), "action": "subscribe"},
                    gr.update(value="Cho phép và bật thông báo Push", visible=True), "", notification_markdown(status))

        btn_push_prepare.click(_guard(prepare_push, 5), [st_token],
                               [push_bridge, st_push, btn_push_enable, tb_push_result, md_notifications], api_name=False)

        def prepare_push_local_remove(token):
            nonce = secrets.token_hex(16)
            marker = (f'<span data-scap-push-request="{nonce}" '
                      'data-scap-push-action="unsubscribe_browser"></span>')
            return (marker, {"nonce": nonce, "account": _token_digest(token), "action": "unsubscribe_browser"},
                    gr.update(value="Xác nhận gỡ Push trên trình duyệt này", visible=True), "",
                    "Bấm **Xác nhận gỡ Push trên trình duyệt này** để dừng nhận Push trên trình duyệt này. "
                    "Sau đó bạn có thể chuẩn bị bật Push cho tài khoản hiện tại.")

        btn_push_local_remove.click(_guard(prepare_push_local_remove, 5), [st_token],
                                    [push_bridge, st_push, btn_push_enable, tb_push_result, md_notifications], api_name=False)

        def finish_push(token, raw, state, password, code):
            closed = ("", {}, gr.update(value="Cho phép và bật thông báo Push", visible=False), "", "", "")
            try:
                payload = json.loads(raw) if isinstance(raw, str) and len(raw) <= 8000 else {}
            except (ValueError, RecursionError):
                payload = {}
            if (not isinstance(payload, dict) or not state or state.get("account") != _token_digest(token)
                    or payload.get("nonce") != state.get("nonce")):
                _ui_notice(gr.Warning, "Yêu cầu Push đã hết hạn; hãy chuẩn bị lại.")
                return closed + (gr.skip(),)
            if "error" in payload:
                _ui_notice(gr.Warning, "Chưa hoàn tất được yêu cầu Push. Kiểm tra HTTPS và quyền thông báo trên trình duyệt.")
                return closed + (gr.skip(),)
            if state.get("action") == "unsubscribe_browser":
                if (payload.get("action") != "unsubscribe_browser"
                        or payload.get("status") not in ("removed", "absent")):
                    _ui_notice(gr.Warning, "Chưa xác nhận được việc gỡ Push. Hãy chuẩn bị yêu cầu mới.")
                    return closed + (gr.skip(),)
                _ui_notice(gr.Info, "Trình duyệt đã gỡ đăng ký Push. Bạn có thể chuẩn bị bật Push cho tài khoản hiện tại.")
                return closed + ("Đã gỡ đăng ký Push trên trình duyệt này. Bấm **Chuẩn bị bật Push trên trình duyệt này** để đăng ký lại.",)
            if payload.get("action") == "unsubscribe_browser":
                _ui_notice(gr.Warning, "Yêu cầu Push không khớp; hãy chuẩn bị lại.")
                return closed + (gr.skip(),)
            try:
                _with_step_up(token, password, code,
                              lambda: _api(token, "POST", "/api/auth/notifications/push", payload.get("subscription")), "Bật Push")
            except gr.Error as error:
                if getattr(error, "status_code", None) != 409:
                    raise
                _ui_notice(gr.Warning,
                           "Đăng ký Push bị trùng hoặc đã đạt giới hạn. Nếu trình duyệt đang gắn tài khoản khác, "
                           "hãy bấm “Gỡ đăng ký Push trên trình duyệt này”, xác nhận rồi chuẩn bị bật Push lại.")
                return closed + (gr.skip(),)
            _ui_notice(gr.Info, "Đã lưu đăng ký Push. Xem trạng thái kênh để phân biệt demo và dịch vụ thật.")
            return closed + (notifications_snapshot(token),)

        btn_push_done.click(_guard(finish_push, 7), [st_token, tb_push_result, st_push, tb_acct_pw, tb_acct_code],
                            [push_bridge, st_push, btn_push_enable, tb_push_result, tb_acct_pw, tb_acct_code,
                             md_notifications], api_name=False)

        def disable_push(token, password, code):
            _with_step_up(token, password, code, lambda: _api(token, "DELETE", "/api/auth/notifications/push"), "Tắt Push")
            return notifications_snapshot(token), "", ""

        btn_push_disable.click(_guard(disable_push, 3), [st_token, tb_acct_pw, tb_acct_code],
                               [md_notifications, tb_acct_pw, tb_acct_code], api_name=False)

        def request_phone(token, phone, password, code):
            response = _with_step_up(token, password, code,
                                     lambda: _api(token, "POST", "/api/auth/notifications/phone/request", {"phone": (phone or "").strip()}),
                                     "Gửi mã xác minh số điện thoại")
            delivery = "Mã được ghi vào outbox demo, chưa gửi SMS thật." if response.get("delivery") == "demo_outbox" else "Nhà cung cấp đã chấp nhận yêu cầu gửi mã."
            return (notifications_snapshot(token) + "\n\n" + delivery,
                    {"challenge_id": response["challenge_id"], "account": _token_digest(token)}, "", "", "")

        btn_phone_request.click(_guard(request_phone, 5), [st_token, tb_alert_phone, tb_acct_pw, tb_acct_code],
                                [md_notifications, st_phone_proof, tb_alert_code, tb_acct_pw, tb_acct_code], api_name=False)

        def verify_phone(token, proof, state):
            if not state or state.get("account") != _token_digest(token):
                raise gr.Error("Yêu cầu xác minh đã hết hạn; hãy gửi mã mới.")
            response = _api(token, "POST", "/api/auth/notifications/phone/verify",
                            {"challenge_id": state["challenge_id"], "code": (proof or "").strip()})
            return notification_markdown(response), {}, "", ""

        btn_phone_verify.click(_guard(verify_phone, 4), [st_token, tb_alert_code, st_phone_proof],
                               [md_notifications, st_phone_proof, tb_alert_code, tb_alert_phone], api_name=False)

        def remove_phone(token, password, code):
            _with_step_up(token, password, code, lambda: _api(token, "DELETE", "/api/auth/notifications/phone"), "Tắt SMS")
            return notifications_snapshot(token), {}, "", "", "", ""

        btn_phone_remove.click(_guard(remove_phone, 6), [st_token, tb_acct_pw, tb_acct_code],
                               [md_notifications, st_phone_proof, tb_alert_phone, tb_alert_code, tb_acct_pw, tb_acct_code], api_name=False)

        # ---- passkey: thêm / xóa ----
        def prepare_passkey(token, name, password, code):
            options = _with_step_up(
                token, password, code,
                lambda: _api(token, "POST", "/api/auth/passkeys/registration/options"),
                "Thêm passkey",
            )
            nonce = secrets.token_hex(16)
            encoded = base64.urlsafe_b64encode(
                json.dumps(options["public_key"], separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            markup = (
                f'<span data-scap-passkey-request="{nonce}" data-scap-passkey-mode="create" '
                f'data-scap-passkey-options="{encoded}"></span>'
            )
            state = {"challenge_id": options["challenge_id"], "nonce": nonce,
                     "name": (name or "").strip()[:64]}
            hint = gr.update(
                value=(
                    "Bấm **Xác nhận trên thiết bị này**, sau đó làm theo hộp thoại của trình duyệt "
                    "(vân tay, khuôn mặt hoặc PIN). Yêu cầu hết hạn sau 3 phút."
                ),
                visible=True,
            )
            return markup, state, hint, gr.update(visible=True), "", ""

        btn_passkey_add.click(
            _guard(prepare_passkey, 6), [st_token, tb_passkey_name, tb_acct_pw, tb_acct_code],
            [passkey_bridge, st_passkey, md_passkey_hint, btn_passkey_create, tb_acct_pw,
             tb_acct_code],
        )

        def finish_passkey_registration(token, result, state):
            payload = _passkey_payload(result, "create")
            closed = ("", {}, gr.update(value="", visible=False), gr.update(visible=False), "")
            if not state or payload.get("nonce") != state.get("nonce"):
                _ui_notice(gr.Warning, "Yêu cầu tạo passkey đã hết hạn; hãy bấm “Thêm passkey” lại.")
                return closed + (gr.skip(), gr.skip(), gr.skip())
            if "error" in payload:
                _ui_notice(gr.Warning, _passkey_error_message(payload))
                return closed + (gr.skip(), gr.skip(), gr.skip())
            row = _api(
                token,
                "POST",
                "/api/auth/passkeys/registration/verify",
                {
                    "challenge_id": state["challenge_id"],
                    "credential": payload.get("credential"),
                    "name": state.get("name") or None,
                },
            )
            _ui_notice(gr.Info, f"Đã thêm passkey “{row['name']}”.")
            table, choices = _passkeys_snapshot(token)
            return closed + (table, gr.update(choices=choices, value=None), "")

        btn_passkey_register_done.click(
            _guard(finish_passkey_registration, 8), [st_token, tb_passkey_result, st_passkey],
            [passkey_bridge, st_passkey, md_passkey_hint, btn_passkey_create, tb_passkey_result,
             df_passkeys, dd_passkey_remove, tb_passkey_name],
            api_name=False,
        )

        def remove_passkey(token, passkey_id, password, code):
            if not passkey_id:
                _ui_notice(gr.Warning, "Chọn passkey cần xóa.")
                return gr.skip(), gr.skip(), gr.skip(), gr.skip()
            _with_step_up(
                token, password, code,
                lambda: _api(token, "DELETE", f"/api/auth/passkeys/{passkey_id}"),
                "Xóa passkey",
            )
            _ui_notice(gr.Info, "Đã xóa passkey.")
            table, choices = _passkeys_snapshot(token)
            return table, gr.update(choices=choices, value=None), "", ""

        btn_passkey_remove.click(
            _guard(remove_passkey, 4), [st_token, dd_passkey_remove, tb_acct_pw, tb_acct_code],
            [df_passkeys, dd_passkey_remove, tb_acct_pw, tb_acct_code],
        )

        # ---- thiết bị ----
        def refresh_devices(token):
            table, revoke = _devices_snapshot(token)
            return table, gr.update(choices=revoke, value=None)

        btn_dev_refresh.click(_guard(refresh_devices, 2), [st_token], [df_devices, dd_revoke])

        def revoke_device(token, jti):
            if not jti:
                _ui_notice(gr.Warning, "Chọn một phiên cần thu hồi.")
                return gr.skip(), gr.skip()
            _api(token, "DELETE", f"/api/auth/sessions/{jti}")
            _ui_notice(gr.Info, "Đã thu hồi phiên đăng nhập.")
            return refresh_devices(token)

        btn_revoke.click(_guard(revoke_device, 2), [st_token, dd_revoke], [df_devices, dd_revoke])

        def logout_all(token, request: gr.Request = None):
            try:
                _api(token, "POST", "/api/auth/logout-all")
            except Exception:
                _ui_notice(gr.Warning, "Không thể thu hồi phiên lúc này. Vui lòng thử lại.")
                return tuple(gr.skip() for _ in RESET_OUTS)
            _ui_notice(gr.Info, "Đã thu hồi mọi phiên đăng nhập.")
            return _reset_tuple(request)

        btn_logout_all.click(_guard(logout_all, len(RESET_OUTS)), [st_token], RESET_OUTS)

        # ---- quản trị ----
        def users_page_snapshot(token, keep=None, previous=None, keep_record=None):
            append = bool(previous and previous.get("account") == _token_digest(token)
                          and previous.get("has_more"))
            page = _read_page(token, "/api/admin/users/page",
                              offset=previous["next_offset"] if append else 0)
            state = _page_state(token, page, previous=previous if append else None)
            if (isinstance(keep_record, dict) and keep_record.get("id") == keep
                and keep not in {item["id"] for item in state["items"]}):
                state["items"].append(keep_record)
            users = state["items"]
            table = _table_html(USER_HEADERS, [
                [u["username"], u["role"], "Hoạt động" if u["is_active"] else "Đã khóa",
                 "Bật" if u["mfa_enabled"] else "—", _fmt(u["created_at"])]
                for u in users
            ])
            choices = [(f"{u['username']} ({u['role']})", u["id"]) for u in users]
            selected = keep if keep in {u["id"] for u in users} else None
            return (table, gr.update(choices=choices, value=selected), state,
                    _page_summary(state, "tài khoản"), gr.update(visible=state["has_more"]))

        def admin_snapshot(token, keep=None, keep_record=None):
            stats = _api(token, "GET", "/api/admin/stats")
            metrics = (
                f"**Người dùng**\n\n## {stats['total_users']}\n\nĐang hoạt động {stats['active_users']}",
                f"**Hội thoại**\n\n## {stats['total_sessions']}\n\nTin nhắn đã mã hóa {stats['total_messages']}",
                f"**Đăng nhập lỗi**\n\n## {stats['recent_login_failures']}\n\nTrong 60 phút gần nhất",
                f"**Từ chối quyền**\n\n## {stats['recent_auth_denials']}\n\nTrong 60 phút gần nhất",
            )
            stats_md = f"Cập nhật: {time.strftime('%d/%m/%Y %H:%M:%S UTC', time.gmtime())}"
            availability = stats.get("availability")
            if availability:
                requests = availability["requests"]
                streams = availability["streams"]
                password_ops = availability["password_operations"]
                rejected = sum(availability["rejections"].values())
                stats_md += (
                    "\n\n**Tài nguyên xử lý · tiến trình hiện tại**\n\n"
                    f"Yêu cầu: **{requests['active']}/{requests['limit']}** · "
                    f"Luồng giao diện: **{streams['active']}/{streams['limit']}** · "
                    f"Băm mật khẩu: **{password_ops['active']}/{password_ops['limit']}**\n\n"
                    f"Sự kiện giao diện lưu giữ: **{availability['gradio_retained_events']}/"
                    f"{availability['gradio_retained_event_limit']}** · "
                    f"Lượt từ chối ghi nhận: **{rejected}**"
                )
                recent = availability.get("http_recent")
                if recent:
                    statuses = recent["status_classes"]
                    stats_md += (
                        f"\n\n**HTTP · tiến trình hiện tại ({recent['window_seconds']} giây)**\n\n"
                        f"Phản hồi: **{recent['responses']}** · "
                        f"Bị giới hạn/quá tải (429/503): **{recent['throttled_responses']}** · "
                        f"Lỗi máy chủ (5xx): **{statuses['5xx']}** · "
                        f"Ngắt trước phản hồi: **{statuses['unanswered']}**\n\n"
                        f"Độ trễ đến header trung bình: **{recent['average_latency_ms']:.2f} ms** · "
                        f"Phản hồi chậm hơn 1 giây: **{recent['slow_responses']}**."
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
            availability_labels = {
                "http_overload": "Nhiều phản hồi bị giới hạn hoặc quá tải (429/503)",
                "http_server_errors": "Tỷ lệ lỗi máy chủ tăng (5xx)",
                "http_unanswered": "Nhiều yêu cầu ngắt trước khi có phản hồi",
                "http_slow_headers": "Nhiều phản hồi mất hơn 1 giây đến header",
                "request_capacity_full": "Các vị trí xử lý yêu cầu đang đầy",
                "stream_capacity_full": "Các vị trí luồng giao diện đang đầy",
                "password_capacity_full": "Các vị trí băm mật khẩu đang đầy",
            }
            observed_alerts = availability.get("alerts", []) if availability else []
            if observed_alerts:
                lines = "\n".join(
                    f"- {'🔴 CAO' if a['severity'] == 'high' else '🟡 TRUNG BÌNH'} — "
                    f"{availability_labels[a['code']]}: **{a['count']}**"
                    for a in observed_alerts if a["code"] in availability_labels
                )
                alerts_md += (
                    "\n\n**Cảnh báo vận hành (60 giây / tài nguyên hiện tại):**\n"
                    + lines
                )
            return (*metrics, stats_md, alerts_md,
                    *users_page_snapshot(token, keep, keep_record=keep_record))

        def refresh_admin(token, keep=None, keep_record=None):
            try:
                return admin_snapshot(token, keep, keep_record)
            except gr.Error as err:
                # A failed multi-API refresh cannot leave an older observation
                # looking current, or retain an account choice no longer read.
                checked_at = time.strftime("%d/%m/%Y %H:%M:%S UTC", time.gmtime())
                diagnostic = _safe_markdown_text(_error_text(err))
                message = f"**Không tải được dữ liệu quản trị.** {diagnostic}\n\nLần thử: {checked_at}"
                _ui_notice(gr.Warning, _error_text(err))
                metrics = tuple(
                    f"**{title}**\n\n## —\n\nKhông tải được\n\nLần thử: {checked_at}"
                    for title in ("Người dùng", "Hội thoại", "Đăng nhập lỗi", "Từ chối quyền")
                )
                return (*metrics, message, message, message, gr.update(choices=[], value=None),
                        {}, message, gr.update(visible=False))

        ADMIN_OUTS = [
            md_metric_users,
            md_metric_sessions,
            md_metric_login,
            md_metric_denials,
            md_stats,
            md_alerts,
            df_users,
            dd_user_pick,
            st_users_page,
            md_users_page,
            btn_users_more,
        ]
        btn_adm_refresh.click(_guard(refresh_admin, len(ADMIN_OUTS)), [st_token], ADMIN_OUTS)
        # Mở tab là điều hướng: số liệu cũ ở lại tới khi số liệu mới về, không
        # phủ lớp "processing" lên từng thẻ.
        adm_tab.select(_guard(refresh_admin, len(ADMIN_OUTS)), [st_token], ADMIN_OUTS, show_progress="hidden")
        btn_users_more.click(
            _guard(users_page_snapshot, 5), [st_token, dd_user_pick, st_users_page],
            [df_users, dd_user_pick, st_users_page, md_users_page, btn_users_more],
            trigger_mode="once",
        )

        def clear_admin_credentials():
            return "", "", ""

        ADMIN_SECRET_OUTS = [tb_admin_pw, tb_admin_code, tb_cu_pw]

        def set_role(token, user_id, role, password="", code=""):
            if not user_id:
                _ui_notice(gr.Warning, "Chọn một người dùng trước.")
                return tuple(gr.skip() for _ in ADMIN_OUTS)
            updated = _with_step_up(
                token, password, code,
                lambda: _api(token, "PATCH", f"/api/admin/users/{user_id}/role", {"role": role}),
                "Đổi vai trò",
            )
            _ui_notice(gr.Info, f"Đã đổi vai trò thành {role}.")
            return refresh_admin(token, keep=user_id, keep_record=updated)

        btn_set_role.click(
            _guard(set_role, len(ADMIN_OUTS)),
            [st_token, dd_user_pick, dd_role_new, tb_admin_pw, tb_admin_code], ADMIN_OUTS,
        ).then(clear_admin_credentials, [], ADMIN_SECRET_OUTS, show_progress="hidden")

        def set_status(token, user_id, active, password="", code=""):
            if not user_id:
                _ui_notice(gr.Warning, "Chọn một người dùng trước.")
                return tuple(gr.skip() for _ in ADMIN_OUTS)
            updated = _with_step_up(
                token, password, code,
                lambda: _api(token, "PATCH", f"/api/admin/users/{user_id}/status", {"is_active": active}),
                "Mở khóa" if active else "Khóa",
            )
            _ui_notice(gr.Info, "Đã mở khóa tài khoản." if active else "Đã khóa tài khoản.")
            return refresh_admin(token, keep=user_id, keep_record=updated)

        btn_lock.click(
            _guard(lambda tk, uid, pw="", code="": set_status(tk, uid, False, pw, code), len(ADMIN_OUTS)),
            [st_token, dd_user_pick, tb_admin_pw, tb_admin_code],
            ADMIN_OUTS,
        ).then(clear_admin_credentials, [], ADMIN_SECRET_OUTS, show_progress="hidden")
        btn_unlock.click(
            _guard(lambda tk, uid, pw="", code="": set_status(tk, uid, True, pw, code), len(ADMIN_OUTS)),
            [st_token, dd_user_pick, tb_admin_pw, tb_admin_code],
            ADMIN_OUTS,
        ).then(clear_admin_credentials, [], ADMIN_SECRET_OUTS, show_progress="hidden")

        USER_DELETE_OUTS = [st_delete_user_target, grp_user_delete, md_user_delete,
                            tb_user_delete_name, tb_admin_pw, tb_admin_code]
        USER_DELETE_HIDDEN = ({}, gr.update(visible=False), "", "", "", "")

        def cancel_delete_user():
            return USER_DELETE_HIDDEN

        def request_delete_user(token, user_id, page_state):
            valid = page_state and page_state.get("account") == _token_digest(token)
            target = next((item for item in page_state.get("items", []) if item["id"] == user_id), None) if valid else None
            if not target:
                _ui_notice(gr.Warning, "Làm mới danh sách và chọn lại tài khoản cần xóa.")
                return USER_DELETE_HIDDEN
            username = target["username"]
            return (
                {"id": user_id, "username": username, "account": _token_digest(token)},
                gr.update(visible=True),
                f"**Xóa vĩnh viễn tài khoản “{_safe_markdown_text(username)}”?**\n\n"
                "Các hội thoại, tin nhắn, phiên đăng nhập và thông tin bảo vệ tài khoản "
                "của người này sẽ bị xóa. Không thể hoàn tác trong ứng dụng. "
                "Nhập đúng tên đăng nhập bên dưới; mật khẩu/mã 2FA quản trị viên vẫn được yêu cầu khi cần xác thực lại.",
                "", "", "",
            )

        btn_del_user.click(
            _guard(request_delete_user, len(USER_DELETE_OUTS)),
            [st_token, dd_user_pick, st_users_page], USER_DELETE_OUTS, trigger_mode="once",
        )
        btn_user_delete_cancel.click(cancel_delete_user, None, USER_DELETE_OUTS, api_name=False)
        dd_user_pick.input(cancel_delete_user, None, USER_DELETE_OUTS, queue=False,
                           api_name=False, show_progress="hidden")
        for trigger in (btn_adm_refresh.click, adm_tab.select, btn_set_role.click,
                        btn_lock.click, btn_unlock.click):
            trigger(cancel_delete_user, None, USER_DELETE_OUTS, queue=False,
                    api_name=False, show_progress="hidden")

        def delete_user(token, user_id, pending, typed_name, password="", code=""):
            skip_admin = tuple(gr.skip() for _ in ADMIN_OUTS)
            if (not pending or pending.get("id") != user_id
                or pending.get("account") != _token_digest(token)):
                _ui_notice(gr.Warning, "Tài khoản hoặc phiên đã thay đổi. Hãy xác nhận lại mục cần xóa.")
                return (*skip_admin, *USER_DELETE_HIDDEN)
            if (typed_name or "").strip() != pending.get("username"):
                return (*skip_admin, pending, gr.update(visible=True),
                        "**Chưa xóa tài khoản.** Nhập đúng tên đăng nhập đã chọn để xác nhận.", "", "", "")
            try:
                _with_step_up(
                    token, password, code,
                    lambda: _api(token, "DELETE", f"/api/admin/users/{pending['id']}"), "Xóa tài khoản",
                )
            except gr.Error as err:
                return (*skip_admin, pending, gr.update(visible=True),
                        "**Chưa xóa được tài khoản.** " + _safe_markdown_text(_error_text(err)),
                        "", "", "")
            _ui_notice(gr.Info, "Đã xóa tài khoản cùng toàn bộ dữ liệu của người đó.")
            return (*refresh_admin(token), *USER_DELETE_HIDDEN)

        btn_user_delete_confirm.click(
            _guard(delete_user, len(ADMIN_OUTS) + len(USER_DELETE_OUTS)),
            [st_token, dd_user_pick, st_delete_user_target, tb_user_delete_name, tb_admin_pw, tb_admin_code],
            [*ADMIN_OUTS, *USER_DELETE_OUTS], trigger_mode="once",
        )

        def create_user(token, username, password, role, admin_password="", code=""):
            username = (username or "").strip()
            if not 3 <= len(username) <= 32:
                _ui_notice(gr.Warning, "Tên đăng nhập phải từ 3 đến 32 ký tự.")
                return tuple(gr.skip() for _ in range(len(ADMIN_OUTS) + 2))
            if len(password or "") < PASSWORD_MIN:
                _ui_notice(gr.Warning, f"Mật khẩu phải có ít nhất {PASSWORD_MIN} ký tự.")
                return tuple(gr.skip() for _ in range(len(ADMIN_OUTS) + 2))
            _with_step_up(
                token, admin_password, code,
                lambda: _api(
                    token, "POST", "/api/admin/users",
                    {"username": username, "password": password, "role": role},
                ),
                "Tạo",
            )
            _ui_notice(gr.Info, "Đã tạo tài khoản mới.")
            return refresh_admin(token) + ("", "")

        btn_cu.click(
            _guard(create_user, len(ADMIN_OUTS) + 2),
            [st_token, tb_cu_name, tb_cu_pw, dd_cu_role, tb_admin_pw, tb_admin_code],
            ADMIN_OUTS + [tb_cu_name, tb_cu_pw],
        ).then(clear_admin_credentials, [], ADMIN_SECRET_OUTS, show_progress="hidden")

        # ---- nhật ký ----
        def load_audit(token, limit):
            checked_at = time.strftime("%d/%m/%Y %H:%M:%S UTC", time.gmtime())
            try:
                rows = _api(token, "GET", "/api/admin/audit", params={"limit": str(int(limit))})
            except gr.Error as err:
                _ui_notice(gr.Warning, _error_text(err))
                return (
                    "**Không tải được nhật ký kiểm toán.** "
                    f"{_safe_markdown_text(_error_text(err))}\n\nLần thử: {checked_at}"
                )
            table = _table_html(AUDIT_HEADERS, [
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
            ])
            return f"Cập nhật: {checked_at}\n\n{table}"

        btn_audit.click(_guard(load_audit, 1), [st_token, sl_audit], [df_audit])
        mod_tab.select(_guard(load_audit, 1), [st_token, sl_audit], [df_audit], show_progress="hidden")
        # Cả phần kéo và ô số đều là cùng một Slider. Phải tải lại bảng khi
        # giá trị đổi, nếu không giao diện chỉ đổi con số cục bộ còn dữ liệu
        # vẫn là lần tải trước đó.
        sl_audit.change(
            _guard(load_audit, 1),
            [st_token, sl_audit],
            [df_audit],
            show_progress="hidden",
            trigger_mode="always_last",
        )

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
                if getattr(err, "status_code", None) == 403:
                    return "**Không thể xác minh chuỗi:** chức năng này cần vai trò admin."
                return f"**Không thể xác minh chuỗi:** {_safe_markdown_text(_error_text(err))}"
            total = _safe_markdown_text(data.get("total_events", 0))
            verified = _safe_markdown_text(data.get("verified_events", 0))
            unsealed = _safe_markdown_text(data.get("unsealed_events", 0))
            checked_at = _safe_markdown_text(_fmt(data.get("checked_at")))
            checked_by = _safe_markdown_text(data.get("checked_by") or "admin")
            if data.get("total_events") == 0:
                chain = (
                    "**Chưa có nhật ký để xác minh.** Hệ thống sẽ tạo nhật ký khi có đăng ký, "
                    "đăng nhập, tạo hội thoại hoặc gửi tin nhắn."
                )
            elif data.get("chain_intact"):
                chain = (
                    f"**Chuỗi nội bộ nguyên vẹn.** Đã xác minh **{verified}/{total}** bản ghi "
                    "còn lưu; nội dung và liên kết trong chuỗi khớp."
                )
            # Trường hợp riêng: không có mắt xích nào sai, nhưng một số bản ghi
            # nằm ngoài chuỗi. Đó là lỗ hổng phạm vi bảo vệ, không phải bằng
            # chứng bị tấn công — và phải nói đúng như vậy.
            elif data.get("reason") == "unsealed_events":
                chain = (
                    f"**Chuỗi chưa phủ hết nhật ký.** {verified}/{total} bản ghi được bảo vệ; "
                    f"**{unsealed} bản ghi chưa được niêm phong** (bản ghi đầu tiên: "
                    f"#{_safe_markdown_text(data.get('first_unsealed_id'))}). Các bản ghi này có thể bị sửa mà "
                    "không bị phát hiện. Chạy python scripts/repair_audit_chain.py để vá."
                )
            else:
                reason = {
                    "entry_hash_mismatch": "nội dung bản ghi đã bị sửa",
                    "prev_hash_mismatch": "có bản ghi bị xoá hoặc bị đảo thứ tự",
                }.get(data.get("reason"), data.get("reason") or "không xác định")
                chain = (
                    "**Chuỗi đã bị phá vỡ.** Bản ghi đầu tiên có vấn đề: "
                    f"#{_safe_markdown_text(data.get('first_broken_id'))} - "
                    f"{_safe_markdown_text(reason)}. Đã xác minh được "
                    f"{verified}/{total} bản ghi trước điểm gãy."
                )
            # An intact local chain does not establish external anchoring. A
            # missing/deleted tail may only be visible in the checkpoint result,
            # including when no local events remain.
            if (data.get("checkpoint_present") is False
                and data.get("checkpoint_reason") == "missing_checkpoint"):
                checkpoint = (
                    "**Chưa có checkpoint.** Chưa có bằng chứng neo WORM để xác nhận "
                    "toàn vẹn đầy đủ; cần tạo và xác minh checkpoint đầu tiên."
                )
            elif data.get("checkpoint_intact") is False:
                checkpoint = (
                    "**Checkpoint không hợp lệ.** Chưa thể xác nhận toàn vẹn đầy đủ. "
                    f"Lý do: {_safe_markdown_text(data.get('checkpoint_reason') or 'không xác định')}."
                )
                if data.get("checkpoint_failed_id") is not None:
                    checkpoint += (
                        f" Checkpoint lỗi: {_safe_markdown_text(data['checkpoint_failed_id'])}."
                    )
                if data.get("checkpoint_failed_event_id") is not None:
                    checkpoint += (
                        f" Bản ghi được neo: #{_safe_markdown_text(data['checkpoint_failed_event_id'])}."
                    )
            elif "checkpoint_intact" not in data:
                checkpoint = "**Chưa có kết quả checkpoint.** Chưa xác nhận được neo WORM bên ngoài."
            elif data.get("external_checkpoint_required") is False:
                checkpoint = (
                    "**Giới hạn bảo vệ: chưa có neo WORM bên ngoài.** "
                    "Chuỗi nội bộ không đủ để loại trừ việc xóa phần đuôi nhật ký."
                )
            elif data.get("verification_scope_changed") is True:
                checkpoint = (
                    "**Nhật ký đã thay đổi trong lúc xác minh.** "
                    "Kết quả chuỗi và checkpoint thuộc hai thời điểm khác nhau; "
                    "hãy chạy xác minh lại để kết luận toàn vẹn đầy đủ."
                )
            elif (
                data.get("chain_intact") is True
                and data.get("checkpoint_intact") is True
                and data.get("external_checkpoint_required") is True
                and data.get("high_assurance_intact") is True
            ):
                checkpoint = "**Đủ bằng chứng neo WORM:** checkpoint và chuỗi khớp theo kết quả máy chủ."
            else:
                pending = _safe_markdown_text(data.get("checkpoint_unanchored_events", "chưa xác định"))
                checkpoint = (
                    "**Chưa đủ bằng chứng neo WORM.** "
                    f"Số bản ghi chưa được neo: {pending}. "
                    f"Trạng thái: {_safe_markdown_text(data.get('checkpoint_reason') or 'checkpoint chưa được xác nhận đầy đủ')}."
                )
            return (
                f"{chain}\n\n{checkpoint}\n\nKiểm tra lúc {checked_at} bởi {checked_by}."
            )

        def detection_rows(token):
            rows = _api(token, "GET", "/api/admin/ids/detections", params={"limit": "100"})
            return [
                [
                    r.get("rule_id", ""),
                    r.get("mitre_technique") or "—",
                    _SEV_ICON.get(r.get("severity"), r.get("severity", "")),
                    r.get("description", ""),
                    r.get("source_ip", ""),
                    f"{r.get('method', '')} {r.get('path', '')}".strip(),
                    (r.get("evidence") or "")[:60],
                ]
                for r in (rows or [])
            ]

        def anomaly_rows(token, window):
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

        def verify_ids_detection_ui(token):
            if not token:
                return "**Không thể kiểm chứng:** phiên đăng nhập đã hết hạn. Hãy đăng nhập lại."
            try:
                data = _api(token, "POST", "/api/admin/ids/verify-detection")
            except gr.Error as err:
                if getattr(err, "status_code", None) == 403:
                    return "**Không thể chạy kiểm chứng:** chức năng này cần vai trò admin."
                return f"**Không thể chạy kiểm chứng:** {_error_text(err)}"
            total = data.get("total_scenarios", 0)
            detected = data.get("detected_scenarios", 0)
            missed = data.get("missed_scenarios", 0)
            rate = data.get("detection_rate", 0)
            if missed == 0:
                return (
                    f"**Đạt: {detected}/{total} Hit ({rate}%).** Các luật chữ ký đang nhận diện "
                    "được nhóm kịch bản T1190 đã hỗ trợ. Kết quả đã được ghi vào audit/SIEM.\n\n"
                    "*Phạm vi: kiểm tra nội bộ engine IDS; không thay thế pentest hay kiểm thử "
                    "pipeline SIEM bên ngoài.*"
                )
            misses = ", ".join(
                item.get("name", "kịch bản")
                for item in data.get("scenarios", [])
                if item.get("result") == "miss"
            )
            return (
                f"**Cần xử lý: {detected}/{total} Hit ({rate}%), bỏ sót {missed}.** "
                f"Kịch bản chưa phát hiện: {misses or 'không xác định'}."
            )

        def load_anomalies(token, window):
            return security_snapshot(
                lambda: anomaly_rows(token, window), "Bất thường", ANOMALY_HEADERS,
                f"Cửa sổ {int(window)} phút",
            )

        def blocklist_rows(token):
            rows = _api(token, "GET", "/api/admin/ids/blocklist")
            return [[r.get("source_ip", ""), r.get("seconds_remaining", "")] for r in (rows or [])]

        def unblock_ip(token, ip, password="", code=""):
            ip = (ip or "").strip()
            if not ip:
                _ui_notice(gr.Warning, "Nhập địa chỉ IP cần gỡ chặn.")
                return gr.skip(), gr.skip(), gr.skip()
            _with_step_up(
                token, password, code,
                lambda: _api(token, "DELETE", f"/api/admin/ids/blocklist/{ip}"), "Gỡ chặn",
            )
            _ui_notice(gr.Info, f"Đã gỡ chặn {ip}.")
            metric, table = security_snapshot(
                lambda: blocklist_rows(token), "Nguồn bị chặn", BLOCKLIST_HEADERS,
                "Đang hiệu lực", admin_only=True,
            )
            return metric, table, ""

        def security_snapshot(fetch_rows, title, headers, detail, *, admin_only=False):
            """Render one response consistently in both its card and table.

            Never turn an unavailable response into an empty successful result.
            The attempted read time remains visible even after its toast fades.
            """
            checked_at = time.strftime("%d/%m/%Y %H:%M:%S UTC", time.gmtime())
            try:
                rows = fetch_rows()
            except gr.Error as err:
                if admin_only and getattr(err, "status_code", None) == 403:
                    status = "Cần vai trò admin"
                else:
                    status = "Không tải được"
                    _ui_notice(gr.Warning, _error_text(err))
                metric = f"**{title}**\n\n## —\n\n{status} · {detail}\n\nLần thử: {checked_at}"
                diagnostic = _safe_markdown_text(_error_text(err))
                table = f"**{status}.** {diagnostic}\n\nLần thử: {checked_at}"
                return metric, table
            return (
                f"**{title}**\n\n## {len(rows)}\n\n{detail}\n\nCập nhật: {checked_at}",
                _table_html(headers, rows),
            )

        def refresh_security(token, window):
            """Nạp ba thẻ số liệu và ba bảng IDS. Mỗi khối bọc riêng để thiếu
            quyền ở một khối không làm trắng toàn bộ màn hình (moderator không
            có quyền admin).

            Xác minh chuỗi audit duyệt lại toàn bộ nhật ký nên chậm dần theo số
            bản ghi; nó chạy ở bước .then() riêng để các thẻ không phải chờ.
            """

            det, det_table = security_snapshot(
                lambda: detection_rows(token), "Dấu hiệu IDS", DETECTION_HEADERS,
                "Tối đa 100 dấu hiệu gần nhất",
            )
            anom, anom_table = load_anomalies(token, window)
            block, block_table = security_snapshot(
                lambda: blocklist_rows(token), "Nguồn bị chặn", BLOCKLIST_HEADERS,
                "Đang hiệu lực", admin_only=True,
            )
            return (
                det, anom, block, det_table, anom_table, block_table,
            )

        SEC_OUTS = [
            md_sec_detections,
            md_sec_anomalies,
            md_sec_blocks,
            df_sec_det,
            df_sec_anom,
            df_sec_block,
        ]
        # Mở tab hay "Làm mới toàn bộ": thẻ số liệu cập nhật tại chỗ, không phủ
        # lớp "processing"; kết luận chuỗi audit điền vào khi kiểm xong.
        for trigger in (btn_sec_all.click, sec_tab.select):
            trigger(
                _guard(refresh_security, len(SEC_OUTS)), [st_token, sl_sec_win], SEC_OUTS,
                show_progress="hidden",
            ).then(verify_chain_ui, [st_token], [md_sec_verdict], show_progress="hidden")
        btn_sec_verify.click(verify_chain_ui, [st_token], [md_sec_verdict])
        btn_sec_verify_ids.click(verify_ids_detection_ui, [st_token], [md_sec_ids_verdict])
        for trigger in (btn_sec_anom.click, sl_sec_win.change):
            trigger(
                _guard(load_anomalies, 2), [st_token, sl_sec_win], [md_sec_anomalies, df_sec_anom],
                show_progress="hidden", trigger_mode="always_last",
            )
        btn_sec_unblock.click(
            _guard(unblock_ip, 3), [st_token, tb_sec_ip, tb_sec_pw, tb_sec_code],
            [md_sec_blocks, df_sec_block, tb_sec_ip],
        ).then(lambda: ("", ""), [], [tb_sec_pw, tb_sec_code], show_progress="hidden")

    # The page triggers events by fn_index. Nothing needs Gradio's public API
    # catalogue (/gradio_api/info, "Use via API"), which listed every handler —
    # login, reset, admin actions — as a ready-made map for bots.
    for fn in demo.fns.values():
        fn.api_visibility = "private"
        if fn.fn is not None and fn.fn.__name__ in {"find_in_session", "load_more_session_search"}:
            fn._scap_scope_ids = (st_session_search_generation._id,)
        if fn.fn is not None and fn.fn.__name__ in {"load_cipher", "load_crypto_info"}:
            fn._scap_scope_ids = (st_cipher_generation._id,)
    demo.config = demo.get_config_file()
    demo.queue(
        max_size=queue_max_size,
        default_concurrency_limit=concurrency_limit,
        api_open=False,
    )
    install_gradio_capacity(
        demo, retained_events=retained_events, result_ttl_seconds=result_ttl_seconds,
        state_capacity=state_capacity,
    )
    _install_session_result_guard(demo, st_token, st_mfa)
    return demo
