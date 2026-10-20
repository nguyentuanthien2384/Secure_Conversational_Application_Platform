// Static same-origin script: works without eval or Gradio's compiled JS hooks.
// Only a short-lived, one-use handoff ticket is read from this dedicated node.
// The browser's opaque session cookie is HttpOnly; bearer tokens stay server-side.
(() => {
  let lastAction = "";
  let pending = Promise.resolve();

  function warn() {
    let notice = document.getElementById("scap-session-warning");
    if (!notice) {
      notice = document.createElement("div");
      notice.id = "scap-session-warning";
      notice.setAttribute("role", "alert");
      const target = document.getElementById("app-sec") || document.body;
      target.prepend(notice);
    }
    notice.textContent = "Chưa lưu được phiên đăng nhập. Bạn sẽ cần đăng nhập lại nếu tải lại trang.";
  }

  async function apply(ticket) {
    const response = await fetch(`/api/ui-session/${ticket ? "attach" : "clear"}`, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: {"Content-Type": "application/json", "X-SCAP-UI": "1"},
      body: ticket ? JSON.stringify({ticket}) : undefined,
    });
    if (!response.ok) throw new Error("Session handoff failed");
    document.getElementById("scap-session-warning")?.remove();
  }

  function inspect() {
    const bridge = document.getElementById("session-bridge");
    const item = bridge?.querySelector("[data-scap-session-ticket], [data-scap-session-clear]");
    if (!item) {
      lastAction = "";
      return;
    }
    const ticket = item.getAttribute("data-scap-session-ticket");
    if (ticket !== null && !/^[A-Za-z0-9_-]{43}$/.test(ticket)) return;
    const action = ticket || "clear";
    if (action === lastAction) return;
    lastAction = action;
    // Preserve action order, especially logout while an attach is in flight.
    pending = pending.then(() => apply(ticket)).catch(warn);
  }

  // Session countdown. The server re-syncs the remaining seconds only every
  // few seconds (data-scap-countdown); the browser ticks the display locally,
  // so the UI no longer needs a server round trip every second.
  const countdowns = new WeakMap();

  function formatLeft(left) {
    const hours = Math.floor(left / 3600);
    const minutes = Math.floor((left % 3600) / 60);
    const seconds = String(left % 60).padStart(2, "0");
    return hours ? `${hours}:${String(minutes).padStart(2, "0")}:${seconds}` : `${minutes}:${seconds}`;
  }

  function tickCountdowns() {
    const now = performance.now();
    for (const node of document.querySelectorAll("[data-scap-countdown]")) {
      const total = Number(node.getAttribute("data-scap-countdown"));
      const warnAt = Number(node.getAttribute("data-scap-warn-at"));
      if (!Number.isInteger(total) || total < 0) continue;
      let base = countdowns.get(node);
      if (!base || base.total !== total) {
        base = {total, at: now};
        countdowns.set(node, base);
      }
      const left = Math.max(0, total - Math.floor((now - base.at) / 1000));
      const text = node.querySelector("strong");
      const icon = node.querySelector("[data-scap-countdown-icon]");
      const shown = formatLeft(left);
      if (text && text.textContent !== shown) text.textContent = shown;
      const mark = Number.isInteger(warnAt) && left <= warnAt ? "⚠️" : "⏳";
      if (icon && icon.textContent !== mark) icon.textContent = mark;
    }
  }

  function chatText(content) {
    const text = (content.innerText || content.textContent || "").trim();
    const links = new Set();
    for (const anchor of content.querySelectorAll("a[href]")) {
      try {
        const url = new URL(anchor.getAttribute("href"));
        if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password &&
            !text.includes(url.href)) links.add(url.href);
      } catch (_) {
        // A relative or malformed destination is never copied as a source URL.
      }
    }
    return text + (links.size ? `\n\nLiên kết:\n${[...links].join("\n")}` : "");
  }

  async function writeChatClipboard(text) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (_) {
      // Some mobile browsers deny the Clipboard API; retain the user gesture's
      // legacy copy path without keeping plaintext in storage or calling APIs.
    }
    const focus = document.activeElement;
    const area = document.createElement("textarea");
    area.value = text;
    area.readOnly = true;
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.append(area);
    area.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch (_) { /* Leave selection available. */ }
    area.remove();
    focus?.focus({preventScroll: true});
    return copied;
  }

  function copyChat(event) {
    const button = event.target instanceof Element ? event.target.closest("button[aria-label]") : null;
    const chat = document.getElementById("chat-history");
    if (!button || !chat?.contains(button)) return;
    const label = button.getAttribute("aria-label");
    const all = ["Copy conversation", "Copied conversation"].includes(label);
    if (!all && !["Copy message", "Copied message"].includes(label)) return;
    // Each button group follows its own row; .message-wrap contains the whole
    // conversation, so selecting its first row would copy somebody else's turn.
    const sibling = button.closest(".message-buttons")?.previousElementSibling;
    const row = button.closest(".message-row") ||
      (sibling?.matches(".message-row") ? sibling : null);
    if (!all && !row) return;
    const rows = all ? [...chat.querySelectorAll(".message-row")] : [row];
    const messages = rows.map(item => {
      const contents = [...item.querySelectorAll(".message-content")].map(chatText).filter(Boolean);
      const text = contents.join("\n\n");
      if (!text || !all) return text;
      return `${item.classList.contains("user-row") ? "Bạn" : "Trợ lý"}:\n${text}`;
    }).filter(Boolean);
    if (!messages.length) return;
    // Gradio copies its content prop, which now contains generated safe HTML.
    // Stop only these native chat copy actions, then copy the visible text.
    event.preventDefault();
    event.stopImmediatePropagation();
    const originalTitle = button.getAttribute("title");
    writeChatClipboard(messages.join("\n\n")).then(copied => {
      button.setAttribute("title", copied ? "Đã sao chép" : "Chưa sao chép được; hãy chọn nội dung để sao chép.");
      setTimeout(() => {
        if (originalTitle === null) button.removeAttribute("title");
        else button.setAttribute("title", originalTitle);
      }, 2000);
    });
  }

  // Chat attachments. The file goes as raw bytes to a dedicated same-origin
  // route (HttpOnly session cookie, no base64, never through the Gradio
  // queue); only the returned one-use upload id or an error code is handed to
  // the hidden Gradio box, so the server can bind the file to this tab's login.
  const CHAT_FILE_UPLOAD_PATH = "/api/ui-session/chat-file";
  const DEFAULT_CHAT_FILE_MAX_BYTES = 10 * 1024 * 1024;
  const CHAT_FILE_ERRORS = new Set([
    "too_large", "empty", "unsupported_type", "invalid_name", "not_utf8", "binary",
    "bidi", "docx_invalid", "docx_too_large", "pdf_invalid", "pdf_encrypted", "pdf_no_text",
    "pdf_too_large", "session", "busy", "rate_limited",
    "timeout",
  ]);
  let chatFileBusy = false;

  function deliverChatFile(payload) {
    const input = document.querySelector("#chat-file-payload textarea, #chat-file-payload input");
    const button = document.querySelector("#btn-chat-file-stage");
    if (!input || !button) return;
    input.value = JSON.stringify(payload);
    input.dispatchEvent(new Event("input", {bubbles: true}));
    setTimeout(() => button.click(), 60);
  }

  function encodeFileName(name) {
    const bytes = new TextEncoder().encode(name);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function showChatFileProgress(picker, text) {
    const hint = picker.closest(".scap-chat-file-bar")?.querySelector("[data-scap-file-label]");
    const label = picker.closest(".scap-chat-file-bar")?.querySelector(".scap-chat-file-btn");
    if (hint) {
      if (hint.dataset.scapIdleText === undefined) hint.dataset.scapIdleText = hint.textContent;
      hint.textContent = text ?? hint.dataset.scapIdleText;
    }
    label?.setAttribute("aria-disabled", text === null ? "false" : "true");
    picker.disabled = text !== null;
  }

  function uploadChatFile(file, onProgress) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", CHAT_FILE_UPLOAD_PATH);
      xhr.responseType = "json";
      xhr.timeout = 180000;
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.setRequestHeader("X-SCAP-UI", "1");
      xhr.setRequestHeader("X-SCAP-File-Name", encodeFileName(file.name || ""));
      xhr.upload.onprogress = event => {
        if (event.lengthComputable && event.total) onProgress(event.loaded / event.total);
      };
      xhr.onload = () => {
        const body = xhr.response && typeof xhr.response === "object" ? xhr.response : {};
        if (xhr.status === 200 && /^[A-Za-z0-9_-]{32}$/.test(body.upload_id || "")) {
          resolve({upload_id: body.upload_id});
        } else if (CHAT_FILE_ERRORS.has(body.code)) {
          resolve({error: body.code});
        } else {
          resolve({error: xhr.status === 413 ? "too_large" : "upload_failed"});
        }
      };
      xhr.onerror = xhr.ontimeout = xhr.onabort = () => resolve({error: "upload_failed"});
      xhr.send(file);
    });
  }

  async function onChatFileChange(event) {
    const picker = event.target instanceof HTMLInputElement ? event.target : null;
    if (!picker || picker.id !== "chat-file-input") return;
    const file = picker.files && picker.files[0];
    picker.value = "";
    if (!file || chatFileBusy) return;
    const limit = Number(picker.dataset.scapMaxBytes) || DEFAULT_CHAT_FILE_MAX_BYTES;
    if (file.size > limit) {
      deliverChatFile({error: "too_large"});
      return;
    }
    if (!file.size) {
      deliverChatFile({error: "empty"});
      return;
    }
    chatFileBusy = true;
    showChatFileProgress(picker, "Đang tải tệp lên… 0%");
    try {
      const result = await uploadChatFile(file, ratio => {
        showChatFileProgress(picker, ratio < 1
          ? `Đang tải tệp lên… ${Math.floor(ratio * 100)}%`
          : "Đang trích xuất nội dung…");
      });
      deliverChatFile(result);
    } catch (_) {
      deliverChatFile({error: "read_failed"});
    } finally {
      chatFileBusy = false;
      showChatFileProgress(picker, null);
    }
  }

  function start() {
    new MutationObserver(inspect).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["data-scap-session-ticket", "data-scap-session-clear"],
    });
    document.addEventListener("click", copyChat, {capture: true});
    document.addEventListener("change", onChatFileChange, {capture: true});
    inspect();
    setInterval(tickCountdowns, 500);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, {once: true});
  } else {
    start();
  }
})();
