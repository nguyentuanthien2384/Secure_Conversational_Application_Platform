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

  const searchWidgets = new WeakMap();
  function renderSearchWidgets() {
    const panel = document.getElementById("chat-search-suggestions");
    for (const node of panel?.querySelectorAll("[data-scap-google-search-widget]") || []) {
      const encoded = node.getAttribute("data-scap-google-search-widget");
      const previous = searchWidgets.get(node);
      if (!encoded || encoded.length > 45000 || previous?.encoded === encoded) continue;
      try {
        // This marker is created only after strict server validation. No raw
        // widget HTML enters the outer page; a closed shadow root contains the
        // provider's unchanged markup and scopes its branding styles.
        const bytes = Uint8Array.from(atob(encoded), char => char.charCodeAt(0));
        const original = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
        if (!original || original.length > 32000) continue;
        // Paint/layout containment prevents even valid provider CSS from
        // covering controls outside the widget's own visible area.
        node.style.contain = "layout paint style";
        node.style.display = "block";
        node.style.overflow = "auto";
        const shadow = previous?.shadow || node.attachShadow({mode: "closed"});
        shadow.innerHTML = original;
        searchWidgets.set(node, {encoded, shadow});
      } catch (_) {
        // Reject malformed markers without exposing contents in browser logs.
      }
    }
  }

  function start() {
    new MutationObserver(inspect).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["data-scap-session-ticket", "data-scap-session-clear"],
    });
    new MutationObserver(renderSearchWidgets).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["data-scap-google-search-widget"],
    });
    document.addEventListener("click", copyChat, {capture: true});
    inspect();
    renderSearchWidgets();
    setInterval(tickCountdowns, 500);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, {once: true});
  } else {
    start();
  }
})();
