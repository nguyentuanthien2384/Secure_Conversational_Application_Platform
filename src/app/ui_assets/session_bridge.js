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

  function start() {
    new MutationObserver(inspect).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["data-scap-session-ticket", "data-scap-session-clear"],
    });
    inspect();
    setInterval(tickCountdowns, 500);
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, {once: true});
  } else {
    start();
  }
})();
