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

  function start() {
    new MutationObserver(inspect).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["data-scap-session-ticket", "data-scap-session-clear"],
    });
    inspect();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, {once: true});
  } else {
    start();
  }
})();
