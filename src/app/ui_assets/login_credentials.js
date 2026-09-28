// Cooperate with the browser password manager. Passwords never enter web storage.
(() => {
  const preferenceKey = "scap.remember-login";
  let pending = null;
  let pendingTimer;
  let revision = 0;
  let syncing = false;
  let loginVisible = false;
  let requested = false;
  let lastAction = "";
  let lastResult = "";
  let inFlight = false;
  let checkboxNode;
  const field = (id) => document.querySelector(`#${id} input, #${id} textarea`);
  const checkbox = () => document.querySelector('#chk-remember-login input[type="checkbox"]');
  const enabled = () => checkbox()?.checked === true;
  const supported = () => typeof window.PasswordCredential === "function" &&
    typeof navigator.credentials?.get === "function";
  const visible = () => Boolean(document.querySelector("#login-ready [data-scap-login-ready]") &&
    field("li-user")?.getClientRects().length && field("li-pass")?.getClientRects().length);

  function discard() {
    pending = null;
    clearTimeout(pendingTimer);
    revision += 1;
  }

  function sync(input, value = input.value) {
    syncing = true;
    try {
      input.value = value;
      input.dispatchEvent(new Event("input", {bubbles: true}));
      input.dispatchEvent(new Event("change", {bubbles: true}));
    } finally {
      syncing = false;
    }
  }

  function capture() {
    // Gradio ignores repeated submissions while its first request is running.
    // Keep its captured credentials paired with that same request.
    if (!visible() || inFlight) return;
    inFlight = true;
    const user = field("li-user");
    const password = field("li-pass");
    discard();
    // Native autofill does not always notify Svelte/Gradio before submission.
    sync(user);
    sync(password);
    if (!enabled() || !supported() || !user.value.trim() || !password.value) return;
    pending = {id: user.value.trim(), password: password.value, origin: location.origin};
    pendingTimer = setTimeout(discard, 300000);
  }

  async function restore() {
    if (!enabled() || !supported() || !visible()) return;
    const user = field("li-user");
    const password = field("li-pass");
    if (user.value || password.value) return;
    const current = revision;
    try {
      const saved = await navigator.credentials.get({password: true, mediation: "optional"});
      // Typing, cancelling or leaving the form always wins over a slow manager.
      if (current !== revision || !enabled() || !visible() ||
          user !== field("li-user") || password !== field("li-pass") ||
          user.value || password.value || saved?.type !== "password") return;
      sync(user, saved.id);
      sync(password, saved.password);
      // Prefill only: the user still chooses when to press Enter or Sign in.
    } catch (_) {
      // Unsupported, disabled or dismissed managers leave normal autofill intact.
    }
  }

  async function save() {
    const credentials = pending;
    discard();
    if (!credentials || !enabled() || !supported()) return;
    try {
      await navigator.credentials.store(new PasswordCredential(credentials));
    } catch (_) {
      // Saving is optional and must never prevent a successful login.
    }
  }

  function inspect() {
    // Gradio's password input currently drops its Python html_attributes.
    // Repair new/remounted inputs as well as the initial login form.
    for (const [id, autocomplete, name] of [
      ["li-user", "username", "username"], ["li-pass", "current-password", "password"],
      ["re-user", "username", "username"], ["re-pass", "new-password", "password"],
    ]) {
      const input = field(id);
      for (const [attribute, value] of [["autocomplete", autocomplete], ["name", name]]) {
        if (input && input.getAttribute(attribute) !== value) input.setAttribute(attribute, value);
      }
    }
    const check = checkbox();
    if (check && check !== checkboxNode) {
      checkboxNode = check;
      try {
        if (localStorage.getItem(preferenceKey) === "false") {
          check.checked = false;
          check.dispatchEvent(new Event("change", {bubbles: true}));
        }
      } catch (_) { /* Storage may be blocked; keep the visible preference. */ }
    }
    const item = document.querySelector(
      "#session-bridge [data-scap-session-ticket], #session-bridge [data-scap-session-clear]",
    );
    const ticket = item?.getAttribute("data-scap-session-ticket");
    const action = item ? ticket || "clear" : "";
    if (action !== lastAction) {
      lastAction = action;
      if (action === "clear") { discard(); inFlight = false; }
      else if (/^[A-Za-z0-9_-]{43}$/.test(ticket || "")) void save();
    }
    const result = document.querySelector("#session-bridge [data-scap-login-result]")
      ?.getAttribute("data-scap-login-result");
    if (result && result !== lastResult) {
      lastResult = result;
      inFlight = false;
    }
    const showing = visible();
    if (showing !== loginVisible) {
      loginVisible = showing;
      requested = false;
      revision += 1;
    }
    if (showing && !requested) {
      requested = true;
      void restore();
    }
  }

  function start() {
    document.addEventListener("input", (event) => {
      if (!syncing && event.target.closest?.("#li-user, #li-pass")) discard();
    }, true);
    document.addEventListener("change", (event) => {
      if (!event.target.closest?.("#chk-remember-login")) return;
      discard();
      try { localStorage.setItem(preferenceKey, String(enabled())); } catch (_) {}
      if (enabled()) void restore();
    }, true);
    document.addEventListener("click", (event) => {
      if (event.target.closest?.("#btn-mfa-cancel, #btn-logout, #btn-logout-all")) discard();
      if (event.target.closest?.("#btn-login")) capture();
    }, true);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing && !event.repeat &&
          event.target.closest?.("#li-user, #li-pass")) capture();
    }, true);
    window.addEventListener("pagehide", discard);
    new MutationObserver(inspect).observe(document.body, {
      childList: true, subtree: true, attributes: true,
      attributeFilter: ["class", "style", "hidden", "autocomplete", "name", "data-scap-login-ready",
        "data-scap-login-result", "data-scap-session-ticket", "data-scap-session-clear"],
    });
    inspect();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, {once: true});
  } else {
    start();
  }
})();
