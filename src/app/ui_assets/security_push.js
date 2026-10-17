// Opt-in Web Push bridge. No bearer token is readable by this script.
// The Python callback validates the one-use nonce and current account before
// forwarding a subscription to the authenticated REST endpoint.
(() => {
  let busy = false;
  const NONCE = /^[a-f0-9]{32}$/;

  function deliver(payload) {
    const input = document.querySelector("#security-push-result textarea, #security-push-result input");
    const done = document.querySelector("#btn-security-push-done");
    if (!input || !done) return;
    input.value = JSON.stringify(payload);
    input.dispatchEvent(new Event("input", {bubbles: true}));
    setTimeout(() => done.click(), 60);
  }

  function decodeKey(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]{87}$/.test(value)) throw new Error("InvalidKey");
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=");
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function enable() {
    if (busy) return;
    const marker = document.querySelector("#security-push-bridge [data-scap-push-request]");
    const nonce = marker?.getAttribute("data-scap-push-request") || "";
    if (!NONCE.test(nonce)) return deliver({error: "not_prepared"});
    const action = marker?.getAttribute("data-scap-push-action") || "subscribe";
    if (action === "unsubscribe_browser") return unsubscribeBrowser(nonce);
    if (action !== "subscribe") return deliver({nonce, error: "not_prepared"});
    if (!window.isSecureContext || !navigator.serviceWorker || !window.PushManager || !window.Notification) {
      return deliver({nonce, error: "unsupported"});
    }
    busy = true;
    try {
      // Permission is requested only from this explicit user click.
      const permission = await Notification.requestPermission();
      if (permission !== "granted") return deliver({nonce, error: "permission_denied"});
      const registration = await navigator.serviceWorker.register("/security-push-worker.js", {scope: "/", updateViaCache: "none"});
      await navigator.serviceWorker.ready;
      const key = decodeKey(marker.getAttribute("data-scap-push-key"));
      let subscription = await registration.pushManager.getSubscription();
      // A changed VAPID deployment needs a fresh browser subscription.
      const currentKey = subscription?.options?.applicationServerKey;
      if (subscription && currentKey && (currentKey.byteLength !== key.byteLength || !Array.from(new Uint8Array(currentKey)).every((byte, index) => byte === key[index]))) {
        await subscription.unsubscribe();
        subscription = null;
      }
      subscription ||= await registration.pushManager.subscribe({userVisibleOnly: true, applicationServerKey: key});
      deliver({nonce, subscription: subscription.toJSON()});
    } catch (_) {
      // Browser errors can include capability URLs; return a fixed reason.
      deliver({nonce, error: "registration_failed"});
    } finally {
      busy = false;
    }
  }

  async function unsubscribeBrowser(nonce) {
    if (!window.isSecureContext || !navigator.serviceWorker?.getRegistration) {
      return deliver({nonce, action: "unsubscribe_browser", error: "unsupported"});
    }
    busy = true;
    try {
      // Use only an existing registration. This action never requests permission,
      // creates a worker, or sends an authenticated request to change server rows.
      const registration = await navigator.serviceWorker.getRegistration("/");
      const subscription = await registration?.pushManager?.getSubscription();
      if (!subscription) return deliver({nonce, action: "unsubscribe_browser", status: "absent"});
      const removed = await subscription.unsubscribe();
      if (!removed) return deliver({nonce, action: "unsubscribe_browser", error: "unsubscribe_failed"});
      deliver({nonce, action: "unsubscribe_browser", status: "removed"});
    } catch (_) {
      deliver({nonce, action: "unsubscribe_browser", error: "unsubscribe_failed"});
    } finally {
      busy = false;
    }
  }

  document.addEventListener("click", (event) => {
    if (event.target.closest?.("#btn-security-push-enable")) void enable();
  }, true);
})();
