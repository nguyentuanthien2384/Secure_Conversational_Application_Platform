// Deliberately no fetch handler: this worker never caches protected API/UI data.
self.addEventListener("push", (event) => {
  let body = "Mo SCAP de kiem tra hoat dong bao mat.";
  try {
    const raw = event.data?.text() || "";
    if (raw.length <= 1024) {
      const value = JSON.parse(raw);
      if (value && typeof value.body === "string" && value.body.length <= 256 && !/[\u0000-\u001f\u007f]/.test(value.body)) body = value.body;
    }
  } catch (_) { /* Display the fixed fallback without exposing parsing errors. */ }
  event.waitUntil(self.registration.showNotification("SCAP: Canh bao bao mat", {
    body, tag: "scap-security", renotify: true,
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    for (const client of await self.clients.matchAll({type: "window", includeUncontrolled: true})) {
      if (new URL(client.url).origin === self.location.origin) return client.focus();
    }
    return self.clients.openWindow("/");
  })());
});
