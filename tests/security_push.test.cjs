"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const bridge = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/security_push.js"), "utf8");
const worker = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/security_push_worker.js"), "utf8");
const nonce = "a".repeat(32);
const key = Buffer.alloc(65, 1).toString("base64url");
const subscription = {endpoint: "https://fcm.googleapis.com/wp/capability", keys: {p256dh: key, auth: "a".repeat(22)}};
const flush = () => new Promise((resolve) => setImmediate(resolve));

function browser({requestNonce = nonce, supported = true, permission = "granted", publicKey = key,
  initial, subscribe, ready = Promise.resolve(), action = "subscribe", registered = true} = {}) {
  const calls = {permission: [], register: [], subscribe: [], done: [], unsubscribe: 0, getRegistration: [], fetch: []};
  const input = {value: "", dispatchEvent() {}};
  let listener, inClick = false;
  const registration = {pushManager: {
    async getSubscription() { return initial || null; },
    async subscribe(options) {
      calls.subscribe.push(options);
      if (subscribe) return subscribe();
      return {toJSON: () => subscription};
    },
  }};
  const context = {
    document: {
      addEventListener(event, callback) { assert.equal(event, "click"); listener = callback; },
      querySelector(selector) {
        if (selector === "#security-push-bridge [data-scap-push-request]") return {getAttribute(name) {
          return {"data-scap-push-request": requestNonce, "data-scap-push-key": publicKey,
            "data-scap-push-action": action}[name];
        }};
        if (selector === "#security-push-result textarea, #security-push-result input") return input;
        if (selector === "#btn-security-push-done") return {click() { calls.done.push(JSON.parse(input.value)); }};
        throw new Error(`Unexpected selector ${selector}`);
      },
    },
    navigator: {serviceWorker: {
      ready,
      async register(...args) { calls.register.push(args); return registration; },
      async getRegistration(...args) { calls.getRegistration.push(args); return registered ? registration : undefined; },
    }},
    isSecureContext: supported,
    PushManager: class {},
    Notification: {async requestPermission() { calls.permission.push(inClick); return permission; }},
    async fetch(...args) { calls.fetch.push(args); throw new Error("No authenticated browser requests allowed"); },
    atob(value) { return Buffer.from(value, "base64").toString("binary"); },
    Uint8Array,
    Event: class {},
    setTimeout(callback) { callback(); },
  };
  context.window = context;
  vm.runInNewContext(bridge, context);
  return {calls, click() {
    inClick = true;
    try { listener({target: {closest: (selector) => selector === "#btn-security-push-enable" ? {} : null}}); }
    finally { inClick = false; }
  }};
}

test("push permission is requested only inside explicit click and nonce accompanies the public result", async () => {
  const b = browser();
  assert.equal(b.calls.permission.length, 0);
  b.click();
  await flush();
  assert.deepEqual(b.calls.permission, [true]);
  assert.deepEqual(JSON.parse(JSON.stringify(b.calls.register)), [["/security-push-worker.js", {scope: "/", updateViaCache: "none"}]]);
  assert.equal(b.calls.subscribe[0].userVisibleOnly, true);
  assert.equal(Buffer.from(b.calls.subscribe[0].applicationServerKey).toString("base64url"), key);
  assert.deepEqual(b.calls.done, [{nonce, subscription}]);
});

test("an invalid prepared nonce cannot request browser permission", async () => {
  const b = browser({requestNonce: "invalid"});
  b.click();
  await flush();
  assert.deepEqual(b.calls.permission, []);
  assert.deepEqual(b.calls.done, [{error: "not_prepared"}]);
});

test("unsupported insecure browsers fail before requesting permission", async () => {
  const b = browser({supported: false});
  b.click();
  await flush();
  assert.deepEqual(b.calls.permission, []);
  assert.deepEqual(b.calls.done, [{nonce, error: "unsupported"}]);
});

test("denied permission never registers a worker or subscribes", async () => {
  const b = browser({permission: "denied"});
  b.click();
  await flush();
  assert.deepEqual(b.calls.register, []);
  assert.deepEqual(b.calls.subscribe, []);
  assert.deepEqual(b.calls.done, [{nonce, error: "permission_denied"}]);
});

test("provider/browser exceptions cannot expose capability URLs or exception text", async () => {
  const b = browser({subscribe: async () => { throw new Error("PRIVATE-CAPABILITY-URL"); }});
  b.click();
  await flush();
  assert.deepEqual(b.calls.done, [{nonce, error: "registration_failed"}]);
  assert.equal(JSON.stringify(b.calls.done).includes("PRIVATE"), false);
});

test("a changed VAPID key retires the old browser subscription before subscribing", async () => {
  let retired = false;
  const b = browser({initial: {
    options: {applicationServerKey: Buffer.alloc(65, 2).buffer},
    async unsubscribe() { retired = true; },
  }});
  b.click();
  await flush();
  assert.equal(retired, true);
  assert.equal(b.calls.subscribe.length, 1);
  assert.deepEqual(b.calls.done, [{nonce, subscription}]);
});

test("matching subscriptions are reused and rapid clicks cannot duplicate permission prompts", async () => {
  const b = browser({initial: {
    options: {applicationServerKey: Uint8Array.from(Buffer.from(key, "base64url")).buffer},
    toJSON: () => subscription,
  }});
  b.click();
  b.click();
  await flush();
  assert.equal(b.calls.permission.length, 1);
  assert.equal(b.calls.subscribe.length, 0);
  assert.deepEqual(b.calls.done, [{nonce, subscription}]);
});

test("local unsubscribe waits for explicit confirmation and never requests permission or changes server state", async () => {
  let removed = 0;
  const b = browser({action: "unsubscribe_browser", initial: {
    async unsubscribe() { removed += 1; return true; },
  }});
  assert.equal(removed, 0);
  assert.deepEqual(b.calls.getRegistration, []);
  b.click();
  b.click();
  await flush();
  assert.equal(removed, 1);
  assert.deepEqual(b.calls.getRegistration, [["/"]]);
  assert.deepEqual(b.calls.permission, []);
  assert.deepEqual(b.calls.register, []);
  assert.deepEqual(b.calls.subscribe, []);
  assert.deepEqual(b.calls.fetch, []);
  assert.deepEqual(b.calls.done, [{nonce, action: "unsubscribe_browser", status: "removed"}]);
});

for (const registered of [true, false]) {
  test(`local unsubscribe reports absence without creating a registration (${registered})`, async () => {
    const b = browser({action: "unsubscribe_browser", registered});
    b.click();
    await flush();
    assert.deepEqual(b.calls.done, [{nonce, action: "unsubscribe_browser", status: "absent"}]);
    assert.deepEqual(b.calls.register, []);
    assert.deepEqual(b.calls.subscribe, []);
    assert.deepEqual(b.calls.permission, []);
  });
}

for (const behavior of ["false", "throw"]) {
  test(`local unsubscribe ${behavior} fails with a fixed reason and no capability text`, async () => {
    const b = browser({action: "unsubscribe_browser", initial: {
      async unsubscribe() {
        if (behavior === "throw") throw new Error("PRIVATE-CAPABILITY-URL");
        return false;
      },
    }});
    b.click();
    await flush();
    assert.deepEqual(b.calls.done, [{nonce, action: "unsubscribe_browser", error: "unsubscribe_failed"}]);
    assert.deepEqual(b.calls.fetch, []);
    assert.deepEqual(b.calls.permission, []);
  });
}

test("local unsubscribe requires the prepared nonce and a secure browser", async () => {
  for (const [requestNonce, supported] of [["invalid", true], [nonce, false]]) {
    const b = browser({action: "unsubscribe_browser", requestNonce, supported});
    b.click();
    await flush();
    assert.deepEqual(b.calls.getRegistration, []);
    assert.deepEqual(b.calls.permission, []);
    assert.equal(b.calls.done[0].error, requestNonce === nonce ? "unsupported" : "not_prepared");
  }
});

test("an unknown prepared action cannot subscribe or remove an existing browser subscription", async () => {
  let removed = false;
  const b = browser({action: "delete_everything", initial: {async unsubscribe() { removed = true; }}});
  b.click();
  await flush();
  assert.equal(removed, false);
  assert.deepEqual(b.calls.getRegistration, []);
  assert.deepEqual(b.calls.permission, []);
  assert.deepEqual(b.calls.done, [{nonce, error: "not_prepared"}]);
});

function serviceWorker({windows = []} = {}) {
  const listeners = {}, notifications = [], opened = [];
  const self = {
    addEventListener(event, handler) { listeners[event] = handler; },
    location: {origin: "https://scap.example"},
    registration: {async showNotification(...args) { notifications.push(args); }},
    clients: {async matchAll() { return windows; }, async openWindow(url) { opened.push(url); }},
  };
  vm.runInNewContext(worker, {self, URL});
  return {listeners, notifications, opened, async push(value) {
    let pending;
    listeners.push({data: {text: () => value}, waitUntil(value) { pending = value; }});
    await pending;
  }, async click() {
    let pending, closed = false;
    listeners.notificationclick({notification: {close() { closed = true; }}, waitUntil(value) { pending = value; }});
    await pending;
    assert.equal(closed, true);
  }};
}

test("worker has no fetch caching and displays only bounded notification text", async () => {
  const w = serviceWorker();
  assert.deepEqual(Object.keys(w.listeners).sort(), ["notificationclick", "push"]);
  await w.push(JSON.stringify({title: "untrusted title", body: "Fixed security alert", url: "https://evil.example"}));
  assert.equal(w.notifications[0][0], "SCAP: Canh bao bao mat");
  assert.equal(w.notifications[0][1].body, "Fixed security alert");
  assert.equal(w.notifications[0][1].data, undefined);
  await w.click();
  assert.deepEqual(w.opened, ["/"]);
});

for (const value of ["invalid-json", JSON.stringify({body: "x".repeat(257)}), JSON.stringify({body: "unsafe\ncontrol"}), "x".repeat(1025)]) {
  test(`worker safely falls back for malformed payload ${value.length}`, async () => {
    const w = serviceWorker();
    await w.push(value);
    assert.equal(w.notifications[0][1].body, "Mo SCAP de kiem tra hoat dong bao mat.");
  });
}

test("notification click focuses only a same-origin window", async () => {
  const focused = [];
  const w = serviceWorker({windows: [
    {url: "https://evil.example/", focus() { throw new Error("Unsafe focus"); }},
    {url: "https://scap.example/account", focus() { focused.push(true); }},
  ]});
  await w.click();
  assert.deepEqual(focused, [true]);
  assert.deepEqual(w.opened, []);
});
