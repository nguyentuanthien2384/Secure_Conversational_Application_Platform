"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/login_credentials.js"), "utf8");
const ticket = "T".repeat(43);
const flush = () => new Promise((resolve) => setImmediate(resolve));

function browser({get = async () => null, supported = true, preference, ready = true} = {}) {
  const state = {ready, visible: true, action: null, result: null};
  const listeners = new Map();
  const timers = new Map();
  const calls = {get: [], store: [], input: [], storage: []};
  let inspect;
  let timerId = 0;
  const storage = new Map(preference === undefined ? [] : [["scap.remember-login", preference]]);
  const dispatch = (type, target, extra = {}) => {
    for (const callback of listeners.get(type) || []) callback({type, target, ...extra});
  };
  const element = (id, value = "") => ({
    id, value, checked: true, attributes: {},
    getAttribute(name) { return this.attributes[name] ?? null; },
    setAttribute(name, value) { this.attributes[name] = value; },
    closest(selectors) { return selectors.split(",").some((item) => item.trim() === `#${id}`) ? this : null; },
    getClientRects() { return state.visible ? [{}] : []; },
    dispatchEvent(event) {
      if (event.type === "input") calls.input.push([id, this.value]);
      dispatch(event.type, this);
    },
  });
  const user = element("li-user");
  const password = element("li-pass");
  const registerUser = element("re-user");
  const registerPassword = element("re-pass");
  const checkbox = element("chk-remember-login");
  const document = {
    body: {}, readyState: "complete",
    addEventListener(type, callback) {
      listeners.set(type, [...(listeners.get(type) || []), callback]);
    },
    querySelector(selector) {
      if (selector === "#li-user input, #li-user textarea") return user;
      if (selector === "#li-pass input, #li-pass textarea") return password;
      if (selector === "#re-user input, #re-user textarea") return registerUser;
      if (selector === "#re-pass input, #re-pass textarea") return registerPassword;
      if (selector === '#chk-remember-login input[type="checkbox"]') return checkbox;
      if (selector === "#login-ready [data-scap-login-ready]") return state.ready ? {} : null;
      if (selector === "#session-bridge [data-scap-login-result]") return state.result ? {
        getAttribute: () => state.result,
      } : null;
      if (selector.startsWith("#session-bridge ")) return state.action ? {
        getAttribute: () => state.action === "clear" ? null : state.action,
      } : null;
      throw new Error(`Unexpected selector ${selector}`);
    },
  };
  const credentials = {
    get(options) { calls.get.push({...options}); return get(options); },
    async store(saved) { calls.store.push({...saved}); },
  };
  const context = {
    document, navigator: {credentials}, location: {origin: "https://scap.test"},
    Event: class { constructor(type) { this.type = type; } },
    MutationObserver: class { constructor(callback) { inspect = callback; } observe() {} },
    localStorage: {
      getItem: (key) => storage.get(key),
      setItem: (key, value) => { calls.storage.push([key, value]); storage.set(key, value); },
    },
    setTimeout: (callback) => { timers.set(++timerId, callback); return timerId; },
    clearTimeout: (id) => timers.delete(id),
    addEventListener: (type, callback) => document.addEventListener(type, callback),
  };
  if (supported) context.PasswordCredential = class {
    constructor(values) { Object.assign(this, values, {type: "password"}); }
  };
  context.window = context;
  vm.runInNewContext(source, context);
  return {
    state, user, password, registerUser, registerPassword, checkbox, calls, credentials, inspect: () => inspect(),
    click: (id) => dispatch("click", element(id)),
    enter: (target, extra) => dispatch("keydown", target, {key: "Enter", ...extra}),
    edit(target, value) { target.value = value; dispatch("input", target); },
    toggle(checked) { checkbox.checked = checked; dispatch("change", checkbox); },
    expire() { for (const callback of [...timers.values()]) callback(); },
    complete(result) { state.result = result; inspect(); },
    authenticate() { state.visible = false; state.action = ticket; state.result = "success"; inspect(); },
  };
}

test("normalizes password-manager attributes that Gradio omits and repairs later changes", () => {
  const b = browser();
  assert.equal(b.user.getAttribute("autocomplete"), "username");
  assert.equal(b.user.getAttribute("name"), "username");
  assert.equal(b.password.getAttribute("autocomplete"), "current-password");
  assert.equal(b.password.getAttribute("name"), "password");
  assert.equal(b.registerUser.getAttribute("autocomplete"), "username");
  assert.equal(b.registerPassword.getAttribute("autocomplete"), "new-password");
  b.password.setAttribute("autocomplete", "");
  b.inspect();
  assert.equal(b.password.getAttribute("autocomplete"), "current-password");
});

test("waits for restore readiness, prefills and emits input without logging in", async () => {
  const b = browser({ready: false, get: async () => ({type: "password", id: "alice", password: "secret"})});
  assert.equal(b.calls.get.length, 0);
  b.state.ready = true;
  b.inspect();
  await flush();
  assert.equal(b.user.value, "alice");
  assert.equal(b.password.value, "secret");
  assert.deepEqual(b.calls.get, [{password: true, mediation: "optional"}]);
  assert.deepEqual(b.calls.input, [["li-user", "alice"], ["li-pass", "secret"]]);
  assert.deepEqual(b.calls.store, []);
  assert.deepEqual(b.calls.storage, []);
  b.inspect();
  assert.equal(b.calls.get.length, 1);
});

for (const trigger of ["click", "username Enter", "password Enter"]) {
  test(`${trigger} synchronizes native autofill and saves only on successful authentication`, async () => {
    const b = browser();
    b.user.value = " alice ";
    b.password.value = "autofilled-password";
    if (trigger === "click") b.click("btn-login");
    else b.enter(trigger.startsWith("username") ? b.user : b.password);
    assert.deepEqual(b.calls.input, [["li-user", " alice "], ["li-pass", "autofilled-password"]]);
    assert.deepEqual(b.calls.store, []);
    b.password.value = ""; // Gradio clears its password output after success.
    b.authenticate();
    await flush();
    assert.deepEqual(b.calls.store, [{id: "alice", password: "autofilled-password", origin: "https://scap.test", type: "password"}]);
    assert.deepEqual(b.calls.storage, []);
    b.inspect();
    assert.equal(b.calls.store.length, 1);
  });
}

test("MFA challenge waits for verification before saving", async () => {
  const b = browser();
  b.user.value = "alice";
  b.password.value = "secret";
  b.click("btn-login");
  b.state.visible = false;
  b.complete("mfa-challenge");
  await flush();
  assert.deepEqual(b.calls.store, []);
  b.authenticate();
  assert.equal(b.calls.store.length, 1);
});

test("failed login without a session ticket never saves", async () => {
  const b = browser();
  b.user.value = "alice";
  b.password.value = "wrong";
  b.click("btn-login");
  b.inspect();
  await flush();
  assert.deepEqual(b.calls.store, []);
});

test("ignored repeat after an edit cannot save credentials from the ignored attempt", () => {
  const b = browser();
  b.user.value = "alice";
  b.password.value = "valid-password";
  b.click("btn-login");
  b.edit(b.password, "not-the-authenticated-password");
  b.enter(b.password);
  b.authenticate();
  assert.deepEqual(b.calls.store, []);
});

test("Shift+Enter does not lock capture when Gradio does not submit it", () => {
  const b = browser();
  b.user.value = "alice";
  b.password.value = "initial";
  b.enter(b.password, {shiftKey: true});
  assert.deepEqual(b.calls.input, []);
  b.edit(b.password, "verified");
  b.enter(b.password);
  b.authenticate();
  assert.equal(b.calls.store.length, 1);
  assert.equal(b.calls.store[0].password, "verified");
});

test("completion releases the capture lock so retrying after failure saves the verified password", () => {
  const b = browser();
  b.user.value = "alice";
  b.password.value = "wrong";
  b.click("btn-login");
  b.complete("failed-attempt-1");
  b.edit(b.password, "correct");
  b.enter(b.password);
  b.authenticate();
  assert.equal(b.calls.store.length, 1);
  assert.equal(b.calls.store[0].password, "correct");
});

for (const reason of ["edit", "cancel", "logout", "clear", "unchecked", "expiry"]) {
  test(`${reason} discards pending credentials even if a ticket arrives later`, () => {
    const b = browser();
    b.user.value = "alice";
    b.password.value = "secret";
    b.click("btn-login");
    if (reason === "edit") b.edit(b.password, "changed");
    if (reason === "cancel") b.click("btn-mfa-cancel");
    if (reason === "logout") b.click("btn-logout");
    if (reason === "clear") { b.state.action = "clear"; b.inspect(); }
    if (reason === "unchecked") b.toggle(false);
    if (reason === "expiry") b.expire();
    b.authenticate();
    assert.deepEqual(b.calls.store, []);
    assert.ok(b.calls.storage.every(([key, value]) => key === "scap.remember-login" && value === "false"));
  });
}

test("persisted opt-out disables retrieval and saving", () => {
  const b = browser({preference: "false"});
  assert.equal(b.checkbox.checked, false);
  assert.equal(b.calls.get.length, 0);
  b.user.value = "alice";
  b.password.value = "secret";
  b.click("btn-login");
  b.authenticate();
  assert.deepEqual(b.calls.store, []);
});

test("late retrieval cannot overwrite edits even when the user clears the field", async () => {
  let resolve;
  const b = browser({get: () => new Promise((done) => { resolve = done; })});
  b.edit(b.user, "new-account");
  b.edit(b.user, "");
  resolve({type: "password", id: "old-account", password: "old-secret"});
  await flush();
  assert.equal(b.user.value, "");
  assert.equal(b.password.value, "");
});

test("returning to the login form restores again without submitting", async () => {
  const b = browser({get: async () => ({type: "password", id: "alice", password: "secret"})});
  await flush();
  b.click("btn-login");
  b.authenticate();
  b.user.value = b.password.value = "";
  b.state.action = "clear";
  b.state.visible = true;
  b.inspect();
  await flush();
  assert.equal(b.calls.get.length, 2);
  assert.equal(b.user.value, "alice");
  assert.equal(b.calls.store.length, 1);
});

test("unsupported browsers still synchronize normal autofill", () => {
  const b = browser({supported: false});
  b.user.value = "alice";
  b.password.value = "secret";
  b.click("btn-login");
  b.authenticate();
  assert.equal(b.calls.input.length, 2);
  assert.deepEqual(b.calls.get, []);
  assert.deepEqual(b.calls.store, []);
});

test("manager rejection does not break login", async () => {
  const b = browser({get: async () => { throw new Error("dismissed"); }});
  b.credentials.store = async () => { throw new Error("disabled"); };
  await flush();
  b.user.value = "alice";
  b.password.value = "secret";
  b.click("btn-login");
  b.authenticate();
  await flush();
  assert.equal(b.calls.input.length, 2);
});
