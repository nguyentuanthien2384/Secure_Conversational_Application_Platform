"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/passkey.js"), "utf8");
const nonce = "a".repeat(32);
const flush = () => new Promise((resolve) => setImmediate(resolve));
const b64 = (value) => Buffer.from(value).toString("base64url");
const buffer = (value) => Uint8Array.from(value).buffer;
const options = {
  rpId: "localhost", challenge: b64([1, 2, 3]), userVerification: "required",
  allowCredentials: [{id: b64([4, 5, 6]), type: "public-key"}],
};

function browser({mode = "step-up", requestNonce = nonce, publicKey = options,
  supported = true, host = "localhost", get, encoded} = {}) {
  const calls = {get: [], create: [], fetch: [], done: [], input: []};
  const input = {
    value: "",
    dispatchEvent(event) { calls.input.push(event.type); },
  };
  const marker = {getAttribute(name) {
    return {
      "data-scap-passkey-request": requestNonce,
      "data-scap-passkey-mode": mode,
      "data-scap-passkey-options": encoded ?? b64(JSON.stringify(publicKey)),
    }[name] ?? null;
  }};
  let listener;
  let activeClick = false;
  const context = {
    document: {
      addEventListener(type, callback) { assert.equal(type, "click"); listener = callback; },
      querySelector(selector) {
        if (selector === "#passkey-bridge [data-scap-passkey-request]") return marker;
        if (selector === "#passkey-result textarea, #passkey-result input") return input;
        if (selector.startsWith("#btn-passkey-") && selector.endsWith("-done")) {
          return {click() { calls.done.push({selector, payload: JSON.parse(input.value)}); }};
        }
        throw new Error(`Unexpected selector ${selector}`);
      },
    },
    location: {hostname: host},
    navigator: {credentials: {
      async create(publicOptions) { calls.create.push(publicOptions); throw new Error("Unexpected create"); },
      get(publicOptions) {
        calls.get.push({options: publicOptions, inClick: activeClick});
        if (get) return get(publicOptions);
        return Promise.resolve({
          id: "BAUG", rawId: buffer([4, 5, 6]), type: "public-key",
          response: {
            clientDataJSON: buffer([7]), authenticatorData: buffer([8]),
            signature: buffer([9]), userHandle: buffer([10]),
          },
          getClientExtensionResults() { return {}; },
        });
      },
    }},
    async fetch(...args) { calls.fetch.push(args); throw new Error("Step-up must use the server callback"); },
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    TextDecoder, Uint8Array,
    Event: class { constructor(type) { this.type = type; } },
    setTimeout(callback) { callback(); },
  };
  context.window = context;
  if (supported) context.PublicKeyCredential = class {};
  vm.runInNewContext(source, context);
  return {
    calls,
    click(id = "btn-passkey-step-up") {
      activeClick = true;
      try {
        listener({target: {closest(selector) { return selector === `#${id}` ? {} : null; }}});
      } finally {
        activeClick = false;
      }
    },
  };
}

test("step-up calls the authenticator in the user gesture and sends only its public result", async () => {
  const b = browser();
  assert.equal(b.calls.get.length, 0);
  b.click();
  assert.equal(b.calls.get.length, 1);
  assert.equal(b.calls.get[0].inClick, true);
  const publicKey = b.calls.get[0].options.publicKey;
  assert.deepEqual([...new Uint8Array(publicKey.challenge)], [1, 2, 3]);
  assert.deepEqual([...new Uint8Array(publicKey.allowCredentials[0].id)], [4, 5, 6]);
  assert.equal(publicKey.userVerification, "required");
  await flush();
  assert.deepEqual(b.calls.done, [{selector: "#btn-passkey-step-up-done", payload: {
    mode: "step-up", nonce,
    credential: {
      id: "BAUG", rawId: "BAUG", type: "public-key", clientExtensionResults: {},
      response: {clientDataJSON: "Bw", authenticatorData: "CA", signature: "CQ", userHandle: "Cg"},
    },
  }}]);
  assert.deepEqual(b.calls.input, ["input"]);
  assert.deepEqual(b.calls.fetch, []);
  assert.deepEqual(b.calls.create, []);
});

for (const requestNonce of ["", "b".repeat(31), "B".repeat(32)]) {
  test(`invalid bridge nonce ${JSON.stringify(requestNonce)} cannot start a step-up`, async () => {
    const b = browser({requestNonce});
    b.click();
    await flush();
    assert.equal(b.calls.get.length, 0);
    assert.deepEqual(b.calls.done[0].payload, {mode: "step-up", error: "not_prepared"});
  });
}

test("registration and step-up cannot consume each other's prepared bridge", async () => {
  const registration = browser({mode: "create"});
  registration.click();
  const stepUp = browser();
  stepUp.click("btn-passkey-create");
  await flush();
  assert.deepEqual(registration.calls.done[0].payload, {mode: "step-up", error: "not_prepared"});
  assert.deepEqual(stepUp.calls.done[0].payload, {mode: "create", error: "not_prepared"});
  assert.equal(registration.calls.get.length, 0);
  assert.equal(stepUp.calls.create.length, 0);
});

test("lookalike RP hosts fail before opening the authenticator", async () => {
  const b = browser({host: "localhost.evil.test"});
  b.click();
  await flush();
  assert.equal(b.calls.get.length, 0);
  assert.deepEqual(b.calls.done[0].payload, {mode: "step-up", nonce, error: "wrong_host", rp_id: "localhost"});
});

test("unsupported browsers return a fixed error bound to the prepared nonce", async () => {
  const b = browser({supported: false});
  b.click();
  await flush();
  assert.equal(b.calls.get.length, 0);
  assert.deepEqual(b.calls.done[0].payload, {mode: "step-up", nonce, error: "unsupported"});
});

test("authenticator cancellation never exposes exception messages or creates a proof", async () => {
  const b = browser({get: async () => {
    const error = new Error("sensitive-device-error-message");
    error.name = "NotAllowedError";
    throw error;
  }});
  b.click();
  await flush();
  assert.deepEqual(b.calls.done[0].payload, {mode: "step-up", nonce, error: "NotAllowedError"});
  assert.equal(JSON.stringify(b.calls.done).includes("sensitive-device"), false);
  assert.deepEqual(b.calls.fetch, []);
});

test("malformed public options fail closed without calling credentials.get", async () => {
  const b = browser({encoded: b64("{")});
  b.click();
  await flush();
  assert.equal(b.calls.get.length, 0);
  assert.deepEqual(b.calls.done[0].payload, {mode: "step-up", nonce, error: "SyntaxError"});
});
