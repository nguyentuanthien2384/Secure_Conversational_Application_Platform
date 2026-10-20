"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {webcrypto} = require("node:crypto");
const source = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/crypto_workbench.js"), "utf8");
const flush = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };
const pair = (name = "alice") => ({privateKey: {type: "private", extractable: false, name},
  publicKey: {type: "public", name}, publicPem: `PUBLIC PEM ${name}`, fingerprint: (name === "alice" ? "a" : "b").repeat(64),
  encryptedBackup: JSON.stringify({format: "scap-key-backup", ciphertext: `ENCRYPTED ${name}`})});

function browser(options = {}) {
  const calls = {create: [], restore: [], reencrypt: [], import: [], encrypt: [], decrypt: [], encryptFile: [], decryptFile: [], clipboard: [], downloads: [],
    revoked: [], contextLoads: [], network: 0, persistence: 0};
  const events = new Map();
  const windowEvents = new Map();
  const timers = new Map();
  const blobs = new Map();
  let nextTimer = 0, nextUrl = 0, observer;
  const app = {visible: true, getClientRects() { return this.visible ? [{}] : []; }};
  let clearMarker = false;
  class Element {
    constructor(attributes = {}, input = false) {
      this.attributes = attributes;
      this.textContent = "";
      this.disabled = false;
      this.isConnected = true;
      this.files = [];
      this.children = [];
      if (input) {
        let contents = "";
        Object.defineProperty(this, "value", {get: () => contents, set: (value) => {
          contents = value;
          if (value === "" && ["recipient-file", "private-file", "file-input"].includes(attributes["data-crypto-field"])) this.files = [];
        }});
      }
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
    setAttribute(name, val) { this.attributes[name] = String(val); }
    removeAttribute(name) { delete this.attributes[name]; }
    append(...nodes) { this.children.push(...nodes); }
    replaceChildren(...nodes) { this.children = [...nodes]; }
    closest(selector) {
      if (selector === "[data-crypto-action]") return this.attributes["data-crypto-action"] ? this : null;
      if (selector === "#btn-logout, #btn-logout-all") return this.logout ? this : null;
      if (selector === "tbody tr") return this.cipherRow || null;
      return null;
    }
    set innerHTML(_) { assert.fail("User data must never reach innerHTML"); }
  }
  function makeRoot() {
    const root = new Element();
    root.fields = new Map();
    for (const name of ["status", "passphrase", "confirm", "own-public", "own-info", "recipient-public", "recipient-file",
      "recipient-info", "private-file", "plaintext", "context", "packet", "decrypted", "packet-info",
      "file-input", "file-info", "file-context", "file-result", "source-message", "source-info"]) {
      root.fields.set(name, new Element({"data-crypto-field": name}, !["status", "own-info", "recipient-info", "packet-info", "file-info", "file-result", "source-info"].includes(name)));
    }
    root.buttons = new Map(["generate", "restore", "export-private", "export-public", "copy-public", "import-public", "encrypt", "decrypt", "encrypt-file", "decrypt-file", "clear"]
      .map((name) => [name, new Element({"data-crypto-action": name})]));
    root.querySelector = (selector) => root.fields.get(/^\[data-crypto-field="([^"]+)"\]$/.exec(selector)?.[1]) || null;
    root.querySelectorAll = (selector) => selector === "[data-crypto-action]" ? [...root.buttons.values()] : [];
    root.contains = (node) => node === root || [...root.fields.values(), ...root.buttons.values()].includes(node);
    return root;
  }
  let root = makeRoot();
  let bridgeMarker = null;
  const cipherRows = new Map();
  const bridgeRoot = {
    querySelector(selector) { return selector === "[data-scap-cipher-extract]" ? bridgeMarker : null; },
  };
  const cipherTable = {
    querySelectorAll(selector) { return selector === "tbody tr" ? [...cipherRows.values()] : []; },
    contains(node) { return [...cipherRows.values()].includes(node); },
  };
  const contextLoadButton = options.loadConversation ? {
    disabled: false,
    click(...args) { calls.contextLoads.push(args); options.loadConversation(...args); },
  } : null;
  const core = {
    limits: {fileBytes: 5242880, fileContainerBytes: 5246380},
    async createKeyPair(...args) { calls.create.push(args); return options.create ? options.create(...args) : pair(); },
    async restoreKeyPair(...args) { calls.restore.push(args); return options.restore ? options.restore(...args) : pair(); },
    async reencryptKeyBackup(...args) {
      calls.reencrypt.push(args);
      if (options.reencrypt) return options.reencrypt(...args);
      if ([...args[2]].length < 16) throw {code: "passphrase"};
      return JSON.stringify({format: "scap-key-backup", ciphertext: "REPROTECTED alice"});
    },
    async importPublicKey(...args) { calls.import.push(args); return options.import ? options.import(...args) : pair("bob"); },
    async encrypt(...args) { calls.encrypt.push(args); return options.encrypt ? options.encrypt(...args) : JSON.stringify({ciphertext: "SAFE CIPHERTEXT"}); },
    async decrypt(...args) { calls.decrypt.push(args); return options.decrypt ? options.decrypt(...args) : "<img src=x onerror=alert(1)> plaintext"; },
    async encryptFile(...args) { calls.encryptFile.push(args); return options.encryptFile ? options.encryptFile(...args) : new Uint8Array([83, 67, 65, 80, 0, 255]); },
    async decryptFile(...args) { calls.decryptFile.push(args); return options.decryptFile ? options.decryptFile(...args) : {bytes: new Uint8Array([0, 255, 17]), name: "original.bin", context: "public purpose", sha256: "d".repeat(64)}; },
  };
  const body = {append(anchor) { anchor.appended = true; }};
  const document = {
    readyState: "complete", visibilityState: "visible", body,
    addEventListener(name, callback) { const list = events.get(name) || []; list.push(callback); events.set(name, list); },
    getElementById(id) {
      if (id === "app-sec") return app;
      if (id === "cipher-workbench-bridge") return bridgeRoot;
      if (id === "cipher-table") return cipherTable;
      if (id === "btn-cipher-load") return contextLoadButton;
      return null;
    },
    querySelector(selector) {
      if (selector === '#crypto-workbench [data-scap-crypto-workbench="1"]') return root;
      if (selector === "#session-bridge [data-scap-session-clear]") return clearMarker ? {} : null;
      throw new Error(`Unexpected selector: ${selector}`);
    },
    createElement(tag) {
      if (tag === "option") return new Element({}, true);
      assert.equal(tag, "a");
      return {click() { calls.downloads.push({url: this.href, filename: this.download, blob: blobs.get(this.href)}); }, remove() {}};
    },
  };
  Object.defineProperty(document, "cookie", {get() { calls.persistence += 1; throw new Error("No cookies allowed"); }});
  const context = {
    document, Blob, TextEncoder, TextDecoder, atob, ArrayBuffer, Uint8Array, crypto: options.noRandom ? {} : webcrypto,
    ScapCryptoCore: options.noCore ? undefined : core, isSecureContext: options.secure !== false,
    navigator: {clipboard: {async writeText(value) { calls.clipboard.push(value); if (options.clipboard) return options.clipboard(value); }}},
    URL: {createObjectURL(blob) { const url = `blob:local-${++nextUrl}`; blobs.set(url, blob); return url; },
      revokeObjectURL(url) { calls.revoked.push(url); blobs.delete(url); }},
    MutationObserver: class { constructor(callback) { observer = callback; } observe() {} },
    addEventListener(name, callback) { windowEvents.set(name, callback); },
    setTimeout(callback, duration) { const id = ++nextTimer; timers.set(id, {callback, duration}); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch() { calls.network += 1; throw new Error("No network allowed"); },
  };
  for (const name of ["localStorage", "sessionStorage"]) Object.defineProperty(context, name,
    {get() { calls.persistence += 1; throw new Error("No persistence allowed"); }});
  vm.runInNewContext(source, context);
  function dispatch(name, target) {
    for (const callback of events.get(name) || []) callback({type: name, target, preventDefault() {}});
  }
  return {
    calls, app, document, core, timers, cipherRows, contextLoadButton,
    field(name) { return root.fields.get(name); },
    button(name) { return root.buttons.get(name); },
    async click(name) { dispatch("click", root.buttons.get(name)); await flush(); },
    async generate() { root.fields.get("passphrase").value = "A separate backup passphrase"; root.fields.get("confirm").value = "A separate backup passphrase"; dispatch("click", root.buttons.get("generate")); await flush(); },
    edit(name, value, type = "input") { root.fields.get(name).value = value; dispatch(type, root.fields.get(name)); },
    file(name, file) { root.fields.get(name).files = [file]; },
    logout() { const target = new Element(); target.logout = true; dispatch("click", target); },
    hide() { document.visibilityState = "hidden"; dispatch("visibilitychange"); },
    show() { document.visibilityState = "visible"; dispatch("visibilitychange"); },
    pagehide() { windowEvents.get("pagehide")(); },
    mutation() { observer(); },
    marker(value) { clearMarker = value; observer(); },
    detach() { root.isConnected = false; observer(); },
    replace() { const old = root; old.isConnected = false; root = makeRoot(); observer(); return old; },
    idle() { const timer = [...timers.values()].find((item) => item.duration === 300000); assert.ok(timer); timer.callback(); },
    removeBridge() { bridgeMarker = null; observer(); },
    async extractCipher(records, nonce = "nonce-1", status, sessionId = "sess-1") {
      cipherRows.clear();
      for (const rec of records) {
        const cell = new Element();
        cell.textContent = String(rec.id);
        const tr = new Element();
        tr.cipherRow = tr;
        tr.querySelector = (sel) => sel === "td" ? cell : null;
        cipherRows.set(String(rec.id), tr);
      }
      const payload = {session_id: sessionId, records};
      if (status !== undefined) payload.status = status;
      const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
      bridgeMarker = new Element({"data-scap-cipher-extract": encoded, "data-scap-cipher-nonce": nonce});
      observer();
      await flush();
    },
    async clickCipherRow(id) {
      const tr = cipherRows.get(String(id));
      assert.ok(tr);
      dispatch("click", tr);
      await flush();
    },
  };
}

test("creation clears passphrase fields immediately and sets local key and recipient", async () => {
  let b;
  b = browser({create() {
    assert.equal(b.field("passphrase").value, "");
    assert.equal(b.field("confirm").value, "");
    return pair();
  }});
  await b.generate();
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.field("recipient-public").value, "PUBLIC PEM alice");
  assert.match(b.field("own-info").textContent, /a{64}/);
  assert.equal(b.button("generate").disabled, false);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("confirmation mismatch clears passwords without generating keys or exposing exception text", async () => {
  const b = browser();
  b.field("passphrase").value = "secret passphrase one";
  b.field("confirm").value = "secret passphrase two";
  await b.click("generate");
  assert.equal(b.calls.create.length, 0);
  assert.equal(b.field("passphrase").value, "");
  assert.equal(b.field("confirm").value, "");
  assert.match(b.field("status").textContent, /chưa khớp/);
  assert.equal(b.field("status").textContent.includes("secret"), false);
});

test("restoration reads only the explicit bounded encrypted file and clears wrong-pass input", async () => {
  const b = browser({restore() { throw Object.assign(new Error("PRIVATE KEY and secret-password must not appear"), {code: "backup"}); }});
  let reads = 0;
  b.file("private-file", {size: 100, async text() { reads += 1; return "ENCRYPTED JSON"; }});
  assert.equal(reads, 0);
  b.field("passphrase").value = "secret-password value";
  b.field("decrypted").value = "OLD PLAINTEXT";
  b.field("packet-info").textContent = "OLD AUTHENTICATED";
  await b.click("restore");
  assert.equal(reads, 1);
  assert.deepEqual(b.calls.restore[0], ["ENCRYPTED JSON", "secret-password value"]);
  assert.equal(b.field("passphrase").value, "");
  assert.equal(b.field("decrypted").value, "");
  assert.equal(b.field("packet-info").textContent, "");
  assert.equal(b.field("status").textContent.includes("PRIVATE"), false);
  assert.match(b.field("status").textContent, /mật khẩu sai/);
});

test("oversize, missing and deceptive files reject before importing key material", async () => {
  for (const file of [null, {size: 16385, text() { assert.fail("must not read oversized file"); }},
    {size: 5, async text() { return "x".repeat(16385); }}, {size: NaN, text() { assert.fail("invalid size"); }}]) {
    const b = browser();
    if (file) b.file("private-file", file);
    b.field("passphrase").value = "a sufficiently long passphrase";
    await b.click("restore");
    assert.equal(b.calls.restore.length, 0);
    assert.equal(b.field("passphrase").value, "");
    assert.match(b.field("status").textContent, /16 KiB/);
  }
  const b = browser();
  b.file("recipient-file", {size: 8193, text() { assert.fail("public file must be bounded before read"); }});
  await b.click("import-public");
  assert.equal(b.calls.import.length, 0);
});

test("recipient import changes encryption target while preserving the owner's private key", async () => {
  const b = browser();
  await b.generate();
  b.edit("recipient-public", "PUBLIC PEM bob");
  await b.click("encrypt");
  assert.equal(b.calls.encrypt.length, 0);
  await b.click("import-public");
  b.field("plaintext").value = "private message";
  b.field("context").value = "public purpose";
  await b.click("encrypt");
  assert.equal(b.calls.encrypt[0][0].fingerprint, "b".repeat(64));
  assert.equal(b.calls.encrypt[0][1], "private message");
  assert.equal(b.calls.encrypt[0][2], "public purpose");
  await b.click("decrypt");
  assert.equal(b.calls.decrypt[0][0].name, "alice");
  assert.equal(b.calls.decrypt[0][1], "a".repeat(64));
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.field("decrypted").value, "<img src=x onerror=alert(1)> plaintext");
});

test("failed recipient import invalidates the old target rather than silently encrypting to it", async () => {
  const b = browser({import() { throw Object.assign(new Error("secret invalid PEM"), {code: "public_key"}); }});
  await b.generate();
  b.edit("recipient-public", "invalid");
  await b.click("import-public");
  await b.click("encrypt");
  assert.equal(b.calls.encrypt.length, 0);
  assert.equal(b.field("packet").value, "");
  assert.match(b.field("status").textContent, /xác nhận khóa công khai/);
});

test("only public keys are copied and downloads contain encrypted private backup or public PEM", async () => {
  const b = browser();
  await b.generate();
  await b.click("copy-public");
  await b.click("export-private");
  await b.click("export-public");
  assert.deepEqual(b.calls.clipboard, ["PUBLIC PEM alice"]);
  assert.deepEqual(b.calls.downloads.map((item) => item.filename), ["scap-private-key.encrypted.json", "scap-public-key.pem"]);
  assert.equal(await b.calls.downloads[0].blob.text(), pair().encryptedBackup);
  assert.equal(await b.calls.downloads[1].blob.text(), "PUBLIC PEM alice");
  assert.equal((await b.calls.downloads[0].blob.text()).includes("PRIVATE KEY"), false);
  assert.equal(b.calls.downloads[0].blob.type, "application/json");
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
  await b.click("clear");
  assert.deepEqual(b.calls.revoked, ["blob:local-1", "blob:local-2"]);
  await b.click("export-private");
  assert.equal(b.calls.downloads.length, 2);
});

test("clear invalidates pending generation and cannot let its completion unlock another operation", async () => {
  const first = deferred();
  const second = deferred();
  let count = 0;
  const b = browser({create() { return ++count === 1 ? first.promise : second.promise; }});
  await b.generate();
  assert.equal(b.button("generate").disabled, true);
  assert.equal(b.button("clear").disabled, false);
  await b.click("clear");
  await b.generate();
  first.resolve(pair("bob"));
  await flush();
  assert.equal(b.field("own-public").value, "");
  assert.equal(b.button("generate").disabled, true);
  second.resolve(pair());
  await flush();
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.button("generate").disabled, false);
});

for (const lifecycle of ["logout", "hide", "pagehide", "idle", "detach", "replace", "marker", "app-hidden"]) {
  test(`${lifecycle} clears key references and drops pending decrypted plaintext`, async () => {
    const pending = deferred();
    const b = browser({decrypt: () => pending.promise});
    await b.generate();
    b.field("plaintext").value = "SENSITIVE INPUT";
    b.field("packet").value = "ciphertext";
    await b.click("decrypt");
    const old = b.field("own-public");
    if (lifecycle === "marker") b.marker(true);
    else if (lifecycle === "app-hidden") { b.app.visible = false; b.mutation(); }
    else b[lifecycle]();
    pending.resolve("LATE PRIVATE PLAINTEXT");
    await flush();
    assert.equal(old.value, "");
    assert.equal(b.field("own-public").value, "");
    assert.equal(b.field("decrypted").value, "");
    assert.equal(b.field("plaintext").value, "");
    assert.equal(b.field("packet").value, "");
    assert.equal(b.field("status").textContent.includes("LATE"), false);
    if (lifecycle === "hide") b.show();
    if (lifecycle === "marker") b.marker(false);
    if (lifecycle === "app-hidden") { b.app.visible = true; b.mutation(); }
    await b.click("export-private");
    assert.equal(b.calls.downloads.length, 0);
  });
}

test("logout during a file read prevents both private-key restoration and stale UI output", async () => {
  const read = deferred();
  const b = browser();
  b.file("private-file", {size: 100, text() { return read.promise; }});
  b.field("passphrase").value = "secret restore passphrase";
  await b.click("restore");
  b.logout();
  read.resolve("ENCRYPTED JSON");
  await flush();
  assert.equal(b.calls.restore.length, 0);
  assert.equal(b.field("own-public").value, "");
  assert.equal(b.field("passphrase").value, "");
});

test("an edited packet or recipient cannot receive stale asynchronous results", async () => {
  const pending = deferred();
  const b = browser({encrypt: () => pending.promise});
  await b.generate();
  b.field("plaintext").value = "initial input";
  await b.click("encrypt");
  b.edit("recipient-public", "PUBLIC PEM bob");
  pending.resolve("OLD CIPHERTEXT");
  await flush();
  assert.equal(b.field("packet").value, "");
  assert.equal(b.button("encrypt").disabled, false);
  await b.click("encrypt");
  assert.equal(b.calls.encrypt.length, 1);
});

test("editing a packet drops its pending plaintext and its completion cannot unlock the newer decryption", async () => {
  const old = deferred();
  const current = deferred();
  let count = 0;
  const b = browser({decrypt: () => ++count === 1 ? old.promise : current.promise});
  await b.generate();
  b.field("packet").value = "original packet";
  await b.click("decrypt");
  b.edit("packet", "new packet");
  assert.equal(b.field("packet").value, "new packet");
  assert.equal(b.button("decrypt").disabled, false);
  await b.click("decrypt");
  old.resolve("OLD PLAINTEXT");
  await flush();
  assert.equal(b.field("decrypted").value, "");
  assert.equal(b.field("packet-info").textContent, "");
  assert.equal(b.field("packet").value, "new packet");
  assert.equal(b.button("decrypt").disabled, true);
  current.resolve("CURRENT PLAINTEXT");
  await flush();
  assert.equal(b.field("decrypted").value, "CURRENT PLAINTEXT");
  assert.equal(b.button("decrypt").disabled, false);
});

test("a private file changed during restore cannot let the old read replace current keys", async () => {
  const pendingFile = deferred();
  const b = browser();
  await b.generate();
  b.file("private-file", {size: 100, text: () => pendingFile.promise});
  b.field("passphrase").value = "old file backup passphrase";
  await b.click("restore");
  b.file("private-file", {size: 200, async text() { return "NEW ENCRYPTED BACKUP"; }});
  b.edit("private-file", "selected new file", "change");
  pendingFile.resolve("OLD ENCRYPTED BACKUP");
  await flush();
  assert.equal(b.calls.restore.length, 0);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  b.field("passphrase").value = "new file backup passphrase";
  await b.click("restore");
  assert.deepEqual(b.calls.restore[0], ["NEW ENCRYPTED BACKUP", "new file backup passphrase"]);
});

test("unknown exceptions never reach DOM and previous decryption claims are cleared", async () => {
  const b = browser({decrypt() { throw new Error("PRIVATE KEY / password / plaintext must not appear"); }});
  await b.generate();
  b.field("decrypted").value = "old plaintext";
  b.field("packet-info").textContent = "old claim";
  await b.click("decrypt");
  assert.equal(b.field("decrypted").value, "");
  assert.equal(b.field("packet-info").textContent, "");
  assert.match(b.field("status").textContent, /chưa hoàn tất/);
  assert.equal(b.field("status").textContent.includes("PRIVATE"), false);
});

test("insecure browsers and unauthenticated hidden UI cannot invoke crypto operations", async () => {
  const insecure = browser({secure: false});
  await insecure.generate();
  assert.equal(insecure.calls.create.length, 0);
  assert.match(insecure.field("status").textContent, /HTTPS/);
  const b = browser();
  b.app.visible = false;
  b.mutation();
  await b.generate();
  assert.equal(b.calls.create.length, 0);
  assert.equal(b.button("generate").disabled, true);
  b.app.visible = true;
  b.mutation();
  await b.generate();
  assert.equal(b.calls.create.length, 1);
});

test("hiding the workbench tab alone preserves keys while the authenticated app remains visible", async () => {
  const b = browser();
  await b.generate();
  b.mutation();
  await b.click("export-private");
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
});

function binaryFile(bytes = [0, 255, 17], name = "sample.bin") {
  return {name, size: bytes.length, async arrayBuffer() { return Uint8Array.from(bytes).buffer; }};
}

test("file encryption reads binary only on request, snapshots recipient and downloads an inert container", async () => {
  const input = [0, 255, 10, 128, 83];
  let reads = 0;
  const b = browser({encryptFile(recipient, bytes, metadata) {
    assert.equal(recipient.fingerprint, "b".repeat(64));
    assert.deepEqual([...bytes], input);
    assert.equal(metadata.name, "binary-data.bin");
    assert.equal(metadata.context, "public file purpose");
    return new Uint8Array([83, 67, 65, 80, 0, 255]);
  }});
  await b.generate();
  b.edit("recipient-public", "PUBLIC PEM bob");
  await b.click("import-public");
  b.file("file-input", {name: "binary-data.bin", size: input.length,
    async arrayBuffer() { reads += 1; return Uint8Array.from(input).buffer; }});
  b.field("file-context").value = "public file purpose";
  assert.equal(reads, 0);
  await b.click("encrypt-file");
  assert.equal(reads, 1);
  assert.equal(b.calls.encryptFile.length, 1);
  assert.deepEqual([...b.calls.encryptFile[0][1]], Array(input.length).fill(0));
  assert.equal(b.calls.downloads.length, 1);
  const download = b.calls.downloads[0];
  assert.equal(download.filename, "scap-encrypted-file.scapenc");
  assert.equal(download.blob.type, "application/octet-stream");
  assert.deepEqual([...new Uint8Array(await download.blob.arrayBuffer())], [83, 67, 65, 80, 0, 255]);
  assert.match(b.field("file-info").textContent, /5 byte/);
  assert.match(b.field("file-result").textContent, /6 byte/);
  assert.match(b.field("file-result").textContent, /b{64}/);
  assert.match(b.field("file-result").textContent, /public file purpose/);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("file selection shows unverified name and size without reading, and clearing removes the old success claim", async () => {
  const b = browser();
  b.field("file-result").textContent = "old authenticated success";
  b.file("file-input", {name: "<img src=x>.bin", size: 2048,
    arrayBuffer() { assert.fail("selection must not read binary data"); },
    text() { assert.fail("selection must not read text data"); }});
  b.edit("file-input", "selected file", "change");
  assert.match(b.field("file-info").textContent, /chưa xác minh/);
  assert.match(b.field("file-info").textContent, /<img src=x>\.bin/);
  assert.match(b.field("file-info").textContent, /2048 byte/);
  assert.equal(b.field("file-result").textContent, "");
  assert.equal(b.calls.encryptFile.length, 0);
  assert.equal(b.calls.decryptFile.length, 0);
  b.field("file-result").textContent = "another old claim";
  b.edit("file-input", "", "change");
  assert.equal(b.field("file-info").textContent, "Chưa chọn tệp.");
  assert.equal(b.field("file-result").textContent, "");
});

test("file decryption shows authenticated metadata as text and uses a fixed inert download name", async () => {
  const restored = new Uint8Array([0, 255, 1, 128]);
  const b = browser({decryptFile(privateKey, fingerprint, bytes) {
    assert.equal(privateKey.name, "alice");
    assert.equal(fingerprint, "a".repeat(64));
    assert.deepEqual([...bytes], [83, 67, 65, 80]);
    return {bytes: restored, name: "../../<img src=x onerror=alert(1)>.html", context: "<script>public context</script>", sha256: "e".repeat(64)};
  }});
  await b.generate();
  b.file("file-input", binaryFile([83, 67, 65, 80], "received.scapenc"));
  await b.click("decrypt-file");
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(b.calls.downloads[0].filename, "scap-restored.bin");
  assert.equal(b.calls.downloads[0].blob.type, "application/octet-stream");
  assert.deepEqual([...new Uint8Array(await b.calls.downloads[0].blob.arrayBuffer())], [0, 255, 1, 128]);
  assert.deepEqual([...restored], [0, 0, 0, 0]);
  assert.match(b.field("file-result").textContent, /<img src=x onerror=alert\(1\)>/);
  assert.match(b.field("file-result").textContent, /<script>public context<\/script>/);
  assert.match(b.field("file-result").textContent, /e{64}/);
  assert.match(b.field("file-result").textContent, /4 byte/);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("file operations require a confirmed key before reading any selected file", async () => {
  const b = browser();
  b.file("file-input", {name: "file.bin", size: 1, arrayBuffer() { assert.fail("key must be checked before read"); }});
  await b.click("encrypt-file");
  assert.match(b.field("status").textContent, /xác nhận khóa công khai/);
  await b.click("decrypt-file");
  assert.match(b.field("status").textContent, /cặp khóa riêng/);
  assert.equal(b.calls.encryptFile.length, 0);
  assert.equal(b.calls.decryptFile.length, 0);
  assert.equal(b.calls.downloads.length, 0);
});

test("missing, invalid and oversize binary files reject before crypto or download", async () => {
  for (const action of ["encrypt-file", "decrypt-file"]) {
    const maximum = action === "encrypt-file" ? 5242880 : 5246380;
    for (const file of [null, {size: maximum + 1, arrayBuffer() { assert.fail("oversize file must not be read"); }},
      {size: NaN, arrayBuffer() { assert.fail("invalid size must not be read"); }},
      {size: -1, arrayBuffer() { assert.fail("invalid size must not be read"); }},
      {size: 0.5, arrayBuffer() { assert.fail("invalid size must not be read"); }},
      {size: 1, async text() { assert.fail("binary file must never be read as text"); }}]) {
      const b = browser();
      await b.generate();
      if (file) b.file("file-input", file);
      await b.click(action);
      assert.equal(b.calls.encryptFile.length, 0);
      assert.equal(b.calls.decryptFile.length, 0);
      assert.equal(b.calls.downloads.length, 0);
      assert.match(b.field("status").textContent, /5 MiB/);
    }
  }
});

test("binary file reads require the exact declared ArrayBuffer size after reading", async () => {
  for (const result of [new Uint8Array([1, 2]).buffer, new Uint8Array(5242881).buffer,
    new Uint8Array([1]), [1], "raw plaintext", null]) {
    const b = browser();
    await b.generate();
    b.file("file-input", {name: "bad.bin", size: 1, async arrayBuffer() { return result; }});
    await b.click("encrypt-file");
    assert.equal(b.calls.encryptFile.length, 0);
    assert.equal(b.calls.downloads.length, 0);
    assert.match(b.field("status").textContent, /5 MiB/);
  }
});

test("empty files and the exact 5 MiB encryption boundary are supported", async () => {
  for (const size of [0, 5242880]) {
    const b = browser({encryptFile(_recipient, bytes) {
      assert.equal(bytes.byteLength, size);
      return new Uint8Array([1, 2, 3]);
    }});
    await b.generate();
    b.file("file-input", {name: "boundary.bin", size, async arrayBuffer() { return new ArrayBuffer(size); }});
    await b.click("encrypt-file");
    assert.equal(b.calls.encryptFile.length, 1);
    assert.equal(b.calls.downloads.length, 1);
  }
});

test("file format, integrity and unexpected errors clear old success claims without exposing details", async () => {
  for (const action of ["encrypt-file", "decrypt-file"]) {
    for (const code of [action === "encrypt-file" ? "encrypt" : "decrypt", "unknown"]) {
      const operation = () => { throw Object.assign(new Error("PRIVATE RAW BYTES / secret metadata"), {code}); };
      const b = browser(action === "encrypt-file" ? {encryptFile: operation} : {decryptFile: operation});
      await b.generate();
      b.file("file-input", binaryFile());
      b.field("file-result").textContent = "old authenticated claim";
      await b.click(action);
      assert.equal(b.calls.downloads.length, 0);
      assert.equal(b.field("file-result").textContent, "");
      assert.equal(b.field("file-info").textContent, "");
      assert.equal(b.field("status").textContent.includes("PRIVATE"), false);
      assert.equal(b.field("status").textContent.includes("secret"), false);
      assert.match(b.field("status").textContent, code === "unknown" ? /chưa hoàn tất/ : /tệp/);
      assert.deepEqual([...b.calls[action === "encrypt-file" ? "encryptFile" : "decryptFile"][0][action === "encrypt-file" ? 1 : 2]], [0, 0, 0]);
    }
  }
});

test("changing the selected file during a read drops the old file before crypto starts", async () => {
  const read = deferred();
  const firstBytes = new Uint8Array([11, 22, 33]);
  const b = browser();
  await b.generate();
  b.file("file-input", {name: "old.bin", size: 3, arrayBuffer: () => read.promise});
  await b.click("encrypt-file");
  b.file("file-input", binaryFile([44], "new.bin"));
  b.edit("file-input", "new selected file", "change");
  read.resolve(firstBytes.buffer);
  await flush();
  assert.equal(b.calls.encryptFile.length, 0);
  assert.equal(b.calls.downloads.length, 0);
  assert.deepEqual([...firstBytes], [0, 0, 0]);
  assert.match(b.field("file-info").textContent, /chưa xác minh.*new\.bin/);
  assert.equal(b.field("file-result").textContent, "");
  await b.click("encrypt-file");
  assert.equal(b.calls.encryptFile.length, 1);
  assert.equal(b.calls.encryptFile[0][2].name, "new.bin");
  assert.equal(b.calls.downloads.length, 1);
});

test("editing a file context drops old output and its completion cannot unlock a newer file operation", async () => {
  const old = deferred();
  const current = deferred();
  let count = 0;
  const b = browser({encryptFile: () => ++count === 1 ? old.promise : current.promise});
  await b.generate();
  b.file("file-input", binaryFile());
  b.field("file-context").value = "old context";
  await b.click("encrypt-file");
  b.edit("file-context", "current context");
  await b.click("encrypt-file");
  const staleBytes = new Uint8Array([1, 2]);
  old.resolve(staleBytes);
  await flush();
  assert.equal(b.calls.downloads.length, 0);
  assert.deepEqual([...staleBytes], [0, 0]);
  assert.equal(b.field("file-result").textContent, "");
  assert.equal(b.button("encrypt-file").disabled, true);
  current.resolve(new Uint8Array([3, 4, 5]));
  await flush();
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(b.button("encrypt-file").disabled, false);
  assert.match(b.field("file-result").textContent, /current context/);
});

test("recipient edits invalidate pending file encryption even after the File was read", async () => {
  const pending = deferred();
  const b = browser({encryptFile: () => pending.promise});
  await b.generate();
  b.file("file-input", binaryFile());
  await b.click("encrypt-file");
  b.edit("recipient-public", "new recipient");
  pending.resolve(new Uint8Array([3, 4, 5]));
  await flush();
  assert.equal(b.calls.downloads.length, 0);
  assert.equal(b.field("file-result").textContent, "");
  await b.click("encrypt-file");
  assert.equal(b.calls.encryptFile.length, 1);
  assert.match(b.field("status").textContent, /xác nhận khóa công khai/);
});

for (const lifecycle of ["clear", "logout", "hide", "pagehide", "idle", "detach", "replace", "marker", "app-hidden"]) {
  test(`${lifecycle} erases selected files, summaries and pending file download`, async () => {
    const pending = deferred();
    const b = browser({decryptFile: () => pending.promise});
    await b.generate();
    b.file("file-input", binaryFile([1, 2, 3], "received.scapenc"));
    b.field("file-context").value = "private local draft";
    await b.click("decrypt-file");
    const oldInput = b.field("file-input");
    const oldContext = b.field("file-context");
    if (lifecycle === "clear") await b.click("clear");
    else if (lifecycle === "marker") b.marker(true);
    else if (lifecycle === "app-hidden") { b.app.visible = false; b.mutation(); }
    else b[lifecycle]();
    const restoredBytes = new Uint8Array([11, 22, 33]);
    pending.resolve({bytes: restoredBytes, name: "LATE SECRET NAME", context: "LATE CONTEXT", sha256: "f".repeat(64)});
    await flush();
    assert.equal(b.calls.downloads.length, 0);
    assert.deepEqual([...restoredBytes], [0, 0, 0]);
    assert.deepEqual(oldInput.files, []);
    assert.equal(oldContext.value, "");
    assert.deepEqual(b.field("file-input").files, []);
    assert.equal(b.field("file-info").textContent, "");
    assert.equal(b.field("file-result").textContent, "");
    assert.equal(b.field("status").textContent.includes("LATE"), false);
  });
}

test("successful file downloads are revoked by lifecycle cleanup and all edits remove stale file claims", async () => {
  const b = browser();
  await b.generate();
  b.file("file-input", binaryFile());
  await b.click("decrypt-file");
  assert.match(b.field("file-result").textContent, /SHA-256/);
  b.edit("file-context", "edited context");
  assert.equal(b.field("file-info").textContent, "");
  assert.equal(b.field("file-result").textContent, "");
  await b.click("encrypt-file");
  assert.ok(b.field("file-result").textContent);
  b.edit("recipient-public", "another recipient");
  assert.equal(b.field("file-result").textContent, "");
  assert.equal(b.calls.downloads.length, 2);
  b.hide();
  assert.deepEqual(b.calls.revoked, ["blob:local-1", "blob:local-2"]);
  assert.deepEqual(b.field("file-input").files, []);
});

test("real WebCrypto file containers roundtrip through the controller without corrupting Blob snapshots", async () => {
  const {createHash} = require("node:crypto");
  const realCore = require("../src/app/ui_assets/crypto_workbench_core.js");
  const realPair = await realCore.createKeyPair("A separate synthetic binary UI backup passphrase 2026");
  const encryptedDone = deferred();
  const decryptedDone = deferred();
  const b = browser({create: () => realPair,
    // The DOM harness runs in a vm realm while the required core runs in this
    // realm. Rebuild the options record here to preserve the core's plain-object
    // check, as it would naturally hold in the shared browser script realm.
    async encryptFile(recipient, bytes, metadata) {
      try { return await realCore.encryptFile(recipient, bytes, {name: metadata.name, context: metadata.context}); }
      finally { encryptedDone.resolve(); }
    },
    async decryptFile(...args) { try { return await realCore.decryptFile(...args); } finally { decryptedDone.resolve(); } }});
  const original = Uint8Array.from({length: 2048}, (_, index) => index % 256);
  const filename = "Hồ sơ demo 🔐.bin";
  const context = "Demo file / ngữ cảnh công khai";
  await b.generate();
  b.file("file-input", binaryFile(original, filename));
  b.field("file-context").value = context;
  await b.click("encrypt-file");
  await encryptedDone.promise;
  await flush();
  assert.equal(b.calls.downloads.length, 1);
  const encryptedBlob = b.calls.downloads[0].blob;
  assert.ok(encryptedBlob.size > original.byteLength);
  assert.ok(encryptedBlob.size <= realCore.limits.fileContainerBytes);
  assert.deepEqual([...original], Array.from({length: 2048}, (_, index) => index % 256));
  b.file("file-input", {name: "received.scapenc", size: encryptedBlob.size, arrayBuffer: () => encryptedBlob.arrayBuffer()});
  b.edit("file-context", "An untrusted current input must not replace authenticated metadata");
  await b.click("decrypt-file");
  await decryptedDone.promise;
  await flush();
  assert.equal(b.calls.downloads.length, 2);
  const restored = b.calls.downloads[1];
  assert.equal(restored.filename, "scap-restored.bin");
  assert.equal(restored.blob.type, "application/octet-stream");
  assert.deepEqual(new Uint8Array(await restored.blob.arrayBuffer()), original);
  assert.ok(b.field("file-result").textContent.includes(filename));
  assert.ok(b.field("file-result").textContent.includes(context));
  assert.ok(b.field("file-result").textContent.includes(createHash("sha256").update(original).digest("hex")));
  assert.equal(b.field("file-result").textContent.includes("An untrusted current input"), false);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("cipher extraction automatically completes all 4 sections (keys, plaintext/AAD, JSON packet/decryption, and file container)", async () => {
  const b = browser({
    encrypt: (_recipient, text, ctx) => JSON.stringify({format: "scap-encrypted-text", ciphertext: `ENC:${text}`, context: ctx}),
    decrypt: (_priv, _fp, packet) => `DEC:${JSON.parse(packet).ciphertext}`,
  });
  await b.extractCipher([
    {
      id: "5c14f839",
      role: "user",
      encryption_scheme: "envelope-v1",
      content: "Xin chào SCAP",
      context: "session:sess-1|msg:5c14f839|role:user|epoch:1|scheme:envelope-v1",
      file_name: "scap-msg-5c14f839.json",
      file_context: "file:session:sess-1|msg:5c14f839|role:user|epoch:1|scheme:envelope-v1",
    },
    {
      id: "bb8148d7",
      role: "assistant",
      encryption_scheme: "envelope-v1",
      content: "Phản hồi bảo mật từ trợ lý",
      context: "session:sess-1|msg:bb8148d7|role:assistant|epoch:1|scheme:envelope-v1",
      file_name: "scap-msg-bb8148d7.json",
      file_context: "file:session:sess-1|msg:bb8148d7|role:assistant|epoch:1|scheme:envelope-v1",
    },
  ]);
  // Section 1 (Khóa của bạn): auto-generated session keypair
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.match(b.field("own-info").textContent, /Khóa phiên tự động/);
  // Section 2 (Người nhận & văn bản gốc)
  assert.equal(b.field("recipient-public").value, "PUBLIC PEM alice");
  assert.equal(b.field("plaintext").value, "Phản hồi bảo mật từ trợ lý");
  assert.equal(b.field("context").value, "session:sess-1|msg:bb8148d7|role:assistant|epoch:1|scheme:envelope-v1");
  // Section 3 (Gói mã hóa và kết quả)
  assert.equal(b.calls.encrypt.length, 1);
  assert.equal(b.calls.decrypt.length, 1);
  assert.match(b.field("packet").value, /ENC:Phản hồi bảo mật từ trợ lý/);
  assert.equal(b.field("decrypted").value, "DEC:ENC:Phản hồi bảo mật từ trợ lý");
  assert.match(b.field("packet-info").textContent, /Toàn vẹn: hợp lệ/);
  // Section 4 (Mã hóa & giải mã tệp)
  assert.equal(b.field("file-context").value, "file:session:sess-1|msg:bb8148d7|role:assistant|epoch:1|scheme:envelope-v1");
  assert.match(b.field("file-info").textContent, /scap-msg-bb8148d7\.json/);
  assert.match(b.field("file-result").textContent, /Toàn vẹn tệp: hợp lệ/);
  assert.equal(b.cipherRows.get("bb8148d7").getAttribute("data-scap-selected-row"), "1");
  assert.equal(b.cipherRows.get("5c14f839").getAttribute("data-scap-selected-row"), null);
  // Clicking encrypt-file / decrypt-file downloads the extracted file without manual file selection
  await b.click("encrypt-file");
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(b.calls.downloads[0].filename, "scap-encrypted-file.scapenc");
  await b.click("decrypt-file");
  assert.equal(b.calls.downloads.length, 2);
  assert.equal(b.calls.downloads[1].filename, "scap-restored.bin");
});

test("cipher extraction preserves existing user keypair and supports clicking rows in #cipher-table", async () => {
  const b = browser({
    encrypt: (_recipient, text, ctx) => JSON.stringify({format: "scap-encrypted-text", ciphertext: `ENC:${text}`, context: ctx}),
    decrypt: (_priv, _fp, packet) => `DEC:${JSON.parse(packet).ciphertext}`,
  });
  await b.generate();
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.calls.encrypt.length, 0);
  await b.extractCipher([
    {
      id: "msg-1",
      role: "user",
      encryption_scheme: "envelope-v1",
      content: "Tin nhắn thứ nhất",
      context: "session:sess-1|msg:msg-1|role:user|epoch:1|scheme:envelope-v1",
    },
    {
      id: "msg-2",
      role: "assistant",
      encryption_scheme: "envelope-v1",
      content: "Tin nhắn thứ hai",
      context: "session:sess-1|msg:msg-2|role:assistant|epoch:1|scheme:envelope-v1",
    },
  ], "nonce-open");
  // Existing keypair is preserved (no second createKeyPair call)
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.calls.encrypt.length, 1);
  assert.equal(b.field("plaintext").value, "Tin nhắn thứ hai");
  assert.match(b.field("packet").value, /ENC:Tin nhắn thứ hai/);
  assert.equal(b.field("decrypted").value, "DEC:ENC:Tin nhắn thứ hai");
  assert.equal(b.cipherRows.get("msg-2").getAttribute("data-scap-selected-row"), "1");
  await b.clickCipherRow("msg-1");
  assert.equal(b.calls.encrypt.length, 2);
  assert.equal(b.field("plaintext").value, "Tin nhắn thứ nhất");
  assert.match(b.field("packet").value, /ENC:Tin nhắn thứ nhất/);
  assert.equal(b.field("decrypted").value, "DEC:ENC:Tin nhắn thứ nhất");
  assert.equal(b.cipherRows.get("msg-1").getAttribute("data-scap-selected-row"), "1");
  assert.equal(b.cipherRows.get("msg-2").getAttribute("data-scap-selected-row"), null);
});

test("cipher extraction loads embedded scap-encrypted-text JSON packet directly into Section 3", async () => {
  const b = browser();
  const embeddedPacket = JSON.stringify({
    format: "scap-encrypted-text",
    version: 1,
    recipientKeySha256: "a".repeat(64),
    encryptedKey: "wrapped-key-b64",
    iv: "iv-b64",
    ciphertext: "cipher-b64",
    context: "custom-aad",
  });
  await b.extractCipher([
    {
      id: "pkt-99",
      role: "user",
      encryption_scheme: "envelope-v1",
      content: embeddedPacket,
      context: "session:sess-1|msg:pkt-99|role:user|epoch:1|scheme:envelope-v1",
    },
  ], "nonce-pkt");
  assert.equal(b.field("context").value, "custom-aad");
  assert.equal(JSON.parse(b.field("packet").value).ciphertext, "cipher-b64");
  assert.match(b.field("packet-info").textContent, /pkt-99/);
});

test("automatic keys require secure randomness instead of exporting a fallback-password backup", async () => {
  const b = browser({noRandom: true});
  await b.extractCipher([{id: "auto-export", content: "Synthetic message", context: "synthetic-context"}]);
  assert.equal(b.calls.create.length, 0);
  assert.equal(b.field("own-public").value, "");
  await b.click("export-private");
  assert.equal(b.calls.downloads.length, 0);
});

test("automatic session backup export requires a matching strong chosen passphrase", async () => {
  const b = browser();
  await b.extractCipher([{id: "auto-export", content: "Synthetic message", context: "synthetic-context"}]);
  await b.click("export-private");
  assert.equal(b.calls.downloads.length, 0);
  assert.match(b.field("status").textContent, /mật khẩu/i);
  b.field("passphrase").value = "A chosen synthetic backup passphrase";
  b.field("confirm").value = "A different synthetic passphrase";
  const beforeMismatch = b.calls.reencrypt.length;
  await b.click("export-private");
  assert.equal(b.calls.reencrypt.length, beforeMismatch);
  assert.equal(b.calls.downloads.length, 0);
  assert.equal(b.field("passphrase").value, "");
  assert.equal(b.field("confirm").value, "");
  assert.match(b.field("status").textContent, /chưa khớp/);
  b.field("passphrase").value = "too short";
  b.field("confirm").value = "too short";
  await b.click("export-private");
  assert.equal(b.calls.downloads.length, 0);
  assert.equal(b.field("passphrase").value, "");
  assert.equal(b.field("confirm").value, "");
  assert.equal(b.field("status").textContent.includes("too short"), false);
});

test("automatic backup export reencrypts the existing identity once and clears password inputs before crypto", async () => {
  const chosen = "A chosen synthetic backup passphrase 2026";
  const replacement = JSON.stringify({format: "scap-key-backup", ciphertext: "REPROTECTED synthetic key"});
  let b;
  b = browser({reencrypt(backup, previous, next) {
    assert.equal(b.field("passphrase").value, "");
    assert.equal(b.field("confirm").value, "");
    assert.equal(backup, pair().encryptedBackup);
    assert.equal(previous, b.calls.create[0][0]);
    assert.match(previous, /^scap-auto-[0-9a-f]{48}$/);
    assert.equal(next, chosen);
    return replacement;
  }});
  await b.extractCipher([{id: "auto-export", content: "Synthetic message", context: "synthetic-context"}]);
  const publicPem = b.field("own-public").value;
  const originalPacket = b.field("packet").value;
  b.field("passphrase").value = chosen;
  b.field("confirm").value = chosen;
  await b.click("export-private");
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.calls.reencrypt.length, 1);
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(await b.calls.downloads[0].blob.text(), replacement);
  assert.equal(b.calls.downloads[0].filename, "scap-private-key.encrypted.json");
  assert.equal(b.field("own-public").value, publicPem);
  assert.equal(b.field("packet").value, originalPacket);
  await b.click("export-private");
  assert.equal(b.calls.reencrypt.length, 1);
  assert.equal(b.calls.downloads.length, 2);
  assert.equal(await b.calls.downloads[1].blob.text(), replacement);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("failed automatic backup reprotection preserves the same key and allows a clean retry", async () => {
  const chosen = "A chosen synthetic backup passphrase 2026";
  let attempts = 0;
  const b = browser({reencrypt(backup) {
    assert.equal(backup, pair().encryptedBackup);
    if (++attempts === 1) throw Object.assign(new Error("PRIVATE KEY and synthetic-secret must not appear"), {code: "backup"});
    return "REPROTECTED BACKUP";
  }});
  await b.extractCipher([{id: "auto-export", content: "Synthetic message", context: "synthetic-context"}]);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    b.field("passphrase").value = chosen;
    b.field("confirm").value = chosen;
    await b.click("export-private");
    assert.equal(b.field("passphrase").value, "");
    assert.equal(b.field("confirm").value, "");
    assert.equal(b.field("status").textContent.includes("PRIVATE"), false);
    assert.equal(b.field("status").textContent.includes("synthetic-secret"), false);
  }
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.calls.reencrypt.length, 2);
  assert.equal(b.calls.downloads.length, 1);
  assert.equal(await b.calls.downloads[0].blob.text(), "REPROTECTED BACKUP");
});

test("restored and manually generated keys retain their already protected backup on export", async () => {
  for (const origin of ["generated", "restored"]) {
    const b = browser({reencrypt() { assert.fail("A user-protected backup must not require an automatic password"); }});
    await b.extractCipher([{id: "old-auto-key", content: "Synthetic message", context: "synthetic-context"}]);
    if (origin === "generated") await b.generate();
    else {
      b.file("private-file", {size: 100, async text() { return pair().encryptedBackup; }});
      b.field("passphrase").value = "An existing synthetic backup passphrase";
      await b.click("restore");
    }
    await b.click("export-private");
    assert.equal(b.calls.reencrypt.length, 0);
    assert.equal(b.calls.downloads.length, 1);
    assert.equal(await b.calls.downloads[0].blob.text(), pair().encryptedBackup);
  }
});

test("clear, logout, hide and input edits invalidate pending automatic backup exports", async () => {
  for (const invalidation of ["clear", "logout", "hide", "edit"]) {
    const pending = deferred();
    const chosen = "A chosen synthetic backup passphrase 2026";
    const b = browser({reencrypt: () => pending.promise});
    await b.extractCipher([{id: "auto-export", content: "Synthetic message", context: "synthetic-context"}]);
    b.field("passphrase").value = chosen;
    b.field("confirm").value = chosen;
    await b.click("export-private");
    assert.equal(b.calls.reencrypt.length, 1);
    if (invalidation === "clear") await b.click("clear");
    else if (invalidation === "logout") b.logout();
    else if (invalidation === "hide") b.hide();
    else b.edit("passphrase", "A newly edited synthetic passphrase");
    pending.resolve("STALE REPROTECTED BACKUP");
    await flush();
    assert.equal(b.calls.downloads.length, 0, invalidation);
    if (invalidation !== "edit") {
      if (invalidation === "hide") b.show();
      await b.generate();
      await b.click("export-private");
      assert.equal(b.calls.reencrypt.length, 1, invalidation);
      assert.equal(await b.calls.downloads[0].blob.text(), pair().encryptedBackup);
    } else {
      b.core.reencryptKeyBackup = async (backup) => {
        assert.equal(backup, pair().encryptedBackup);
        return "CURRENT REPROTECTED BACKUP";
      };
      b.field("passphrase").value = chosen;
      b.field("confirm").value = chosen;
      await b.click("export-private");
      assert.equal(await b.calls.downloads[0].blob.text(), "CURRENT REPROTECTED BACKUP");
    }
  }
});

test("real automatic key export restores in a fresh controller and decrypts the original message packet", async () => {
  const realCore = require("../src/app/ui_assets/crypto_workbench_core.js");
  const chosen = "A chosen synthetic backup passphrase 2026";
  const message = "Synthetic saved conversation 🔐\nRestore must retain this exact content.";
  const extractionDone = deferred(), reencryptDone = deferred(), restoreDone = deferred(), decryptDone = deferred();
  let createdPair, restoredPair;
  const b = browser({
    async create(passphrase) { createdPair = await realCore.createKeyPair(passphrase); return createdPair; },
    encrypt: (...args) => realCore.encrypt(...args),
    decrypt: (...args) => realCore.decrypt(...args),
    async decryptFile() {
      extractionDone.resolve();
      return {bytes: new Uint8Array([1]), name: "synthetic.json", context: "synthetic-context", sha256: "a".repeat(64)};
    },
    async reencrypt(...args) {
      try { return await realCore.reencryptKeyBackup(...args); }
      finally { reencryptDone.resolve(); }
    },
  });
  await b.extractCipher([{id: "synthetic-message", content: message, context: "synthetic-context"}]);
  await extractionDone.promise;
  await flush();
  const fingerprint = createdPair.fingerprint;
  const originalBackup = createdPair.encryptedBackup;
  const packet = b.field("packet").value;
  assert.equal(b.field("decrypted").value, message);
  b.field("passphrase").value = chosen;
  b.field("confirm").value = chosen;
  await b.click("export-private");
  await reencryptDone.promise;
  await flush();
  assert.equal(b.calls.downloads.length, 1);
  const exported = await b.calls.downloads[0].blob.text();
  assert.notEqual(exported, originalBackup);
  assert.equal(JSON.parse(exported).fingerprint, fingerprint);
  assert.equal(b.field("packet").value, packet);
  assert.equal(b.calls.create.length, 1);
  await b.click("clear");
  const fresh = browser({
    async restore(...args) {
      try { restoredPair = await realCore.restoreKeyPair(...args); return restoredPair; }
      finally { restoreDone.resolve(); }
    },
    async decrypt(...args) {
      try { return await realCore.decrypt(...args); }
      finally { decryptDone.resolve(); }
    },
  });
  fresh.file("private-file", {size: Buffer.byteLength(exported), async text() { return exported; }});
  fresh.field("passphrase").value = chosen;
  await fresh.click("restore");
  await restoreDone.promise;
  await flush();
  assert.equal(restoredPair.fingerprint, fingerprint);
  assert.equal(restoredPair.privateKey.extractable, false);
  fresh.field("packet").value = packet;
  await fresh.click("decrypt");
  await decryptDone.promise;
  await flush();
  assert.equal(fresh.field("decrypted").value, message);
  assert.equal(fresh.calls.create.length, 0);
  assert.equal(b.calls.network + fresh.calls.network, 0);
  assert.equal(b.calls.persistence + fresh.calls.persistence, 0);
});

async function restoreSyntheticKey(b) {
  b.file("private-file", {size: 100, async text() { return pair().encryptedBackup; }});
  b.field("passphrase").value = "Synthetic restore passphrase 2026";
  await b.click("restore");
}

function conversationRecord(id = "source-message", content = "Nội dung tệp được lưu trong hội thoại.") {
  return {id, role: "user", content,
    context: `session:sess-1|msg:${id}|role:user|epoch:1|scheme:envelope-v1`};
}

function matchingTextHooks() {
  return {
    encrypt: (_recipient, text, context) => JSON.stringify({ciphertext: text, context}),
    decrypt: (_key, _fingerprint, packet) => JSON.parse(packet).ciphertext,
  };
}

test("restoring a key requests selected conversation data without transmitting local key fields", async () => {
  const b = browser({
    ...matchingTextHooks(),
    loadConversation(...args) { assert.deepEqual(args, []); },
  });
  await restoreSyntheticKey(b);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.calls.create.length, 0);
  assert.deepEqual(b.calls.contextLoads, [[]]);
  assert.equal(b.field("passphrase").value, "");
  assert.equal(b.field("confirm").value, "");
  assert.match(b.field("status").textContent, /Đã mở khóa.*[Đđ]ang nạp/);
  const record = conversationRecord();
  await b.extractCipher([record], "fresh-restore-reply", "ready");
  assert.equal(b.field("plaintext").value, record.content);
  assert.equal(b.field("context").value, record.context);
  assert.equal(JSON.parse(b.field("packet").value).ciphertext, record.content);
  assert.equal(b.field("decrypted").value, record.content);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.calls.encrypt[0][0].fingerprint, pair().fingerprint);
  assert.equal(b.calls.create.length, 0);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("a failed key restore does not request conversation data or expose the failed password", async () => {
  const b = browser({
    restore() { throw {code: "backup"}; },
    loadConversation() { assert.fail("Only an opened key may trigger the selected conversation loader"); },
  });
  await restoreSyntheticKey(b);
  assert.equal(b.calls.contextLoads.length, 0);
  assert.equal(b.field("own-public").value, "");
  assert.match(b.field("status").textContent, /mật khẩu sai/);
  assert.equal(b.field("status").textContent.includes("Synthetic"), false);
});

for (const reply of ["no_selection", "empty", "unavailable"]) {
  test(`restoration finishes with clear ${reply} feedback when conversation data is absent`, async () => {
    const b = browser({loadConversation() {}});
    await restoreSyntheticKey(b);
    assert.equal(b.calls.contextLoads.length, 1);
    await b.extractCipher([], `restore-${reply}`, reply);
    assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
    assert.equal(b.field("plaintext").value, "");
    assert.equal(b.field("packet").value, "");
    assert.equal(b.field("decrypted").value, "");
    assert.equal(b.calls.encrypt.length, 0);
    assert.doesNotMatch(b.field("status").textContent, /[Đđ]ang nạp/);
    assert.match(b.field("status").textContent, reply === "no_selection"
      ? /chọn.*hội thoại/i : reply === "empty" ? /chưa có|không có|trống/i : /chưa.*nạp|không.*nạp|khả dụng|thử lại/i);
  });
}

test("an absent conversation selection does not erase independently entered text after opening a backup", async () => {
  const b = browser({loadConversation() {}});
  b.field("plaintext").value = "Manually entered text has no saved conversation source.";
  b.field("context").value = "manual-public-context";
  await restoreSyntheticKey(b);
  await b.extractCipher([], "no-selected-conversation", "no_selection");
  assert.equal(b.field("plaintext").value, "Manually entered text has no saved conversation source.");
  assert.equal(b.field("context").value, "manual-public-context");
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
});

test("restoration after a hidden-page clear reloads data with the restored identity instead of a new automatic key", async () => {
  const b = browser({...matchingTextHooks(), loadConversation() {}, restore: () => pair("bob")});
  await b.extractCipher([conversationRecord("before-hide")], "old-bridge");
  assert.equal(b.calls.create.length, 1);
  b.hide();
  b.show();
  assert.equal(b.field("own-public").value, "");
  assert.equal(b.field("plaintext").value, "");
  await restoreSyntheticKey(b);
  assert.equal(b.calls.contextLoads.length, 1);
  assert.equal(b.field("own-public").value, "PUBLIC PEM bob");
  const record = conversationRecord("after-restore", "Nội dung được nạp lại sau khi mở khóa.");
  await b.extractCipher([record], "fresh-after-restore", "ready");
  assert.equal(b.field("plaintext").value, record.content);
  assert.equal(b.field("decrypted").value, record.content);
  assert.equal(b.calls.create.length, 1);
  assert.equal(b.calls.encrypt.at(-1)[0].fingerprint, pair("bob").fingerprint);
});

test("removing conversation data invalidates pending ciphertext and clears source fields without closing the key", async () => {
  const pending = deferred();
  let encryptions = 0;
  const b = browser({
    ...matchingTextHooks(),
    encrypt(_recipient, text, context) {
      return ++encryptions === 2 ? pending.promise : JSON.stringify({ciphertext: text, context});
    },
  });
  await b.generate();
  await b.extractCipher([conversationRecord("old-message", "OLD CONVERSATION CONTENT")], "old-data");
  assert.equal(b.field("decrypted").value, "OLD CONVERSATION CONTENT");
  await b.click("encrypt");
  b.removeBridge();
  for (const name of ["plaintext", "context", "packet", "decrypted", "file-context"]) {
    assert.equal(b.field(name).value, "", name);
  }
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  pending.resolve(JSON.stringify({ciphertext: "STALE OLD CONVERSATION"}));
  await flush();
  assert.equal(b.field("packet").value, "");
  assert.equal(b.field("decrypted").value, "");
  const record = conversationRecord("new-message", "NEW CONVERSATION CONTENT");
  await b.extractCipher([record], "new-data", "ready", "other-session");
  assert.equal(b.field("plaintext").value, record.content);
  assert.equal(b.field("decrypted").value, record.content);
  assert.equal(b.calls.create.length, 1);
});

test("a new conversation bridge cancels earlier asynchronous extraction before publishing its plaintext", async () => {
  const pending = deferred();
  let encryptions = 0;
  const b = browser({
    ...matchingTextHooks(),
    encrypt(_recipient, text, context) {
      return ++encryptions === 1 ? pending.promise : JSON.stringify({ciphertext: text, context});
    },
  });
  await b.generate();
  await b.extractCipher([conversationRecord("previous-message", "OLD ACCOUNT CONVERSATION")], "previous-data");
  const current = conversationRecord("current-message", "CURRENT CONVERSATION");
  await b.extractCipher([current], "current-data", "ready", "other-session");
  pending.resolve(JSON.stringify({ciphertext: "OLD ACCOUNT CONVERSATION"}));
  await flush();
  assert.equal(b.field("plaintext").value, current.content);
  assert.equal(b.field("decrypted").value, current.content);
  assert.equal(JSON.parse(b.field("packet").value).ciphertext, current.content);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
});

test("encrypting with the opened own key returns exact plaintext and comparison feedback with real WebCrypto", async () => {
  const realCore = require("../src/app/ui_assets/crypto_workbench_core.js");
  const key = await realCore.createKeyPair("Synthetic comparison backup passphrase 2026");
  const message = "Nội dung tệp gốc 🔐\nGiữ nguyên dấu, xuống dòng và khoảng trắng.  ";
  const done = deferred();
  const b = browser({
    create: () => key,
    encrypt: (...args) => realCore.encrypt(...args),
    async decrypt(...args) {
      try { return await realCore.decrypt(...args); }
      finally { done.resolve(); }
    },
  });
  await b.generate();
  b.field("plaintext").value = message;
  b.field("context").value = "synthetic-message-comparison";
  await b.click("encrypt");
  await done.promise;
  await flush();
  assert.equal(b.field("decrypted").value, message);
  assert.match(b.field("packet-info").textContent, /Đối chiếu: khớp nguyên văn bản gốc\./);
  assert.equal(b.calls.encrypt.length, 1);
  assert.equal(b.calls.decrypt.length, 1);
  assert.equal(b.calls.network, 0);
  assert.equal(b.calls.persistence, 0);
});

test("encrypting for another recipient does not claim to decrypt or compare their plaintext", async () => {
  const b = browser();
  await b.generate();
  b.edit("recipient-public", "PUBLIC PEM bob");
  await b.click("import-public");
  b.field("plaintext").value = "Synthetic content for another person";
  await b.click("encrypt");
  assert.equal(b.calls.encrypt.length, 1);
  assert.equal(b.calls.decrypt.length, 0);
  assert.equal(b.field("decrypted").value, "");
  assert.doesNotMatch(b.field("packet-info").textContent, /khớp nguyên văn/);
});

for (const action of ["encrypt", "generate"]) {
  test(`edited plaintext keeps the selected conversation as comparison baseline after ${action}`, async () => {
    const b = browser(matchingTextHooks());
    await b.generate();
    const sourceRecord = conversationRecord("original-source", "Original source content with exact wording.");
    await b.extractCipher([sourceRecord], `baseline-${action}`, "ready");
    assert.equal(b.field("decrypted").value, sourceRecord.content);
    const edited = "Edited text has a valid crypto roundtrip but differs from the saved source.";
    b.edit("plaintext", edited);
    if (action === "generate") await b.generate();
    else await b.click("encrypt");
    assert.equal(b.field("plaintext").value, edited);
    assert.equal(b.field("decrypted").value, edited);
    assert.match(b.field("packet-info").textContent, /Đối chiếu: không khớp văn bản gốc\./);
    assert.doesNotMatch(b.field("packet-info").textContent, /Đối chiếu: khớp nguyên văn bản gốc\./);
    await b.click("decrypt");
    assert.equal(b.field("decrypted").value, edited);
    assert.match(b.field("packet-info").textContent, /Đối chiếu: không khớp văn bản gốc\./);
    assert.doesNotMatch(b.field("packet-info").textContent, /Đối chiếu: khớp nguyên văn bản gốc\./);
  });
}

test("source selection distinguishes file-reading user content from the assistant summary without replacing the opened key", async () => {
  const b = browser({...matchingTextHooks(), loadConversation() {}});
  await restoreSyntheticKey(b);
  const original = conversationRecord("139", "Văn bản được trích xuất từ tệp gốc; cần đối chiếu nguyên văn.");
  const summary = {...conversationRecord("140", "Bản tóm tắt từ trợ lý."), role: "assistant"};
  await b.extractCipher([original, summary], "two-source-messages", "ready");
  assert.equal(b.field("plaintext").value, summary.content);
  const options = b.field("source-message").children;
  assert.ok(options.some(option => option.value === original.id));
  assert.ok(options.some(option => option.value === summary.id));
  assert.equal(options.some(option => option.textContent.includes(original.content)), false);
  assert.equal(options.some(option => option.textContent.includes(summary.content)), false);
  b.edit("source-message", original.id, "change");
  await flush();
  assert.equal(b.field("plaintext").value, original.content);
  assert.equal(b.field("decrypted").value, original.content);
  assert.equal(b.field("source-message").value, original.id);
  assert.equal(b.field("own-public").value, "PUBLIC PEM alice");
  assert.equal(b.calls.create.length, 0);
});


