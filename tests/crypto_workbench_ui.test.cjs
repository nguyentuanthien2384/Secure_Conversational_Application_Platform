"use strict";
const {test} = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/crypto_workbench.js"), "utf8");
const flush = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return {promise, resolve, reject}; };
const pair = (name = "alice") => ({privateKey: {type: "private", extractable: false, name},
  publicKey: {type: "public", name}, publicPem: `PUBLIC PEM ${name}`, fingerprint: (name === "alice" ? "a" : "b").repeat(64),
  encryptedBackup: JSON.stringify({format: "scap-key-backup", ciphertext: `ENCRYPTED ${name}`})});

function browser(options = {}) {
  const calls = {create: [], restore: [], import: [], encrypt: [], decrypt: [], encryptFile: [], decryptFile: [], clipboard: [], downloads: [],
    revoked: [], network: 0, persistence: 0};
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
      if (input) {
        let contents = "";
        Object.defineProperty(this, "value", {get: () => contents, set: (value) => {
          contents = value;
          if (value === "" && ["recipient-file", "private-file", "file-input"].includes(attributes["data-crypto-field"])) this.files = [];
        }});
      }
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
    closest(selector) {
      if (selector === "[data-crypto-action]") return this.attributes["data-crypto-action"] ? this : null;
      if (selector === "#btn-logout, #btn-logout-all") return this.logout ? this : null;
      return null;
    }
    set innerHTML(_) { assert.fail("User data must never reach innerHTML"); }
  }
  function makeRoot() {
    const root = new Element();
    root.fields = new Map();
    for (const name of ["status", "passphrase", "confirm", "own-public", "own-info", "recipient-public", "recipient-file",
      "recipient-info", "private-file", "plaintext", "context", "packet", "decrypted", "packet-info",
      "file-input", "file-info", "file-context", "file-result"]) {
      root.fields.set(name, new Element({"data-crypto-field": name}, !["status", "own-info", "recipient-info", "packet-info", "file-info", "file-result"].includes(name)));
    }
    root.buttons = new Map(["generate", "restore", "export-private", "export-public", "copy-public", "import-public", "encrypt", "decrypt", "encrypt-file", "decrypt-file", "clear"]
      .map((name) => [name, new Element({"data-crypto-action": name})]));
    root.querySelector = (selector) => root.fields.get(/^\[data-crypto-field="([^"]+)"\]$/.exec(selector)?.[1]) || null;
    root.querySelectorAll = (selector) => selector === "[data-crypto-action]" ? [...root.buttons.values()] : [];
    root.contains = (node) => node === root || [...root.fields.values(), ...root.buttons.values()].includes(node);
    return root;
  }
  let root = makeRoot();
  const core = {
    limits: {fileBytes: 5242880, fileContainerBytes: 5246380},
    async createKeyPair(...args) { calls.create.push(args); return options.create ? options.create(...args) : pair(); },
    async restoreKeyPair(...args) { calls.restore.push(args); return options.restore ? options.restore(...args) : pair(); },
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
    getElementById(id) { return id === "app-sec" ? app : null; },
    querySelector(selector) {
      if (selector === '#crypto-workbench [data-scap-crypto-workbench="1"]') return root;
      if (selector === "#session-bridge [data-scap-session-clear]") return clearMarker ? {} : null;
      throw new Error(`Unexpected selector: ${selector}`);
    },
    createElement(tag) {
      assert.equal(tag, "a");
      return {click() { calls.downloads.push({url: this.href, filename: this.download, blob: blobs.get(this.href)}); }, remove() {}};
    },
  };
  Object.defineProperty(document, "cookie", {get() { calls.persistence += 1; throw new Error("No cookies allowed"); }});
  const context = {
    document, Blob, TextEncoder, ArrayBuffer, Uint8Array, ScapCryptoCore: options.noCore ? undefined : core, isSecureContext: options.secure !== false,
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
    calls, app, document, core, timers,
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
