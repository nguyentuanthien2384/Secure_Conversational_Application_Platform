const {test, before} = require("node:test");
const assert = require("node:assert/strict");
const {webcrypto} = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const core = require("../src/app/ui_assets/crypto_workbench_core.js");
const PASSPHRASE = "My separate backup passphrase #2026";
const encoder = new TextEncoder();
let alice;
let bob;
let packet;

function b64(value) { return Buffer.from(value).toString("base64url"); }
function unb64(value) { return Buffer.from(value, "base64url"); }
function changedByte(value) {
  const result = unb64(value);
  result[0] ^= 1;
  return b64(result);
}
function mutated(value, changes) { return JSON.stringify({...JSON.parse(value), ...changes}); }
function safeError(code) {
  return (error) => error instanceof core.CryptoWorkbenchError && error.code === code &&
    !error.message.includes(PASSPHRASE) && !error.message.includes("PRIVATE KEY");
}
function isolated(provider) {
  const context = vm.createContext({crypto: provider, TextEncoder, TextDecoder, Uint8Array, atob, btoa});
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/crypto_workbench_core.js"), "utf8"), context);
  return context.ScapCryptoCore;
}

before(async () => {
  alice = await core.createKeyPair(PASSPHRASE);
  bob = await core.createKeyPair(PASSPHRASE);
  packet = await core.encrypt(alice, "Bảo mật 🔐\n零知識\u0000", "demo-workbench");
});

test("keypair only exposes a nonextractable private CryptoKey and encrypted backup", async () => {
  assert.deepEqual(Object.keys(alice).sort(), ["encryptedBackup", "fingerprint", "privateKey", "publicKey", "publicPem"].sort());
  assert.equal(alice.privateKey.extractable, false);
  assert.deepEqual(alice.privateKey.usages, ["decrypt"]);
  assert.equal(alice.privateKey.algorithm.modulusLength, 3072);
  assert.equal(alice.privateKey.algorithm.hash.name, "SHA-256");
  assert.match(alice.fingerprint, /^[0-9a-f]{64}$/);
  assert.ok(!alice.encryptedBackup.includes("PRIVATE KEY"));
  assert.ok(!alice.encryptedBackup.includes(PASSPHRASE));
  await assert.rejects(webcrypto.subtle.exportKey("pkcs8", alice.privateKey));
  await assert.rejects(webcrypto.subtle.exportKey("jwk", alice.privateKey));
  assert.equal(Object.isFrozen(core), true);
});

test("public SPKI PEM imports canonically and fingerprint identifies its full DER", async () => {
  const imported = await core.importPublicKey(alice.publicPem.replace(/\n/g, "\r\n"));
  assert.equal(imported.publicPem, alice.publicPem);
  assert.equal(imported.fingerprint, alice.fingerprint);
  const der = await webcrypto.subtle.exportKey("spki", imported.publicKey);
  const digest = await webcrypto.subtle.digest("SHA-256", der);
  assert.equal(Buffer.from(digest).toString("hex"), alice.fingerprint);
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, await core.encrypt(imported, "public recipient")), "public recipient");
});

test("encrypted backup restores the same nonextractable private key and public identity", async () => {
  const restored = await core.restoreKeyPair(alice.encryptedBackup, PASSPHRASE);
  assert.equal(restored.privateKey.extractable, false);
  assert.equal(restored.fingerprint, alice.fingerprint);
  assert.equal(restored.publicPem, alice.publicPem);
  assert.equal(restored.encryptedBackup, alice.encryptedBackup);
  assert.equal(await core.decrypt(restored.privateKey, restored.fingerprint, packet), "Bảo mật 🔐\n零知識\u0000");
  await assert.rejects(webcrypto.subtle.exportKey("pkcs8", restored.privateKey));
});

test("Unicode and empty plaintext roundtrip without ciphertext containing cleartext", async () => {
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, packet), "Bảo mật 🔐\n零知識\u0000");
  assert.ok(!packet.includes("Bảo mật"));
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, await core.encrypt(alice, "")), "");
});

test("every encryption uses a distinct nonce and AES key", async () => {
  const first = JSON.parse(await core.encrypt(alice, "same text", "same context"));
  const second = JSON.parse(await core.encrypt(alice, "same text", "same context"));
  assert.notEqual(first.nonce, second.nonce);
  const header = ({format, version, suite, recipient, context}) => ({format, version, suite, recipient, context});
  const unwrap = (value) => webcrypto.subtle.decrypt({name: "RSA-OAEP", label: encoder.encode(JSON.stringify(header(value)))}, alice.privateKey, unb64(value.wrappedKey));
  const left = Buffer.from(await unwrap(first));
  const right = Buffer.from(await unwrap(second));
  assert.equal(left.length, 32);
  assert.equal(right.length, 32);
  assert.notDeepEqual(left, right);
  left.fill(0);
  right.fill(0);
});

test("wrong backup passphrase and ciphertext changes produce fixed safe failures", async () => {
  await assert.rejects(core.restoreKeyPair(alice.encryptedBackup, "An entirely wrong passphrase"), safeError("backup"));
  const backup = JSON.parse(alice.encryptedBackup);
  await assert.rejects(core.restoreKeyPair(mutated(alice.encryptedBackup, {ciphertext: changedByte(backup.ciphertext)}), PASSPHRASE), safeError("backup"));
  await assert.rejects(core.restoreKeyPair(mutated(alice.encryptedBackup, {salt: changedByte(backup.salt)}), PASSPHRASE), safeError("backup"));
  await assert.rejects(core.restoreKeyPair(mutated(alice.encryptedBackup, {nonce: changedByte(backup.nonce)}), PASSPHRASE), safeError("backup"));
});

test("backup header is authenticated and public/private pair substitution is rejected", async () => {
  const old = JSON.parse(alice.encryptedBackup);
  const other = JSON.parse(bob.encryptedBackup);
  await assert.rejects(core.restoreKeyPair(mutated(alice.encryptedBackup,
    {publicSpki: other.publicSpki, fingerprint: other.fingerprint}), PASSPHRASE), safeError("backup"));

  // Re-authenticate Alice's DER with Bob's public metadata using the known passphrase:
  // only the explicit RSA pair proof can reject this otherwise authentic backup.
  const material = await webcrypto.subtle.importKey("raw", encoder.encode(PASSPHRASE), "PBKDF2", false, ["deriveKey"]);
  const derived = await webcrypto.subtle.deriveKey({name: "PBKDF2", hash: "SHA-256", iterations: 600000, salt: unb64(old.salt)},
    material, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  const {nonce, ciphertext, ...header} = old;
  const privateDer = await webcrypto.subtle.decrypt({name: "AES-GCM", iv: unb64(nonce), additionalData: encoder.encode(JSON.stringify(header))}, derived, unb64(ciphertext));
  const replacement = {...header, publicSpki: other.publicSpki, fingerprint: other.fingerprint};
  const replacementCiphertext = await webcrypto.subtle.encrypt({name: "AES-GCM", iv: unb64(nonce), additionalData: encoder.encode(JSON.stringify(replacement))}, derived, privateDer);
  new Uint8Array(privateDer).fill(0);
  await assert.rejects(core.restoreKeyPair(JSON.stringify({...replacement, nonce, ciphertext: b64(replacementCiphertext)}), PASSPHRASE), safeError("backup"));
});

test("backup schema, algorithms and KDF costs reject before any derivation", async () => {
  let derivations = 0;
  const wrappedSubtle = new Proxy(webcrypto.subtle, {get(target, name) {
    if (name === "deriveKey") return (...args) => { derivations += 1; return target.deriveKey(...args); };
    const value = target[name];
    return typeof value === "function" ? value.bind(target) : value;
  }});
  const checked = isolated({subtle: wrappedSubtle, getRandomValues: webcrypto.getRandomValues.bind(webcrypto)});
  for (const changes of [{iterations: 1}, {iterations: 600001}, {iterations: 1e12}, {iterations: "600000"},
    {version: 2}, {kdf: "PBKDF2-SHA1"}, {suite: "RSA1_5"}, {extra: true}, {fingerprint: "f".repeat(63)},
    {salt: "!"}, {salt: "AA"}, {nonce: "AA"}, {publicSpki: "A".repeat(1500)}]) {
    await assert.rejects(checked.restoreKeyPair(mutated(alice.encryptedBackup, changes), PASSPHRASE),
      (error) => error.code === "backup");
  }
  await assert.rejects(checked.restoreKeyPair("x".repeat(16001), PASSPHRASE), (error) => error.code === "backup");
  await assert.rejects(checked.restoreKeyPair(alice.encryptedBackup.replace('"iterations":', '"iterations":600000,"iterations":'), PASSPHRASE),
    (error) => error.code === "backup");
  assert.equal(derivations, 0);
});

test("passphrase policy rejects weak, invalid UTF-16, and unbounded input", async () => {
  for (const passphrase of ["", "short password", "a".repeat(257), "🔑".repeat(65), "\ud800".repeat(16), null, {}]) {
    await assert.rejects(core.createKeyPair(passphrase), safeError("passphrase"));
    await assert.rejects(core.restoreKeyPair(alice.encryptedBackup, passphrase), safeError("passphrase"));
  }
});

test("packet metadata, context, nonce, wrapped key, ciphertext and tag are authenticated", async () => {
  const original = JSON.parse(packet);
  for (const changes of [{context: "different purpose"}, {nonce: changedByte(original.nonce)},
    {wrappedKey: changedByte(original.wrappedKey)}, {ciphertext: changedByte(original.ciphertext)},
    {recipient: bob.fingerprint}, {version: 2}, {suite: "RSA1_5"}, {format: "unknown"}, {extra: "not allowed"}]) {
    await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, mutated(packet, changes)), safeError("decrypt"));
  }
});

test("ciphertext cannot be decrypted with another private key or fingerprint", async () => {
  await assert.rejects(core.decrypt(bob.privateKey, bob.fingerprint, packet), safeError("decrypt"));
  await assert.rejects(core.decrypt(bob.privateKey, alice.fingerprint, packet), safeError("decrypt"));
  await assert.rejects(core.decrypt(alice.privateKey, bob.fingerprint, packet), safeError("decrypt"));
  await assert.rejects(core.encrypt({...alice, fingerprint: bob.fingerprint}, "secret"), safeError("encrypt"));
});

test("all packet bounds and malformed base64url are rejected", async () => {
  for (const changes of [{nonce: "AA"}, {nonce: "A".repeat(17)}, {wrappedKey: "AA"}, {ciphertext: "AA"},
    {nonce: "A".repeat(16) + "="}, {nonce: "A".repeat(15) + "+"}, {ciphertext: "A"},
    {context: "x".repeat(257)}, {context: null}, {context: {}}, {recipient: null}, {nonce: []}, {ciphertext: false}]) {
    await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, mutated(packet, changes)), safeError("decrypt"));
  }
  for (const value of ["null", "[]", "{}", "invalid JSON", "x".repeat(96001), null, {}, 7,
    packet.replace('"format":', '"__proto__":{},"format":')]) {
    await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, value), safeError("decrypt"));
  }
});

test("noncanonical base64url unused bits are rejected", async () => {
  const original = JSON.parse(packet);
  // GCM ciphertext length is not fixed; select a one-byte plaintext to give a
  // 17-byte ciphertext+tag and one unused base64 bit pair.
  const chosen = JSON.parse(await core.encrypt(alice, "x"));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const tail = chosen.ciphertext.slice(-1);
  const index = alphabet.indexOf(tail);
  assert.equal(index % 4, 0);
  const alternate = chosen.ciphertext.slice(0, -1) + alphabet[index + 1];
  assert.deepEqual(unb64(alternate), unb64(chosen.ciphertext));
  await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, JSON.stringify({...chosen, ciphertext: alternate})), safeError("decrypt"));
  assert.equal(original.nonce.length, 16);
});

test("duplicate and escaped duplicate JSON fields are rejected without rejecting pretty JSON", async () => {
  const pretty = JSON.stringify(JSON.parse(packet), null, 2);
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, pretty), "Bảo mật 🔐\n零知識\u0000");
  for (const value of [packet.replace('"version":', '"version":1,"version":'),
    packet.replace('"version":', '"vers\\u0069on":1,"version":')]) {
    await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, value), safeError("decrypt"));
  }
});

test("plaintext limits count UTF-8 bytes and do not truncate or replace invalid UTF-16", async () => {
  const boundary = "🔐".repeat(16384);
  const encrypted = await core.encrypt(alice, boundary, "x".repeat(256));
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, encrypted), boundary);
  for (const value of ["a".repeat(65537), boundary + "x", "\ud800", "a\udc00", "\udc00\udc00", null, {}]) {
    await assert.rejects(core.encrypt(alice, value), safeError("encrypt"));
  }
  await assert.rejects(core.encrypt(alice, "x", "🔐".repeat(65)), safeError("encrypt"));
});

test("weak RSA public keys, alternative exponents, private PEM and malformed public keys reject", async () => {
  const weak = await webcrypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 1024,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"}, true, ["encrypt", "decrypt"]);
  const spki = Buffer.from(await webcrypto.subtle.exportKey("spki", weak.publicKey)).toString("base64");
  const weakPem = `-----BEGIN PUBLIC KEY-----\n${spki}\n-----END PUBLIC KEY-----`;
  await assert.rejects(core.importPublicKey(weakPem), safeError("public_key"));
  await assert.rejects(core.encrypt({publicKey: weak.publicKey, fingerprint: alice.fingerprint}, "x"), safeError("encrypt"));
  const exponent3 = await webcrypto.subtle.generateKey({name: "RSA-OAEP", modulusLength: 3072,
    publicExponent: new Uint8Array([3]), hash: "SHA-256"}, true, ["encrypt", "decrypt"]);
  const exponentDer = Buffer.from(await webcrypto.subtle.exportKey("spki", exponent3.publicKey)).toString("base64");
  await assert.rejects(core.importPublicKey(`-----BEGIN PUBLIC KEY-----\n${exponentDer}\n-----END PUBLIC KEY-----`), safeError("public_key"));
  for (const value of ["-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", alice.publicPem + "trailing garbage",
    alice.publicPem.replace("PUBLIC KEY", "RSA PUBLIC KEY"), "x".repeat(2049), null, {}]) {
    await assert.rejects(core.importPublicKey(value), safeError("public_key"));
  }
});

test("unsupported browsers fail safely without network or storage globals", async () => {
  const unavailable = isolated(undefined);
  await assert.rejects(unavailable.createKeyPair(PASSPHRASE), (error) => error.code === "unsupported");
  await assert.rejects(unavailable.encrypt(alice, "private"), (error) => error.code === "unsupported");
  await assert.rejects(unavailable.decrypt(alice.privateKey, alice.fingerprint, packet), (error) => error.code === "unsupported");
  const isolatedCore = isolated(webcrypto);
  const imported = await isolatedCore.importPublicKey(alice.publicPem);
  assert.equal(imported.fingerprint, alice.fingerprint);
});
