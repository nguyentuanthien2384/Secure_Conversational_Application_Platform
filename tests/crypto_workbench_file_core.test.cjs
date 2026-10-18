const {test, before} = require("node:test");
const assert = require("node:assert/strict");
const {webcrypto, createHash} = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const core = require("../src/app/ui_assets/crypto_workbench_core.js");

const PASSPHRASE = "File backup demonstration passphrase 2026";
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", {fatal: true});
const FILE_NAME = "Hồ sơ demo 🔐.bin";
const CONTENT = Uint8Array.from([0, 255, 254, 0, 128, 65, 0, 10]);
let alice;
let bob;
let encrypted;

function failure(code) {
  return (error) => error instanceof core.CryptoWorkbenchError && error.code === code &&
    !error.message.includes(FILE_NAME) && !error.message.includes(PASSPHRASE);
}
function lengthPrefix(size) {
  const value = Buffer.alloc(4);
  value.writeUInt32BE(size);
  return value;
}
function parts(value) {
  const data = Buffer.from(value);
  const headerLength = data.readUInt32BE(8);
  const nonceOffset = 12 + headerLength;
  const wrappedOffset = nonceOffset + 12;
  const ciphertextOffset = wrappedOffset + 384;
  return {data, header: JSON.parse(decoder.decode(data.subarray(12, nonceOffset))),
    headerBytes: data.subarray(12, nonceOffset), nonce: data.subarray(nonceOffset, wrappedOffset),
    wrappedKey: data.subarray(wrappedOffset, ciphertextOffset),
    label: data.subarray(0, wrappedOffset), aad: data.subarray(0, ciphertextOffset),
    ciphertext: data.subarray(ciphertextOffset), nonceOffset, wrappedOffset, ciphertextOffset};
}
function replacingHeader(value, headerText) {
  const parsed = parts(value);
  const header = Buffer.from(headerText);
  return Buffer.concat([parsed.data.subarray(0, 8), lengthPrefix(header.length), header,
    parsed.nonce, parsed.wrappedKey, parsed.ciphertext]);
}
async function unwrapped(value) {
  const parsed = parts(value);
  return new Uint8Array(await webcrypto.subtle.decrypt({name: "RSA-OAEP", label: parsed.label},
    alice.privateKey, parsed.wrappedKey));
}
async function payload(value) {
  const parsed = parts(value);
  const rawKey = await unwrapped(value);
  try {
    const key = await webcrypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    return Buffer.from(await webcrypto.subtle.decrypt({name: "AES-GCM", iv: parsed.nonce,
      additionalData: parsed.aad, tagLength: 128}, key, parsed.ciphertext));
  } finally { rawKey.fill(0); }
}
async function withPayload(value, cleartext) {
  const parsed = parts(value);
  const rawKey = await unwrapped(value);
  try {
    const key = await webcrypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
    const cipher = await webcrypto.subtle.encrypt({name: "AES-GCM", iv: parsed.nonce,
      additionalData: parsed.aad, tagLength: 128}, key, cleartext);
    return Buffer.concat([parsed.aad, Buffer.from(cipher)]);
  } finally { rawKey.fill(0); }
}
async function withMetadata(value, metadataText, content = CONTENT) {
  const metadata = Buffer.from(metadataText);
  return withPayload(value, Buffer.concat([lengthPrefix(metadata.length), metadata, content]));
}
async function withAuthenticatedHeader(value, headerBytes) {
  const parsed = parts(value);
  const rawKey = await unwrapped(value);
  const cleartext = await payload(value);
  try {
    const label = Buffer.concat([parsed.data.subarray(0, 8), lengthPrefix(headerBytes.length), headerBytes, parsed.nonce]);
    const wrapped = await webcrypto.subtle.encrypt({name: "RSA-OAEP", label}, alice.publicKey, rawKey);
    const aad = Buffer.concat([label, Buffer.from(wrapped)]);
    const key = await webcrypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
    const cipher = await webcrypto.subtle.encrypt({name: "AES-GCM", iv: parsed.nonce, additionalData: aad, tagLength: 128}, key, cleartext);
    return Buffer.concat([aad, Buffer.from(cipher)]);
  } finally {
    rawKey.fill(0);
    cleartext.fill(0);
  }
}
function isolated(provider) {
  const context = vm.createContext({crypto: provider, TextEncoder, TextDecoder, Uint8Array,
    DataView, atob, btoa});
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../src/app/ui_assets/crypto_workbench_core.js"), "utf8"), context);
  return context.ScapCryptoCore;
}
function observingCore() {
  const calls = [];
  const observingSubtle = new Proxy(webcrypto.subtle, {get(target, field) {
    const member = target[field];
    if (typeof member !== "function") return member;
    return (...args) => { calls.push(field); return member.apply(target, args); };
  }});
  return {api: isolated({subtle: observingSubtle, getRandomValues: webcrypto.getRandomValues.bind(webcrypto)}), calls};
}

before(async () => {
  alice = await core.createKeyPair(PASSPHRASE);
  bob = await core.createKeyPair(PASSPHRASE);
  encrypted = await core.encryptFile(alice, CONTENT, {name: FILE_NAME, context: "demo-file"});
});

test("file limits and versioned binary format are explicit and bounded", () => {
  assert.equal(core.limits.fileBytes, 5242880);
  assert.equal(core.limits.fileContainerBytes, 5246380);
  assert.equal(core.limits.fileNameBytes, 255);
  assert.equal(core.fileFormat, "scap-encrypted-file");
  assert.equal(Buffer.from(encrypted.subarray(0, 8)).toString("ascii"), "SCAPFIL1");
  assert.deepEqual(parts(encrypted).header, {format: "scap-encrypted-file", version: 1,
    suite: core.suite, recipient: alice.fingerprint, context: "demo-file"});
  assert.equal(parts(encrypted).nonce.length, 12);
  assert.equal(parts(encrypted).wrappedKey.length, 384);
});

test("arbitrary binary bytes and the original UTF-8 name roundtrip without text conversion", async () => {
  const original = Uint8Array.from({length: 256 * 4}, (_, index) => index % 256);
  const packet = await core.encryptFile(alice, original, {name: FILE_NAME, context: "hồ sơ 🔐"});
  const restored = await core.decryptFile(alice.privateKey, alice.fingerprint, packet);
  assert.ok(restored.bytes instanceof Uint8Array);
  assert.deepEqual(restored.bytes, original);
  assert.equal(restored.name, FILE_NAME);
  assert.equal(restored.context, "hồ sơ 🔐");
  assert.equal(restored.sha256, createHash("sha256").update(original).digest("hex"));
});

test("name, original size and digest exist only inside the authenticated ciphertext", async () => {
  const digest = createHash("sha256").update(CONTENT).digest("hex");
  const packet = Buffer.from(encrypted);
  assert.equal(packet.includes(Buffer.from(FILE_NAME)), false);
  assert.equal(packet.includes(Buffer.from(digest)), false);
  assert.equal(packet.includes(Buffer.from('"size":')), false);
  const inner = await payload(encrypted);
  const metadata = JSON.parse(decoder.decode(inner.subarray(4, 4 + inner.readUInt32BE(0))));
  assert.deepEqual(metadata, {name: FILE_NAME, size: CONTENT.length, sha256: digest});
  inner.fill(0);
});

test("empty files are valid and preserve the standard SHA256 empty digest", async () => {
  const packet = await core.encryptFile(alice, new Uint8Array(), {name: "empty.bin"});
  const restored = await core.decryptFile(alice.privateKey, alice.fingerprint, packet);
  assert.equal(restored.bytes.length, 0);
  assert.equal(restored.context, "");
  assert.equal(restored.sha256, createHash("sha256").digest("hex"));
});

test("exact 5 MiB files roundtrip byte-for-byte and oversized input is rejected", async () => {
  const content = Uint8Array.from({length: core.limits.fileBytes}, (_, index) => index % 251);
  const packet = await core.encryptFile(alice, content, {name: "maximum.bin", context: "\u0000".repeat(256)});
  assert.ok(packet.length <= core.limits.fileContainerBytes);
  const restored = await core.decryptFile(alice.privateKey, alice.fingerprint, packet);
  assert.deepEqual(restored.bytes, content);
  assert.equal(content[1], 1, "encryption must not wipe the caller-owned bytes");
  await assert.rejects(core.encryptFile(alice, new Uint8Array(core.limits.fileBytes + 1), {name: "too-big.bin"}), failure("encrypt"));
});

test("each file gets a fresh nonce and a distinct independently wrapped AES256 key", async () => {
  const second = await core.encryptFile(alice, CONTENT, {name: FILE_NAME, context: "demo-file"});
  assert.notDeepEqual(parts(second).nonce, parts(encrypted).nonce);
  const firstKey = await unwrapped(encrypted);
  const secondKey = await unwrapped(second);
  assert.equal(firstKey.length, 32);
  assert.equal(secondKey.length, 32);
  assert.notDeepEqual(firstKey, secondKey);
  firstKey.fill(0);
  secondKey.fill(0);
});

test("file encryption snapshots caller bytes and metadata before asynchronous operations", async () => {
  const input = Uint8Array.from(CONTENT);
  const options = {name: "before.bin", context: "before"};
  const pending = core.encryptFile(alice, input, options);
  input.fill(123);
  options.name = "after.bin";
  options.context = "after";
  const restored = await core.decryptFile(alice.privateKey, alice.fingerprint, await pending);
  assert.deepEqual(restored.bytes, CONTENT);
  assert.equal(restored.name, "before.bin");
  assert.equal(restored.context, "before");
  assert.ok(input.every((byte) => byte === 123));
});

test("file encryption snapshots the recipient key and identity before asynchronous operations", async () => {
  const recipient = {...alice};
  const pending = core.encryptFile(recipient, CONTENT, {name: "recipient-snapshot.bin"});
  recipient.publicKey = bob.publicKey;
  recipient.fingerprint = bob.fingerprint;
  const packet = await pending;
  assert.equal(parts(packet).header.recipient, alice.fingerprint);
  assert.deepEqual((await core.decryptFile(alice.privateKey, alice.fingerprint, packet)).bytes, CONTENT);
  await assert.rejects(core.decryptFile(bob.privateKey, bob.fingerprint, packet), failure("decrypt"));
});

test("file decryption snapshots a mutable subarray before its first await", async () => {
  const padded = new Uint8Array(encrypted.length + 20);
  padded.set(encrypted, 11);
  const view = padded.subarray(11, 11 + encrypted.length);
  const pending = core.decryptFile(alice.privateKey, alice.fingerprint, view);
  view.fill(0);
  assert.deepEqual((await pending).bytes, CONTENT);
});

test("wrong fingerprint, wrong private key and mismatched recipient public identity fail safely", async () => {
  await assert.rejects(core.decryptFile(alice.privateKey, bob.fingerprint, encrypted), failure("decrypt"));
  await assert.rejects(core.decryptFile(bob.privateKey, alice.fingerprint, encrypted), failure("decrypt"));
  await assert.rejects(core.encryptFile({...alice, fingerprint: bob.fingerprint}, CONTENT, {name: "x.bin"}), failure("encrypt"));
});

test("file input accepts only bounded Uint8Array binary views", async () => {
  for (const value of [null, undefined, "binary", [0, 255], new ArrayBuffer(10), new DataView(new ArrayBuffer(10)), new Uint16Array(10)]) {
    await assert.rejects(core.encryptFile(alice, value, {name: "x.bin"}), failure("encrypt"));
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, value), failure("decrypt"));
  }
});

test("unsafe or unbounded original names and malformed options are rejected", async () => {
  const names = ["", " ", ".", "..", "../x", "dir/x", "dir\\x", "a\u0000b", "a\nb", "a\u007fb", "a\u0085b",
    "a\u202eb", "a\u2066b", "a\ud800b", "a".repeat(256), "🔐".repeat(64)];
  for (const name of names) await assert.rejects(core.encryptFile(alice, CONTENT, {name}), failure("encrypt"));
  for (const options of [undefined, null, {}, [], {name: "x.bin", unknown: true}, {name: "x.bin", context: null}]) {
    await assert.rejects(core.encryptFile(alice, CONTENT, options), failure("encrypt"));
  }
  const packet = await core.encryptFile(alice, CONTENT, {name: "a".repeat(255)});
  assert.equal((await core.decryptFile(alice.privateKey, alice.fingerprint, packet)).name.length, 255);
});

test("file public context uses UTF-8 byte limits and rejects lone surrogates", async () => {
  for (const context of ["a".repeat(257), "🔐".repeat(65), "x\ud800", 0, null]) {
    await assert.rejects(core.encryptFile(alice, CONTENT, {name: "x.bin", context}), failure("encrypt"));
  }
});

test("every outer framing component and ciphertext tag is authenticated", async () => {
  const parsed = parts(encrypted);
  const offsets = [0, 7, 8, 11, 12, parsed.nonceOffset, parsed.wrappedOffset,
    parsed.ciphertextOffset, encrypted.length - 1];
  for (const offset of offsets) {
    const packet = Uint8Array.from(encrypted);
    packet[offset] ^= 1;
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, packet), failure("decrypt"));
  }
  for (const field of ["context", "recipient", "format", "version", "suite"]) {
    const header = {...parsed.header, [field]: field === "version" ? 2 : "changed"};
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
      replacingHeader(encrypted, JSON.stringify(header))), failure("decrypt"));
  }
});

test("OAEP label includes the nonce and cannot be unwrapped after nonce substitution", async () => {
  const parsed = parts(encrypted);
  const label = Buffer.from(parsed.label);
  label[label.length - 1] ^= 1;
  await assert.rejects(webcrypto.subtle.decrypt({name: "RSA-OAEP", label}, alice.privateKey, parsed.wrappedKey));
});

test("GCM AAD includes the exact wrapped key bytes, even for an equivalent valid rewrap", async () => {
  const parsed = parts(encrypted);
  const rawKey = await unwrapped(encrypted);
  try {
    const replacement = new Uint8Array(await webcrypto.subtle.encrypt({name: "RSA-OAEP", label: parsed.label}, alice.publicKey, rawKey));
    assert.notDeepEqual(replacement, new Uint8Array(parsed.wrappedKey));
    const packet = Uint8Array.from(encrypted);
    packet.set(replacement, parsed.wrappedOffset);
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, packet), failure("decrypt"));
  } finally { rawKey.fill(0); }
});

test("truncation, extra trailing bytes and over-limit containers are rejected", async () => {
  const parsed = parts(encrypted);
  for (const end of [0, 7, 8, 11, 12, parsed.nonceOffset - 1, parsed.wrappedOffset - 1,
    parsed.ciphertextOffset - 1, encrypted.length - 1]) {
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, encrypted.subarray(0, end)), failure("decrypt"));
  }
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
    Buffer.concat([encrypted, Buffer.from([0])])), failure("decrypt"));
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
    new Uint8Array(core.limits.fileContainerBytes + 1)), failure("decrypt"));
});

test("header schema, versions, duplicate properties and noncanonical JSON reject before key operations", async () => {
  const {api, calls} = observingCore();
  const header = parts(encrypted).header;
  const missing = {...header};
  delete missing.context;
  const mutations = [JSON.stringify(missing), JSON.stringify({...header, extra: 1}),
    JSON.stringify({...header, version: "1"}), JSON.stringify({...header, version: 0}),
    JSON.stringify({...header, format: "scap-encrypted-text"}), JSON.stringify({...header, suite: "AES-ECB"}),
    JSON.stringify({...header, recipient: header.recipient.toUpperCase()}),
    JSON.stringify({...header, context: "x".repeat(257)}), JSON.stringify({...header, context: "\ud800"}),
    JSON.stringify({...header, context: null}), JSON.stringify(header, null, 2),
    JSON.stringify(header).replace('"version":1', '"version":1,"version":1'),
    JSON.stringify(header).replace('"version":1', '"version":1,"\\u0076ersion":1')];
  for (const text of mutations) {
    await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint, replacingHeader(encrypted, text)),
      (error) => error.code === "decrypt");
  }
  assert.deepEqual(calls, []);
});

test("hostile header lengths and malformed UTF-8 reject before key operations", async () => {
  const {api, calls} = observingCore();
  for (const size of [0, 1, 2049, 0xffffffff]) {
    const packet = Buffer.from(encrypted);
    packet.writeUInt32BE(size, 8);
    await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint, packet), (error) => error.code === "decrypt");
  }
  const invalidUtf8 = Buffer.from(encrypted);
  invalidUtf8[12] = 0xff;
  await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint, invalidUtf8), (error) => error.code === "decrypt");
  assert.deepEqual(calls, []);
});

test("file and container max-plus-one bounds reject before any cryptographic operation", async () => {
  const {api, calls} = observingCore();
  const options = Object.assign(Object.create(Object.getPrototypeOf(api)), {name: "too-big.bin"});
  await assert.rejects(api.encryptFile(alice, new Uint8Array(core.limits.fileBytes + 1), options),
    (error) => error.code === "encrypt");
  await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint,
    new Uint8Array(core.limits.fileContainerBytes + 1)), (error) => error.code === "decrypt");
  assert.deepEqual(calls, []);
});

test("authenticated UTF-8 BOM headers and metadata cannot bypass canonical byte validation", async () => {
  const {api, calls} = observingCore();
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  const headerBytes = Buffer.concat([bom, parts(encrypted).headerBytes]);
  const packet = await withAuthenticatedHeader(encrypted, headerBytes);
  await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint, packet), (error) => error.code === "decrypt");
  assert.deepEqual(calls, [], "BOM header must reject before OAEP rather than merely failing authentication");
  const cleartext = await payload(encrypted);
  const oldLength = cleartext.readUInt32BE(0);
  const metadata = Buffer.concat([bom, cleartext.subarray(4, 4 + oldLength)]);
  const innerPacket = await withPayload(encrypted, Buffer.concat([lengthPrefix(metadata.length), metadata,
    cleartext.subarray(4 + oldLength)]));
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, innerPacket), failure("decrypt"));
  cleartext.fill(0);
});

test("authenticated inner metadata enforces exact name, size and SHA256 semantics", async () => {
  const digest = createHash("sha256").update(CONTENT).digest("hex");
  const metadata = {name: FILE_NAME, size: CONTENT.length, sha256: digest};
  for (const change of [{size: CONTENT.length + 1}, {size: -1}, {size: "8"}, {size: 0.5},
    {size: core.limits.fileBytes + 1}, {sha256: "0".repeat(64)}, {sha256: digest.toUpperCase()},
    {name: "../bad.bin"}, {name: "\u202eevil.bin"}, {name: "\ud800"}, {extra: true}]) {
    const packet = await withMetadata(encrypted, JSON.stringify({...metadata, ...change}));
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, packet), failure("decrypt"));
  }
});

test("authenticated inner duplicate and noncanonical metadata are rejected", async () => {
  const metadata = {name: FILE_NAME, size: CONTENT.length, sha256: createHash("sha256").update(CONTENT).digest("hex")};
  const canonical = JSON.stringify(metadata);
  for (const text of [JSON.stringify(metadata, null, 2), canonical.replace('"size":8', '"size":8,"size":8'),
    canonical.replace('"size":8', '"size":8,"\\u0073ize":8'), JSON.stringify({size: 8, name: FILE_NAME, sha256: metadata.sha256})]) {
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
      await withMetadata(encrypted, text)), failure("decrypt"));
  }
});

test("authenticated inner metadata lengths, malformed UTF-8 and oversized content are rejected", async () => {
  const digest = createHash("sha256").update(CONTENT).digest("hex");
  const original = await payload(encrypted);
  for (const size of [0, 1, 1025, 0xffffffff, original.length]) {
    const malformed = Buffer.from(original);
    malformed.writeUInt32BE(size, 0);
    await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
      await withPayload(encrypted, malformed)), failure("decrypt"));
  }
  const invalidUtf8 = Buffer.from(original);
  invalidUtf8[4] = 0xff;
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
    await withPayload(encrypted, invalidUtf8)), failure("decrypt"));
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
    await withPayload(encrypted, new Uint8Array(5))), failure("decrypt"));
  const extraContent = new Uint8Array(core.limits.fileBytes + 1);
  const metadata = JSON.stringify({name: "x.bin", size: extraContent.length, sha256: digest});
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint,
    await withMetadata(encrypted, metadata, extraContent)), failure("decrypt"));
  original.fill(0);
});

test("text packets, encrypted backups and file packets are separated by format and domain", async () => {
  const textPacket = await core.encrypt(alice, "binary is not text", "demo-file");
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, encoder.encode(textPacket)), failure("decrypt"));
  await assert.rejects(core.decryptFile(alice.privateKey, alice.fingerprint, encoder.encode(alice.encryptedBackup)), failure("decrypt"));
  await assert.rejects(core.decrypt(alice.privateKey, alice.fingerprint, encrypted), failure("decrypt"));
  assert.equal(await core.decrypt(alice.privateKey, alice.fingerprint, textPacket), "binary is not text");
});

test("unsupported browsers fail with a fixed safe error without network or storage APIs", async () => {
  const api = isolated({});
  await assert.rejects(api.encryptFile(alice, CONTENT, {name: "x.bin"}), (error) => error.code === "unsupported");
  await assert.rejects(api.decryptFile(alice.privateKey, alice.fingerprint, encrypted), (error) => error.code === "unsupported");
});
