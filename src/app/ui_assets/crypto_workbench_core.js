// Browser-only encryption workbench. This module has no network or persistence API.
// Its local RSA key is independent from account keys and the Olm/MLS chat protocols.
((root, factory) => {
  const api = factory(root.crypto);
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ScapCryptoCore = api;
})(globalThis, (cryptoProvider) => {
  "use strict";
  const SUITE = "RSA-OAEP-3072-SHA256+A256GCM";
  const BACKUP_FORMAT = "scap-key-backup";
  const PACKET_FORMAT = "scap-encrypted-text";
  const ITERATIONS = 600000;
  const MAX_TEXT_BYTES = 65536;
  const MAX_PACKET_BYTES = 96000;
  const MAX_BACKUP_BYTES = 16000;
  const FILE_FORMAT = "scap-encrypted-file";
  const FILE_MAGIC = new Uint8Array([83, 67, 65, 80, 70, 73, 76, 49]); // SCAPFIL1
  const MAX_FILE_BYTES = 5 * 1024 * 1024;
  const MAX_FILE_HEADER_BYTES = 2048;
  const MAX_FILE_METADATA_BYTES = 1024;
  const MAX_FILE_NAME_BYTES = 255;
  const MAX_FILE_CONTAINER_BYTES = 12 + MAX_FILE_HEADER_BYTES + 12 + 384 + 4 +
    MAX_FILE_METADATA_BYTES + MAX_FILE_BYTES + 16;
  const encoder = new TextEncoder();
  const failures = Object.freeze({
    unsupported: "This browser does not support secure Web Crypto.",
    passphrase: "Use a passphrase of at least 16 characters and at most 256 UTF-8 bytes.",
    public_key: "The public key must be a valid RSA-OAEP 3072-bit SPKI key with exponent 65537.",
    backup: "The encrypted key backup is invalid or its passphrase is incorrect.",
    encrypt: "Encryption failed. Check the recipient key and input limits.",
    decrypt: "Decryption failed. Check the key, encrypted packet, and its integrity.",
  });
  class CryptoWorkbenchError extends Error {
    constructor(code) {
      super(failures[code] || failures.decrypt);
      this.name = "CryptoWorkbenchError";
      this.code = code;
    }
  }
  function fail(code) { throw new CryptoWorkbenchError(code); }
  function subtle() {
    if (!cryptoProvider?.subtle || !cryptoProvider.getRandomValues) fail("unsupported");
    return cryptoProvider.subtle;
  }
  function bytes(value) { return new Uint8Array(value); }
  function random(size) { return cryptoProvider.getRandomValues(new Uint8Array(size)); }
  function encode64(value) {
    let binary = "";
    for (const byte of bytes(value)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function decode64(value, minimum, maximum) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) ||
        value.length > Math.ceil(maximum * 4 / 3) || value.length % 4 === 1) throw new Error();
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "="));
    const result = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (result.length < minimum || result.length > maximum || encode64(result) !== value) throw new Error();
    return result;
  }
  function object(value, fields) {
    if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key))) throw new Error();
    return value;
  }
  function parse(value, limit) {
    if (typeof value !== "string" || value.length > limit || encoder.encode(value).length > limit) throw new Error();
    const result = JSON.parse(value);
    // JSON.parse otherwise silently accepts duplicate keys. After its grammar
    // validation, scan only strings and containers to reject ambiguous input.
    const containers = [];
    for (let index = 0; index < value.length; index += 1) {
      const char = value[index];
      if (char === "{" || char === "[") containers.push(char === "{" ? new Set() : null);
      else if (char === "}" || char === "]") containers.pop();
      else if (char === '"') {
        const start = index;
        for (index += 1; index < value.length; index += 1) {
          if (value[index] === "\\") index += 1;
          else if (value[index] === '"') break;
        }
        let next = index + 1;
        while (/\s/.test(value[next] || "") && next < value.length) next += 1;
        if (value[next] === ":") {
          const key = JSON.parse(value.slice(start, index + 1));
          const keys = containers[containers.length - 1];
          if (!keys || keys.has(key)) throw new Error();
          keys.add(key);
        }
      }
    }
    return result;
  }
  function boundedText(value, limit) {
    // Reject lone UTF-16 surrogates: TextEncoder otherwise replaces them silently.
    if (typeof value !== "string" || value.length > limit ||
        /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) throw new Error();
    const result = encoder.encode(value);
    if (result.length > limit) throw new Error();
    return result;
  }
  function checkedPassphrase(value) {
    try {
      if (typeof value !== "string" || value.length > 256 || [...value].length < 16) throw new Error();
      return boundedText(value, 256);
    } catch { fail("passphrase"); }
  }
  function validFingerprint(value) { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
  function validRsa(key, type) {
    const algorithm = key?.algorithm;
    const exponent = algorithm?.publicExponent;
    return key?.type === type && algorithm?.name === "RSA-OAEP" && algorithm.modulusLength === 3072 &&
      algorithm.hash?.name === "SHA-256" && exponent?.length === 3 &&
      exponent[0] === 1 && exponent[1] === 0 && exponent[2] === 1 &&
      key.usages?.length === 1 && key.usages[0] === (type === "private" ? "decrypt" : "encrypt") &&
      (type !== "private" || key.extractable === false);
  }
  async function fingerprint(der) {
    return Array.from(bytes(await subtle().digest("SHA-256", der)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  function pem(der) {
    const binary = encode64(der).replace(/-/g, "+").replace(/_/g, "/");
    const base64 = binary.padEnd(Math.ceil(binary.length / 4) * 4, "=");
    return `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
  }
  async function publicFromDer(der) {
    const publicKey = await subtle().importKey("spki", der, {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]);
    if (!validRsa(publicKey, "public")) throw new Error();
    // Use Web Crypto's canonical encoding for fingerprints and exported PEM.
    const canonicalDer = bytes(await subtle().exportKey("spki", publicKey));
    if (encode64(canonicalDer) !== encode64(der)) throw new Error();
    return {publicKey, publicPem: pem(canonicalDer), fingerprint: await fingerprint(canonicalDer)};
  }
  async function importPublicKey(value) {
    try {
      subtle();
      if (typeof value !== "string" || value.length > 2048) throw new Error();
      const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END PUBLIC KEY-----\s*$/.exec(value.trim());
      if (!match) throw new Error();
      const encoded = match[1].replace(/[\r\n]/g, "");
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0) throw new Error();
      const der = decode64(encoded.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), 384, 1024);
      if (btoa(String.fromCharCode(...der)) !== encoded) throw new Error();
      return await publicFromDer(der);
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("public_key");
    }
  }
  function backupHeader(publicSpki, publicFingerprint, salt) {
    return {format: BACKUP_FORMAT, version: 1, suite: SUITE, kdf: "PBKDF2-SHA256", iterations: ITERATIONS,
      salt, publicSpki, fingerprint: publicFingerprint};
  }
  async function backupKey(passphraseBytes, salt) {
    const material = await subtle().importKey("raw", passphraseBytes, "PBKDF2", false, ["deriveKey"]);
    return subtle().deriveKey({name: "PBKDF2", hash: "SHA-256", iterations: ITERATIONS, salt},
      material, {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
  }
  async function createKeyPair(passphrase) {
    const passphraseBytes = checkedPassphrase(passphrase);
    let privateDer;
    try {
      const pair = await subtle().generateKey({name: "RSA-OAEP", modulusLength: 3072,
        publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256"}, true, ["encrypt", "decrypt"]);
      const publicDer = bytes(await subtle().exportKey("spki", pair.publicKey));
      privateDer = bytes(await subtle().exportKey("pkcs8", pair.privateKey));
      const publicData = await publicFromDer(publicDer);
      const salt = random(16);
      const nonce = random(12);
      const header = backupHeader(encode64(publicDer), publicData.fingerprint, encode64(salt));
      const key = await backupKey(passphraseBytes, salt);
      const ciphertext = await subtle().encrypt({name: "AES-GCM", iv: nonce,
        additionalData: encoder.encode(JSON.stringify(header)), tagLength: 128}, key, privateDer);
      const privateKey = await subtle().importKey("pkcs8", privateDer,
        {name: "RSA-OAEP", hash: "SHA-256"}, false, ["decrypt"]);
      return {...publicData, privateKey,
        encryptedBackup: JSON.stringify({...header, nonce: encode64(nonce), ciphertext: encode64(ciphertext)})};
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("backup");
    } finally {
      passphraseBytes.fill(0);
      privateDer?.fill(0);
    }
  }
  async function restoreKeyPair(encryptedBackup, passphrase) {
    const passphraseBytes = checkedPassphrase(passphrase);
    let privateDer;
    try {
      subtle();
      const backup = object(parse(encryptedBackup, MAX_BACKUP_BYTES),
        ["format", "version", "suite", "kdf", "iterations", "salt", "publicSpki", "fingerprint", "nonce", "ciphertext"]);
      if (backup.format !== BACKUP_FORMAT || backup.version !== 1 || backup.suite !== SUITE ||
          backup.kdf !== "PBKDF2-SHA256" || backup.iterations !== ITERATIONS || !validFingerprint(backup.fingerprint)) throw new Error();
      const salt = decode64(backup.salt, 16, 16);
      const nonce = decode64(backup.nonce, 12, 12);
      const publicDer = decode64(backup.publicSpki, 384, 1024);
      const ciphertext = decode64(backup.ciphertext, 1000, 4096);
      const publicData = await publicFromDer(publicDer);
      if (publicData.fingerprint !== backup.fingerprint) throw new Error();
      const header = backupHeader(backup.publicSpki, backup.fingerprint, backup.salt);
      const key = await backupKey(passphraseBytes, salt);
      privateDer = bytes(await subtle().decrypt({name: "AES-GCM", iv: nonce,
        additionalData: encoder.encode(JSON.stringify(header)), tagLength: 128}, key, ciphertext));
      const privateKey = await subtle().importKey("pkcs8", privateDer,
        {name: "RSA-OAEP", hash: "SHA-256"}, false, ["decrypt"]);
      if (!validRsa(privateKey, "private")) throw new Error();
      const proof = random(32);
      const proofCiphertext = await subtle().encrypt({name: "RSA-OAEP"}, publicData.publicKey, proof);
      const decryptedProof = bytes(await subtle().decrypt({name: "RSA-OAEP"}, privateKey, proofCiphertext));
      let difference = decryptedProof.length ^ proof.length;
      for (let index = 0; index < proof.length; index += 1) difference |= proof[index] ^ decryptedProof[index];
      proof.fill(0);
      decryptedProof.fill(0);
      if (difference !== 0) throw new Error();
      return {...publicData, privateKey, encryptedBackup};
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("backup");
    } finally {
      passphraseBytes.fill(0);
      privateDer?.fill(0);
    }
  }
  function packetHeader(recipient, context) {
    return {format: PACKET_FORMAT, version: 1, suite: SUITE, recipient, context};
  }
  async function encrypt(recipient, plaintext, context = "") {
    let plaintextBytes;
    let keyBytes;
    try {
      subtle();
      if (!recipient || !validRsa(recipient.publicKey, "public") || !validFingerprint(recipient.fingerprint)) throw new Error();
      const publicDer = await subtle().exportKey("spki", recipient.publicKey);
      if (await fingerprint(publicDer) !== recipient.fingerprint) throw new Error();
      plaintextBytes = boundedText(plaintext, MAX_TEXT_BYTES);
      boundedText(context, 256);
      const header = packetHeader(recipient.fingerprint, context);
      const aad = encoder.encode(JSON.stringify(header));
      const nonce = random(12);
      keyBytes = random(32);
      const key = await subtle().importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["encrypt"]);
      const wrappedKey = await subtle().encrypt({name: "RSA-OAEP", label: aad}, recipient.publicKey, keyBytes);
      const ciphertext = await subtle().encrypt({name: "AES-GCM", iv: nonce, additionalData: aad,
        tagLength: 128}, key, plaintextBytes);
      return JSON.stringify({...header, nonce: encode64(nonce), wrappedKey: encode64(wrappedKey), ciphertext: encode64(ciphertext)});
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("encrypt");
    } finally {
      plaintextBytes?.fill(0);
      keyBytes?.fill(0);
    }
  }
  async function decrypt(privateKey, ownFingerprint, packetJSON) {
    let keyBytes;
    let plaintextBytes;
    try {
      subtle();
      if (!validRsa(privateKey, "private") || !validFingerprint(ownFingerprint)) throw new Error();
      const packet = object(parse(packetJSON, MAX_PACKET_BYTES),
        ["format", "version", "suite", "recipient", "context", "nonce", "wrappedKey", "ciphertext"]);
      if (packet.format !== PACKET_FORMAT || packet.version !== 1 || packet.suite !== SUITE || packet.recipient !== ownFingerprint) throw new Error();
      boundedText(packet.context, 256);
      const nonce = decode64(packet.nonce, 12, 12);
      const wrappedKey = decode64(packet.wrappedKey, 384, 384);
      const ciphertext = decode64(packet.ciphertext, 16, MAX_TEXT_BYTES + 16);
      const aad = encoder.encode(JSON.stringify(packetHeader(packet.recipient, packet.context)));
      keyBytes = bytes(await subtle().decrypt({name: "RSA-OAEP", label: aad}, privateKey, wrappedKey));
      if (keyBytes.length !== 32) throw new Error();
      const key = await subtle().importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["decrypt"]);
      plaintextBytes = bytes(await subtle().decrypt({name: "AES-GCM", iv: nonce,
        additionalData: aad, tagLength: 128}, key, ciphertext));
      return new TextDecoder("utf-8", {fatal: true}).decode(plaintextBytes);
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("decrypt");
    } finally {
      keyBytes?.fill(0);
      plaintextBytes?.fill(0);
    }
  }
  function boundedBinary(value, minimum, maximum) {
    if (!(value instanceof Uint8Array) || value.byteLength < minimum || value.byteLength > maximum) throw new Error();
    // Own the snapshot before the first await, even when the caller passes a subarray.
    return new Uint8Array(value);
  }
  function joinBinary(parts) {
    const result = new Uint8Array(parts.reduce((size, part) => size + part.byteLength, 0));
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.byteLength;
    }
    return result;
  }
  function lengthPrefix(size) {
    const result = new Uint8Array(4);
    new DataView(result.buffer).setUint32(0, size, false);
    return result;
  }
  function readLength(value, offset) {
    return new DataView(value.buffer, value.byteOffset + offset, 4).getUint32(0, false);
  }
  function canonicalObject(value, limit, fields) {
    if (value.byteLength > limit) throw new Error();
    const text = new TextDecoder("utf-8", {fatal: true}).decode(value);
    const result = object(parse(text, limit), fields);
    const canonical = {};
    for (const field of fields) canonical[field] = result[field];
    const canonicalBytes = encoder.encode(JSON.stringify(canonical));
    if (canonicalBytes.byteLength !== value.byteLength ||
        canonicalBytes.some((byte, index) => byte !== value[index])) throw new Error();
    return result;
  }
  function checkedFileName(name) {
    boundedText(name, MAX_FILE_NAME_BYTES);
    if (!name.trim() || name === "." || name === ".." ||
        /[/\\\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(name)) throw new Error();
    return name;
  }
  function fileHeader(recipient, context) {
    return {format: FILE_FORMAT, version: 1, suite: SUITE, recipient, context};
  }
  async function encryptFile(recipient, fileBytes, options) {
    let input;
    let payload;
    let keyBytes;
    try {
      subtle();
      const publicKey = recipient?.publicKey;
      const recipientFingerprint = recipient?.fingerprint;
      if (!validRsa(publicKey, "public") || !validFingerprint(recipientFingerprint)) throw new Error();
      if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype ||
          !Object.hasOwn(options, "name") || Object.keys(options).some((field) => field !== "name" && field !== "context")) throw new Error();
      const name = checkedFileName(options.name);
      const context = Object.hasOwn(options, "context") ? options.context : "";
      boundedText(context, 256);
      input = boundedBinary(fileBytes, 0, MAX_FILE_BYTES);
      const publicDer = await subtle().exportKey("spki", publicKey);
      if (await fingerprint(publicDer) !== recipientFingerprint) throw new Error();
      const metadata = boundedText(JSON.stringify({name, size: input.byteLength, sha256: await fingerprint(input)}),
        MAX_FILE_METADATA_BYTES);
      payload = joinBinary([lengthPrefix(metadata.byteLength), metadata, input]);
      const header = boundedText(JSON.stringify(fileHeader(recipientFingerprint, context)), MAX_FILE_HEADER_BYTES);
      const label = joinBinary([FILE_MAGIC, lengthPrefix(header.byteLength), header, random(12)]);
      const nonce = label.subarray(label.byteLength - 12);
      keyBytes = random(32);
      const key = await subtle().importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["encrypt"]);
      const wrappedKey = bytes(await subtle().encrypt({name: "RSA-OAEP", label}, publicKey, keyBytes));
      const aad = joinBinary([label, wrappedKey]);
      const ciphertext = bytes(await subtle().encrypt({name: "AES-GCM", iv: nonce, additionalData: aad,
        tagLength: 128}, key, payload));
      return joinBinary([aad, ciphertext]);
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("encrypt");
    } finally {
      input?.fill(0);
      payload?.fill(0);
      keyBytes?.fill(0);
    }
  }
  async function decryptFile(privateKey, ownFingerprint, encryptedBytes) {
    let keyBytes;
    let payload;
    try {
      subtle();
      if (!validRsa(privateKey, "private") || !validFingerprint(ownFingerprint)) throw new Error();
      const container = boundedBinary(encryptedBytes, 12 + 1 + 12 + 384 + 4 + 2 + 16, MAX_FILE_CONTAINER_BYTES);
      if (FILE_MAGIC.some((byte, index) => container[index] !== byte)) throw new Error();
      const headerLength = readLength(container, 8);
      if (headerLength < 2 || headerLength > MAX_FILE_HEADER_BYTES) throw new Error();
      const nonceOffset = 12 + headerLength;
      const wrappedOffset = nonceOffset + 12;
      const ciphertextOffset = wrappedOffset + 384;
      const ciphertextLength = container.byteLength - ciphertextOffset;
      if (ciphertextLength < 4 + 2 + 16 || ciphertextLength > 4 + MAX_FILE_METADATA_BYTES + MAX_FILE_BYTES + 16) throw new Error();
      const header = canonicalObject(container.subarray(12, nonceOffset), MAX_FILE_HEADER_BYTES,
        ["format", "version", "suite", "recipient", "context"]);
      if (header.format !== FILE_FORMAT || header.version !== 1 || header.suite !== SUITE ||
          !validFingerprint(header.recipient) || header.recipient !== ownFingerprint) throw new Error();
      boundedText(header.context, 256);
      const nonce = container.subarray(nonceOffset, wrappedOffset);
      const wrappedKey = container.subarray(wrappedOffset, ciphertextOffset);
      const label = container.subarray(0, wrappedOffset);
      const aad = container.subarray(0, ciphertextOffset);
      keyBytes = bytes(await subtle().decrypt({name: "RSA-OAEP", label}, privateKey, wrappedKey));
      if (keyBytes.length !== 32) throw new Error();
      const key = await subtle().importKey("raw", keyBytes, {name: "AES-GCM"}, false, ["decrypt"]);
      payload = bytes(await subtle().decrypt({name: "AES-GCM", iv: nonce, additionalData: aad,
        tagLength: 128}, key, container.subarray(ciphertextOffset)));
      if (payload.byteLength < 6) throw new Error();
      const metadataLength = readLength(payload, 0);
      if (metadataLength < 2 || metadataLength > MAX_FILE_METADATA_BYTES || 4 + metadataLength > payload.byteLength) throw new Error();
      const metadata = canonicalObject(payload.subarray(4, 4 + metadataLength), MAX_FILE_METADATA_BYTES,
        ["name", "size", "sha256"]);
      const name = checkedFileName(metadata.name);
      const content = payload.subarray(4 + metadataLength);
      if (!Number.isSafeInteger(metadata.size) || metadata.size < 0 || metadata.size > MAX_FILE_BYTES ||
          metadata.size !== content.byteLength || !validFingerprint(metadata.sha256) ||
          await fingerprint(content) !== metadata.sha256) throw new Error();
      return {bytes: new Uint8Array(content), name, context: header.context, sha256: metadata.sha256};
    } catch (error) {
      if (error instanceof CryptoWorkbenchError && error.code === "unsupported") throw error;
      fail("decrypt");
    } finally {
      keyBytes?.fill(0);
      payload?.fill(0);
    }
  }
  return Object.freeze({createKeyPair, restoreKeyPair, importPublicKey, encrypt, decrypt, encryptFile, decryptFile, CryptoWorkbenchError,
    limits: Object.freeze({textBytes: MAX_TEXT_BYTES, contextBytes: 256, backupBytes: MAX_BACKUP_BYTES,
      packetBytes: MAX_PACKET_BYTES, passphraseMinimumCharacters: 16, passphraseMaximumBytes: 256,
      fileBytes: MAX_FILE_BYTES, fileContainerBytes: MAX_FILE_CONTAINER_BYTES, fileNameBytes: MAX_FILE_NAME_BYTES}),
    suite: SUITE, fileFormat: FILE_FORMAT});
});
