// Local-only DOM controller. No account keys, requests, cookies or web storage.
(() => {
  "use strict";
  const IDLE_MS = 5 * 60 * 1000;
  const FIELDS = ["passphrase", "confirm", "own-public", "own-info", "recipient-public", "recipient-file",
    "recipient-info", "private-file", "plaintext", "context", "packet", "decrypted", "packet-info",
    "file-input", "file-info", "file-context", "file-result"];
  const MESSAGES = Object.freeze({
    unsupported: "Trình duyệt cần HTTPS hoặc localhost và hỗ trợ Web Crypto.",
    passphrase: "Dùng mật khẩu sao lưu riêng từ 16 ký tự, tối đa 256 byte UTF-8.",
    mismatch: "Hai lần nhập mật khẩu sao lưu chưa khớp. Vui lòng nhập lại.",
    public_key: "Khóa công khai phải là SPKI PEM, RSA 3072 bit và số mũ 65537.",
    backup: "Không khôi phục được: mật khẩu sai hoặc bản sao lưu không hợp lệ.",
    encrypt: "Không mã hóa được. Kiểm tra khóa người nhận và giới hạn văn bản.",
    decrypt: "Không giải mã được. Kiểm tra khóa riêng, gói mã hóa và tính toàn vẹn.",
    no_key: "Hãy tạo hoặc khôi phục cặp khóa riêng trước.",
    no_recipient: "Hãy nhập và xác nhận khóa công khai của người nhận trước.",
    file: "Chọn tệp sao lưu JSON không quá 16 KiB hoặc tệp khóa công khai PEM không quá 8 KiB.",
    file_input: "Chọn tệp gốc không quá 5 MiB để mã hóa, hoặc gói .scapenc có kích thước hợp lệ để giải mã.",
    encrypt_file: "Không mã hóa được tệp. Kiểm tra khóa người nhận, tên tệp và ngữ cảnh công khai tối đa 256 byte UTF-8.",
    decrypt_file: "Không giải mã được tệp. Kiểm tra khóa riêng, định dạng gói .scapenc và tính toàn vẹn.",
    clipboard: "Không sao chép được. Bạn có thể chọn và sao chép ô khóa công khai.",
    failed: "Thao tác chưa hoàn tất. Kiểm tra dữ liệu và thử lại.",
  });
  let state = null;
  function field(item, name) { return item.node.querySelector(`[data-crypto-field="${name}"]`); }
  function value(item, name) { return field(item, name)?.value || ""; }
  function write(item, name, content) {
    const node = field(item, name);
    if (!node) return;
    if ("value" in node) node.value = content;
    else node.textContent = content;
  }
  function status(item, message) {
    const node = field(item, "status");
    if (node && node.textContent !== message) node.textContent = message;
  }
  function blocked() {
    const app = document.getElementById("app-sec");
    return document.visibilityState === "hidden" || !app || app.getClientRects().length === 0 ||
      Boolean(document.querySelector("#session-bridge [data-scap-session-clear]"));
  }
  function buttons(item) {
    for (const button of item.node.querySelectorAll("[data-crypto-action]")) {
      button.disabled = button.getAttribute("data-crypto-action") !== "clear" && (item.busy || item.blocked);
    }
  }
  function highlightCipherRow(recordId) {
    const tableRoot = document.getElementById("cipher-table");
    if (!tableRoot || typeof tableRoot.querySelectorAll !== "function") return;
    for (const row of tableRoot.querySelectorAll("tbody tr")) {
      const cell = typeof row.querySelector === "function" ? row.querySelector("td") : null;
      const id = cell ? String(cell.textContent || "").trim() : "";
      if (recordId && id === String(recordId)) row.setAttribute("data-scap-selected-row", "1");
      else if (typeof row.removeAttribute === "function") row.removeAttribute("data-scap-selected-row");
    }
  }
  function decodeBridgePayload(encoded) {
    if (typeof encoded !== "string" || !encoded || encoded.length > 524288) return null;
    try {
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      const decoded = new TextDecoder("utf-8", {fatal: true}).decode(bytes);
      const parsed = JSON.parse(decoded);
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.records)) return null;
      return parsed;
    } catch {
      return null;
    }
  }
  function extractScapPacket(text) {
    if (typeof text !== "string" || !text.includes('"scap-encrypted-text"')) return null;
    const trimmed = text.trim();
    const candidates = [trimmed];
    const start = trimmed.indexOf("{");
    const end = trimmed.lastIndexOf("}");
    if (start >= 0 && end > start && (start > 0 || end < trimmed.length - 1)) {
      candidates.push(trimmed.slice(start, end + 1));
    }
    for (const candidate of candidates) {
      if (candidate.length > 100000) continue;
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === "object" && parsed.format === "scap-encrypted-text" &&
            typeof parsed.ciphertext === "string" && typeof parsed.encryptedKey === "string" &&
            typeof parsed.iv === "string") {
          return {
            packet: JSON.stringify(parsed, null, 2),
            context: typeof parsed.context === "string" ? parsed.context : "",
            recipientKeySha256: typeof parsed.recipientKeySha256 === "string" ? parsed.recipientKeySha256 : "",
          };
        }
      } catch {}
    }
    return null;
  }
  function pickDefaultExtractedRecord(records) {
    for (let i = records.length - 1; i >= 0; i -= 1) {
      if (extractScapPacket(records[i]?.content)) return records[i];
    }
    for (let i = records.length - 1; i >= 0; i -= 1) {
      if (typeof records[i]?.content === "string" && records[i].content.length > 0) return records[i];
    }
    return records[records.length - 1] || null;
  }
  function generateAutoPassphrase() {
    const bytes = new Uint8Array(24);
    if (typeof globalThis.crypto?.getRandomValues !== "function") uiError("unsupported");
    globalThis.crypto.getRandomValues(bytes);
    let hex = "scap-auto-";
    for (let i = 0; i < bytes.length; i += 1) hex += bytes[i].toString(16).padStart(2, "0");
    bytes.fill(0);
    return hex;
  }
  function clearExtractedFile(item) {
    if (!item?.extractedFile) return;
    item.extractedFile.bytes?.fill(0);
    item.extractedFile.containerBytes?.fill(0);
    item.extractedFile = null;
  }
  async function populateFileSectionFromRecord(item, epoch, core, rec) {
    clearExtractedFile(item);
    const fileName = rec.file_name || `scap-msg-${rec.id || "cipher"}.json`;
    const fileContext = rec.file_context || `file:${rec.context}`.slice(0, 200);
    const snapshot = JSON.stringify({
      id: rec.id,
      role: rec.role,
      encryption_scheme: rec.encryption_scheme,
      nonce: rec.nonce,
      ciphertext_preview: rec.ciphertext_preview,
      created_at: rec.created_at,
      context: rec.context,
      content: rec.content,
    }, null, 2);
    const rawBytes = new TextEncoder().encode(snapshot);
    write(item, "file-context", fileContext);
    write(item, "file-info", `Tệp trích xuất tự động: ${fileName}\nKích thước gốc: ${rawBytes.byteLength} byte`);
    if (!item.recipient || !isSecureContext || !core || typeof core.encryptFile !== "function") {
      item.extractedFile = {name: fileName, context: fileContext, bytes: rawBytes, containerBytes: null};
      write(item, "file-result", "");
      return;
    }
    try {
      const containerBytes = await core.encryptFile(item.recipient, new Uint8Array(rawBytes), {
        name: fileName,
        context: fileContext,
      });
      if (!valid(item, epoch)) { rawBytes.fill(0); containerBytes?.fill?.(0); return; }
      item.extractedFile = {name: fileName, context: fileContext, bytes: rawBytes, containerBytes};
      if (item.keypair && item.recipient.fingerprint === item.keypair.fingerprint && typeof core.decryptFile === "function") {
        const restored = await core.decryptFile(
          item.keypair.privateKey,
          item.keypair.fingerprint,
          new Uint8Array(containerBytes),
        );
        const restoredSize = restored?.bytes?.byteLength ?? rawBytes.byteLength;
        restored?.bytes?.fill?.(0);
        if (!valid(item, epoch)) return;
        write(
          item,
          "file-result",
          `Gói mã hóa (.scapenc): ${containerBytes.byteLength} byte\nTên tệp gốc: ${restored.name}\nDung lượng: ${restoredSize} byte\nSHA-256 nội dung: ${restored.sha256}\nNgười nhận SHA-256: ${item.recipient.fingerprint}\nNgữ cảnh công khai: ${restored.context || "(trống)"}\nToàn vẹn tệp: hợp lệ (bấm nút trên để tải .scapenc hoặc .bin)`,
        );
      } else {
        write(
          item,
          "file-result",
          `Gói mã hóa (.scapenc): ${containerBytes.byteLength} byte\nNgười nhận SHA-256: ${item.recipient.fingerprint}\nNgữ cảnh công khai: ${fileContext || "(trống)"}`,
        );
      }
    } catch {
      if (valid(item, epoch)) {
        item.extractedFile = {name: fileName, context: fileContext, bytes: rawBytes, containerBytes: null};
        write(item, "file-result", "");
      } else rawBytes.fill(0);
    }
  }
  async function applyExtractedRecord(item, record) {
    if (!item || !record || item.blocked || blocked()) return;
    const id = String(record.id || "");
    const content = typeof record.content === "string" ? record.content : "";
    const context = typeof record.context === "string" ? record.context : "";
    const fileContext = typeof record.file_context === "string" && record.file_context
      ? record.file_context
      : `file:${context}`.slice(0, 200);
    const fileName = typeof record.file_name === "string" && record.file_name
      ? record.file_name
      : `scap-msg-${id || "cipher"}.json`;
    const embedded = extractScapPacket(content);
    item.extractedRecord = {
      id,
      role: String(record.role || ""),
      encryption_scheme: String(record.encryption_scheme || ""),
      nonce: String(record.nonce || ""),
      ciphertext_preview: String(record.ciphertext_preview || ""),
      created_at: String(record.created_at || ""),
      content,
      context: embedded?.context || context,
      file_name: fileName,
      file_context: fileContext,
      packet: embedded?.packet || "",
      recipientKeySha256: embedded?.recipientKeySha256 || "",
    };
    highlightCipherRow(id);
    touch(item);
    write(item, "decrypted", "");
    write(item, "file-context", fileContext);
    if (embedded) {
      write(item, "context", item.extractedRecord.context);
      write(item, "packet", embedded.packet);
      const fpInfo = embedded.recipientKeySha256 ? ` · Người nhận SHA-256: ${embedded.recipientKeySha256}` : "";
      write(item, "packet-info", `Đã trích xuất gói bản mã JSON từ tin nhắn #${id}${fpInfo}`);
      status(item, `Đã trích xuất gói bản mã từ tin nhắn #${id} vào mục 3. Bấm “Giải mã bằng khóa của bạn” để giải mã.`);
      return;
    }
    write(item, "plaintext", content);
    write(item, "context", context);
    const core = globalThis.ScapCryptoCore;
    if (!isSecureContext || !core || item.busy) {
      write(item, "packet", "");
      write(item, "packet-info", `Đã nạp tin nhắn #${id} vào mục 2.`);
      status(item, `Đã trích xuất tin nhắn #${id} vào mục 2.`);
      return;
    }
    const epoch = item.epoch;
    item.busy = true;
    buttons(item);
    try {
      if (!item.keypair && !item.recipient && typeof core.createKeyPair === "function") {
        const autoPassphrase = generateAutoPassphrase();
        const autoPair = await core.createKeyPair(autoPassphrase);
        if (!valid(item, epoch)) return;
        setPair(item, autoPair);
        item.autoBackupPassphrase = autoPassphrase;
        write(item, "own-info", `RSA-OAEP 3072 / SHA-256 · SHA-256: ${autoPair.fingerprint} (Khóa phiên tự động; đặt mật khẩu ở hai ô trên trước khi xuất bản sao)`);
      }
      if (content && item.recipient && typeof core.encrypt === "function") {
        const recipient = item.recipient;
        const encrypted = await core.encrypt(recipient, content, context);
        if (!valid(item, epoch)) return;
        write(item, "packet", encrypted);
        if (item.keypair && recipient.fingerprint === item.keypair.fingerprint && typeof core.decrypt === "function") {
          const decrypted = await core.decrypt(item.keypair.privateKey, item.keypair.fingerprint, encrypted);
          if (!valid(item, epoch)) return;
          write(item, "decrypted", decrypted);
          write(item, "packet-info", `Đã tự động đóng gói & giải mã tin nhắn #${id} · Người nhận SHA-256: ${recipient.fingerprint} · Toàn vẹn: hợp lệ.`);
        } else {
          write(item, "packet-info", `Đã tự động đóng gói bản mã từ tin nhắn #${id} · Người nhận SHA-256: ${recipient.fingerprint}`);
        }
      } else {
        write(item, "packet", "");
        write(item, "packet-info", `Bản ghi #${id} (${item.extractedRecord.encryption_scheme || "cipher"}) · Không có văn bản gốc từ máy chủ.`);
      }
      await populateFileSectionFromRecord(item, epoch, core, item.extractedRecord);
      if (!valid(item, epoch)) return;
      status(item, `Đã tự động trích xuất và hoàn tất cả 4 mục cho tin nhắn #${id}.`);
    } catch {
      if (valid(item, epoch)) {
        write(item, "packet", "");
        write(item, "packet-info", `Đã nạp tin nhắn #${id} vào mục 2.`);
        status(item, `Đã trích xuất tin nhắn #${id} vào mục 2.`);
      }
    } finally {
      if (valid(item, epoch)) { item.busy = false; buttons(item); touch(item); }
    }
  }
  async function syncExtractedAfterKeyReady(item, epoch, core, baseStatus) {
    if (!item.extractedRecord || !item.recipient) {
      status(item, baseStatus);
      return;
    }
    const rec = item.extractedRecord;
    if (rec.packet) {
      write(item, "context", rec.context);
      write(item, "packet", rec.packet);
      const fpInfo = rec.recipientKeySha256 ? ` · Người nhận SHA-256: ${rec.recipientKeySha256}` : "";
      write(item, "packet-info", `Đã trích xuất gói bản mã JSON từ tin nhắn #${rec.id}${fpInfo}`);
      await populateFileSectionFromRecord(item, epoch, core, rec);
      if (!valid(item, epoch)) return;
      status(item, `${baseStatus} Gói bản mã của tin nhắn #${rec.id} đã sẵn sàng ở mục 3 & 4.`);
      return;
    }
    const text = value(item, "plaintext") || rec.content;
    const ctx = value(item, "context") || rec.context;
    if (!text) {
      await populateFileSectionFromRecord(item, epoch, core, rec);
      if (!valid(item, epoch)) return;
      status(item, baseStatus);
      return;
    }
    write(item, "plaintext", text);
    write(item, "context", ctx);
    const recipient = item.recipient;
    const encrypted = await core.encrypt(recipient, text, ctx);
    if (!valid(item, epoch)) return;
    write(item, "packet", encrypted);
    if (item.keypair && recipient.fingerprint === item.keypair.fingerprint && typeof core.decrypt === "function") {
      const decrypted = await core.decrypt(item.keypair.privateKey, item.keypair.fingerprint, encrypted);
      if (!valid(item, epoch)) return;
      write(item, "decrypted", decrypted);
      write(item, "packet-info", `Đã tự động đóng gói & giải mã tin nhắn #${rec.id} · Người nhận SHA-256: ${recipient.fingerprint} · Toàn vẹn: hợp lệ.`);
    } else {
      write(item, "packet-info", `Đã tự động đóng gói bản mã từ tin nhắn #${rec.id} · Người nhận SHA-256: ${recipient.fingerprint}`);
    }
    await populateFileSectionFromRecord(item, epoch, core, {...rec, content: text, context: ctx});
    if (!valid(item, epoch)) return;
    status(item, `${baseStatus} Đã tự động cập nhật bản mã văn bản (mục 3) và tệp (mục 4) cho tin nhắn #${rec.id}.`);
  }
  function clear(item, message) {
    item.epoch += 1;
    item.busy = false;
    item.keypair = null;
    item.autoBackupPassphrase = "";
    item.recipient = null;
    item.extractedRecord = null;
    item.extractedRecords = [];
    clearExtractedFile(item);
    highlightCipherRow("");
    clearTimeout(item.idle);
    item.idle = null;
    for (const [url, timer] of item.urls) {
      clearTimeout(timer);
      URL.revokeObjectURL(url);
    }
    item.urls.clear();
    for (const name of FIELDS) write(item, name, "");
    item.blocked = blocked();
    buttons(item);
    status(item, message);
  }
  function touch(item) {
    clearTimeout(item.idle);
    item.idle = setTimeout(() => {
      if (state === item) clear(item, "Đã khóa sau 5 phút không thao tác.");
    }, IDLE_MS);
  }
  function inspect() {
    const node = document.querySelector('#crypto-workbench [data-scap-crypto-workbench="1"]');
    if (state?.node !== node) {
      if (state) clear(state, "Đã xóa khóa và dữ liệu cục bộ.");
      state = node ? {node, epoch: 0, busy: false, keypair: null, autoBackupPassphrase: "", recipient: null,
        extractNonce: "", extractedRecords: [], extractedRecord: null, extractedFile: null,
        idle: null, urls: new Map(), blocked: blocked()} : null;
      if (state) buttons(state);
    }
    if (state) {
      const mustBlock = blocked() || !state.node.isConnected;
      if (mustBlock && !state.blocked) clear(state, "Đã xóa khóa và dữ liệu khi phiên kết thúc hoặc trang bị ẩn.");
      if (state.blocked !== mustBlock) { state.blocked = mustBlock; buttons(state); }
      if (!state.blocked) {
        const bridgeRoot = document.getElementById("cipher-workbench-bridge");
        const marker = bridgeRoot && typeof bridgeRoot.querySelector === "function"
          ? bridgeRoot.querySelector("[data-scap-cipher-extract]")
          : null;
        if (!marker) {
          if (state.extractNonce) {
            state.extractNonce = "";
            state.extractedRecords = [];
            highlightCipherRow("");
          }
        } else {
          const nonce = marker.getAttribute?.("data-scap-cipher-nonce") || "";
          const encoded = marker.getAttribute?.("data-scap-cipher-extract") || "";
          if (nonce && nonce !== state.extractNonce) {
            state.extractNonce = nonce;
            const payload = decodeBridgePayload(encoded);
            state.extractedRecords = payload ? payload.records : [];
            const selected = pickDefaultExtractedRecord(state.extractedRecords);
            if (selected) void applyExtractedRecord(state, selected);
          }
        }
      }
    }
  }
  function valid(item, epoch) {
    if (state !== item || item.epoch !== epoch) return false;
    if (!item.node.isConnected || blocked()) {
      clear(item, "Đã xóa khóa và dữ liệu khi phiên kết thúc hoặc trang bị ẩn.");
      return false;
    }
    return true;
  }
  function uiError(code) { throw {code}; }
  function setPair(item, pair) {
    item.keypair = pair;
    item.autoBackupPassphrase = "";
    item.recipient = {publicKey: pair.publicKey, publicPem: pair.publicPem, fingerprint: pair.fingerprint};
    write(item, "own-public", pair.publicPem);
    write(item, "own-info", `RSA-OAEP 3072 / SHA-256 · SHA-256: ${pair.fingerprint}`);
    write(item, "recipient-public", pair.publicPem);
    write(item, "recipient-file", "");
    write(item, "recipient-info", `Người nhận hiện tại: khóa của bạn · SHA-256: ${pair.fingerprint}`);
    write(item, "packet", "");
    write(item, "private-file", "");
  }
  async function readFile(item, name, maximum, epoch) {
    const file = field(item, name)?.files?.[0];
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximum || typeof file.text !== "function") uiError("file");
    const result = await file.text();
    if (!valid(item, epoch)) return null;
    if (typeof result !== "string" || result.length > maximum || new TextEncoder().encode(result).length > maximum) uiError("file");
    return result;
  }
  async function readBinaryFile(item, file, maximum, epoch) {
    if (!file || !Number.isSafeInteger(maximum) || maximum < 1 ||
        !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum ||
        typeof file.arrayBuffer !== "function") uiError("file_input");
    const size = file.size;
    const buffer = await file.arrayBuffer();
    // A real File resolves to an ArrayBuffer of exactly File.size bytes. Check
    // both bounds before passing data to crypto, including unusual File shims.
    if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== size || buffer.byteLength > maximum) uiError("file_input");
    const bytes = new Uint8Array(buffer);
    if (!valid(item, epoch)) { bytes.fill(0); return null; }
    return bytes;
  }
  function download(item, epoch, content, filename, type) {
    if (!valid(item, epoch)) return;
    const url = URL.createObjectURL(new Blob([content], {type}));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    try {
      document.body.append(anchor);
      if (valid(item, epoch)) anchor.click();
    } finally {
      anchor.remove();
      if (valid(item, epoch)) {
        const timer = setTimeout(() => { URL.revokeObjectURL(url); item.urls.delete(url); }, 10000);
        item.urls.set(url, timer);
      } else URL.revokeObjectURL(url);
    }
  }
  async function act(item, action) {
    if (action === "clear") { clear(item, "Đã xóa khóa và toàn bộ dữ liệu cục bộ trong công cụ."); return; }
    if (item.busy || item.blocked || blocked()) return;
    const core = globalThis.ScapCryptoCore;
    const epoch = item.epoch;
    item.busy = true;
    buttons(item);
    touch(item);
    write(item, "decrypted", "");
    write(item, "packet-info", "");
    write(item, "file-info", "");
    write(item, "file-result", "");
    status(item, "Đang xử lý…");
    let inputFileBytes;
    let outputFileBytes;
    try {
      if (!isSecureContext || !core) uiError("unsupported");
      if (action === "generate" || action === "restore") {
        const passphrase = value(item, "passphrase");
        const confirmation = value(item, "confirm");
        write(item, "passphrase", "");
        write(item, "confirm", "");
        if (action === "generate" && passphrase !== confirmation) uiError("mismatch");
        let pair;
        if (action === "generate") pair = await core.createKeyPair(passphrase);
        else {
          const backup = await readFile(item, "private-file", 16384, epoch);
          if (!valid(item, epoch)) return;
          pair = await core.restoreKeyPair(backup, passphrase);
        }
        if (!valid(item, epoch)) return;
        setPair(item, pair);
        await syncExtractedAfterKeyReady(item, epoch, core, action === "generate" ? "Đã tạo cặp khóa." : "Đã mở khóa.");
      } else if (action === "import-public") {
        item.recipient = null;
        write(item, "recipient-info", "");
        const hasFile = Boolean(field(item, "recipient-file")?.files?.length);
        const publicPem = hasFile ? await readFile(item, "recipient-file", 8192, epoch) : value(item, "recipient-public");
        if (!valid(item, epoch)) return;
        const imported = await core.importPublicKey(publicPem);
        if (!valid(item, epoch)) return;
        item.recipient = imported;
        write(item, "recipient-public", imported.publicPem);
        write(item, "recipient-file", "");
        write(item, "recipient-info", `SHA-256 của người nhận: ${imported.fingerprint}`);
        await syncExtractedAfterKeyReady(item, epoch, core, "Đã nhập khóa công khai người nhận.");
      } else if (action === "encrypt") {
        write(item, "packet", "");
        if (!item.recipient) uiError("no_recipient");
        const recipient = item.recipient;
        const result = await core.encrypt(recipient, value(item, "plaintext"), value(item, "context"));
        if (!valid(item, epoch)) return;
        write(item, "packet", result);
        write(item, "packet-info", `RSA-OAEP 3072 + AES-256-GCM · Người nhận SHA-256: ${recipient.fingerprint}`);
        status(item, "Đã mã hóa văn bản.");
      } else if (action === "decrypt") {
        if (!item.keypair) uiError("no_key");
        const result = await core.decrypt(item.keypair.privateKey, item.keypair.fingerprint, value(item, "packet"));
        if (!valid(item, epoch)) return;
        write(item, "decrypted", result);
        write(item, "packet-info", "Toàn vẹn: hợp lệ.");
        status(item, "Đã giải mã văn bản.");
      } else if (action === "encrypt-file" || action === "decrypt-file") {
        const encrypting = action === "encrypt-file";
        if (typeof core.encryptFile !== "function" || typeof core.decryptFile !== "function") uiError("unsupported");
        if (encrypting ? !item.recipient : !item.keypair) uiError(encrypting ? "no_recipient" : "no_key");
        const file = field(item, "file-input")?.files?.[0];
        const recipient = item.recipient;
        const keypair = item.keypair;
        const context = value(item, "file-context");
        let name = file?.name;
        write(item, "file-info", "");
        if (file) {
          inputFileBytes = await readBinaryFile(item, file,
            encrypting ? core.limits.fileBytes : core.limits.fileContainerBytes, epoch);
        } else if (item.extractedFile) {
          if (encrypting && item.extractedFile.bytes instanceof Uint8Array) {
            name = item.extractedFile.name;
            inputFileBytes = new Uint8Array(item.extractedFile.bytes);
          } else if (!encrypting && item.extractedFile.containerBytes instanceof Uint8Array) {
            name = "scap-encrypted-file.scapenc";
            inputFileBytes = new Uint8Array(item.extractedFile.containerBytes);
          } else uiError("file_input");
        } else uiError("file_input");
        if (!valid(item, epoch)) return;
        if (encrypting) {
          outputFileBytes = await core.encryptFile(recipient, inputFileBytes, {name, context});
          if (!valid(item, epoch)) return;
          write(item, "file-info", `Tệp gốc: ${name}\nKích thước gốc: ${inputFileBytes.byteLength} byte`);
          download(item, epoch, outputFileBytes, "scap-encrypted-file.scapenc", "application/octet-stream");
          if (!valid(item, epoch)) return;
          write(item, "file-result", `Gói mã hóa: ${outputFileBytes.byteLength} byte\nNgười nhận SHA-256: ${recipient.fingerprint}\nNgữ cảnh công khai: ${context || "(trống)"}`);
          status(item, "Đã mã hóa và tải tệp.");
        } else {
          const result = await core.decryptFile(keypair.privateKey, keypair.fingerprint, inputFileBytes);
          outputFileBytes = result.bytes;
          if (!valid(item, epoch)) return;
          write(item, "file-info", `Gói mã hóa: ${name}\nKích thước gói: ${inputFileBytes.byteLength} byte`);
          download(item, epoch, outputFileBytes, "scap-restored.bin", "application/octet-stream");
          if (!valid(item, epoch)) return;
          write(item, "file-result", `Tên tệp gốc: ${result.name}\nDung lượng: ${outputFileBytes.byteLength} byte\nSHA-256 nội dung: ${result.sha256}\nNgữ cảnh công khai: ${result.context || "(trống)"}\nTệp tải xuống: scap-restored.bin`);
          status(item, "Đã giải mã và tải tệp.");
        }
      } else if (action === "export-private" || action === "export-public" || action === "copy-public") {
        if (!item.keypair) uiError("no_key");
        if (action === "copy-public") {
          if (!navigator.clipboard?.writeText) uiError("clipboard");
          try { await navigator.clipboard.writeText(item.keypair.publicPem); } catch { uiError("clipboard"); }
          if (!valid(item, epoch)) return;
          status(item, "Đã sao chép khóa công khai của bạn.");
        } else {
          const privateBackup = action === "export-private";
          if (privateBackup && item.autoBackupPassphrase) {
            const passphrase = value(item, "passphrase");
            const confirmation = value(item, "confirm");
            write(item, "passphrase", "");
            write(item, "confirm", "");
            if (passphrase !== confirmation) uiError("mismatch");
            if (typeof core.reencryptKeyBackup !== "function") uiError("unsupported");
            const backup = await core.reencryptKeyBackup(
              item.keypair.encryptedBackup, item.autoBackupPassphrase, passphrase,
            );
            if (!valid(item, epoch)) return;
            item.keypair.encryptedBackup = backup;
            item.autoBackupPassphrase = "";
            write(item, "own-info", `RSA-OAEP 3072 / SHA-256 · SHA-256: ${item.keypair.fingerprint} (Bản sao đã được bảo vệ bằng mật khẩu bạn đặt)`);
          }
          download(item, epoch, privateBackup ? item.keypair.encryptedBackup : item.keypair.publicPem,
            privateBackup ? "scap-private-key.encrypted.json" : "scap-public-key.pem",
            privateBackup ? "application/json" : "text/plain;charset=utf-8");
          if (!valid(item, epoch)) return;
          status(item, privateBackup ? "Đã tải khóa riêng đã mã hóa." : "Đã tải khóa công khai.");
        }
      } else uiError("failed");
    } catch (error) {
      if (valid(item, epoch)) {
        write(item, "decrypted", "");
        write(item, "packet-info", "");
        write(item, "file-result", "");
        let code = typeof error?.code === "string" && Object.hasOwn(MESSAGES, error.code) ? error.code : "failed";
        if (code === "encrypt" && action === "encrypt-file") code = "encrypt_file";
        if (code === "decrypt" && action === "decrypt-file") code = "decrypt_file";
        status(item, MESSAGES[code]);
      }
    } finally {
      // Blob construction snapshots the bytes synchronously. Remove our
      // temporary binary references after success, error or lifecycle changes.
      inputFileBytes?.fill(0);
      outputFileBytes?.fill(0);
      if (valid(item, epoch)) { item.busy = false; buttons(item); touch(item); }
    }
  }
  document.addEventListener("click", (event) => {
    if (event.target?.closest?.("#btn-logout, #btn-logout-all")) {
      if (state) clear(state, "Đã xóa khóa và dữ liệu cục bộ khi đăng xuất.");
      return;
    }
    const cipherTable = document.getElementById("cipher-table");
    const row = cipherTable && typeof event.target?.closest === "function" ? event.target.closest("tbody tr") : null;
    if (row && typeof cipherTable.contains === "function" && cipherTable.contains(row)) {
      inspect();
      if (!state || !state.extractedRecords.length) return;
      if (typeof row.querySelector === "function" && row.querySelector(".scap-table-empty")) return;
      const cell = typeof row.querySelector === "function" ? row.querySelector("td") : null;
      const rowId = cell ? String(cell.textContent || "").trim() : "";
      const matched = state.extractedRecords.find((item) => String(item.id) === rowId);
      if (matched) void applyExtractedRecord(state, matched);
      return;
    }
    const button = event.target?.closest?.("[data-crypto-action]");
    if (!button) return;
    inspect();
    if (!state?.node.contains(button)) return;
    event.preventDefault();
    void act(state, button.getAttribute("data-crypto-action"));
  }, true);
  function activity(event) {
    if (!state?.node.contains(event.target)) return;
    touch(state);
    if (event.type === "input" || event.type === "change") {
      const name = event.target.getAttribute?.("data-crypto-field");
      if (state.busy && name) {
        // An asynchronous result belongs to the exact input the user submitted.
        // Edits can start a new operation without allowing its predecessor to
        // overwrite the newer value or unlock that newer operation's buttons.
        state.epoch += 1;
        state.busy = false;
        buttons(state);
        write(state, "decrypted", "");
        write(state, "packet-info", "");
        write(state, "file-result", "");
        status(state, "Dữ liệu đã thay đổi. Vui lòng thực hiện lại.");
      }
      if (name === "recipient-public" || name === "recipient-file") {
        state.recipient = null;
        write(state, "recipient-info", "Nhấn nhập khóa công khai để xác nhận người nhận mới.");
      }
      if (name === "packet") { write(state, "decrypted", ""); write(state, "packet-info", ""); }
      if (name) { write(state, "file-info", ""); write(state, "file-result", ""); }
      if (name === "file-input") {
        clearExtractedFile(state);
        const file = field(state, "file-input")?.files?.[0];
        const size = file && Number.isSafeInteger(file.size) && file.size >= 0 ? `${file.size} byte` : "không hợp lệ";
        write(state, "file-info", file ? `Đã chọn tệp (chưa xác minh): ${file.name}\nKích thước: ${size}` : "Chưa chọn tệp.");
      }
    }
  }
  for (const name of ["input", "change", "pointerdown", "keydown"]) document.addEventListener(name, activity, true);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && state) clear(state, "Đã xóa khóa và dữ liệu cục bộ khi trang bị ẩn.");
    inspect();
  });
  addEventListener("pagehide", () => { if (state) clear(state, "Đã xóa khóa và dữ liệu cục bộ khi rời trang."); });
  const observe = () => {
    inspect();
    if (document.body) new MutationObserver(inspect).observe(document.body, {childList: true, subtree: true,
      attributes: true, attributeFilter: ["style", "class", "hidden", "aria-hidden", "data-scap-session-clear"]});
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", observe, {once: true});
  else observe();
})();
