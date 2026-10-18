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
  function clear(item, message) {
    item.epoch += 1;
    item.busy = false;
    item.keypair = null;
    item.recipient = null;
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
      state = node ? {node, epoch: 0, busy: false, keypair: null, recipient: null,
        idle: null, urls: new Map(), blocked: blocked()} : null;
      if (state) buttons(state);
    }
    if (state) {
      const mustBlock = blocked() || !state.node.isConnected;
      if (mustBlock && !state.blocked) clear(state, "Đã xóa khóa và dữ liệu khi phiên kết thúc hoặc trang bị ẩn.");
      if (state.blocked !== mustBlock) { state.blocked = mustBlock; buttons(state); }
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
        status(item, action === "generate" ? "Đã tạo cặp khóa." : "Đã mở khóa.");
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
        status(item, "Đã nhập khóa công khai người nhận.");
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
        const name = file?.name;
        write(item, "file-info", "");
        inputFileBytes = await readBinaryFile(item, file,
          encrypting ? core.limits.fileBytes : core.limits.fileContainerBytes, epoch);
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
          write(item, "file-info", `Gói mã hóa: ${file.name}\nKích thước gói: ${inputFileBytes.byteLength} byte`);
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
