"""Fixed local-only crypto controls; user input never becomes Gradio state."""

WORKBENCH_HTML = """
<section class="crypto-workbench" data-scap-crypto-workbench="1" aria-label="Công cụ mã hóa cục bộ">
  <h3>Mã hóa &amp; giải mã trong trình duyệt</h3>
  <p role="status" aria-live="polite" data-crypto-field="status"></p>
  <div class="crypto-grid">
    <fieldset>
      <legend>1 · Khóa của bạn</legend>
      <label for="cw-passphrase">Mật khẩu bản sao khóa riêng (ít nhất 16 ký tự)</label>
      <input id="cw-passphrase" type="password" maxlength="256" autocomplete="new-password"
             spellcheck="false" data-crypto-field="passphrase">
      <label for="cw-confirm">Nhập lại mật khẩu khi tạo khóa</label>
      <input id="cw-confirm" type="password" maxlength="256" autocomplete="new-password"
             spellcheck="false" data-crypto-field="confirm">
      <div class="crypto-actions"><button type="button" data-crypto-action="generate">Tạo cặp khóa</button></div>
      <label for="cw-private-file">Nhập bản sao khóa riêng đã mã hóa (.scapkey.json)</label>
      <input id="cw-private-file" type="file" accept=".json,.scapkey.json" data-crypto-field="private-file">
      <div class="crypto-actions">
        <button type="button" data-crypto-action="restore">Mở bản sao bằng mật khẩu</button>
        <button type="button" data-crypto-action="export-private">Xuất khóa riêng đã mã hóa</button>
      </div>
      <p data-crypto-field="own-info">Chưa có khóa riêng đang mở.</p>
      <label for="cw-own-public">Public key của bạn · SPKI PEM</label>
      <textarea id="cw-own-public" rows="6" readonly spellcheck="false" data-crypto-field="own-public"></textarea>
      <div class="crypto-actions">
        <button type="button" data-crypto-action="copy-public">Sao chép public key</button>
        <button type="button" data-crypto-action="export-public">Xuất public key</button>
      </div>
    </fieldset>
    <fieldset>
      <legend>2 · Người nhận và văn bản gốc</legend>
      <label for="cw-recipient-public">Public key người nhận · SPKI PEM</label>
      <textarea id="cw-recipient-public" rows="6" maxlength="8192" spellcheck="false"
                data-crypto-field="recipient-public"></textarea>
      <label for="cw-recipient-file">Hoặc chọn file public key (.pem / .pub)</label>
      <input id="cw-recipient-file" type="file" accept=".pem,.pub" data-crypto-field="recipient-file">
      <div class="crypto-actions"><button type="button" data-crypto-action="import-public">Dùng public key người nhận</button></div>
      <p data-crypto-field="recipient-info">Chưa chọn người nhận.</p>
      <label for="cw-plaintext">Văn bản gốc · tối đa 64 KiB UTF-8</label>
      <textarea id="cw-plaintext" rows="6" maxlength="65536" spellcheck="false"
                autocomplete="off" data-crypto-field="plaintext"></textarea>
      <label for="cw-context">Ngữ cảnh công khai (AAD) · tối đa 256 byte UTF-8</label>
      <input id="cw-context" type="text" maxlength="256" autocomplete="off" data-crypto-field="context">
      <div class="crypto-actions"><button type="button" data-crypto-action="encrypt">Mã hóa văn bản</button></div>
    </fieldset>
  </div>
  <fieldset>
    <legend>3 · Gói mã hóa và kết quả</legend>
    <label for="cw-packet">Gói bản mã JSON</label>
    <textarea id="cw-packet" rows="8" maxlength="100000" spellcheck="false"
              autocomplete="off" data-crypto-field="packet"></textarea>
    <div class="crypto-actions"><button type="button" data-crypto-action="decrypt">Giải mã bằng khóa của bạn</button></div>
    <p data-crypto-field="packet-info"></p>
    <label for="cw-decrypted">Văn bản đã giải mã</label>
    <textarea id="cw-decrypted" rows="6" readonly spellcheck="false" data-crypto-field="decrypted"></textarea>
  </fieldset>
  <fieldset>
    <legend>4 · Mã hóa &amp; giải mã tệp</legend>
    <dl class="crypto-profile" data-crypto-file-profile="1">
      <div><dt>Loại mã hóa</dt><dd>Mã hóa lai: AES + RSA</dd></div>
      <div><dt>Thuật toán / kích thước khóa</dt><dd>AES-256-GCM / 256 bit</dd></div>
      <div><dt>Nonce / thẻ xác thực</dt><dd>96 bit / 128 bit</dd></div>
      <div><dt>Padding</dt><dd>Không dùng (GCM)</dd></div>
      <div><dt>Bảo vệ khóa tệp</dt><dd>RSA-OAEP 3072 / SHA-256</dd></div>
      <div><dt>Khóa / nonce</dt><dd>Ngẫu nhiên</dd></div>
    </dl>
    <label for="cw-file-input">Tệp gốc · tối đa 5 MiB (5.242.880 byte) / gói .scapenc</label>
    <input id="cw-file-input" type="file" data-crypto-field="file-input">
    <p data-crypto-field="file-info" aria-live="polite">Chưa chọn tệp.</p>
    <label for="cw-file-context">Ngữ cảnh công khai của tệp (AAD) · tối đa 256 byte UTF-8</label>
    <input id="cw-file-context" type="text" maxlength="256" autocomplete="off"
           spellcheck="false" data-crypto-field="file-context">
    <div class="crypto-actions">
      <button type="button" data-crypto-action="encrypt-file">Mã hóa &amp; tải tệp .scapenc</button>
      <button type="button" data-crypto-action="decrypt-file">Giải mã &amp; tải tệp .bin</button>
    </div>
    <p role="status" aria-live="polite" data-crypto-field="file-result"></p>
  </fieldset>
  <div class="crypto-actions"><button type="button" data-crypto-action="clear">Khóa &amp; xóa dữ liệu tại tab</button></div>
</section>
"""

WORKBENCH_CSS = """
.crypto-workbench { border:1px solid #cbd5e1; border-radius:14px; padding:20px; margin-top:20px; color:var(--body-text-color); }
.crypto-workbench .crypto-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; }
.crypto-workbench fieldset { min-width:0; border:1px solid #cbd5e1; border-radius:10px; padding:16px; margin:12px 0; }
.crypto-workbench legend { font-weight:700; padding:0 6px; }
.crypto-workbench label { display:block; font-weight:600; margin:12px 0 5px; }
.crypto-workbench textarea,.crypto-workbench input { box-sizing:border-box; width:100%; max-width:100%; padding:10px; border:1px solid #94a3b8; border-radius:7px; color:inherit; background:var(--input-background-fill,#fff); }
.crypto-workbench textarea { font-family:ui-monospace,monospace; overflow-wrap:anywhere; resize:vertical; }
.crypto-workbench input[type=file] { font-size:14px; }
.crypto-workbench p { overflow-wrap:anywhere; }
.crypto-workbench .crypto-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
.crypto-workbench .crypto-profile { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin:12px 0; }
.crypto-workbench .crypto-profile div { padding:10px; border:1px solid #cbd5e1; border-radius:7px; }
.crypto-workbench .crypto-profile dt { font-weight:600; }
.crypto-workbench .crypto-profile dd { margin:4px 0 0; }
.crypto-workbench [data-crypto-field=file-result] { white-space:pre-wrap; }
.crypto-workbench button { cursor:pointer; padding:10px 14px; min-height:44px; border:1px solid #64748b; border-radius:7px; font:inherit; color:inherit; background:var(--button-secondary-background-fill,#f1f5f9); }
.crypto-workbench button:focus-visible,.crypto-workbench input:focus-visible,.crypto-workbench textarea:focus-visible { outline:3px solid #2563eb; outline-offset:2px; }
.crypto-workbench button:disabled { cursor:wait; opacity:.6; }
.crypto-workbench [data-crypto-field=status] { font-weight:600; min-height:24px; }
@media(max-width:800px) { .crypto-workbench .crypto-grid,.crypto-workbench .crypto-profile { grid-template-columns:1fr; } .crypto-workbench { padding:12px; } }
"""
