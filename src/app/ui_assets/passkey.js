// Passkey (WebAuthn) bridge. Static same-origin script: no eval, no inline code.
// Private keys never leave the authenticator and bearer tokens never reach this
// script. Ceremonies start inside the user's click, which browsers (Safari in
// particular) require before showing the passkey prompt.
(() => {
  const NONCE = /^[a-f0-9]{32}$/;

  function toBuffer(value) {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes.buffer;
  }

  function toBase64url(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return (list || []).map((item) => ({...item, id: toBuffer(item.id)}));
  }

  function serialize(credential) {
    const response = credential.response;
    const result = {
      id: credential.id,
      rawId: toBase64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults?.() || {},
      response: {clientDataJSON: toBase64url(response.clientDataJSON)},
    };
    if (credential.authenticatorAttachment) {
      result.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (response.attestationObject) {
      result.response.attestationObject = toBase64url(response.attestationObject);
      result.response.transports = response.getTransports?.() || [];
    } else {
      result.response.authenticatorData = toBase64url(response.authenticatorData);
      result.response.signature = toBase64url(response.signature);
      if (response.userHandle) result.response.userHandle = toBase64url(response.userHandle);
    }
    return result;
  }

  function deliver(target, payload) {
    const input = document.querySelector("#passkey-result textarea, #passkey-result input");
    const button = document.querySelector(target);
    if (!input || !button) return;
    input.value = JSON.stringify(payload);
    input.dispatchEvent(new Event("input", {bubbles: true}));
    // Let the component store the value before the event reads its inputs.
    setTimeout(() => button.click(), 60);
  }

  function failure(error) {
    return error && typeof error.name === "string" ? error.name : "UnknownError";
  }

  function supported() {
    return Boolean(window.PublicKeyCredential && navigator.credentials?.create);
  }

  function wrongHost(rpId) {
    const host = location.hostname;
    return host !== rpId && !host.endsWith(`.${rpId}`);
  }

  async function signIn() {
    const done = "#btn-passkey-login-done";
    if (!supported()) return deliver(done, {mode: "get", error: "unsupported"});
    try {
      const response = await fetch("/api/auth/passkeys/authentication/options", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        headers: {"Content-Type": "application/json"},
        body: "{}",
      });
      if (!response.ok) return deliver(done, {mode: "get", error: `http_${response.status}`});
      const options = await response.json();
      const publicKey = options.public_key;
      if (wrongHost(publicKey.rpId)) {
        return deliver(done, {mode: "get", error: "wrong_host", rp_id: publicKey.rpId});
      }
      const credential = await navigator.credentials.get({
        publicKey: {
          ...publicKey,
          challenge: toBuffer(publicKey.challenge),
          allowCredentials: descriptors(publicKey.allowCredentials),
        },
      });
      deliver(done, {mode: "get", challenge_id: options.challenge_id, credential: serialize(credential)});
    } catch (error) {
      deliver(done, {mode: "get", error: failure(error)});
    }
  }

  async function register() {
    const done = "#btn-passkey-register-done";
    const marker = document.querySelector("#passkey-bridge [data-scap-passkey-request]");
    const nonce = marker?.getAttribute("data-scap-passkey-request") || "";
    if (!NONCE.test(nonce)) return deliver(done, {mode: "create", error: "not_prepared"});
    if (!supported()) return deliver(done, {mode: "create", nonce, error: "unsupported"});
    try {
      const encoded = marker.getAttribute("data-scap-passkey-options") || "";
      const publicKey = JSON.parse(new TextDecoder().decode(toBuffer(encoded)));
      if (wrongHost(publicKey.rp.id)) {
        return deliver(done, {mode: "create", nonce, error: "wrong_host", rp_id: publicKey.rp.id});
      }
      const credential = await navigator.credentials.create({
        publicKey: {
          ...publicKey,
          challenge: toBuffer(publicKey.challenge),
          user: {...publicKey.user, id: toBuffer(publicKey.user.id)},
          excludeCredentials: descriptors(publicKey.excludeCredentials),
        },
      });
      deliver(done, {mode: "create", nonce, credential: serialize(credential)});
    } catch (error) {
      deliver(done, {mode: "create", nonce, error: failure(error)});
    }
  }

  document.addEventListener("click", (event) => {
    if (event.target.closest?.("#btn-passkey-login")) void signIn();
    else if (event.target.closest?.("#btn-passkey-create")) void register();
  }, true);
})();
