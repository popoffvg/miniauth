"use strict";
// Runs the WebAuthn ceremonies of miniauth. The server sends the options as JSON with
// base64url byte fields, and reads the credential back as JSON with base64url byte fields.
(function () {
  function fromBase64URL(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "===".slice((base64.length + 3) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
  }

  function toBase64URL(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function withIDs(list) {
    return (list || []).map((c) => Object.assign({}, c, { id: fromBase64URL(c.id) }));
  }

  function credentialJSON(credential) {
    const r = credential.response;
    const response = { clientDataJSON: toBase64URL(r.clientDataJSON) };
    if (r.attestationObject) {
      response.attestationObject = toBase64URL(r.attestationObject);
      response.transports = r.getTransports ? r.getTransports() : [];
    } else {
      response.authenticatorData = toBase64URL(r.authenticatorData);
      response.signature = toBase64URL(r.signature);
      if (r.userHandle) {
        response.userHandle = toBase64URL(r.userHandle);
      }
    }
    return {
      id: credential.id,
      rawId: toBase64URL(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      response: response,
      clientExtensionResults: credential.getClientExtensionResults(),
    };
  }

  async function post(path, body) {
    const reply = await fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await reply.json().catch(() => ({}));
    if (!reply.ok) {
      throw new Error(data.detail || "The passkey step failed. Try again.");
    }
    return data;
  }

  function show(error) {
    const message = document.querySelector("[data-passkey-message]");
    if (message) {
      message.textContent = error.name === "NotAllowedError" ? "The passkey step was cancelled." : error.message;
      message.hidden = false;
    }
  }

  async function signIn(path) {
    const options = (await post(path + "/options", {})).publicKey;
    options.challenge = fromBase64URL(options.challenge);
    options.allowCredentials = withIDs(options.allowCredentials);
    const credential = await navigator.credentials.get({ publicKey: options });
    const done = await post(path, credentialJSON(credential));
    window.location.assign(done.location);
  }

  async function add(path, name) {
    const options = (await post(path + "/options", {})).publicKey;
    options.challenge = fromBase64URL(options.challenge);
    options.user.id = fromBase64URL(options.user.id);
    options.excludeCredentials = withIDs(options.excludeCredentials);
    const credential = await navigator.credentials.create({ publicKey: options });
    const done = await post(path, { name: name, credential: credentialJSON(credential) });
    window.location.assign(done.location);
  }

  for (const button of document.querySelectorAll("[data-passkey-login]")) {
    button.addEventListener("click", () => signIn(button.dataset.passkeyLogin).catch(show));
  }
  for (const form of document.querySelectorAll("[data-passkey-add]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      add(form.dataset.passkeyAdd, form.elements.name.value).catch(show);
    });
  }
  if (!window.PublicKeyCredential) {
    show(new Error("This browser does not support passkeys."));
  }
})();
