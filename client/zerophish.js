// ZeroPhish browser helpers (Person 2)
// Guest analogy: this file is the guest's pocket - it makes the secret pen (private key),
// hands the hotel a copy of the signature style (public key), and keeps the pen safe.

const ZP = (() => {
  const DB_NAME = "zerophish";
  const STORE = "keys";

  // ArrayBuffer -> standard base64 text (the server expects standard base64, not URL-safe)
  function toBase64(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  // Make a fresh ECDSA P-256 key pair.
  // The 'false' means the PRIVATE key is NON-EXTRACTABLE: even our own code can never read it out.
  async function generateKeyPair() {
    return crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
  }

  // Public key -> "raw" 65-byte format -> base64 (this is what /register wants)
  async function exportPublicKey(publicKey) {
    return toBase64(await crypto.subtle.exportKey("raw", publicKey));
  }

  // ---- IndexedDB: the browser's small built-in storage, private to this website ----
  function openDb() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => request.result.createObjectStore(STORE);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }

  async function saveKey(username, privateKey) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(privateKey, username);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function loadKey(username) {
    const db = await openDb();
    return new Promise((resolve, reject) => {
      const request = db.transaction(STORE).objectStore(STORE).get(username);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  }

  // Full registration: make keys -> send PUBLIC key to server -> keep PRIVATE key here.
  // We only save the private key AFTER the server accepts, so a "username taken"
  // answer can never overwrite a working key.
  async function register(username) {
    const { publicKey, privateKey } = await generateKeyPair();
    const response = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, public_key: await exportPublicKey(publicKey) }),
    });
    const result = await response.json();
    if (result.ok) await saveKey(username, privateKey);
    return result;
  }

  // Sign some text with the private key -> 64-byte signature -> base64 (what /login wants)
  async function signMessage(privateKey, message) {
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      new TextEncoder().encode(message)
    );
    return toBase64(signature);
  }

  // Full login: get a one-time number -> sign "number|this website's address" -> send it.
  async function login(username) {
    const privateKey = await loadKey(username);
    if (!privateKey) {
      return { ok: false, message: "No key for that username on this device. Register first." };
    }

    const challenge = await (await fetch("/challenge", { cache: "no-store" })).json();

    // THE anti-phishing trick: the origin comes from the BROWSER's own address bar,
    // never from the server. On a fake site this would be the fake site's address.
    const origin = window.location.origin;
    const signature = await signMessage(privateKey, `${challenge.nonce}|${origin}`);

    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, nonce: challenge.nonce, signature, origin }),
    });
    const result = await response.json();
    if (result.ok) {
      sessionStorage.setItem("zp_token", result.token);      // the "room key" for later steps
      sessionStorage.setItem("zp_username", result.username);
    }
    return result;
  }

  // Ask the server "is my room key still valid?" -> username, or null if not.
  async function currentUser() {
    const token = sessionStorage.getItem("zp_token");
    if (!token) return null;
    const response = await fetch("/me", {
      headers: { Authorization: "Bearer " + token },
      cache: "no-store",
    });
    const result = await response.json();
    if (result.ok) return result.username;
    logout();                       // server says the key is expired/invalid
    return null;
  }

  // Throw away the room key. (The secret signing key stays safely in IndexedDB.)
  function logout() {
    sessionStorage.removeItem("zp_token");
    sessionStorage.removeItem("zp_username");
  }

  return {
    toBase64, generateKeyPair, exportPublicKey, saveKey, loadKey,
    register, signMessage, login, currentUser, logout,
  };
})();

// Lets us test the crypto helpers outside the browser (ignored in the browser).
if (typeof module !== "undefined") module.exports = ZP;
