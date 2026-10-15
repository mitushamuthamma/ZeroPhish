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
  // Normal mode (extractable = false): the PRIVATE key is NON-EXTRACTABLE, so even our own
  // code can never read it out. Demo mode (extractable = true) exists ONLY for the phishing demo.
  async function generateKeyPair(extractable = false) {
    return crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      extractable,
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
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(privateKey, username);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });

    // Also persist backup in localStorage if key is extractable
    if (privateKey.extractable) {
      try {
        const jwk = await crypto.subtle.exportKey("jwk", privateKey);
        localStorage.setItem("zp_key_" + username, JSON.stringify(jwk));
      } catch (e) {}
    }
    // Remember registered account
    try {
      const list = JSON.parse(localStorage.getItem("zp_users") || "[]");
      if (!list.includes(username)) {
        list.push(username);
        localStorage.setItem("zp_users", JSON.stringify(list));
      }
      localStorage.setItem("zp_last_user", username);
    } catch (e) {}
  }

  async function loadKey(username) {
    let key = null;
    try {
      const db = await openDb();
      key = await new Promise((resolve, reject) => {
        const request = db.transaction(STORE).objectStore(STORE).get(username);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } catch (e) {
      key = null;
    }

    // Resilient fallback: recover from localStorage backup if IndexedDB is empty
    if (!key) {
      const backup = localStorage.getItem("zp_key_" + username);
      if (backup) {
        try {
          const jwk = JSON.parse(backup);
          key = await crypto.subtle.importKey(
            "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]
          );
          // Restore back into IndexedDB
          try {
            const db = await openDb();
            const tx = db.transaction(STORE, "readwrite");
            tx.objectStore(STORE).put(key, username);
          } catch (e) {}
        } catch (e) {
          key = null;
        }
      }
    }
    return key;
  }

  // Full registration: make keys -> send PUBLIC key to server -> keep PRIVATE key here.
  // Supports optional secondary email verification check.
  async function register(username, email = null, demoMode = true) {
    const { publicKey, privateKey } = await generateKeyPair(true);
    const payload = { username, public_key: await exportPublicKey(publicKey) };
    if (email) payload.email = email;
    const response = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (result.ok) {
      if (result.requires_verification) {
        window._pendingRegKey = { username, privateKey };
      } else {
        await saveKey(username, privateKey);
      }
    }
    return result;
  }

  // Point 6: Complete secondary registration check with confirmation code
  async function verifyRegistration(username, code) {
    const response = await fetch("/register/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, code }),
    });
    const result = await response.json();
    if (result.ok && window._pendingRegKey && window._pendingRegKey.username === username) {
      await saveKey(username, window._pendingRegKey.privateKey);
      delete window._pendingRegKey;
    }
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

  // ---- DEMO ONLY: move a key to another website address ----
  // Real passkeys live in a phone or security key that signs for WHATEVER address the browser
  // reports. These two functions imitate that "key that follows the user", so we can show a
  // signature being made on the fake site and then rejected by the real server.
  async function exportDemoKey(username) {
    const privateKey = await loadKey(username);
    if (!privateKey) throw new Error("No key for that username on this device.");
    if (!privateKey.extractable) {
      throw new Error("This key is non-extractable (normal, secure mode). " +
        "For the demo, register a NEW account with 'Demo mode' ticked.");
    }
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    return JSON.stringify({ username, jwk }, null, 2);
  }

  async function importDemoKey(text) {
    let data;
    try { data = JSON.parse(text); } catch (e) { data = null; }
    if (!data || !data.username || !data.jwk || !data.jwk.d) {
      throw new Error("That file is not a ZeroPhish demo key.");
    }
    let privateKey;
    try {
      privateKey = await crypto.subtle.importKey(
        "jwk", data.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    } catch (e) {
      throw new Error("That key file is damaged or not a P-256 key.");
    }
    await saveKey(data.username, privateKey);   // saved for THIS website address only
    return data.username;
  }

  return {
    toBase64, generateKeyPair, exportPublicKey, saveKey, loadKey,
    register, verifyRegistration, signMessage, login, currentUser, logout,
    exportDemoKey, importDemoKey,
  };
})();

// Lets us test the crypto helpers outside the browser (ignored in the browser).
if (typeof module !== "undefined") module.exports = ZP;
