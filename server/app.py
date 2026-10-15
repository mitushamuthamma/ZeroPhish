"""
ZeroPhish server  (Person 1: Backend Lead)
Flask + SQLite + ECDSA (curve P-256, SHA-256) + AES-256-GCM Storage Encryption

Hotel analogy:
  /register  -> guest hands over a copy of their signature style (PUBLIC key)
                + secondary verification (email confirmation OTP)
  /challenge -> front desk gives a one-time random number (nonce)
  /login     -> guest signs "number + hotel name"; desk checks the signature
                and binds the session strictly to that private key
  /action/*  -> same idea again for risky things (change email, transfer funds)
                with AES-256-GCM encryption of sensitive details at rest

Run:   python app.py      then open  http://localhost:5000   (NOT 127.0.0.1)
"""
import base64
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
import webbrowser

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, g, jsonify, redirect, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flask also serves Person 2's pages from ../client, so the page and the API
# share ONE origin (http://localhost:5000).
app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "..", "client"),
    static_url_path="",
)
app.config.update(
    DATABASE=os.path.join(BASE_DIR, "zerophish.db"),
    EXPECTED_ORIGIN="http://localhost:5000",  # the REAL website's address
    LOGIN_CHALLENGE_TTL=60,    # seconds a login nonce stays valid
    ACTION_CHALLENGE_TTL=30,   # sensitive actions get an even shorter window
    SESSION_TTL=900,           # 15 minutes
    STORAGE_KEY_FILE=os.path.join(BASE_DIR, ".storage_key"),
)

ALLOWED_ACTIONS = {"change_email", "transfer_funds"}
USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("zerophish")

# ------------------------------------------------ Point 7: AES-256-GCM Encryption
def get_or_create_storage_key():
    key_path = app.config.get("STORAGE_KEY_FILE") or os.path.join(BASE_DIR, ".storage_key")
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                key = f.read()
                if len(key) == 32:
                    return key
        except Exception:
            pass
    key = AESGCM.generate_key(bit_length=256)
    try:
        with open(key_path, "wb") as f:
            f.write(key)
    except Exception:
        pass
    return key


STORAGE_KEY = get_or_create_storage_key()


def encrypt_stored_data(plaintext: str) -> str:
    """Encrypt sensitive payload before saving to SQLite database using AES-256-GCM."""
    if not plaintext:
        return ""
    aesgcm = AESGCM(STORAGE_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"enc:v1:{base64.b64encode(nonce).decode()}:{base64.b64encode(ciphertext).decode()}"


def decrypt_stored_data(encrypted_str: str) -> str:
    """Decrypt sensitive SQLite data using AES-256-GCM."""
    if not encrypted_str:
        return ""
    if not encrypted_str.startswith("enc:v1:"):
        return encrypted_str  # legacy plaintext fallback
    try:
        parts = encrypted_str.split(":", 3)
        nonce = base64.b64decode(parts[2])
        ciphertext = base64.b64decode(parts[3])
        aesgcm = AESGCM(STORAGE_KEY)
        return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
    except Exception as e:
        log.error("Failed to decrypt stored data: %s", e)
        return "[ENCRYPTED_DATA_DECRYPTION_ERROR]"


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,          -- base64 of 65-byte uncompressed P-256 point
    email      TEXT,                   -- optional verified email from secondary check
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_registrations (
    username   TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    public_key TEXT NOT NULL,
    otp_code   TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    nonce      TEXT PRIMARY KEY,
    purpose    TEXT NOT NULL,          -- 'login' or 'action:<name>'
    username   TEXT,                   -- who it was issued to (actions only)
    expires_at REAL NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    public_key TEXT,                   -- Point 3: session strictly bound to this key
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS action_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    action      TEXT NOT NULL,
    details     TEXT NOT NULL,         -- Point 7: AES-256-GCM encrypted ciphertext
    approved_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    ip_address  TEXT NOT NULL,
    username    TEXT,
    details     TEXT NOT NULL,
    severity    TEXT NOT NULL,         -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    timestamp   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS blocked_entities (
    entity        TEXT PRIMARY KEY,    -- IP or username
    reason        TEXT NOT NULL,
    blocked_until REAL NOT NULL
);
"""


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    db.executescript(SCHEMA)
    cursor = db.cursor()
    # Migration checks for existing databases
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in cursor.fetchall()]
    if "email" not in user_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")

    cursor.execute("PRAGMA table_info(sessions)")
    sess_cols = [col[1] for col in cursor.fetchall()]
    if "public_key" not in sess_cols:
        cursor.execute("ALTER TABLE sessions ADD COLUMN public_key TEXT")

    db.commit()
    db.close()


# ------------------------------------------------ Point 5: Anomaly Detection
ANOMALY_WINDOW_SECONDS = 60
ANOMALY_FAILURE_THRESHOLD = 5  # consecutive failed verifications before temporary lockout


def record_security_event(event_type, ip_address, username, details, severity="MEDIUM"):
    """Record security anomaly event to database for audit and inspection."""
    try:
        db = get_db()
        now = time.time()
        db.execute(
            "INSERT INTO security_events (event_type, ip_address, username, details, severity, timestamp) "
            "VALUES (?,?,?,?,?,?)",
            (event_type, ip_address, username, details, severity, now)
        )
        db.commit()
    except Exception as e:
        log.error("Failed recording security event: %s", e)


def check_anomaly_lockout(ip_address, username=None):
    """Check if an entity is currently blocked due to repeated security anomalies."""
    try:
        db = get_db()
        now = time.time()
        targets = [ip_address]
        if username:
            targets.append(username)
        q = f"SELECT * FROM blocked_entities WHERE entity IN ({','.join(['?']*len(targets))}) AND blocked_until > ?"
        row = db.execute(q, (*targets, now)).fetchone()
        if row:
            rem = int(row["blocked_until"] - now)
            return fail("anomaly_blocked", f"Temporarily blocked due to repeated security anomalies. Try again in {rem}s.", 429)
    except Exception:
        pass
    return None


def evaluate_anomalies(ip_address, username=None):
    """Evaluate recent failure patterns and trigger automated lockout if threshold is exceeded."""
    if not username:
        return
    try:
        db = get_db()
        now = time.time()
        cutoff = now - ANOMALY_WINDOW_SECONDS
        count = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE username = ? AND severity IN ('HIGH', 'CRITICAL') AND timestamp > ?",
            (username, cutoff)
        ).fetchone()[0]

        if count >= ANOMALY_FAILURE_THRESHOLD:
            block_until = now + 120  # 2 minute quarantine
            db.execute(
                "INSERT OR REPLACE INTO blocked_entities (entity, reason, blocked_until) VALUES (?,?,?)",
                (username, f"Exceeded {count} security anomalies in {ANOMALY_WINDOW_SECONDS}s", block_until)
            )
            db.commit()
            record_security_event("ANOMALY_QUARANTINE_TRIGGERED", ip_address, username,
                                  f"Account placed in quarantine for 120s ({count} high-severity anomalies)", "CRITICAL")
            log.warning("ANOMALY QUARANTINE: Locked account %s for 120s", username)
    except Exception as e:
        log.error("Anomaly evaluation error: %s", e)


# ----------------------------------------------------------------- helpers
def fail(code, message, status=401, username=None, severity="MEDIUM"):
    """One place to build every error, log it, and dispatch to anomaly detection."""
    log.warning("REJECTED  [%s]  %s", code, message)
    # Track anomalous verification failures and replay attacks
    if code in {"wrong_domain", "invalid_signature", "challenge_used", "unknown_challenge",
                "wrong_purpose", "session_hijack_detected", "anomaly_blocked"}:
        try:
            ip = request.remote_addr or "127.0.0.1" if request else "127.0.0.1"
            sev = "HIGH" if code in {"wrong_domain", "invalid_signature", "session_hijack_detected"} else severity
            record_security_event(code.upper(), ip, username, message, sev)
            if username:
                evaluate_anomalies(ip, username)
        except Exception:
            pass
    return jsonify(ok=False, error=code, message=message), status


def b64d(text):
    return base64.b64decode(text, validate=True)  # standard base64, not URL-safe


def load_public_key(b64_text):
    raw = b64d(b64_text)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def verify_signature(public_key_b64, signature_b64, message):
    """
    The browser (WebCrypto) gives a RAW 64-byte signature (r || s).
    Python's `cryptography` wants DER, so we convert first.
    """
    try:
        public_key = load_public_key(public_key_b64)
        raw_sig = b64d(signature_b64)
        if len(raw_sig) != 64:
            return False
        r = int.from_bytes(raw_sig[:32], "big")
        s = int.from_bytes(raw_sig[32:], "big")
        public_key.verify(
            encode_dss_signature(r, s),
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def new_nonce(purpose, ttl, username=None):
    db = get_db()
    nonce = secrets.token_urlsafe(32)
    now = time.time()
    db.execute("DELETE FROM challenges WHERE expires_at < ?", (now - 3600,))  # tidy up
    db.execute(
        "INSERT INTO challenges (nonce, purpose, username, expires_at) VALUES (?,?,?,?)",
        (nonce, purpose, username, now + ttl),
    )
    db.commit()
    return nonce


def consume_challenge(nonce, purpose, username=None):
    """
    Check the nonce is real, right purpose, unused, unexpired - then BURN it.
    We burn it BEFORE checking the signature, so a failed attempt can never be retried.
    Returns (row, None) on success or (None, error_response).
    """
    db = get_db()
    row = db.execute("SELECT * FROM challenges WHERE nonce = ?", (nonce,)).fetchone()
    if row is None:
        return None, fail("unknown_challenge", "Unknown challenge. Request a new one.", username=username)
    if row["purpose"] != purpose:
        return None, fail("wrong_purpose", "This challenge was issued for something else.", username=username)
    if row["used"]:
        return None, fail("challenge_used", "Challenge already used (replay blocked).", username=username)
    if time.time() > row["expires_at"]:
        return None, fail("challenge_expired", "Challenge expired. Request a new one.", username=username)
    cur = db.execute("UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0", (nonce,))
    db.commit()
    if cur.rowcount != 1:  # someone else burned it a split second earlier
        return None, fail("challenge_used", "Challenge already used (replay blocked).", username=username)
    return row, None


def check_origin(claimed_origin, username=None):
    """Friendly error for the demo. The REAL protection is the signature check below."""
    expected = app.config["EXPECTED_ORIGIN"]
    if claimed_origin != expected:
        return fail(
            "wrong_domain",
            f"Signature was made for '{claimed_origin}' but this server is '{expected}'. "
            "Possible phishing site.",
            username=username,
            severity="HIGH"
        )
    return None


def get_current_session():
    """Retrieve the session row matching the Authorization Bearer token."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:]
    row = get_db().execute(
        "SELECT * FROM sessions WHERE token = ? AND expires_at > ?",
        (token, time.time()),
    ).fetchone()
    return row


def current_user():
    sess = get_current_session()
    return sess["username"] if sess else None


def public_key_of(username):
    row = get_db().execute("SELECT public_key FROM users WHERE username = ?", (username,)).fetchone()
    return row["public_key"] if row else None


# ------------------------------------------------------------------ routes
@app.before_request
def canonical_origin_redirect():
    if request.host.startswith("127.0.0.1:5000"):
        new_url = request.url.replace("127.0.0.1:5000", "localhost:5000", 1)
        return redirect(new_url, code=302)


@app.get("/")
def index():
    return app.send_static_file("index.html")


# ------------------------------------------------ Point 6: Secure Registration
@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip()
    public_key = data.get("public_key", "")

    if not USERNAME_RE.fullmatch(username):
        return fail("bad_request", "Username: 3-32 characters, letters/numbers/_/- only.", 400)
    try:
        load_public_key(public_key)
    except (ValueError, TypeError):
        return fail("bad_request", "public_key must be base64 of a 65-byte P-256 public key.", 400)

    db = get_db()
    # Check duplicate username
    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        return fail("user_exists", "That username is already taken.", 409)

    # Secondary check: If email is provided, issue a secondary 6-digit confirmation code
    if email:
        if "@" not in email or len(email) < 5:
            return fail("bad_request", "Please enter a valid email for secondary verification.", 400)

        # Check rapid registration flood (Anomaly detection check)
        ip = request.remote_addr or "127.0.0.1"
        now = time.time()
        recent_regs = db.execute(
            "SELECT COUNT(*) FROM security_events WHERE ip_address = ? AND event_type = 'REGISTRATION_INITIATED' AND timestamp > ?",
            (ip, now - 60)
        ).fetchone()[0]
        if recent_regs >= 8:
            record_security_event("SUSPICIOUS_REGISTRATION_FLOOD", ip, username, f"Over {recent_regs} registrations in 60s", "HIGH")
            return fail("anomaly_blocked", "Too many registration attempts. Please wait a minute.", 429)

        otp_code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = now + 300  # 5 minutes
        db.execute(
            "INSERT OR REPLACE INTO pending_registrations (username, email, public_key, otp_code, created_at, expires_at) "
            "VALUES (?,?,?,?,?,?)",
            (username, email, public_key, otp_code, now, expires_at)
        )
        db.commit()
        record_security_event("REGISTRATION_INITIATED", ip, username, f"Secondary OTP issued to {email}", "LOW")
        log.info("REGISTRATION CHALLENGE  user=%s email=%s code=%s (5 min TTL)", username, email, otp_code)

        return jsonify(
            ok=True,
            requires_verification=True,
            username=username,
            email=email,
            simulated_otp=otp_code,
            message="Secondary check required: 6-digit confirmation code issued to email."
        ), 200

    # Direct registration fallback for legacy automated tests
    try:
        db.execute(
            "INSERT INTO users (username, public_key, created_at, email) VALUES (?,?,?,?)",
            (username, public_key, time.time(), None),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return fail("user_exists", "That username is already taken.", 409)
    log.info("REGISTERED  user=%s  (only the PUBLIC key was stored)", username)
    return jsonify(ok=True, message="Registered. Only your public key was stored."), 201


@app.post("/register/verify")
def register_verify():
    """Point 6: Verify secondary registration confirmation code."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    code = str(data.get("code", "")).strip()

    if not username or not code:
        return fail("bad_request", "Missing username or confirmation code.", 400)

    db = get_db()
    row = db.execute("SELECT * FROM pending_registrations WHERE username = ?", (username,)).fetchone()
    if not row:
        return fail("unknown_registration", "No pending registration found for this username. Please sign up again.", 404)

    if time.time() > row["expires_at"]:
        db.execute("DELETE FROM pending_registrations WHERE username = ?", (username,))
        db.commit()
        return fail("code_expired", "Confirmation code expired. Please sign up again.", 400)

    if row["otp_code"] != code:
        record_security_event("REGISTRATION_VERIFICATION_FAILED", request.remote_addr or "127.0.0.1", username,
                              f"Invalid confirmation code attempt: {code}", "MEDIUM")
        return fail("invalid_code", "Incorrect confirmation code.", 401)

    try:
        db.execute(
            "INSERT INTO users (username, public_key, created_at, email) VALUES (?,?,?,?)",
            (row["username"], row["public_key"], time.time(), row["email"])
        )
        db.execute("DELETE FROM pending_registrations WHERE username = ?", (username,))
        db.commit()
    except sqlite3.IntegrityError:
        return fail("user_exists", "That username is already taken.", 409)

    record_security_event("REGISTRATION_VERIFIED", request.remote_addr or "127.0.0.1", username,
                          f"Secondary email verification verified for {row['email']}", "LOW")
    log.info("REGISTERED (SECONDARY VERIFIED)  user=%s email=%s", username, row["email"])
    return jsonify(ok=True, message="Account created and secondary email verified successfully!"), 201


@app.get("/challenge")
def challenge():
    ttl = app.config["LOGIN_CHALLENGE_TTL"]
    nonce = new_nonce("login", ttl)
    return jsonify(ok=True, nonce=nonce, expires_in=ttl)


# ------------------------------------------------ Point 3: Bound Sessions
@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    nonce = data.get("nonce")
    signature = data.get("signature")
    claimed_origin = data.get("origin")
    if not all(isinstance(v, str) and v for v in (username, nonce, signature, claimed_origin)):
        return fail("bad_request", "Need username, nonce, signature, origin.", 400)

    # Point 5: Check anomaly quarantine
    lock_err = check_anomaly_lockout(request.remote_addr or "127.0.0.1", username)
    if lock_err:
        return lock_err

    _, err = consume_challenge(nonce, "login", username=username)
    if err:
        return err
    err = check_origin(claimed_origin, username=username)
    if err:
        return err

    # The server rebuilds the message with ITS OWN origin.
    message = f"{nonce}|{app.config['EXPECTED_ORIGIN']}"
    public_key = public_key_of(username)
    if public_key is None or not verify_signature(public_key, signature, message):
        return fail("invalid_signature", "Signature check failed.", username=username)

    token = secrets.token_urlsafe(32)
    ttl = app.config["SESSION_TTL"]
    db = get_db()
    # Point 3: Bind session record explicitly to the verified public key
    db.execute("INSERT INTO sessions (token, username, public_key, expires_at) VALUES (?,?,?,?)",
               (token, username, public_key, time.time() + ttl))
    db.commit()
    log.info("LOGIN OK  user=%s (bound to public key)", username)
    return jsonify(ok=True, token=token, username=username, expires_in=ttl, key_bound=True)


@app.get("/me")
def me():
    sess = get_current_session()
    if sess is None:
        return fail("unauthorized", "Please log in.")
    return jsonify(
        ok=True,
        username=sess["username"],
        key_bound=bool(sess["public_key"]),
        session_expires_at=sess["expires_at"]
    )


# ------------------------------------------- Objective 3: Sensitive Actions & Storage Encryption
@app.post("/action/challenge")
def action_challenge():
    sess = get_current_session()
    if sess is None:
        return fail("unauthorized", "Please log in first.")
    user = sess["username"]
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in ALLOWED_ACTIONS:
        return fail("bad_request", f"action must be one of {sorted(ALLOWED_ACTIONS)}.", 400)
    ttl = app.config["ACTION_CHALLENGE_TTL"]
    nonce = new_nonce(f"action:{action}", ttl, username=user)
    return jsonify(ok=True, nonce=nonce, expires_in=ttl)


@app.post("/action/confirm")
def action_confirm():
    sess = get_current_session()
    if sess is None:
        return fail("unauthorized", "Please log in first.")
    user = sess["username"]

    # Point 3: Strict cryptographic session binding check
    user_pk = public_key_of(user)
    if sess["public_key"] and sess["public_key"] != user_pk:
        return fail("session_hijack_detected", "Session is bound to a different key! Possible session cookie theft.", 403, username=user)

    data = request.get_json(silent=True) or {}
    nonce = data.get("nonce")
    signature = data.get("signature")
    claimed_origin = data.get("origin")
    action = data.get("action")
    details = data.get("details", "")
    if not all(isinstance(v, str) and v for v in (nonce, signature, claimed_origin, action)) \
            or not isinstance(details, str) or len(details) > 200 or action not in ALLOWED_ACTIONS:
        return fail("bad_request", "Need nonce, signature, origin, action (+ optional details).", 400, username=user)

    row, err = consume_challenge(nonce, f"action:{action}", username=user)
    if err:
        return err
    if row["username"] != user:
        return fail("unauthorized", "This challenge was issued to a different user.", username=user)
    err = check_origin(claimed_origin, username=user)
    if err:
        return err

    # The signature covers WHAT is being approved (action + details), not just "yes".
    message = f"{nonce}|{app.config['EXPECTED_ORIGIN']}|{action}|{details}"
    if not verify_signature(user_pk, signature, message):
        return fail("invalid_signature", "Signature check failed.", username=user)

    # Point 7: Encrypt sensitive action data at rest using AES-256-GCM
    encrypted_details = encrypt_stored_data(details)
    db = get_db()
    db.execute("INSERT INTO action_log (username, action, details, approved_at) VALUES (?,?,?,?)",
               (user, action, encrypted_details, time.time()))
    db.commit()
    log.info("ACTION APPROVED  user=%s  action=%s  (encrypted at rest: %s...)", user, action, encrypted_details[:24])
    return jsonify(
        ok=True,
        message=f"Action '{action}' approved.",
        encrypted_storage=True,
        storage_ciphertext=encrypted_details
    )


@app.get("/action/history")
def action_history():
    """Retrieve action log demonstrating AES-256-GCM storage encryption at rest."""
    sess = get_current_session()
    if sess is None:
        return fail("unauthorized", "Please log in.")
    user = sess["username"]
    db = get_db()
    rows = db.execute(
        "SELECT id, action, details, approved_at FROM action_log WHERE username = ? ORDER BY approved_at DESC LIMIT 10",
        (user,)
    ).fetchall()
    history = []
    for r in rows:
        raw_val = r["details"]
        decrypted = decrypt_stored_data(raw_val)
        history.append({
            "id": r["id"],
            "action": r["action"],
            "raw_encrypted_at_rest": raw_val,
            "decrypted": decrypted,
            "approved_at": r["approved_at"]
        })
    return jsonify(ok=True, history=history)


# ------------------------------------------------ Security Telemetry & Anomaly APIs
@app.get("/security/status")
def security_status():
    """Point 5: Real-time anomaly detection monitor and audit log."""
    db = get_db()
    now = time.time()
    cutoff_24h = now - 86400
    try:
        total_events = db.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ?", (cutoff_24h,)).fetchone()[0]
        high_sev = db.execute("SELECT COUNT(*) FROM security_events WHERE timestamp > ? AND severity IN ('HIGH', 'CRITICAL')", (cutoff_24h,)).fetchone()[0]
        active_blocks = db.execute("SELECT COUNT(*) FROM blocked_entities WHERE blocked_until > ?", (now,)).fetchone()[0]
        recent_events = db.execute(
            "SELECT id, event_type, ip_address, username, details, severity, timestamp "
            "FROM security_events ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
        events_list = [dict(r) for r in recent_events]
    except Exception:
        total_events = high_sev = active_blocks = 0
        events_list = []

    return jsonify(
        ok=True,
        total_24h=total_events,
        high_severity_24h=high_sev,
        active_blocks=active_blocks,
        events=events_list
    )


if __name__ == "__main__":
    init_db()
    # Automatically open the site in the default browser on startup
    if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        threading.Timer(1.25, lambda: webbrowser.open("http://localhost:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=True)
