"""
ZeroPhish server  (Person 1: Backend Lead)
Flask + SQLite + ECDSA (curve P-256, SHA-256)

Hotel analogy:
  /register  -> guest hands over a copy of their signature style (PUBLIC key)
  /challenge -> front desk gives a one-time random number (nonce)
  /login     -> guest signs "number + hotel name"; desk checks the signature
  /action/*  -> same idea again for risky things (change email, transfer funds)

Run:   python app.py      then open  http://localhost:5000   (NOT 127.0.0.1)
"""
import base64
import logging
import os
import re
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import Flask, g, jsonify, request

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
)

ALLOWED_ACTIONS = {"change_email", "transfer_funds"}
USERNAME_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("zerophish")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username   TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,          -- base64 of 65-byte uncompressed P-256 point
    created_at REAL NOT NULL
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
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS action_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    action      TEXT NOT NULL,
    details     TEXT NOT NULL,
    approved_at REAL NOT NULL
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
    db.commit()
    db.close()


# ----------------------------------------------------------------- helpers
def fail(code, message, status=401):
    """One place to build every error, and log it (nice for the demo screen)."""
    log.warning("REJECTED  [%s]  %s", code, message)
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


def consume_challenge(nonce, purpose):
    """
    Check the nonce is real, right purpose, unused, unexpired - then BURN it.
    We burn it BEFORE checking the signature, so a failed attempt can never be retried.
    Returns (row, None) on success or (None, error_response).
    """
    db = get_db()
    row = db.execute("SELECT * FROM challenges WHERE nonce = ?", (nonce,)).fetchone()
    if row is None:
        return None, fail("unknown_challenge", "Unknown challenge. Request a new one.")
    if row["purpose"] != purpose:
        return None, fail("wrong_purpose", "This challenge was issued for something else.")
    if row["used"]:
        return None, fail("challenge_used", "Challenge already used (replay blocked).")
    if time.time() > row["expires_at"]:
        return None, fail("challenge_expired", "Challenge expired. Request a new one.")
    cur = db.execute("UPDATE challenges SET used = 1 WHERE nonce = ? AND used = 0", (nonce,))
    db.commit()
    if cur.rowcount != 1:  # someone else burned it a split second earlier
        return None, fail("challenge_used", "Challenge already used (replay blocked).")
    return row, None


def check_origin(claimed_origin):
    """Friendly error for the demo. The REAL protection is the signature check below."""
    expected = app.config["EXPECTED_ORIGIN"]
    if claimed_origin != expected:
        return fail(
            "wrong_domain",
            f"Signature was made for '{claimed_origin}' but this server is '{expected}'. "
            "Possible phishing site.",
        )
    return None


def current_user():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    row = get_db().execute(
        "SELECT username FROM sessions WHERE token = ? AND expires_at > ?",
        (header[7:], time.time()),
    ).fetchone()
    return row["username"] if row else None


def public_key_of(username):
    row = get_db().execute("SELECT public_key FROM users WHERE username = ?", (username,)).fetchone()
    return row["public_key"] if row else None


# ------------------------------------------------------------------ routes
@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    public_key = data.get("public_key", "")
    if not USERNAME_RE.fullmatch(username):
        return fail("bad_request", "Username: 3-32 characters, letters/numbers/_/- only.", 400)
    try:
        load_public_key(public_key)
    except (ValueError, TypeError):
        return fail("bad_request", "public_key must be base64 of a 65-byte P-256 public key.", 400)
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, public_key, created_at) VALUES (?,?,?)",
            (username, public_key, time.time()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return fail("user_exists", "That username is already taken.", 409)
    log.info("REGISTERED  user=%s  (only the PUBLIC key was stored)", username)
    return jsonify(ok=True, message="Registered. Only your public key was stored."), 201


@app.get("/challenge")
def challenge():
    ttl = app.config["LOGIN_CHALLENGE_TTL"]
    nonce = new_nonce("login", ttl)
    # NOTE: we deliberately do NOT send the origin. The browser must use its OWN
    # address (window.location.origin) - that is the whole anti-phishing trick.
    return jsonify(ok=True, nonce=nonce, expires_in=ttl)


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    nonce = data.get("nonce")
    signature = data.get("signature")
    claimed_origin = data.get("origin")
    if not all(isinstance(v, str) and v for v in (username, nonce, signature, claimed_origin)):
        return fail("bad_request", "Need username, nonce, signature, origin.", 400)

    _, err = consume_challenge(nonce, "login")
    if err:
        return err
    err = check_origin(claimed_origin)
    if err:
        return err

    # The server rebuilds the message with ITS OWN origin. If the user really signed
    # for a different site, the maths simply does not match.
    message = f"{nonce}|{app.config['EXPECTED_ORIGIN']}"
    public_key = public_key_of(username)
    # Unknown user and bad signature give the SAME answer (no user-guessing).
    if public_key is None or not verify_signature(public_key, signature, message):
        return fail("invalid_signature", "Signature check failed.")

    token = secrets.token_urlsafe(32)
    ttl = app.config["SESSION_TTL"]
    db = get_db()
    db.execute("INSERT INTO sessions (token, username, expires_at) VALUES (?,?,?)",
               (token, username, time.time() + ttl))
    db.commit()
    log.info("LOGIN OK  user=%s", username)
    return jsonify(ok=True, token=token, username=username, expires_in=ttl)


@app.get("/me")
def me():
    user = current_user()
    if user is None:
        return fail("unauthorized", "Please log in.")
    return jsonify(ok=True, username=user)


# ------------------------------------------- Objective 3: sensitive actions
@app.post("/action/challenge")
def action_challenge():
    user = current_user()
    if user is None:
        return fail("unauthorized", "Please log in first.")
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in ALLOWED_ACTIONS:
        return fail("bad_request", f"action must be one of {sorted(ALLOWED_ACTIONS)}.", 400)
    ttl = app.config["ACTION_CHALLENGE_TTL"]
    nonce = new_nonce(f"action:{action}", ttl, username=user)
    return jsonify(ok=True, nonce=nonce, expires_in=ttl)


@app.post("/action/confirm")
def action_confirm():
    user = current_user()
    if user is None:
        return fail("unauthorized", "Please log in first.")
    data = request.get_json(silent=True) or {}
    nonce = data.get("nonce")
    signature = data.get("signature")
    claimed_origin = data.get("origin")
    action = data.get("action")
    details = data.get("details", "")
    if not all(isinstance(v, str) and v for v in (nonce, signature, claimed_origin, action)) \
            or not isinstance(details, str) or len(details) > 200 or action not in ALLOWED_ACTIONS:
        return fail("bad_request", "Need nonce, signature, origin, action (+ optional details).", 400)

    row, err = consume_challenge(nonce, f"action:{action}")
    if err:
        return err
    if row["username"] != user:
        return fail("unauthorized", "This challenge was issued to a different user.")
    err = check_origin(claimed_origin)
    if err:
        return err

    # The signature covers WHAT is being approved (action + details), not just "yes".
    message = f"{nonce}|{app.config['EXPECTED_ORIGIN']}|{action}|{details}"
    if not verify_signature(public_key_of(user), signature, message):
        return fail("invalid_signature", "Signature check failed.")

    db = get_db()
    db.execute("INSERT INTO action_log (username, action, details, approved_at) VALUES (?,?,?,?)",
               (user, action, details, time.time()))
    db.commit()
    log.info("ACTION APPROVED  user=%s  action=%s  details=%s", user, action, details)
    return jsonify(ok=True, message=f"Action '{action}' approved.")


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
