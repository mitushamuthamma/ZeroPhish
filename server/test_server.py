"""
Tests the server WITHOUT any browser. A 'FakeBrowser' signs things exactly the
way WebCrypto will (ECDSA P-256 + SHA-256, raw 64-byte signature, base64).

Run:  python test_server.py
"""
import base64
import os
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import app, init_db

REAL = app.config["EXPECTED_ORIGIN"]   # http://localhost:5000
FAKE = "http://localhost:5001"          # the phishing site

app.config["DATABASE"] = os.path.join(tempfile.mkdtemp(), "test.db")  # throwaway DB
init_db()
client = app.test_client()

passed = failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


class FakeBrowser:
    def __init__(self, username):
        self.username = username
        self.key = ec.generate_private_key(ec.SECP256R1())

    def public_key_b64(self):
        raw = self.key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return base64.b64encode(raw).decode()

    def sign(self, message):
        der = self.key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def get_nonce():
    return client.get("/challenge").get_json()["nonce"]


def login(user, nonce, signature, origin=REAL):
    return client.post("/login", json={
        "username": user.username, "nonce": nonce, "signature": signature, "origin": origin})


def code(resp):
    return resp.get_json().get("error")


alice, mallory = FakeBrowser("alice"), FakeBrowser("mallory")

print("\nRegistration")
reg = {"username": "alice", "public_key": alice.public_key_b64()}
check("register works", client.post("/register", json=reg).status_code == 201)
check("duplicate username rejected", client.post("/register", json=reg).status_code == 409)
check("garbage public key rejected",
      client.post("/register", json={"username": "bob", "public_key": "not-a-key"}).status_code == 400)

print("\nNormal login")
n = get_nonce()
sig = alice.sign(f"{n}|{REAL}")
r = login(alice, n, sig)
check("valid login succeeds", r.status_code == 200 and r.get_json()["ok"])
token = r.get_json()["token"]
auth = {"Authorization": f"Bearer {token}"}
check("/me works with the session token", client.get("/me", headers=auth).get_json()["username"] == "alice")

print("\nAttacks on login")
check("replaying the same signature is blocked", code(login(alice, n, sig)) == "challenge_used")

n = get_nonce()
check("signature made for the FAKE site -> wrong_domain",
      code(login(alice, n, alice.sign(f"{n}|{FAKE}"), origin=FAKE)) == "wrong_domain")

n = get_nonce()
check("attacker LYING about origin still fails (invalid_signature)",
      code(login(alice, n, alice.sign(f"{n}|{FAKE}"), origin=REAL)) == "invalid_signature")

n = get_nonce()
raw = bytearray(base64.b64decode(alice.sign(f"{n}|{REAL}")))
raw[10] ^= 1  # flip one bit
check("tampered signature rejected",
      code(login(alice, n, base64.b64encode(bytes(raw)).decode())) == "invalid_signature")

n = get_nonce()
check("another person's key cannot log in as alice",
      code(login(alice, n, mallory.sign(f"{n}|{REAL}"))) == "invalid_signature")

check("made-up nonce rejected", code(login(alice, "made-up", alice.sign("x"))) == "unknown_challenge")

app.config["LOGIN_CHALLENGE_TTL"] = 1
n = get_nonce()
time.sleep(1.3)
app.config["LOGIN_CHALLENGE_TTL"] = 60
check("expired nonce rejected", code(login(alice, n, alice.sign(f"{n}|{REAL}"))) == "challenge_expired")

print("\nSensitive actions (Objective 3)")


def action_challenge(action, headers=auth):
    return client.post("/action/challenge", json={"action": action}, headers=headers)


def confirm(nonce, sig, action, details, origin=REAL, headers=auth):
    return client.post("/action/confirm", headers=headers, json={
        "nonce": nonce, "signature": sig, "origin": origin, "action": action, "details": details})


check("action challenge needs a session", code(action_challenge("change_email", headers={})) == "unauthorized")

n = action_challenge("change_email").get_json()["nonce"]
sig = alice.sign(f"{n}|{REAL}|change_email|new@mail.com")
check("fresh signature approves the action", confirm(n, sig, "change_email", "new@mail.com").status_code == 200)
check("same action signature cannot be replayed",
      code(confirm(n, sig, "change_email", "new@mail.com")) == "challenge_used")

n = action_challenge("change_email").get_json()["nonce"]
sig = alice.sign(f"{n}|{REAL}|change_email|new@mail.com")
check("changing the details after signing is caught",
      code(confirm(n, sig, "change_email", "evil@mail.com")) == "invalid_signature")

n = get_nonce()  # a LOGIN nonce
check("a login challenge cannot approve an action",
      code(confirm(n, alice.sign(f"{n}|{REAL}|change_email|x"), "change_email", "x")) == "wrong_purpose")

app.config["ACTION_CHALLENGE_TTL"] = 1
n = action_challenge("transfer_funds").get_json()["nonce"]
time.sleep(1.3)
app.config["ACTION_CHALLENGE_TTL"] = 30
check("expired action challenge rejected",
      code(confirm(n, alice.sign(f"{n}|{REAL}|transfer_funds|500"), "transfer_funds", "500")) == "challenge_expired")

print("\nBeyond Login (Points 3, 5, 6, 7)")

# Point 7: Data at rest encryption
import sqlite3
test_db = sqlite3.connect(app.config["DATABASE"])
row = test_db.execute("SELECT details FROM action_log WHERE username='alice' ORDER BY id DESC LIMIT 1").fetchone()
check("sensitive action details stored ENCRYPTED with AES-256-GCM (starts with enc:v1:)",
      row is not None and row[0].startswith("enc:v1:"))
test_db.close()

hist_resp = client.get("/action/history", headers=auth).get_json()
check("/action/history correctly decrypts on-the-fly for authorized session",
      hist_resp.get("ok") and len(hist_resp["history"]) > 0 and hist_resp["history"][0]["decrypted"] == "new@mail.com")

# Point 6: Secondary registration check (email confirmation)
bob = FakeBrowser("bob_sec")
reg_secondary = client.post("/register", json={
    "username": "bob_sec",
    "email": "bob@example.com",
    "public_key": bob.public_key_b64()
}).get_json()
check("registration with email issues secondary confirmation challenge",
      reg_secondary.get("ok") and reg_secondary.get("requires_verification") and "simulated_otp" in reg_secondary)

otp = reg_secondary["simulated_otp"]
check("invalid secondary confirmation code rejected",
      client.post("/register/verify", json={"username": "bob_sec", "code": "000000"}).status_code == 401)
check("valid secondary confirmation code completes registration",
      client.post("/register/verify", json={"username": "bob_sec", "code": otp}).status_code == 201)

# Point 3: Key-bound session
me_resp = client.get("/me", headers=auth).get_json()
check("session is actively bound to verified public key",
      me_resp.get("ok") and me_resp.get("key_bound") is True)

# Point 5: Anomaly detection telemetry
sec_status = client.get("/security/status").get_json()
check("anomaly telemetry tracks security events and audit trail",
      sec_status.get("ok") and sec_status.get("total_24h") > 0 and len(sec_status.get("events")) > 0)

print(f"\n{passed} passed, {failed} failed\n")
sys.exit(1 if failed else 0)
