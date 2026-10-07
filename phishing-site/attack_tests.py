"""
ZeroPhish attack tests  (Person 2: Apeksha)  -  fills the results table for the report

Thief analogy: this script plays the thief and tries 16 different tricks on the hotel desk.
Each trick is written down with what we EXPECT and what ACTUALLY happened.

Needs BOTH running first:
    real server  ->  python app.py     (in server/, port 5000)
    fake site    ->  python relay.py   (in phishing-site/, port 5001)

Run:
    python attack_tests.py          (about 70 seconds - it waits for challenges to expire)
    python attack_tests.py --fast   (skips the two expiry tests)

Output: a table on screen, plus attack_results.md and attack_results.csv in this folder.
"""
import argparse
import base64
import csv
import secrets
import sys
import time

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REAL = "http://localhost:5000"   # the real website
FAKE = "http://localhost:5001"   # the phishing site (relay)

parser = argparse.ArgumentParser()
parser.add_argument("--fast", action="store_true", help="skip the two slow expiry tests")
FAST = parser.parse_args().fast


# ------------------------------------------------------------------ helpers
class Person:
    """A fake browser: has a secret key and signs exactly like WebCrypto does."""

    def __init__(self, name):
        self.name = name
        self.key = ec.generate_private_key(ec.SECP256R1())

    def public_key_b64(self):
        raw = self.key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        return base64.b64encode(raw).decode()

    def sign(self, message):
        r, s = decode_dss_signature(self.key.sign(message.encode(), ec.ECDSA(hashes.SHA256())))
        return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def post(base, path, body=None, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return requests.post(base + path, json=body or {}, headers=headers, timeout=10)


def get_nonce(base=REAL):
    return requests.get(base + "/challenge", timeout=10).json()["nonce"]


def login(username, nonce, signature, origin, via=REAL):
    return post(via, "/login", {"username": username, "nonce": nonce, "signature": signature, "origin": origin})


def action_nonce(token, action, via=REAL):
    return post(via, "/action/challenge", {"action": action}, token).json()["nonce"]


def confirm(token, nonce, signature, origin, action, details, via=REAL):
    return post(via, "/action/confirm", {"nonce": nonce, "signature": signature, "origin": origin,
                                         "action": action, "details": details}, token)


def outcome(response):
    data = response.json()
    return "accepted" if data.get("ok") else data.get("error", "?")


rows = []


def record(attack, thief_does, expected, response):
    actual = outcome(response)
    if expected == "accepted":
        verdict = "ALLOWED (as intended)" if actual == "accepted" else f"PROBLEM: got {actual}"
    else:
        verdict = "BLOCKED" if actual == expected else f"PROBLEM: got {actual}"
    rows.append([len(rows) + 1, attack, thief_does, expected, actual, verdict])
    print(f"  {len(rows):>2}. {verdict:<24} {attack}")


# ------------------------------------------------------------- connectivity
for name, url in (("real server", REAL), ("fake site", FAKE)):
    try:
        requests.get(url + "/challenge", timeout=5)
    except requests.RequestException:
        print(f"\nCannot reach the {name} at {url}.")
        print("Start both first:  python app.py (in server/)  and  python relay.py (in phishing-site/)\n")
        sys.exit(1)

# ------------------------------------------------------------------- setup
victim = Person("victim_" + secrets.token_hex(3))
mallory = Person("mallory")  # the thief's OWN key pair
print(f"\nRegistering test user '{victim.name}' on the real server...")
assert post(REAL, "/register", {"username": victim.name, "public_key": victim.public_key_b64()}).status_code == 201

print("\nRunning attacks:\n")

# ---------------------------------------------------- Objective 1 + 2: login
n1 = get_nonce()
sig1 = victim.sign(f"{n1}|{REAL}")
r = login(victim.name, n1, sig1, REAL)
record("Normal login (control)", "Nothing - honest user on the real site", "accepted", r)
token = r.json().get("token")

record("Replay a used login", "Sends the exact same nonce + signature again",
       "challenge_used", login(victim.name, n1, sig1, REAL))

n3 = get_nonce(FAKE)  # nonce fetched THROUGH the phishing site
sig3 = victim.sign(f"{n3}|{FAKE}")  # victim is fooled and signs on the fake site
record("Phishing relay (honest thief)", "Fake site forwards the victim's login to the real server",
       "wrong_domain", login(victim.name, n3, sig3, FAKE, via=FAKE))

record("Reuse the signature stolen by the phishing site", "Thief takes the signature from the line above and tries it directly on the real server",
       "challenge_used", login(victim.name, n3, sig3, REAL))

n4 = get_nonce()
sig4 = victim.sign(f"{n4}|{FAKE}")
record("Phishing relay that LIES about the address", "Thief rewrites the origin to the real address, keeping the fake-site signature",
       "invalid_signature", login(victim.name, n4, sig4, REAL))

n5 = get_nonce()
raw = bytearray(base64.b64decode(victim.sign(f"{n5}|{REAL}")))
raw[10] ^= 1
record("Tampered signature", "Flips one bit of a valid signature",
       "invalid_signature", login(victim.name, n5, base64.b64encode(bytes(raw)).decode(), REAL))

n6 = get_nonce()
record("Thief's own key", "Signs correctly, but with the thief's key instead of the victim's",
       "invalid_signature", login(victim.name, n6, mallory.sign(f"{n6}|{REAL}"), REAL))

record("Made-up challenge", "Invents a nonce the server never issued",
       "unknown_challenge", login(victim.name, "made-up-nonce", victim.sign("made-up-nonce"), REAL))

# --------------------------------------------- Objective 3: sensitive actions
record("Sensitive action without logging in", "Asks for an action challenge with no session",
       "unauthorized", post(REAL, "/action/challenge", {"action": "change_email"}))

an = action_nonce(token, "change_email")
asig = victim.sign(f"{an}|{REAL}|change_email|new@mail.com")
record("Approve a sensitive action (control)", "Nothing - honest user changes email",
       "accepted", confirm(token, an, asig, REAL, "change_email", "new@mail.com"))

record("Replay an approved action", "Sends the same action signature again",
       "challenge_used", confirm(token, an, asig, REAL, "change_email", "new@mail.com"))

an2 = action_nonce(token, "change_email")
asig2 = victim.sign(f"{an2}|{REAL}|change_email|new@mail.com")
record("Change the details after signing", "Victim signed 'new@mail.com', thief swaps in 'evil@mail.com'",
       "invalid_signature", confirm(token, an2, asig2, REAL, "change_email", "evil@mail.com"))

login_nonce = get_nonce()
record("Use a LOGIN challenge to approve an action", "Tries to turn a login signature into a transfer approval",
       "wrong_purpose", confirm(token, login_nonce, victim.sign(f"{login_nonce}|{REAL}|transfer_funds|500"),
                                REAL, "transfer_funds", "500"))

an3 = action_nonce(token, "transfer_funds", via=FAKE)  # challenge fetched through the fake site
asig3 = victim.sign(f"{an3}|{FAKE}|transfer_funds|500")
record("Phishing site tricks victim into approving a transfer", "Fake site relays the 'approve transfer' request",
       "wrong_domain", confirm(token, an3, asig3, FAKE, "transfer_funds", "500", via=FAKE))

# ------------------------------------------------------ slow expiry tests
if FAST:
    print("\n  (--fast: skipping the two expiry tests)")
else:
    exp_login_nonce = get_nonce()
    exp_action_nonce = action_nonce(token, "transfer_funds")
    print("\n  Waiting 62 seconds for the challenges to expire", end="", flush=True)
    for _ in range(62):
        time.sleep(1)
        print(".", end="", flush=True)
    print("\n")
    record("Use an expired login challenge", "Waits over 60 seconds, then sends a valid signature",
           "challenge_expired", login(victim.name, exp_login_nonce, victim.sign(f"{exp_login_nonce}|{REAL}"), REAL))
    record("Use an expired action challenge", "Waits over 30 seconds, then sends a valid signature",
           "challenge_expired", confirm(token, exp_action_nonce,
                                        victim.sign(f"{exp_action_nonce}|{REAL}|transfer_funds|500"),
                                        REAL, "transfer_funds", "500"))

# ------------------------------------------------------------------ results
header = ["#", "Attack", "What the thief does", "Expected", "Actual", "Result"]
blocked = sum(1 for row in rows if row[5] == "BLOCKED")
allowed = sum(1 for row in rows if row[5].startswith("ALLOWED"))
problems = [row for row in rows if row[5].startswith("PROBLEM")]

with open("attack_results.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(rows)

with open("attack_results.md", "w", encoding="utf-8") as f:
    f.write("| " + " | ".join(header) + " |\n|" + "---|" * len(header) + "\n")
    for row in rows:
        f.write("| " + " | ".join(str(cell).replace("|", "/") for cell in row) + " |\n")

print(f"\n{blocked} attacks blocked, {allowed} normal actions allowed, {len(problems)} problems.")
print("Saved: attack_results.md  and  attack_results.csv\n")
sys.exit(1 if problems else 0)
