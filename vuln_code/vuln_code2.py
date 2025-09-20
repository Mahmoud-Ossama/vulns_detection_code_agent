# vulnerable_app2.py
# Purpose: intentionally vulnerable example for scanner/agent testing.
# Run: python vulnerable_app2.py
# Warning: Do not expose this to the public internet.

from flask import Flask, request, make_response, jsonify, render_template_string
import requests
import xml.etree.ElementTree as ET  # vulnerable to XXE when parsing untrusted XML
import yaml  # PyYAML: yaml.load is unsafe with untrusted input
import time
import hmac, hashlib, base64, os

app = Flask(__name__)

# ===== Vulnerability: Insecure CORS (allows everything) =====
@app.after_request
def add_cors(resp):
    # VULN: wildcard CORS allows any origin (risk for stored XSS / credential leakage)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

# ===== Vulnerability: Reflected XSS =====
@app.route("/search")
def search():
    # VULN: reflect user input directly into HTML without escaping
    q = request.args.get("q", "")
    html = f"<h1>Search results for: {q}</h1>"
    return render_template_string(html)

# ===== Vulnerability: Stored XSS (in-memory) =====
messages = []  # stored messages (no sanitization)
@app.route("/post_message", methods=["POST"])
def post_message():
    # VULN: stores raw HTML from user
    msg = request.form.get("msg", "")
    messages.append(msg)
    return "Message stored", 201

@app.route("/messages")
def list_messages():
    # VULN: returns stored messages rendered unsafely
    html = "<br>".join(messages)
    return render_template_string(html)

# ===== Vulnerability: SSRF (server-side request forgery) =====
@app.route("/fetch")
def fetch():
    # VULN: fetches any URL provided by user, no allowlist
    url = request.args.get("url", "http://example.com")
    resp = requests.get(url, timeout=3)  # can be used to reach internal services
    return make_response((resp.text[:200], resp.status_code))

# ===== Vulnerability: Insecure XML Parsing (XXE) =====
@app.route("/upload_xml", methods=["POST"])
def upload_xml():
    # VULN: naive XML parsing using ElementTree (does not protect against external entities)
    f = request.files.get("file")
    if not f:
        return "No file", 400
    data = f.read()
    try:
        root = ET.fromstring(data)  # vulnerable to XXE
        # naive extraction
        elems = [e.text for e in root.findall(".//item")]
        return jsonify({"items": elems})
    except Exception as e:
        return str(e), 400

# ===== Vulnerability: Insecure YAML deserialization =====
@app.route("/upload_yaml", methods=["POST"])
def upload_yaml():
    # VULN: yaml.load on untrusted data can execute arbitrary code via tags
    f = request.files.get("file")
    if not f:
        return "No file", 400
    data = f.read().decode("utf-8")
    try:
        obj = yaml.load(data, Loader=yaml.FullLoader)  # still risky: FullLoader may construct objects
        return jsonify({"type": type(obj).__name__})
    except Exception as e:
        return str(e), 400

# ===== Vulnerability: Insecure JWT-ish token (predictable / weak) =====
SECRET = "hardcoded_secret_key"  # VULN: hardcoded secret
def make_token(user):
    # VULN: predictable timestamp-based token using HMAC but secret is hardcoded
    payload = f"{user}:{int(time.time())}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    tok = base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()
    return tok

def verify_token(tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        user, ts, sig = raw.split(":")
        payload = f"{user}:{ts}"
        expected = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False

@app.route("/get_token")
def get_token():
    user = request.args.get("user", "guest")
    return make_token(user)

@app.route("/protected")
def protected():
    tok = request.args.get("token", "")
    if verify_token(tok):
        return "Access granted"
    return "Forbidden", 403

# ===== Vulnerability: Predictable reset token (insecure randomness) =====
@app.route("/reset_request", methods=["POST"])
def reset_request():
    # VULN: predictable token using time and username (no crypto randomness)
    user = request.form.get("user", "guest")
    token = f"reset-{user}-{int(time.time())}"
    # pretend to email token...
    return jsonify({"reset_token": token})

if __name__ == "__main__":
    # dev server only
    app.run(host="127.0.0.1", port=5001, debug=True)
