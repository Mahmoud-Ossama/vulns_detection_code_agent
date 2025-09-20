from flask import Flask, request, redirect, send_from_directory, jsonify, render_template_string, make_response
import sqlite3
import subprocess
import pickle
import os
import requests
import xml.etree.ElementTree as ET
import yaml
import time
import hmac, hashlib, base64

app = Flask(__name__)
DB = "vuln3.db"
UPLOAD_DIR = "uploads3"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'adminpass')")
    conn.commit()
    conn.close()

init_db()

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    if row:
        return "OK:%s" % row[0]
    return "FAIL", 401

@app.route("/exec")
def exec_cmd():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.getoutput("ping -c 1 %s" % host)
    return "<pre>%s</pre>" % out

@app.route("/deserialize", methods=["POST"])
def deserialize():
    f = request.files.get("file")
    if not f:
        return "No", 400
    data = f.read()
    try:
        obj = pickle.loads(data)
        return jsonify({"type": type(obj).__name__, "repr": repr(obj)[:200]})
    except Exception as e:
        return str(e), 400

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return "No", 400
    filename = f.filename
    dest = os.path.join(UPLOAD_DIR, filename)
    f.save(dest)
    return "SAVED:%s" % dest

@app.route("/file/<path:fname>")
def get_file(fname):
    return send_from_directory(UPLOAD_DIR, fname)

SECRET_KEY = "hardkey1234"

@app.route("/token")
def token():
    user = request.args.get("user", "guest")
    payload = "%s:%d" % (user, int(time.time()))
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    tok = base64.urlsafe_b64encode(("%s:%s" % (payload, sig)).encode()).decode()
    return tok

@app.route("/check")
def check():
    tok = request.args.get("token", "")
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        user, ts, sig = raw.split(":")
        payload = "%s:%s" % (user, ts)
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, sig):
            return "OK"
    except Exception:
        pass
    return "NO", 403

@app.after_request
def cors(r):
    r.headers["Access-Control-Allow-Origin"] = "*"
    return r

messages = []
@app.route("/submit", methods=["POST"])
def submit():
    m = request.form.get("m", "")
    messages.append(m)
    return "OK", 201

@app.route("/view")
def view():
    return render_template_string("<br>".join(messages))

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "http://example.com")
    resp = requests.get(url, timeout=3)
    return make_response((resp.text[:200], resp.status_code))

@app.route("/xml", methods=["POST"])
def xml_upload():
    f = request.files.get("file")
    if not f:
        return "No", 400
    data = f.read()
    try:
        root = ET.fromstring(data)
        items = [e.text for e in root.findall(".//item")]
        return jsonify({"items": items})
    except Exception as e:
        return str(e), 400

@app.route("/yaml", methods=["POST"])
def yaml_upload():
    f = request.files.get("file")
    if not f:
        return "No", 400
    data = f.read().decode("utf-8")
    try:
        obj = yaml.load(data, Loader=yaml.FullLoader)
        return jsonify({"type": type(obj).__name__})
    except Exception as e:
        return str(e), 400

@app.route("/redir")
def redir():
    to = request.args.get("to", "/")
    return redirect(to)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)
