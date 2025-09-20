from flask import Flask, request, redirect, send_from_directory, jsonify
import sqlite3
import subprocess
import pickle
import os

app = Flask(__name__)
DB = "vuln.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'pass123')")
    conn.commit()
    conn.close()

init_db()

@app.route("/login_insecure", methods=["POST"])
def login_insecure():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    if row:
        return "Logged in as user id: %s" % row[0]
    return "Invalid credentials", 401

@app.route("/ping", methods=["GET"])
def ping():
    target = request.args.get("host", "127.0.0.1")
    out = subprocess.getoutput(f"ping -c 1 {target}")
    return "<pre>%s</pre>" % out

@app.route("/upload_pickle", methods=["POST"])
def upload_pickle():
    f = request.files.get("file")
    if not f:
        return "No file", 400
    data = f.read()
    try:
        obj = pickle.loads(data)
        return jsonify({"type": type(obj).__name__, "repr": repr(obj)[:200]})
    except Exception as e:
        return f"Error: {e}", 400

@app.route("/upload_file", methods=["POST"])
def upload_file():
    f = request.files.get("file")
    if not f:
        return "No file", 400
    filename = f.filename
    dest = os.path.join(UPLOAD_DIR, filename)
    f.save(dest)
    return f"Saved to {dest}"

@app.route("/get_upload/<path:filename>")
def get_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename)

API_KEY = "SECRET_API_KEY_123456"

@app.route("/api/data")
def api_data():
    key = request.args.get("key", "")
    if key == API_KEY:
        return jsonify({"secret": "sensitive-data"})
    return "Forbidden", 403

@app.route("/redirect")
def open_redirect():
    url = request.args.get("to", "/")
    return redirect(url)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
