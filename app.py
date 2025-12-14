import os
import re
import logging
import requests
from datetime import datetime
from flask import Flask, request, Response, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ================= CONFIG =================
VALID_KEYS = {
    "vald7": datetime(2025, 11, 15, 23, 59, 59),
    "keyneverzion6601": datetime(2095, 11, 30, 23, 59, 59),
    "zionix777": datetime(2026, 11, 27, 23, 59, 59),
}

HEADERS = {
    "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36",
    "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "application/json;q=0.8,*/*;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Referer": "http://zionix.rf.gd/",
}

# ================= AES COOKIE =================
def extract_hex_values(html):
    matches = re.findall(r'toNumbers\(["\']([0-9a-fA-F]+)["\']\)', html)
    if len(matches) >= 3:
        return matches[:3]

    fallback = re.findall(r'\b[0-9a-fA-F]{32,}\b', html)
    if len(fallback) >= 3:
        return fallback[:3]

    return None, None, None


def hexpair(s):
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def pkcs7_unpad(d):
    pad = d[-1]
    if 1 <= pad <= 16 and d[-pad:] == bytes([pad]) * pad:
        return d[:-pad]
    return d


def compute_cookie(url):
    r = requests.get(url, headers=HEADERS, timeout=15)
    html = r.text

    a, b, c = extract_hex_values(html)
    if not a:
        return url, None

    cipher = AES.new(hexpair(a), AES.MODE_CBC, hexpair(b))
    pt = pkcs7_unpad(cipher.decrypt(hexpair(c)))
    cookie = pt.hex()

    m = re.search(r'location\.href\s*=\s*"([^"]+)"', html)
    target = m.group(1) if m else url

    return target, cookie

# ================= API =================
@app.route("/api", methods=["GET"])
def api():
    key = requests.utils.unquote(request.args.get("key", "")).lower()
    type_ = request.args.get("type", "").lower()
    term = request.args.get("term", "")

    if not key:
        return jsonify(error="Missing API key"), 401

    expiry = VALID_KEYS.get(key)
    if not expiry:
        return jsonify(error="Invalid API key"), 401

    if datetime.utcnow() > expiry:
        return jsonify(error="API key expired"), 410

    if not type_ or not term:
        return jsonify(error="Missing type or term"), 400

    ROUTES = {
        "mobile": f"https://zionix.rf.gd/proxy.php?type=mobile&term={term}",
        "aadhar": f"http://zionix.rf.gd/proxy.php?type=id_number&term={term}",
        "pak": f"http://zionix.rf.gd/proxy.php?type=pak&term={term}",
        "email": f"http://zionix.rf.gd/proxy.php?mode=mailinfo&term={term}",
        "vehicle": f"https://zionix.rf.gd/proxy.php?type=rc&term={term}",
        "instagram": f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={term}",
    }

    target = ROUTES.get(type_)
    if not target:
        return jsonify(error="Unknown type"), 400

    session = requests.Session()
    session.headers.update(HEADERS)

    if type_ in ("mobile", "aadhar"):
        target, cookie = compute_cookie(target)
        if not cookie:
            return jsonify(error="Cookie challenge failed"), 502
        session.cookies.set("__test", cookie)

    try:
        resp = session.get(target, timeout=20, allow_redirects=True)
    except Exception:
        return jsonify(error="Target fetch failed"), 502

    excluded = {"content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

    return Response(resp.content, resp.status_code, headers)

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))