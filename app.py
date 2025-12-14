import os
import re
import logging
import requests
from datetime import datetime
from flask import Flask, request, Response, jsonify
from Crypto.Cipher import AES

# ================= FLASK =================
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ================= CONFIG =================
# Keys are stored lowercase for case-insensitive lookup
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

# ==================================================
# UNIVERSAL AES COOKIE PARSER (FIXED)
# ==================================================
def extract_hex_values(html):
    """
    Extracts AES key, IV and ciphertext from JS challenge page
    """
    matches = re.findall(
        r'toNumbers\(["\']([0-9a-fA-F]+)["\']\)', html
    )
    if len(matches) >= 3:
        return matches[0], matches[1], matches[2]

    fallback = re.findall(r'\b[0-9a-fA-F]{32,}\b', html)
    if len(fallback) >= 3:
        return fallback[0], fallback[1], fallback[2]

    return None, None, None


def hexpair(s):
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


def pkcs7_unpad(data):
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def compute_cookie(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        html = r.text

        a_hex, b_hex, c_hex = extract_hex_values(html)
        if not a_hex:
            logging.error("AES hex extraction failed")
            return url, None

        key = hexpair(a_hex)
        iv = hexpair(b_hex)
        ct = hexpair(c_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = pkcs7_unpad(cipher.decrypt(ct))
        cookie = pt.hex()

        m = re.search(r'location\.href\s*=\s*"([^"]+)"', html)
        target = m.group(1) if m else url

        return target, cookie

    except Exception as e:
        logging.error(f"Cookie compute error: fuck")
        return url, None

# ==================================================
# API ENDPOINT
# ==================================================
@app.route("/api", methods=["GET"])
def proxy():
    raw_key = request.args.get("key", "")
    type_ = request.args.get("type", "").lower()
    term = request.args.get("term", "")

    key = requests.utils.unquote(raw_key).lower()

    if not key:
        return jsonify(success=False, error="Missing API key"), 401

    expiry = VALID_KEYS.get(key)
    if not expiry:
        return jsonify(success=False, error="Invalid API key"), 401

    if datetime.utcnow() > expiry:
        return jsonify(success=False, error="API key expired"), 410

    if not type_ or not term:
        return jsonify(success=False, error="Missing type or term"), 400

    ROUTES = {
        "mobile": f"https://zionix.rf.gd/proxy.php?type=mobile&term={term}",
        "aadhar": f"http://zionix.rf.gd/proxy.php?type=id_number&term={term}",
        "pak": f"http://shaurya-number-lookup.xo.je/proxy.php?type=pak&term={term}",
        "user": f"https://tginfo-zionix.vercel.app/user-details?user={term}",
        "email": f"http://zionix.rf.gd/proxy.php?mode=mailinfo&term={term}",
        "vehicle": f"https://zionix.rf.gd/proxy.php?type=rc&term={term}",
        "instagram": f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={term}",
    }

    target_url = ROUTES.get(type_)
    if not target_url:
        return jsonify(success=False, error="Unknown type"), 400

    session = requests.Session()
    session.headers.update(HEADERS)

    # JS cookie required routes
    if type_ in ("mobile", "aadhar", "vehicle"):
        target_url, cookie = compute_cookie(target_url)
        if not cookie:
            return jsonify(success=False, error="JS challenge failed"), 502
        session.cookies.set("__test", cookie)

    try:
        resp = session.get(
            target_url,
            timeout=20,
            allow_redirects=True
        )
    except requests.RequestException:
        return jsonify(success=False, error="Target fetch failed"), 502

    excluded = {"content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    headers.append(("X-Join", "Join @zionix_portal"))

    return Response(resp.content, resp.status_code, headers)

# ==================================================
# RUN
# ==================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)