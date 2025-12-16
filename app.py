import os
import re
import logging
import requests
from datetime import datetime
from flask import Flask, request, Response, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ================================================
# CONFIG
# ================================================
VALID_KEYS = {
    "vald7": datetime(2025, 11, 15, 23, 59, 59),
    "keyneverzion6601": datetime(2095, 11, 30, 23, 59, 59),
    "zionix777": datetime(2024, 11, 27, 23, 59, 59),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "https://zionix.rf.gd/"
}

# ================================================
# AES COOKIE PARSER
# ================================================
def extract_hex_values(html):
    matches = re.findall(r'toNumbers\(["\']([0-9a-fA-F]+)["\']\)', html)
    if len(matches) >= 3:
        return matches[0], matches[1], matches[2]

    fallback = re.findall(r'\b[0-9a-fA-F]{32,}\b', html)
    if len(fallback) >= 3:
        return fallback[0], fallback[1], fallback[2]

    return None, None, None


def hexpair(s):
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)


def pkcs7_unpad(d):
    p = d[-1]
    if 1 <= p <= AES.block_size and d[-p:] == bytes([p]) * p:
        return d[:-p]
    return d


def compute_cookie(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        html = r.text

        a_hex, b_hex, c_hex = extract_hex_values(html)
        if not a_hex or not b_hex or not c_hex:
            return url, None

        key = hexpair(a_hex)
        iv = hexpair(b_hex)
        ct = hexpair(c_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = pkcs7_unpad(cipher.decrypt(ct))
        cookie = pt.hex()

        m = re.search(r'location.href\s*=\s*"([^"]+)"', html)
        target = m.group(1) if m else url

        return target, cookie
    except Exception as e:
        logging.error("Cookie error: %s", e)
        return url, None


# ================================================
# API ENDPOINT
# ================================================
@app.route("/api", methods=["GET"])
def proxy():
    raw_key = request.args.get("key")
    type_ = request.args.get("type")
    term = request.args.get("term")

    # ---------------- KEY CHECK ----------------
    if not raw_key:
        return jsonify({
            "success": False,
            "error": "API key missing",
            "message": "Provide a valid API key"
        }), 401

    key = requests.utils.unquote(raw_key).lower()
    expiry = VALID_KEYS.get(key)

    if not expiry:
        return jsonify({
            "success": False,
            "error": "Invalid API key",
            "message": "Your API key is not valid"
        }), 401

    if datetime.utcnow() > expiry:
        return jsonify({
            "success": False,
            "error": "API key expired",
            "message": "Your API key has expired buy new key from zionix (@TalktozionixBot)"
        }), 410

    # ---------------- PARAM CHECK ----------------
    if not type_ or not term:
        return jsonify({
            "success": False,
            "error": "Missing parameters",
            "message": "type and term are required"
        }), 400

    # ---------------- ROUTES ----------------
    ROUTES = {
        "mobile": lambda t: f"https://zionix.rf.gd/proxy.php?type=mobile&term={t}",
        "aadhar": lambda t: f"https://zionix.rf.gd/proxy.php?type=id_number&term={t}",
        "pak": lambda t: f"https://zionix.rf.gd/proxy.php?type=pak&term={t}",
        "user": lambda t: f"https://tginfo-zionix.vercel.app/user-details?user={t}",
        "email": lambda t: f"https://zionix.rf.gd/proxy.php?type=mailinfo&term={t}",
        "vehicle": lambda t: f"https://zionix.rf.gd/proxy.php?type=rc&term={t}",
        "instagram": lambda t: f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={t}",
    }

    route_fn = ROUTES.get(type_.lower())
    if not route_fn:
        return jsonify({
            "success": False,
            "error": "Unknown type",
            "message": f"Type '{type_}' not supported"
        }), 400

    target_url = route_fn(term)
    session = requests.Session()

    # ---------------- JS COOKIE TYPES ----------------
    if type_.lower() in ["mobile", "aadhar","vehicle","email","pak"]:
        target_url, cookie = compute_cookie(target_url)
        if not cookie:
            return jsonify({
                "success": False,
                "error": "JS challenge failed",
                "message": "Unable to bypass JavaScript protection"
            }), 500
        session.cookies.update({"__test": cookie})

    # ---------------- FETCH ----------------
    try:
        resp = session.get(
            target_url,
            headers=HEADERS,
            timeout=(5, 20),
            stream=True,
            allow_redirects=True
        )
    except requests.RequestException:
        return jsonify({
            "success": False,
            "error": "Upstream error",
            "message": "Target site unreachable"
        }), 502

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    headers.append(("X-Join", "Join @zionix_portal"))

    return Response(resp.iter_content(8192), status=resp.status_code, headers=headers)


# ================================================
# RUN
# ================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
