import os
import re
import logging
import requests
from datetime import datetime
from flask import Flask, request, Response, jsonify
from Crypto.Cipher import AES

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- CONFIG ---
# store keys lowercased to make lookups case-insensitive
VALID_KEYS = {
    "vald7": datetime(2025, 11, 15, 23, 59, 59),
    "keyneverzion6601": datetime(2095, 11, 30, 23, 59, 59),
    "zionix777": datetime(2026, 11, 27, 23, 59, 59),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "http://zionix.rf.gd/"
}

# ================================================
# UNIVERSAL AES COOKIE PARSER
# ================================================
def extract_hex_values(html):
    """
    Universal regex that matches JS hex arrays or long hex strings.
    """
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
            logging.error("Hex extraction failed (site changed?)")
            return url, None

        key = hexpair(a_hex)
        iv = hexpair(b_hex)
        ct = hexpair(c_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt = pkcs7_unpad(pt)
        cookie = pt.hex()

        m = re.search(r'location.href\s*=\s*"([^"]+)"', html)
        target = m.group(1) if m else url

        return target, cookie
    except Exception as e:
        logging.error(f"Cookie compute error: {e}")
        return url, None


# ================================================
# PROXY ENDPOINT
# ================================================
@app.route("/api", methods=["GET"])
def proxy():
    raw_key = request.args.get("key", "")
    type_ = request.args.get("type", "")
    term = request.args.get("term", "")

    # URL-decode and normalize key to lowercase for case-insensitive lookup
    key = requests.utils.unquote(raw_key).lower()

    if not key:
        return jsonify({"success": False, "error": "Missing API key", "message": "Join @zionix_portal"}), 401

    expiry = VALID_KEYS.get(key)
    if not expiry:
        return jsonify({"success": False, "error": "Invalid key", "message": "Join @zionix_portal"}), 401

    if datetime.utcnow() > expiry:
        return jsonify({"success": False, "error": "api key expired", "message": "Join @zionix_portal"}), 410

    if not type_ or not term:
        return jsonify({"success": False, "error": "Missing type or term", "message": "Join @zionix_portal"}), 400

    ROUTES = {
        "mobile": lambda t: f"https://zionix.rf.gd/proxy.php?type=mobile&term={t}",
        "aadhar": lambda t: f"http://zionix.rf.gd/proxy.php?mode=id_number&term={t}",
        "pak": lambda t: f"http://shaurya-number-lookup.xo.je/proxy.php?type=pak&term={t}",
        "user": lambda t: f"https://tginfo-zionix.vercel.app/user-details?user={t}",
        "vehicle": lambda t: f"https://zionix.rf.gd/proxy.php?type=rc&term={t}",
        "instagram": lambda t: f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={t}",
    }

    route_fn = ROUTES.get(type_.lower())
    if not route_fn:
        return jsonify({"success": False, "error": f"Unknown type '{type_}'", "message": "Join @zionix_portal"}), 400

    target_url = route_fn(term)
    logging.info("Proxy request -> %s", target_url)

    session = requests.Session()

    if type_.lower() in ["mobile", "aadhar", "family"]:
        target_url, cookie_val = compute_cookie(target_url)
        if not cookie_val:
            return jsonify({"success": False, "error": "Failed to compute cookie", "message": "Join @zionix_portal"}), 500
        session.cookies.update({"__test": cookie_val})

    try:
        resp = session.get(target_url, headers=HEADERS, timeout=(5, 20), stream=True, allow_redirects=True)
    except requests.RequestException as e:
        logging.error("Request failed: %s")
        return jsonify({"success": False, "error": f"Failed to fetch target URL: contact @TalktozionixBot", "message": "Join @zionix_portal"}), 502

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    headers.append(("X-Join", "Join @zionix_portal"))

    return Response(resp.iter_content(chunk_size=8192), status=resp.status_code, headers=headers)


# --- Run server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=True only for local dev; remove or set False in production
    app.run(host="0.0.0.0", port=port, debug=True)