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
VALID_KEYS = {
    "VALD7": datetime(2025, 11, 15, 23, 59, 59),
    "EXAMKI@##QW": datetime(2025, 11, 30, 23, 59, 59),  # NEW KEY
}

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": "http://shaurya-number-lookup.xo.je/"
}


# ================================================
# UNIVERSAL AES COOKIE PARSER (FIXED)
# ================================================
def extract_hex_values(html):
    """
    New universal regex that matches ANY hex array used in JS.
    Works even if site changes formatting.
    """

    # match: toNumbers("hex")
    matches = re.findall(r'toNumbers\(["\']([0-9a-fA-F]+)["\']\)', html)

    if len(matches) >= 3:
        return matches[0], matches[1], matches[2]

    # fallback: find ANY hex strings of correct length
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
        pt = pkcs7_unpad(cipher.decrypt(ct))
        cookie = pt.hex()

        # redirect target page
        m = re.search(r'location.href\s*=\s*"([^"]+)"', html)
        target = m.group(1) if m else url

        return target, cookie

    except Exception as e:
        logging.error(f"Cookie compute error: {e}")
        return url, None


# ================================================
# PROXY ENDPOINT
# ================================================
@app.route("/api")
def api():
    key = request.args.get("key", "")
    type_ = request.args.get("type", "")
    term = request.args.get("term", "")

    # Auto-decode URL-encoded keys (%40, %23, etc)
    key = requests.utils.unquote(key)

    if key not in VALID_KEYS:
        return jsonify({
            "success": False,
            "error": "Invalid key",
            "message": "Join @zionix_portal"
        }), 401

    if datetime.utcnow() > VALID_KEYS[key]:
        return jsonify({
            "success": False,
            "error": "Key expired",
            "message": "Join @zionix_portal"
        }), 410

    if not type_ or not term:
        return jsonify({
            "success": False,
            "error": "Missing type or term",
            "message": "Join @zionix_portal"
        }), 400

    ROUTES = {
        "mobile": lambda t: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=mobile&term={t}",
        "aadhar": lambda t: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=aadhar&term={t}",
        "family": lambda t: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=family&term={t}",
        "user": lambda t: f"https://tg-info-neon.vercel.app/user-details?user={t}",
        "vehicle": lambda t: f"https://anmol-vehicle-info.vercel.app/vehicle_info?vehicle_no={t}",
        "instagram": lambda t: f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={t}",
    }

    if type_.lower() not in ROUTES:
        return jsonify({
            "success": False,
            "error": "Unknown type",
            "message": "Join @zionix_portal"
        }), 400

    target_url = ROUTES[type_.lower()](term)
    session = requests.Session()

    if type_.lower() in ["mobile", "aadhar", "family"]:
        target_url, cookie = compute_cookie(target_url)
        if not cookie:
            return jsonify({
                "success": False,
                "error": "Failed to compute cookie",
                "message": "Join @zionix_portal"
            }), 500

        session.cookies.update({"__test": cookie})

    try:
        resp = session.get(target_url, headers=HEADERS, timeout=20, stream=True)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "message": "Join @zionix_portal"
        }), 502

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

    headers.append(("X-Join", "Join @zionix_portal"))

    return Response(resp.iter_content(8192), status=resp.status_code, headers=headers)


# --- Run ---
if __name__ == "__main__":
    app.run(port=5000, debug=True)        return (
            jsonify({"success": False, "error": "api key expired", "message": "Join @zionix_portal"}),
            410,
        )

    if not type_ or not term:
        return (
            jsonify({"success": False, "error": "Missing type or term", "message": "Join @zionix_portal"}),
            400,
        )

    route_fn = ROUTES.get(type_.lower())
    if not route_fn:
        return (
            jsonify({"success": False, "error": f"Unknown type '{type_}'", "message": "Join @zionix_portal"}),
            400,
        )

    target_url = route_fn(term)
    logging.info("Proxy request -> %s", target_url)

    session = requests.Session()

    # For some routes compute cookie first
    if type_.lower() in ["mobile", "aadhar", "family"]:
        target_url, cookie_val = compute_cookie(target_url)
        if not cookie_val:
            return (
                jsonify({"success": False, "error": "Failed to compute cookie", "message": "Join @zionix_portal"}),
                500,
            )
        # set cookie
        session.cookies.update({"__test": cookie_val})

    try:
        resp = session.get(target_url, headers=HEADERS, timeout=(5, 20), stream=True, allow_redirects=True)
    except requests.RequestException as e:
        logging.error("Request failed: %s", e)
        return (
            jsonify({"success": False, "error": f"Failed to fetch target URL: {e}", "message": "Join @zionix_portal"}),
            502,
        )

    # Remove hop-by-hop headers
    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}

    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    # add the requested join message into response headers so it appears "sab mei"
    headers.append(("X-Join", "Join @zionix_portal"))

    return Response(resp.iter_content(chunk_size=8192), status=resp.status_code, headers=headers)


# --- Run server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=True only for local dev; remove or set False in production
    app.run(host="0.0.0.0", port=port, debug=True)
