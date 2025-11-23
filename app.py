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
# Keep existing key VALD7 (as requested) and add Examki@##qw valid until 30 Nov 2025
VALID_KEYS = {
    "VALD7": datetime(2025, 11, 15, 23, 59, 59),
    "Examki@##qw": datetime(2025, 11, 30, 23, 59, 59),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/117 Safari/537.36",
    "Referer": "http://shaurya-number-lookup.xo.je/",
}

# --- ROUTES ---
ROUTES = {
    "mobile": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=mobile&term={term}",
    "aadhar": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=aadhar&term={term}",
    "family": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=family&term={term}",
    "user": lambda term: f"https://tg-info-neon.vercel.app/user-details?user={term}",
    "vehicle": lambda term: f"https://anmol-vehicle-info.vercel.app/vehicle_info?vehicle_no={term}",
    "instagram": lambda term: f"https://insta-profile-info-api.vercel.app/api/instagram.php?username={term}",
}

# --- Helper for AES cookie computation ---
def hexpairs_to_bytes(s: str) -> bytes:
    # if odd length, prefix '0'
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)


def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b


def compute_cookie(url: str):
    """
    Fetch page at url, extract hex values, decrypt AES CBC to get cookie.
    Returns (target_url, cookie_hexstr) or (url, None) on failure.
    """
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        html = r.text

        # This pattern was in your original -- keep it as-is (contains special markers).
        hex_matches = re.findall(r'toNumbers"([0-9a-fA-F]+)"', html)
        if len(hex_matches) < 3:
            logging.info("Not enough hex matches found for cookie computation.")
            return url, None

        a_hex, b_hex, c_hex = hex_matches[0], hex_matches[1], hex_matches[2]

        key = hexpairs_to_bytes(a_hex)
        iv = hexpairs_to_bytes(b_hex)
        ct = hexpairs_to_bytes(c_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt = pkcs7_unpad(pt)
        cookie_val = pt.hex()

        m_href = re.search(r'location.href\s*=\s*"([^"]+)"', html)
        target_url = m_href.group(1) if m_href else url
        return target_url, cookie_val
    except Exception as e:
        logging.error("Failed to compute cookie: %s", e)
        return url, None


# --- Proxy endpoint ---
@app.route("/api", methods=["GET"])
def proxy():
    key = request.args.get("key", "")
    type_ = request.args.get("type", "")
    term = request.args.get("term", "")

    # --- Key & expiry checks ---
    if not key:
        return (
            jsonify({"success": False, "error": "Missing API key", "message": "Join @zionix_portal"}),
            401,
        )

    expiry = VALID_KEYS.get(key)
    if not expiry:
        return (
            jsonify({"success": False, "error": "Invalid key", "message": "Join @zionix_portal"}),
            401,
        )

    if datetime.utcnow() > expiry:
        return (
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
