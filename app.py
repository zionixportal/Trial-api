import os, re, json
from flask import Flask, request, Response, jsonify
import requests
from datetime import datetime
from Crypto.Cipher import AES
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- CONFIG ---
VALID_KEY = "VALD7"
EXPIRE_AT = datetime(2025, 11, 15, 23, 59, 59)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/117 Safari/537.36",
    "Referer": "http://shaurya-number-lookup.xo.je/"
}

# --- ROUTES ---
ROUTES = {
    "mobile": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=mobile&term={term}",
    "aadhar": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=aadhar&term={term}",
    "family": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=family&term={term}",
    "user": lambda term: f"https://tginfo-zionix.vercel.app/user-details?user={term}",
    "vehicle": lambda term: f"https://anmol-vehicle-info.vercel.app/vehicle_info?vehicle_no={term}"
}

# --- Helper for AES cookie computation ---
def hexpairs_to_bytes(s):
    if len(s) % 2 != 0:
        s = "0" + s
    return bytes.fromhex(s)

def pkcs7_unpad(b):
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad])*pad:
        return b[:-pad]
    return b

def compute_cookie(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        html = r.text
        hex_matches = re.findall(r'toNumbers\("([0-9a-fA-F]+)"\)', html)
        if len(hex_matches) < 3:
            return url, None
        a_hex, b_hex, c_hex = hex_matches[0], hex_matches[1], hex_matches[2]
        key = hexpairs_to_bytes(a_hex)
        iv  = hexpairs_to_bytes(b_hex)
        ct  = hexpairs_to_bytes(c_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = pkcs7_unpad(cipher.decrypt(ct))
        cookie_val = pt.hex()
        # Try to find redirected URL
        m_href = re.search(r'location\.href\s*=\s*"([^"]+)"', html)
        target_url = m_href.group(1) if m_href else url
        return target_url, cookie_val
    except Exception as e:
        logging.error("Failed to compute cookie: %s", e)
        return url, None

# --- Proxy endpoint ---
@app.route("/api", methods=["GET"])
def proxy():
    key = request.args.get("key")
    type_ = request.args.get("type")
    term = request.args.get("term")

    # --- Key & expiry checks ---
    if key != VALID_KEY:
        return jsonify({"success": False, "error": "Invalid key"}), 401
    if datetime.utcnow() > EXPIRE_AT:
        return jsonify({"success": False, "error": "api key expired dm at @TalktozionixBot for paid api's/njoin:@zionix_portal for more"}), 410
    if not type_ or not term:
        return jsonify({"success": False, "error": "Missing type or term"}), 400

    route_fn = ROUTES.get(type_.lower())
    if not route_fn:
        return jsonify({"success": False, "error": f"Unknown type '{type_}'"}), 400

    target_url = route_fn(term)
    logging.info("Proxy request -> %s", target_url)

    # --- Use cookie method for Shaurya site (mobile/aadhar/family) ---
    SESSION = requests.Session()
    if type_.lower() in ["mobile", "aadhar", "family"]:
        target_url, cookie_val = compute_cookie(target_url)
        if not cookie_val:
            return jsonify({"success": False, "error": "Failed to compute cookie"}), 500
        SESSION.cookies.update({"__test": cookie_val})
    
    try:
        resp = SESSION.get(target_url, headers=HEADERS, timeout=(5, 20), stream=True, allow_redirects=True)
    except requests.RequestException as e:
        logging.error("Request failed: %s", e)
        return jsonify({"success": False, "error": f"Failed to fetch target URL: {e}"}), 502

    excluded = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]

    return Response(resp.iter_content(chunk_size=8192), status=resp.status_code, headers=headers)

# --- Run server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
